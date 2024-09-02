#![deny(unsafe_code)]

use std::mem;
use std::ops::ControlFlow;
use std::time::Duration;
use directories::ProjectDirs;
use nanosql::Utc;
use zeroize::Zeroizing;
use ratatui::{
    Frame,
    layout::{Rect, Offset, Constraint},
    style::{Style, Modifier},
    widgets::{
        Clear, Table, TableState, Row, Paragraph,
        block::{Block, BorderType},
    },
    crossterm::{
        event::{self, Event, KeyEventKind, KeyCode, KeyModifiers},
    },
};
use tui_textarea::TextArea;
use crate::{
    crypto::EncryptionInput,
    db::{Database, Item, DisplayItem, AddItemInput},
    screen::ScreenGuard,
    error::{Error, Result},
};

mod db;
mod crypto;
mod error;
mod screen;


#[derive(Debug)]
struct App {
    screen: ScreenGuard,
    state: State,
}

impl App {
    fn new(state: State) -> Result<Self> {
        Ok(App {
            screen: ScreenGuard::open()?,
            state,
        })
    }

    fn run(mut self) -> Result<()> {
        while self.state.is_running {
            self.screen.draw(|frame| self.state.draw(frame))?;

            if let Err(error) = self.state.handle_events() {
                self.state.popup_error = Some(error);
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
struct State {
    db: Database,
    is_running: bool,
    new_item: Option<NewItemState>,
    popup_error: Option<Error>,
    items: Vec<DisplayItem>,
    table_state: TableState,
}

impl State {
    fn new(db: Database) -> Result<Self> {
        let items = db.list_items_for_display()?;

        let table_state = TableState::new()
            .with_selected(if items.is_empty() { None } else { Some(0) });

        Ok(State {
            db,
            is_running: true,
            new_item: None,
            popup_error: None,
            items,
            table_state,
        })
    }

    fn draw(&mut self, frame: &mut Frame) {
        let help_height = 3;
        let table_area = {
            let mut area = frame.area();
            area.height -= help_height;
            area
        };
        let help_area = Rect {
            x: table_area.x,
            y: table_area.y + table_area.height,
            width: table_area.width,
            height: help_height,
        };
        let table = Table::new(
            self.items.iter().map(|item| {
                Row::new([
                    item.label.clone(),
                    item.account.clone().unwrap_or_default(),
                    item.last_modified_at.format("%F %T").to_string(),
                ])
            }),
            [Constraint::Percentage(40), Constraint::Percentage(40), Constraint::Min(24)]
        ).header(
            Row::new(["Title", "Username or account", "Modified at (UTC)"])
        ).highlight_style(
            Modifier::REVERSED
        ).block(
            Block::bordered().title(" Secrets ").border_type(BorderType::Rounded)
        );
        frame.render_stateful_widget(table, table_area, &mut self.table_state);
        frame.render_widget(
            Paragraph::new(
                " [C]opy to clipboard    [V]iew secret    [N]ew item    [D]elete    [Q]uit"
            ).block(
                Block::bordered().title(" Actions ").border_type(BorderType::Rounded)
            ),
            help_area,
        );

        if let Some(error) = self.popup_error.as_ref() {
            let mut dialog_area = table_area;
            if dialog_area.width > 72 + 2 { // allow 72 characters at most, +2 for the borders
                dialog_area.width = 72 + 2;
                dialog_area.x = table_area.x + (table_area.width - dialog_area.width) / 2;
            }
            if dialog_area.height > 3 + 2 {
                dialog_area.height = 3 + 2; // 3 for the message, +2 for the borders
                dialog_area.y = table_area.y + (table_area.height - dialog_area.height) / 2;
            }

            let block = Block::bordered()
                .title(" Error ")
                .title_bottom(" <Esc> Close ")
                .border_type(BorderType::Rounded);

            let msg = Paragraph::new(format!("\n{error}\n"))
                .centered()
                .block(block);

            frame.render_widget(Clear, dialog_area);
            frame.render_widget(msg, dialog_area);
        } else if let Some(new_item) = self.new_item.as_ref() {
            let mut dialog_area = table_area;

            if dialog_area.width > 72 + 2 { // allow 72 characters at most, +2 for the borders
                dialog_area.width = 72 + 2;
                dialog_area.x = table_area.x + (table_area.width - dialog_area.width) / 2;
            }
            if dialog_area.height > 12 + 2 {
                dialog_area.height = 12 + 2; // 3 for each text area, +2 for the borders
                dialog_area.y = table_area.y + (table_area.height - dialog_area.height) / 2;
            }

            let outer = Block::bordered()
                .title(" New secret item ")
                .title_bottom(" <Enter> Save ")
                .title_bottom(" <Esc> Cancel ")
                .title_bottom(format!(
                    " <^H> {} secret ",
                    if new_item.show_secret { "Hide" } else { "Show" }
                ))
                .title_bottom(format!(
                    " <^E> {} enc passwd ",
                    if new_item.show_enc_pass { "Hide" } else { "Show" }
                ))
                .border_type(BorderType::Rounded);

            frame.render_widget(Clear, dialog_area);
            frame.render_widget(&outer, dialog_area);

            dialog_area.width -= 2;

            let label_rect = Rect { height: 3, ..dialog_area }.offset(Offset { x: 1, y: 1 });
            let desc_rect = Rect { height: 3, ..dialog_area }.offset(Offset { x: 1, y: 4 });
            let secret_rect = Rect { height: 3, ..dialog_area }.offset(Offset { x: 1, y: 7 });
            let passwd_rect = Rect { height: 3, ..dialog_area }.offset(Offset { x: 1, y: 10 });

            frame.render_widget(&new_item.label, label_rect);
            frame.render_widget(&new_item.account, desc_rect);
            frame.render_widget(&new_item.secret, secret_rect);
            frame.render_widget(&new_item.enc_pass, passwd_rect);
        }
    }

    fn handle_events(&mut self) -> Result<()> {
        if !event::poll(Duration::from_millis(50))? {
            return Ok(());
        }
        let event = event::read()?;

        let event = match self.handle_error_input(event)? {
            ControlFlow::Break(()) => return Ok(()),
            ControlFlow::Continue(event) => event,
        };
        let event = match self.handle_text_input(event)? {
            ControlFlow::Break(()) => return Ok(()),
            ControlFlow::Continue(event) => event,
        };

        let Event::Key(key) = event else {
            return Ok(());
        };

        if key.kind != KeyEventKind::Press {
            return Ok(());
        };

        match key.code {
            KeyCode::Up => {
                self.table_state.select_previous();
            }
            KeyCode::Down | KeyCode::Tab => {
                self.table_state.select_next();
            }
            KeyCode::Char('1') => {
                self.table_state.select_first();
            }
            KeyCode::Char('0') => {
                self.table_state.select_last();
            }
            KeyCode::Char('n' | 'N') => {
                self.new_item = Some(NewItemState::default());
            }
            KeyCode::Char('q' | 'Q') => {
                self.is_running = false;
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_error_input(&mut self, event: Event) -> Result<ControlFlow<(), Event>> {
        if self.popup_error.is_none() {
            return Ok(ControlFlow::Continue(event));
        }

        match event {
            Event::Key(evt) => match evt.code {
                KeyCode::Esc => {
                    self.popup_error = None;
                }
                _ => {}
            }
            _ => {}
        }

        Ok(ControlFlow::Break(()))
    }

    fn handle_text_input(&mut self, event: Event) -> Result<ControlFlow<(), Event>> {
        // if the input text area is not open, ignore the event and give it back right away
        let Some(new_item) = self.new_item.as_mut() else {
            return Ok(ControlFlow::Continue(event));
        };

        match event {
            Event::Key(evt) => match evt.code {
                KeyCode::Esc => {
                    self.new_item = None;
                }
                KeyCode::Down | KeyCode::Tab => {
                    new_item.cycle_forward();
                }
                KeyCode::Up => {
                    new_item.cycle_back();
                }
                KeyCode::Enter => {
                    let result = mem::take(new_item).add_item(&self.db);
                    self.new_item = None; // close dialog even if an error occurred

                    let added = result?;
                    self.sync_data()?;

                    if let Some((idx, _item)) = self.items
                        .iter()
                        .enumerate()
                        .rev() // the new item will _usually_ be the last one
                        .find(|(_idx, item)| item.uid == added.uid)
                    {
                        self.table_state.select(Some(idx));
                    }
                }
                KeyCode::Char('h' | 'H') if evt.modifiers.contains(KeyModifiers::CONTROL) => {
                    new_item.toggle_show_secret();
                }
                KeyCode::Char('e' | 'E') if evt.modifiers.contains(KeyModifiers::CONTROL) => {
                    new_item.toggle_show_enc_pass();
                }
                _ => {
                    new_item.focused_text_area().input(event);
                }
            },
            _ => {
                new_item.focused_text_area().input(event);
            }
        }

        Ok(ControlFlow::Break(()))
    }

    fn sync_data(&mut self) -> Result<()> {
        self.items = self.db.list_items_for_display()?;
        Ok(())
    }
}

#[derive(Debug)]
struct NewItemState {
    label: TextArea<'static>,
    account: TextArea<'static>,
    secret: TextArea<'static>,
    enc_pass: TextArea<'static>,
    focused: FocusedTextArea,
    show_secret: bool,
    show_enc_pass: bool,
}

impl NewItemState {
    fn text_areas(&mut self) -> impl Iterator<Item = &mut TextArea<'static>> {
        IntoIterator::into_iter([
            &mut self.label,
            &mut self.account,
            &mut self.secret,
            &mut self.enc_pass,
        ])
    }

    fn focused_text_area(&mut self) -> &mut TextArea<'static> {
        match self.focused {
            FocusedTextArea::Label   => &mut self.label,
            FocusedTextArea::Account => &mut self.account,
            FocusedTextArea::Secret  => &mut self.secret,
            FocusedTextArea::EncPass => &mut self.enc_pass,
        }
    }

    fn set_focused_text_area(&mut self, which: FocusedTextArea) {
        self.focused = which;

        for ta in self.text_areas() {
            if let Some(block) = ta.block() {
                ta.set_block(block.clone().style(Style::default()));
            }
        }

        let ta = self.focused_text_area();

        if let Some(block) = ta.block() {
            ta.set_block(
                block.clone().style(
                    Style::default().add_modifier(Modifier::BOLD)
                )
            );
        }
    }

    fn cycle_forward(&mut self) {
        self.set_focused_text_area(self.focused.next());
    }

    fn cycle_back(&mut self) {
        self.set_focused_text_area(self.focused.prev());
    }

    fn set_show_secret(&mut self, flag: bool) {
        self.show_secret = flag;

        if flag {
            self.secret.clear_mask_char();
        } else {
            self.secret.set_mask_char('●');
        }
    }

    fn set_show_enc_pass(&mut self, flag: bool) {
        self.show_enc_pass = flag;

        if flag {
            self.enc_pass.clear_mask_char();
        } else {
            self.enc_pass.set_mask_char('●');
        }
    }

    fn toggle_show_secret(&mut self) {
        self.set_show_secret(!self.show_secret);
    }

    fn toggle_show_enc_pass(&mut self) {
        self.set_show_enc_pass(!self.show_enc_pass);
    }

    fn add_item(self, db: &Database) -> Result<Item> {
        let label = match self.label.lines() {
            [line] if !line.is_empty() => line.trim(),
            _ => return Err(Error::LabelRequired),
        };
        let account = match self.account.lines() {
            [] => None,
            [line] => if line.is_empty() { None } else { Some(line.trim()) },
            _ => return Err(Error::AccountNameSingleLine),
        };

        // Steal the contents of the secret and wrap it in a `Zeroizing`, so
        // that it's cleared upon drop (even if an error occurs).
        let secret_lines = Zeroizing::new(self.secret.into_lines());
        let secret = match secret_lines.as_slice() {
            [] => return Err(Error::SecretRequired),
            [line] if line.is_empty() => return Err(Error::SecretRequired),
            lines => Zeroizing::new(lines.join("\n")),
        };

        // Do the same to the encryption password.
        let mut enc_pass_lines = Zeroizing::new(self.enc_pass.into_lines());
        let enc_pass = match enc_pass_lines.as_mut_slice() {
            [line] if !line.is_empty() => Zeroizing::new(mem::take(line)),
            _ => return Err(Error::EncryptionPasswordRequired),
        };

        let encryption_input = EncryptionInput {
            plaintext_secret: secret.as_bytes(),
            label,
            account,
        };
        let encryption_output = encryption_input.encrypt_and_authenticate(enc_pass.as_bytes())?;

        db.add_item(AddItemInput {
            uid: nanosql::Null,
            label,
            account,
            last_modified_at: Utc::now(),
            encrypted_secret: encryption_output.enc_secret.as_slice(),
            kdf_salt: encryption_output.kdf_salt,
            auth_nonce: encryption_output.auth_nonce,
        })
    }
}

impl Default for NewItemState {
    fn default() -> Self {
        let mut state = NewItemState {
            label: TextArea::default(),
            account: TextArea::default(),
            secret: TextArea::default(),
            enc_pass: TextArea::default(),
            focused: FocusedTextArea::default(),
            show_secret: false,
            show_enc_pass: false,
        };

        // set initial styles
        state.set_show_secret(false);
        state.set_show_enc_pass(false);

        let props = [
            ("Label",   true),
            ("Account", false),
            ("Secret (stored)",  true),
            ("Encryption (master) password", true),
        ];

        for (ta, (title, required)) in state.text_areas().zip(props) {
            ta.set_block(
                Block::bordered().title(format!(" {title} ")).border_type(BorderType::Rounded)
            );
            ta.set_placeholder_text(if required { "Required" } else { "Optional" });
        }

        state.set_focused_text_area(FocusedTextArea::default());
        state
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
enum FocusedTextArea {
    #[default]
    Label,
    Account,
    Secret,
    EncPass,
}

impl FocusedTextArea {
    fn next(self) -> Self {
        use FocusedTextArea::*;

        match self {
            Label   => Account,
            Account => Secret,
            Secret  => EncPass,
            EncPass => Label,
        }
    }

    fn prev(self) -> Self {
        use FocusedTextArea::*;

        match self {
            Label   => EncPass,
            Account => Label,
            Secret  => Account,
            EncPass => Secret,
        }
    }
}

fn main() -> Result<()> {
    let dirs = ProjectDirs::from("org", "h2co3", "steelsafe").ok_or(Error::MissingDatabaseDir)?;
    let db_dir = dirs.data_dir();
    let db_path = db_dir.join("secrets.sqlite3");

    std::fs::create_dir_all(db_dir)?;

    let db = Database::open(db_path)?;
    let state = State::new(db)?;
    let app = App::new(state)?;

    app.run()
}
