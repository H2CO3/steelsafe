//! The bulk of the actual user interface logic.

use std::mem;
use std::ops::ControlFlow;
use std::time::Duration;
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
    error::{Error, Result},
};


#[derive(Debug)]
pub struct State {
    db: Database,
    is_running: bool,
    find: Option<FindItemState>,
    new_item: Option<NewItemState>,
    popup_error: Option<Error>,
    items: Vec<DisplayItem>,
    table_state: TableState,
}

impl State {
    pub fn new(db: Database) -> Result<Self> {
        let items = db.list_items_for_display(None)?;

        let table_state = TableState::new()
            .with_selected(if items.is_empty() { None } else { Some(0) });

        Ok(State {
            db,
            is_running: true,
            find: None,
            new_item: None,
            popup_error: None,
            items,
            table_state,
        })
    }

    pub const fn is_running(&self) -> bool {
        self.is_running
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        let find_height = 3;
        let table_area = {
            let mut area = frame.area();
            area.height -= find_height;
            area
        };
        let find_area = Rect {
            x: table_area.x,
            y: table_area.y + table_area.height,
            width: table_area.width,
            height: find_height,
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
            Block::bordered()
                .title(format!(" SteelSafe v{} ", env!("CARGO_PKG_VERSION")))
                .title_bottom(" [C]opy secret ")
                .title_bottom(" [F]ind ")
                .title_bottom(" [1] First ")
                .title_bottom(" [0] Last ")
                .title_bottom(" [N]ew item ")
                .title_bottom(" [Q]uit ")
                .border_type(BorderType::Rounded)
        );

        if let Some(find_state) = self.find.as_mut() {
            let block = find_state.search_term.block().cloned().unwrap_or_default();
            let block = if find_state.has_focus {
                block.style(Style::default().add_modifier(Modifier::BOLD))
            } else {
                block.style(Style::default())
            };
            find_state.search_term.set_block(block);

            frame.render_stateful_widget(table, table_area, &mut self.table_state);
            frame.render_widget(&find_state.search_term, find_area);
        } else {
            frame.render_stateful_widget(table, frame.area(), &mut self.table_state);
        }

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
                    " <^E> {} encr passwd ",
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

    pub fn handle_events(&mut self) {
        if let Err(error) = self.handle_events_impl() {
            self.popup_error = Some(error);
        }
    }

    fn handle_events_impl(&mut self) -> Result<()> {
        if !event::poll(Duration::from_millis(50))? {
            return Ok(());
        }
        let event = event::read()?;

        let event = match self.handle_error_input(event)? {
            ControlFlow::Break(()) => return Ok(()),
            ControlFlow::Continue(event) => event,
        };
        let event = match self.handle_find_input(event)? {
            ControlFlow::Break(()) => return Ok(()),
            ControlFlow::Continue(event) => event,
        };
        let event = match self.handle_new_input(event)? {
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
            KeyCode::Char('f' | 'F' | '/') => {
                // if we are already in find mode, do NOT reset
                // the search term, just give back focus.
                if let Some(find_state) = self.find.as_mut() {
                    find_state.has_focus = true;
                } else {
                    self.find = Some(FindItemState::default());
                }
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

        if let Event::Key(evt) = event {
            if evt.code == KeyCode::Esc {
                self.popup_error = None;
            }
        }

        Ok(ControlFlow::Break(()))
    }

    fn handle_find_input(&mut self, event: Event) -> Result<ControlFlow<(), Event>> {
        let Some(find_state) = self.find.as_mut() else {
            return Ok(ControlFlow::Continue(event));
        };

        match event {
            Event::Key(evt) => match evt.code {
                KeyCode::Esc => {
                    self.find = None;
                    self.sync_data(true)?;
                    Ok(ControlFlow::Break(()))
                }
                KeyCode::Enter if find_state.has_focus => {
                    find_state.has_focus = false;
                    Ok(ControlFlow::Break(()))
                }
                _ if find_state.has_focus => {
                    find_state.search_term.input(event);
                    self.sync_data(true)?;
                    Ok(ControlFlow::Break(()))
                }
                _ => Ok(ControlFlow::Continue(event))
            }
            _ => Ok(ControlFlow::Continue(event))
        }
    }

    fn handle_new_input(&mut self, event: Event) -> Result<ControlFlow<(), Event>> {
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
                    self.sync_data(false)?;

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

    fn sync_data(&mut self, adjust_selection: bool) -> Result<()> {
        let search_term = self.find.as_ref().and_then(|find_state| {
            find_state
                .search_term
                .lines()
                .first()
                .map(|line| format!("%{}%", line.trim()))
        });
        self.items = self.db.list_items_for_display(search_term.as_deref())?;

        #[allow(unused_parens)]
        if (
            adjust_selection
            &&
            !self.items.is_empty()
            &&
            !self.table_state.selected().is_some_and(|idx| idx < self.items.len())
        ) {
            self.table_state.select_last();
        }

        Ok(())
    }
}

#[derive(Debug)]
struct FindItemState {
    search_term: TextArea<'static>,
    has_focus: bool,
}

impl Default for FindItemState {
    fn default() -> Self {
        let mut search_term = TextArea::default();

        search_term.set_block(
            Block::bordered()
                .title(" Search term ")
                .title_bottom(" <Enter> Focus secrets ")
                .title_bottom(" <Esc> Exit search ")
                .border_type(BorderType::Rounded)
        );

        FindItemState {
            search_term,
            has_focus: true,
        }
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
