//! The bulk of the actual user interface logic.

use std::mem;
use std::ops::{ControlFlow, Deref, DerefMut};
use std::time::Duration;
use std::fmt::{self, Debug, Formatter};
use nanosql::Utc;
use zeroize::Zeroizing;
use ratatui::{
    Frame,
    layout::{Rect, Offset, Constraint, Margin},
    text::Line,
    style::Modifier,
    widgets::{
        Clear, Table, TableState, Row, Paragraph,
        block::{Block, BorderType},
    },
    crossterm::event::{self, Event, KeyEventKind, KeyCode, KeyModifiers, MouseEventKind},
};
use tui_textarea::TextArea;
use arboard::Clipboard;
use crate::{
    config::Theme,
    crypto::{EncryptionInput, DecryptionInput},
    db::{Database, Item, DisplayItem, AddItemInput},
    error::{Error, Result},
};


/// The top-level UI state, the basis of rendering.
#[derive(Debug)]
pub struct State {
    db: Database,
    clipboard: ClipboardDebugWrapper,
    theme: Theme,
    is_running: bool,
    passwd_entry: Option<PasswordEntryState>,
    find: Option<FindItemState>,
    new_item: Option<NewItemState>,
    popup_error: Option<Error>,
    items: Vec<DisplayItem>,
    table_state: TableState,
}

impl State {
    pub fn new(db: Database, theme: Theme) -> Result<Self> {
        let items = db.list_items_for_display(None)?;
        let clipboard = ClipboardDebugWrapper(Clipboard::new()?);

        let table_state = TableState::new()
            .with_selected(if items.is_empty() { None } else { Some(0) });

        Ok(State {
            db,
            clipboard,
            theme,
            is_running: true,
            passwd_entry: None,
            find: None,
            new_item: None,
            popup_error: None,
            items,
            table_state,
        })
    }

    /// Returns `true` as long as the application should run.
    /// Once this returns `false`, the application will exit.
    pub const fn is_running(&self) -> bool {
        self.is_running
    }

    /// Top-level widget rendering.
    pub fn draw(&mut self, frame: &mut Frame) {
        let bottom_input_height = 3;
        let mut table_area = {
            let mut area = frame.area();
            area.height -= bottom_input_height;
            area
        };
        let bottom_input_area = Rect {
            x: table_area.x,
            y: table_area.y + table_area.height,
            width: table_area.width,
            height: bottom_input_height,
        };
        let table = self.main_table();

        if let Some(passwd_entry) = self.passwd_entry.as_mut() {
            frame.render_widget(&passwd_entry.enc_pass, bottom_input_area);
        } else if let Some(find_state) = self.find.as_mut() {
            frame.render_widget(&find_state.search_term, bottom_input_area);
        } else {
            table_area = frame.area();
        }

        frame.render_stateful_widget(table, table_area, &mut self.table_state);

        if let Some(error) = self.popup_error.as_ref() {
            let margin = Margin {
                horizontal: table_area.width.saturating_sub(72 + 2) / 2,
                vertical: table_area.height.saturating_sub(3 + 2) / 2,
            };
            let dialog_area = table_area.inner(margin);
            let modal = self.error_modal(error);

            frame.render_widget(Clear, dialog_area);
            frame.render_widget(modal, dialog_area);
        } else if let Some(new_item) = self.new_item.as_ref() {
            let inputs_total_height = new_item.text_areas().len() as u16 * 3;
            let margin = Margin {
                horizontal: table_area.width.saturating_sub(72 + 2) / 2,
                vertical: table_area.height.saturating_sub(inputs_total_height + 2) / 2,
            };
            let dialog_area = table_area.inner(margin);
            let outer = self.new_item_background(new_item);

            frame.render_widget(Clear, dialog_area);
            frame.render_widget(&outer, dialog_area);

            let label_rect = Rect { height: 3, ..outer.inner(dialog_area) };
            let desc_rect = label_rect.offset(Offset { x: 0, y: 3 });
            let secret_rect = desc_rect.offset(Offset { x: 0, y: 3 });
            let passwd_rect = secret_rect.offset(Offset { x: 0, y: 3 });
            let confirm_rect = passwd_rect.offset(Offset { x: 0, y: 3 });

            frame.render_widget(&new_item.label, label_rect);
            frame.render_widget(&new_item.account, desc_rect);
            frame.render_widget(&new_item.secret, secret_rect);
            frame.render_widget(&new_item.enc_pass, passwd_rect);
            frame.render_widget(&new_item.confirm, confirm_rect);
        }
    }

    fn main_table(&self) -> Table<'static> {
        Table::new(
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
                .style(self.theme.default().add_modifier(Modifier::BOLD))
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
                .border_style(if self.main_table_has_focus() {
                    self.theme.border().add_modifier(Modifier::BOLD)
                } else {
                    self.theme.border()
                })
        ).style(
            self.theme.default()
        )
    }

    fn error_modal(&self, error: &Error) -> Paragraph<'static> {
        let block = Block::bordered()
            .title(" Error ")
            .title_bottom(" <Esc> Close ")
            .border_type(BorderType::Rounded)
            .border_style(self.theme.error().add_modifier(Modifier::BOLD));

        Paragraph::new(format!("\n{error}\n"))
            .centered()
            .block(block)
            .style(self.theme.error())
    }

    fn new_item_background(&self, state: &NewItemState) -> Block<'static> {
        Block::bordered()
            .title(" New secret item ")
            .title_top(Line::from(" <^G> Generate password ").right_aligned())
            .title_bottom(" <Enter> Save ")
            .title_bottom(" <Esc> Cancel ")
            .title_bottom(format!(
                " <^H> {} secret ",
                if state.show_secret { "Hide" } else { "Show" }
            ))
            .title_bottom(format!(
                " <^E> {} encr passwd ",
                if state.show_enc_pass { "Hide" } else { "Show" }
            ))
            .border_type(BorderType::Rounded)
            .style(self.theme.border_highlight())
            .border_style(self.theme.border_highlight().add_modifier(Modifier::BOLD))
    }

    /// Event polling and error handling.
    pub fn handle_events(&mut self) {
        if let Err(error) = self.handle_events_impl() {
            self.popup_error = Some(error);
        }
    }

    /// The bulk of the actual event handling logic.
    fn handle_events_impl(&mut self) -> Result<()> {
        if !event::poll(Duration::from_millis(50))? {
            return Ok(());
        }
        let event = event::read()?;

        let event = match self.handle_error_input(event)? {
            ControlFlow::Break(()) => return Ok(()),
            ControlFlow::Continue(event) => event,
        };
        let event = match self.handle_passwd_entry_input(event)? {
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

        self.handle_main_table_event(event)
    }

    /// Handles events when the main table has focus.
    fn handle_main_table_event(&mut self, event: Event) -> Result<()> {
        if let Event::Mouse(mouse) = event {
            match mouse.kind {
                MouseEventKind::ScrollDown => {
                    self.table_state.select_next();
                }
                MouseEventKind::ScrollUp => {
                    self.table_state.select_previous();
                }
                _ => {}
            }
            return Ok(());
        }

        let Event::Key(key) = event else {
            return Ok(());
        };

        if key.kind != KeyEventKind::Press {
            return Ok(());
        };

        match key.code {
            KeyCode::Up | KeyCode::Char('k' | 'K') => {
                self.table_state.select_previous();
            }
            KeyCode::Down | KeyCode::Tab | KeyCode::Char('j' | 'J') => {
                self.table_state.select_next();
            }
            KeyCode::Char('1') => {
                self.table_state.select_first();
            }
            KeyCode::Char('0') => {
                self.table_state.select_last();
            }
            KeyCode::Char('c' | 'C') | KeyCode::Enter => {
                self.passwd_entry = Some(PasswordEntryState::with_theme(self.theme.clone()));
            }
            KeyCode::Char('f' | 'F' | '/') => {
                // if we are already in find mode, do NOT reset
                // the search term, just give back focus.
                if let Some(find_state) = self.find.as_mut() {
                    find_state.set_focus(true);
                } else {
                    self.find = Some(FindItemState::with_theme(self.theme.clone()));
                }
            }
            KeyCode::Char('n' | 'N') => {
                self.new_item = Some(NewItemState::with_theme(self.theme.clone()));
            }
            KeyCode::Char('q' | 'Q') => {
                self.is_running = false;
            }
            _ => {}
        }

        Ok(())
    }

    /// Handles events when the error modal is open.
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

    /// Handles events for the password entry panel before decrypting a secret.
    fn handle_passwd_entry_input(&mut self, event: Event) -> Result<ControlFlow<(), Event>> {
        let Some(passwd_entry) = self.passwd_entry.as_mut() else {
            return Ok(ControlFlow::Continue(event));
        };

        match event {
            Event::Key(evt) => match evt.code {
                KeyCode::Esc => {
                    self.passwd_entry = None;
                }
                KeyCode::Enter => {
                    let password = Zeroizing::new(passwd_entry.enc_pass.lines().join("\n"));
                    self.passwd_entry = None;
                    self.copy_secret_to_clipboard(&password)?;
                }
                KeyCode::Char('h' | 'H') if evt.modifiers.contains(KeyModifiers::CONTROL) => {
                    passwd_entry.toggle_show_enc_pass();
                }
                _ => {
                    passwd_entry.enc_pass.input(event);
                }
            },
            _ => {
                passwd_entry.enc_pass.input(event);
            }
        }

        Ok(ControlFlow::Break(()))
    }

    /// Handles events for the Find panel.
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
                    find_state.set_focus(false);
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

    /// Handles events for the "New item" dialog.
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
                    // close dialog even if an error occurred
                    let new_item = self.new_item.take().expect("just checked that new_item is Some");
                    let added = new_item.add_item(&self.db)?;

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
                KeyCode::Char('g' | 'G') if evt.modifiers.contains(KeyModifiers::CONTROL) => {
                    new_item.generate_random_password();
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

    /// Reloads the contents of the database from disk to memory.
    /// If `adjust_selection` is set, the last item of the table
    /// will be selected. This is useful after certain operations
    /// that act destructively on the table state (e.g., search).
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

    /// Actually copy the decrypted plaintext secret to the clipboard.
    /// We can't zeroize the clipboard content, so we don't even bother.
    fn copy_secret_to_clipboard(&mut self, enc_pass: &str) -> Result<()> {
        let index = self.table_state.selected().ok_or(Error::SelectionRequired)?;
        let uid = self.items[index].uid;
        let item = self.db.item_by_id(uid)?;

        let input = DecryptionInput {
            encrypted_secret: &item.encrypted_secret,
            kdf_salt: item.kdf_salt,
            auth_nonce: item.auth_nonce,
            label: item.label.as_str(),
            account: item.account.as_deref(),
            last_modified_at: item.last_modified_at,
        };
        let plaintext_secret = input.decrypt_and_verify(enc_pass.as_bytes())?;

        // we do NOT use `String::from_utf8()`, because that would copy the
        // bytes, and complicate correct zeroization of the secret on error.
        let secret_str = std::str::from_utf8(&plaintext_secret)?;

        self.clipboard.set_text(secret_str).map_err(Into::into)
    }

    /// The main table has focus when none of the other widgets do.
    fn main_table_has_focus(&self) -> bool {
        (
            self.find.is_none()
            ||
            self.find.as_ref().is_some_and(|find| !find.has_focus)
        )
        && self.passwd_entry.is_none()
        && self.new_item.is_none()
        && self.popup_error.is_none()
    }
}

#[derive(Debug)]
struct PasswordEntryState {
    is_visible: bool,
    enc_pass: TextArea<'static>,
    theme: Theme,
}

impl PasswordEntryState {
    fn with_theme(theme: Theme) -> Self {
        let mut enc_pass = TextArea::default();
        enc_pass.set_style(theme.default());

        // set up text field style
        let mut state = PasswordEntryState {
            is_visible: false,
            enc_pass,
            theme,
        };
        state.set_visible(false);
        state
    }

    fn toggle_show_enc_pass(&mut self) {
        self.set_visible(!self.is_visible);
    }

    fn set_visible(&mut self, is_visible: bool) {
        self.is_visible = is_visible;

        if self.is_visible {
            self.enc_pass.clear_mask_char();
        } else {
            self.enc_pass.set_mask_char('●');
        }

        let show_hide_title = format!(
            " <^H> {} password ",
            if self.is_visible { "Hide" } else { "Show" },
        );

        self.enc_pass.set_block(
            Block::bordered()
                .title(" Enter decryption (master) password ")
                .title_bottom(" <Enter> OK ")
                .title_bottom(" <Esc> Cancel ")
                .title_bottom(show_hide_title)
                .border_type(BorderType::Rounded)
                .border_style(self.theme.border().add_modifier(Modifier::BOLD))
        );
    }
}

#[derive(Debug)]
struct FindItemState {
    search_term: TextArea<'static>,
    has_focus: bool,
    theme: Theme,
}

impl FindItemState {
    fn with_theme(theme: Theme) -> Self {
        let mut search_term = TextArea::default();

        search_term.set_block(
            Block::bordered()
                .title(" Search term ")
                .title_bottom(" <Enter> Focus secrets ")
                .title_bottom(" <Esc> Exit search ")
                .border_type(BorderType::Rounded)
        );

        let mut state = FindItemState {
            search_term,
            has_focus: true,
            theme,
        };
        state.set_focus(true);
        state
    }

    fn set_focus(&mut self, has_focus: bool) {
        self.has_focus = has_focus;

        let block = self.search_term.block().cloned().unwrap_or_default();

        if self.has_focus {
            self.search_term.set_style(self.theme.default().add_modifier(Modifier::BOLD));
            self.search_term.set_block(
                block.border_style(self.theme.border().add_modifier(Modifier::BOLD))
            )
        } else {
            self.search_term.set_style(self.theme.default());
            self.search_term.set_block(
                block.border_style(self.theme.border())
            )
        }
    }
}

#[derive(Debug)]
struct NewItemState {
    label: TextArea<'static>,
    account: TextArea<'static>,
    secret: TextArea<'static>,
    enc_pass: TextArea<'static>,
    confirm: TextArea<'static>,
    focused: FocusedTextArea,
    show_secret: bool,
    show_enc_pass: bool,
    theme: Theme,
}

impl NewItemState {
    fn with_theme(theme: Theme) -> Self {
        let mut state = NewItemState {
            label: TextArea::default(),
            account: TextArea::default(),
            secret: TextArea::default(),
            enc_pass: TextArea::default(),
            confirm: TextArea::default(),
            focused: FocusedTextArea::default(),
            show_secret: false,
            show_enc_pass: false,
            theme,
        };

        // set initial styles
        state.set_show_secret(false);
        state.set_show_enc_pass(false);

        let props = [
            ("Title or label",               true),
            ("Username or account",          false),
            ("Secret (to be stored)",        true),
            ("Encryption (master) password", true),
            ("Confirm master password",      true),
        ];
        let border_style = state.theme.border_highlight();

        for (ta, (title, required)) in state.text_areas_mut().into_iter().zip(props) {
            ta.set_block(
                Block::bordered()
                    .title(format!(" {title} "))
                    .border_type(BorderType::Rounded)
                    .border_style(border_style)
            );
            ta.set_placeholder_text(if required { "Required" } else { "Optional" });
        }

        state.set_focused_text_area(FocusedTextArea::default());
        state
    }

    fn text_areas(&self) -> Vec<&TextArea<'static>> {
        vec![
            &self.label,
            &self.account,
            &self.secret,
            &self.enc_pass,
            &self.confirm,
        ]
    }

    fn text_areas_mut(&mut self) -> Vec<&mut TextArea<'static>> {
        vec![
            &mut self.label,
            &mut self.account,
            &mut self.secret,
            &mut self.enc_pass,
            &mut self.confirm,
        ]
    }

    fn focused_text_area(&mut self) -> &mut TextArea<'static> {
        match self.focused {
            FocusedTextArea::Label   => &mut self.label,
            FocusedTextArea::Account => &mut self.account,
            FocusedTextArea::Secret  => &mut self.secret,
            FocusedTextArea::EncPass => &mut self.enc_pass,
            FocusedTextArea::Confirm => &mut self.confirm,
        }
    }

    fn set_focused_text_area(&mut self, which: FocusedTextArea) {
        self.focused = which;

        let highlight_style = self.theme.highlight();

        for ta in self.text_areas_mut() {
            if let Some(block) = ta.block() {
                ta.set_block(block.clone().style(highlight_style));
            }
        }

        let ta = self.focused_text_area();

        if let Some(block) = ta.block() {
            ta.set_block(block.clone().style(highlight_style.add_modifier(Modifier::BOLD)));
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
            self.confirm.clear_mask_char();
        } else {
            self.enc_pass.set_mask_char('●');
            self.confirm.set_mask_char('●');
        }
    }

    fn toggle_show_secret(&mut self) {
        self.set_show_secret(!self.show_secret);
    }

    fn toggle_show_enc_pass(&mut self) {
        self.set_show_enc_pass(!self.show_enc_pass);
    }

    fn generate_random_password(&mut self) {
        let password = crate::crypto::generate_password();
        self.secret.select_all();
        self.secret.insert_str(password.as_str());
    }

    fn add_item(self, db: &Database) -> Result<Item> {
        let label = match self.label.lines() {
            [line] if !line.trim().is_empty() => line.trim(),
            _ => return Err(Error::LabelRequired),
        };
        let account = match self.account.lines() {
            [] => None,
            [line] => if line.trim().is_empty() { None } else { Some(line.trim()) },
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

        let confirm_pass_lines = Zeroizing::new(self.confirm.into_lines());
        let confirm_pass = Zeroizing::new(confirm_pass_lines.join("\n"));

        if enc_pass != confirm_pass {
            return Err(Error::ConfirmPasswordMismatch);
        }

        let encryption_input = EncryptionInput {
            plaintext_secret: secret.as_bytes(),
            label,
            account,
            last_modified_at: Utc::now(),
        };
        let encryption_output = encryption_input.encrypt_and_authenticate(enc_pass.as_bytes())?;

        db.add_item(AddItemInput {
            uid: nanosql::Null, // generate fresh unique ID
            label,
            account,
            last_modified_at: encryption_input.last_modified_at,
            encrypted_secret: encryption_output.encrypted_secret.as_slice(),
            kdf_salt: encryption_output.kdf_salt,
            auth_nonce: encryption_output.auth_nonce,
        })
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
enum FocusedTextArea {
    #[default]
    Label,
    Account,
    Secret,
    EncPass,
    Confirm,
}

impl FocusedTextArea {
    fn next(self) -> Self {
        use FocusedTextArea::*;

        match self {
            Label   => Account,
            Account => Secret,
            Secret  => EncPass,
            EncPass => Confirm,
            Confirm => Label,
        }
    }

    fn prev(self) -> Self {
        use FocusedTextArea::*;

        match self {
            Label   => Confirm,
            Account => Label,
            Secret  => Account,
            EncPass => Secret,
            Confirm => EncPass,
        }
    }
}

/// The sole purpose of this is to implement `Debug` so that it doesn't break literally everything.
struct ClipboardDebugWrapper(Clipboard);

impl Debug for ClipboardDebugWrapper {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Clipboard").finish_non_exhaustive()
    }
}

impl Deref for ClipboardDebugWrapper {
    type Target = Clipboard;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ClipboardDebugWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
