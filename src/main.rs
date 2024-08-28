#![deny(unsafe_code)]

use std::ops::ControlFlow;
use std::time::Duration;
use directories::ProjectDirs;
use ratatui::{
    Frame,
    layout::Rect,
    widgets::{Paragraph, block::{Block, BorderType}},
    crossterm::{
        event::{self, Event, KeyEventKind, KeyCode},
    },
};
use tui_textarea::{TextArea, Input};
use crate::{
    db::{Database, Item},
    screen::ScreenGuard,
    error::{Error, Result},
};

mod db;
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

            if self.state.handle_events()? {
                self.state.sync_data()?;
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
    items: Vec<Item>,
}

impl State {
    fn new(db: Database) -> Result<Self> {
        let items = db.list_items()?;
        Ok(State {
            db,
            is_running: true,
            new_item: None,
            items,
        })
    }

    fn draw(&self, frame: &mut Frame) {
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
        frame.render_widget(
            Paragraph::new("Hello World!").block(
                Block::bordered().title(" Secrets ").border_type(BorderType::Rounded)
            ),
            table_area,
        );
        frame.render_widget(
            Paragraph::new(
                " [C]opy to clipboard    [V]iew secret    [N]ew item    [D]elete    [Q]uit"
            ).block(
                Block::bordered().title(" Actions ").border_type(BorderType::Rounded)
            ),
            help_area,
        );
        if let Some(new_item) = self.new_item.as_ref() {
            frame.render_widget(&new_item.text_area, help_area);
        }
    }

    /// Returns `Ok(true)` if the state needs to be synced due to the handled events.
    fn handle_events(&mut self) -> Result<bool> {
        if !event::poll(Duration::from_millis(50))? {
            return Ok(false);
        }
        let event = event::read()?;
        let event = match self.handle_text_input(event) {
            ControlFlow::Break(redraw) => return Ok(redraw),
            ControlFlow::Continue(event) => event,
        };

        let Event::Key(key) = event else {
            return Ok(false)
        };

        if key.kind != KeyEventKind::Press {
            return Ok(false)
        };

        Ok(match key.code {
            KeyCode::Char('n' | 'N') => {
                self.new_item = Some(NewItemState::default());
                true
            }
            KeyCode::Char('q' | 'Q') => {
                self.is_running = false;
                false
            }
            KeyCode::Esc => {
                self.new_item = None;
                true
            }
            _ => false
        })
    }

    fn handle_text_input(&mut self, event: Event) -> ControlFlow<bool, Event> {
        // if the input text area is not open, ignore the event and give it back right away
        let Some(new_item) = self.new_item.as_mut() else {
            return ControlFlow::Continue(event);
        };

        match event {
            Event::Key(evt) if evt.code == KeyCode::Esc => return ControlFlow::Continue(event),
            // Event::Key(KeyCode::Enter) => {
                // TODO: store the text just entered
            // }
            _ => {}
        }

        new_item.text_area.input(event);

        ControlFlow::Break(true)
    }

    fn sync_data(&mut self) -> Result<()> {
        self.items = self.db.list_items()?;
        Ok(())
    }
}

#[derive(Default, Debug)]
struct NewItemState {
    label: String,
    description: String,
    secret: String,
    text_area: TextArea<'static>,
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
