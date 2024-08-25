#![deny(unsafe_code)]

use std::time::Duration;
use directories::ProjectDirs;
use ratatui::{
    Frame,
    crossterm::{
        event::{self, Event, KeyEventKind, KeyCode},
    },
    widgets::{Block, Paragraph},
};
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
    items: Vec<Item>,
}

impl State {
    fn new(db: Database) -> Result<Self> {
        let items = db.list_items()?;
        Ok(State {
            db,
            is_running: true,
            items,
        })
    }

    fn draw(&self, frame: &mut Frame) {
        frame.render_widget(
            Paragraph::new("Hello World!").block(Block::bordered().title("Greeting")),
            frame.area(),
        );
    }

    /// Returns `Ok(true)` if the state needs to be synced due to the handled events.
    fn handle_events(&mut self) -> Result<bool> {
        if !event::poll(Duration::from_millis(50))? {
            return Ok(false);
        }

        let Event::Key(key) = event::read()? else { return Ok(false) };

        if (key.kind, key.code) == (KeyEventKind::Press, KeyCode::Char('q')) {
            self.is_running = false;
        }

        Ok(false)
    }

    fn sync_data(&mut self) -> Result<()> {
        self.items = self.db.list_items()?;
        Ok(())
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
