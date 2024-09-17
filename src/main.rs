#![deny(unsafe_code)]

use directories::ProjectDirs;
use crate::{
    db::Database,
    tui::State,
    screen::ScreenGuard,
    error::{Error, Result},
};

mod db;
mod crypto;
mod error;
mod screen;
mod tui;


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

    /// The main run loop.
    fn run(mut self) -> Result<()> {
        while self.state.is_running() {
            self.screen.draw(|frame| self.state.draw(frame))?;
            self.state.handle_events();
        }

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
