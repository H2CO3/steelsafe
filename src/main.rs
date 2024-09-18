#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/", "README.md"))]
#![forbid(unsafe_code)]

use crate::{
    config::Config,
    db::Database,
    tui::State,
    screen::ScreenGuard,
    error::Result,
};

mod db;
mod crypto;
mod config;
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
    let config = Config::from_rc_file()?;
    let db_path = config.ensure_db_dir()?.join("secrets.sqlite3");
    let db = Database::open(db_path)?;
    let state = State::new(db, config.theme)?;
    let app = App::new(state)?;

    app.run()
}
