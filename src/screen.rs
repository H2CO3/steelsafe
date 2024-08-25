//! A guard object that makes sure the screen and terminal mode
//! is always restored, even when an error or panic occurs.

use std::ops::{Deref, DerefMut};
use std::io::{self, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    crossterm::{
        terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
        ExecutableCommand,
    },
};
use crate::error::{Error, Result};


static IS_OPEN: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub struct ScreenGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl ScreenGuard {
    pub fn open() -> Result<Self> {
        let mut result = Err(Error::ScreenAlreadyOpen);

        // only set the flag to true if we successfully acquired the terminal
        let _ = IS_OPEN.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |flag| {
            if flag {
                result = Err(Error::ScreenAlreadyOpen);
                return None;
            }

            if let Err(error) = terminal::enable_raw_mode() {
                result = Err(error.into());
                return None;
            }

            if let Err(error) = io::stdout().execute(EnterAlternateScreen) {
                result = Err(error.into());
                return None;
            }

            match Terminal::new(CrosstermBackend::new(io::stdout())) {
                Ok(terminal) => {
                    result = Ok(ScreenGuard { terminal });
                    Some(true)
                }
                Err(error) => {
                    result = Err(error.into());
                    None
                }
            }
        });

        result
    }

    /*
    pub fn close(mut self) -> Result<()> {
        self.finalize()
    }
    */

    fn finalize(&mut self) -> Result<()> {
        terminal::disable_raw_mode()?;
        io::stdout().execute(LeaveAlternateScreen)?;
        IS_OPEN.store(false, Ordering::SeqCst);
        Ok(())
    }
}

impl Deref for ScreenGuard {
    type Target = Terminal<CrosstermBackend<Stdout>>;

    fn deref(&self) -> &Self::Target {
        &self.terminal
    }
}

impl DerefMut for ScreenGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.terminal
    }
}

impl Drop for ScreenGuard {
    fn drop(&mut self) {
        if let Err(error) = self.finalize() {
            eprintln!("Error restoring terminal: {error:#}");
        }
    }
}
