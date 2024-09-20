//! Configures the environment of the application: color themes, database path, etc.

use std::io::ErrorKind;
use std::borrow::Cow;
use std::fs::File;
use std::path::{Path, PathBuf};
use serde::Deserialize;
use directories::{UserDirs, ProjectDirs};
use ratatui::style::{Style, Color};
use crate::error::{Error, Result, ResultExt};


/// Configures the environment of the application.
#[derive(Clone, Default, Debug, Deserialize)]
pub struct Config {
    /// Colors and other TUI style settings.
    #[serde(default)]
    pub theme: Theme,
    /// The path to the password storage directory, where an SQLite database will be created.
    #[serde(default)]
    pub database: Option<PathBuf>,
}

impl Config {
    /// Reads the config from the `.steelsaferc` file if it exists.
    /// Otherwise, returns the default configuration.
    ///
    /// The config is first searched at the [permanent config directory][1],
    /// and then under `$HOME`
    ///
    /// If the file exists but it contains syntax errors, an error is returned.
    pub fn from_rc_file() -> Result<Self> {
        // First, search in the config directory
        if let Ok(project_dirs) = Self::project_dirs() {
            let config_path = project_dirs.config_dir().join(".steelsaferc");
            if let Some(config_file) = Self::open_file_if_exists(&config_path)? {
                // do NOT silently ignore JSON syntax/semantic errors!
                return serde_json::from_reader(config_file).context("Invalid .steelsaferc");
            }
        }

        // If not found, search in $HOME
        if let Some(user_dirs) = UserDirs::new() {
            let config_path = user_dirs.home_dir().join(".steelsaferc");
            if let Some(config_file) = Self::open_file_if_exists(&config_path)? {
                return serde_json::from_reader(config_file).context("Invalid .steelsaferc");
            }
        }

        // not found anywhere, return the built-in default config
        Ok(Config::default())
    }

    fn project_dirs() -> Result<ProjectDirs> {
        ProjectDirs::from("org", "h2co3", "steelsafe").ok_or(Error::MissingDatabaseDir)
    }

    fn open_file_if_exists(path: &Path) -> Result<Option<File>> {
        match File::open(path) {
            Ok(file) => Ok(Some(file)),
            Err(error) => {
                if [ErrorKind::NotFound, ErrorKind::PermissionDenied].contains(&error.kind()) {
                    Ok(None)
                } else {
                    Err(Error::context(error, "Found .steelsaferc but cannot open"))
                }
            }
        }
    }

    /// Creates the directory containing the password database.
    /// Returns its path if creating the directory succeeded.
    pub fn ensure_db_dir(&self) -> Result<Cow<'_, Path>> {
        if let Some(path) = self.database.as_ref() {
            std::fs::create_dir_all(path)?;
            return Ok(path.into());
        }

        let dirs = Self::project_dirs()?;
        let db_dir = dirs.data_dir();

        std::fs::create_dir_all(db_dir)?;

        Ok(db_dir.to_owned().into())
    }
}

/// A pair of background and foreground colors.
#[derive(Clone, Default, Debug, Deserialize)]
pub struct ColorPair {
    /// The background color.
    #[serde(default)]
    pub bg: Option<Color>,
    /// The foreground color.
    #[serde(default)]
    pub fg: Option<Color>,
}

/// Colors and other TUI style settings.
#[derive(Clone, Default, Debug, Deserialize)]
pub struct Theme {
    /// The default colors, for general content/text.
    #[serde(default)]
    pub default: ColorPair,
    /// Colors for important content.
    #[serde(default)]
    pub highlight: ColorPair,
    /// Colors for block/box borders.
    #[serde(default)]
    pub border: ColorPair,
    /// Colors for block/box borders around important content.
    #[serde(default)]
    pub border_highlight: ColorPair,
    /// Text and border colors for error reporting.
    #[serde(default)]
    pub error: ColorPair,
}

impl Theme {
    pub fn default(&self) -> Style {
        Style::default()
            .bg(self.default.bg.unwrap_or(Color::Black))
            .fg(self.default.fg.unwrap_or(Color::LightYellow))
    }

    pub fn highlight(&self) -> Style {
        Style::default()
            .bg(self.highlight.bg.unwrap_or(Color::LightYellow))
            .fg(self.highlight.fg.unwrap_or(Color::Black))
    }

    pub fn border(&self) -> Style {
        Style::default()
            .bg(self.border.bg.unwrap_or(Color::Black))
            .fg(self.border.fg.unwrap_or(Color::LightCyan))
    }

    pub fn border_highlight(&self) -> Style {
        Style::default()
            .bg(self.border_highlight.bg.unwrap_or(Color::LightYellow))
            .fg(self.border_highlight.fg.unwrap_or(Color::Cyan))
    }

    pub fn error(&self) -> Style {
        Style::default()
            .bg(self.error.bg.unwrap_or(Color::LightYellow))
            .fg(self.error.fg.unwrap_or(Color::LightRed))
    }
}
