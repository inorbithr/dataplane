//! Opens an address in the desktop's default browser (`open` on macOS, `xdg-open`
//! elsewhere), with nothing of its output on ours.

use std::process::{Child, Command, Stdio};

/// The program that opens addresses here.
#[must_use]
pub fn opener() -> &'static str {
    if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    }
}

/// Starts the opener on `url`; the caller waits on it or lets it go.
///
/// # Errors
/// The opener could not be started.
pub fn open(url: &str) -> std::io::Result<Child> {
    Command::new(opener())
        .arg(url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}
