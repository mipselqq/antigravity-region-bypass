//! Windows PowerShell is a system dependency; resolve it independently of PATH.
use std::{io, path::PathBuf, process::Output};

pub fn executable() -> io::Result<PathBuf> {
    super::command::executable("powershell").map_err(|error| io::Error::new(error.kind(), format!("Windows PowerShell недоступен: {error}. Проверьте наличие и доступность этого компонента Windows.")))
}

#[cfg(test)]
pub fn command() -> io::Result<std::process::Command> {
    let mut command = std::process::Command::new(executable()?);
    super::process::no_window(&mut command);
    Ok(command)
}

pub fn output(script: &str) -> io::Result<Output> {
    super::command::output(
        "powershell",
        ["-NoProfile", "-NonInteractive", "-Command", script],
    )
}
