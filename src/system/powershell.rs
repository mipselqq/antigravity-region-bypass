//! Windows PowerShell is a system dependency; resolve it independently of PATH.
use std::{ffi::OsString, io, os::windows::ffi::OsStringExt, path::PathBuf, process::Command};

pub fn executable() -> io::Result<PathBuf> {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    // Query Windows itself: environment variables and the current directory can
    // be changed by launchers, and PATH can omit WindowsPowerShell entirely.
    let mut buffer = vec![0u16; 260];
    loop {
        let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if length == 0 {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("Не удалось определить системный каталог Windows: {error}"),
            ));
        }
        if (length as usize) < buffer.len() {
            let path = PathBuf::from(OsString::from_wide(&buffer[..length as usize]))
                .join(r"WindowsPowerShell\v1.0\powershell.exe");
            match path.metadata() {
                Ok(metadata) if metadata.is_file() => return Ok(path),
                Ok(_) => return Err(io::Error::new(io::ErrorKind::NotFound, "Системный путь Windows PowerShell не является файлом")),
                Err(error) => return Err(io::Error::new(error.kind(), format!(
                    "Windows PowerShell недоступен по системному пути {}: {error}. Проверьте наличие и доступность этого компонента Windows.",
                    path.display()
                ))),
            }
        }
        if length > 32768 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Некорректная длина системного пути Windows",
            ));
        }
        buffer.resize(length as usize, 0);
    }
}

pub fn command() -> io::Result<Command> {
    let mut command = Command::new(executable()?);
    super::process::no_window(&mut command);
    Ok(command)
}
