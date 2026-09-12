//! Restart Manager is used only to inspect locks. Shutdown uses individual PIDs
//! so Windows cannot broadcast a close event to a console shared with the patcher.
use std::path::PathBuf;

pub fn holders(paths: &[PathBuf]) -> Result<Vec<String>, String> {
    query(paths)
}

pub fn close_application(paths: &[PathBuf]) -> Result<(), String> {
    #[cfg(not(windows))]
    return if holders(paths)?.is_empty() {
        Ok(())
    } else {
        Err("Закройте Antigravity вручную и повторите отключение.".into())
    };
    #[cfg(windows)]
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            // IDE shutdown can make another PID from the snapshot exit while
            // we are trying to stop it. Decide using fresh process/lock state.
            let stop_error = stop_owned_processes(paths).err();
            if running_applications(paths)?.is_empty() && holders(paths)?.is_empty() {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(stop_error.unwrap_or_else(|| {
                    "Приложение не завершило работу. Закройте его вручную и повторите.".into()
                }));
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
}

pub fn running_applications(paths: &[PathBuf]) -> Result<Vec<String>, String> {
    #[cfg(windows)]
    {
        Ok(crate::system::process::snapshot()?
            .iter()
            .filter(|p| owned_application(&p.executable, paths))
            .map(|p| {
                format!(
                    "{} (PID {})",
                    p.executable
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy(),
                    p.pid
                )
            })
            .collect())
    }
    #[cfg(not(windows))]
    holders(paths)
}

#[cfg(windows)]
fn stop_owned_processes(paths: &[PathBuf]) -> Result<(), String> {
    let processes = crate::system::process::snapshot()?;
    let protected = crate::system::process::ancestor_pids(&processes, std::process::id());
    let targets: Vec<_> = processes
        .iter()
        .filter(|p| owned_application(&p.executable, paths))
        .collect();
    if targets.iter().any(|p| protected.contains(&p.pid)) {
        return Err("Патчер запущен из Antigravity. Откройте патчер в отдельном терминале Windows, чтобы закрыть IDE без потери этого окна.".into());
    }
    let mut errors = Vec::new();
    for process in targets {
        if let Err(error) = crate::system::process::terminate_verified(process) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn owned_application(executable: &std::path::Path, paths: &[PathBuf]) -> bool {
    let name = executable
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    let normalize = |path: &std::path::Path| {
        path.to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase()
    };
    if (name.starts_with("language_server") || name == "agy.exe" || name.starts_with("agy-"))
        && name.ends_with(".exe")
    {
        return paths.iter().any(|p| normalize(p) == normalize(executable));
    }
    if matches!(
        name.as_str(),
        "crashpad_handler.exe" | "node.exe" | "rg.exe"
    ) {
        // Bundled helpers belong to the installation only; never target a
        // system-wide Node.js/ripgrep process by its image name.
        return paths.iter().any(|p| {
            let target = normalize(p);
            target
                .find("\\resources\\")
                .is_some_and(|index| normalize(executable).starts_with(&target[..index + 1]))
        });
    }
    if name != "antigravity.exe" {
        return false;
    }
    let Some(parent) = executable.parent() else {
        return false;
    };
    let prefix = format!("{}\\", normalize(parent));
    paths.iter().any(|p| normalize(p).starts_with(&prefix))
}

fn query(paths: &[PathBuf]) -> Result<Vec<String>, String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::{Foundation::ERROR_MORE_DATA, System::RestartManager::*};
        if paths.is_empty() {
            return Ok(vec![]);
        }
        let mut handle = 0;
        let mut key = [0u16; 33];
        let code = unsafe { RmStartSession(&mut handle, 0, key.as_mut_ptr()) };
        if code != 0 {
            return Err(format!("Restart Manager: {code}"));
        }
        struct Session(u32);
        impl Drop for Session {
            fn drop(&mut self) {
                unsafe {
                    RmEndSession(self.0);
                }
            }
        }
        let _session = Session(handle);
        let names: Vec<Vec<u16>> = paths
            .iter()
            .map(|p| p.as_os_str().encode_wide().chain(Some(0)).collect())
            .collect();
        let pointers: Vec<_> = names.iter().map(|n| n.as_ptr()).collect();
        let code = unsafe {
            RmRegisterResources(
                handle,
                pointers.len() as u32,
                pointers.as_ptr(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
            )
        };
        if code != 0 {
            return Err(format!("Регистрация файлов в Restart Manager: {code}"));
        }
        let mut needed = 0;
        let mut count = 0;
        let mut reasons = 0;
        let mut entries = Vec::<RM_PROCESS_INFO>::new();
        for _ in 0..3 {
            let code = unsafe {
                RmGetList(
                    handle,
                    &mut needed,
                    &mut count,
                    if entries.is_empty() {
                        std::ptr::null_mut()
                    } else {
                        entries.as_mut_ptr()
                    },
                    &mut reasons,
                )
            };
            if code == 0 {
                let mut result: Vec<_> = entries
                    .iter()
                    .take(count as usize)
                    .map(|p| {
                        let length = p
                            .strAppName
                            .iter()
                            .position(|c| *c == 0)
                            .unwrap_or(p.strAppName.len());
                        format!(
                            "{} (PID {})",
                            String::from_utf16_lossy(&p.strAppName[..length]),
                            p.Process.dwProcessId
                        )
                    })
                    .collect();
                result.sort();
                result.dedup();
                return Ok(result);
            }
            if code != ERROR_MORE_DATA || needed > 4096 {
                return Err(format!("Проверка занятых файлов: {code}"));
            }
            entries.resize(needed as usize, RM_PROCESS_INFO::default());
            count = needed;
        }
        Err("Список процессов меняется; повторите проверку".into())
    }
    #[cfg(target_os = "macos")]
    {
        if paths.is_empty() {
            return Ok(vec![]);
        }
        let output = std::process::Command::new("/usr/sbin/lsof")
            .args(["-n", "-P", "-Fpc", "--"])
            .args(paths)
            .output()
            .map_err(|e| format!("Проверка открытых файлов: {e}"))?;
        parse_lsof(
            output.status.code(),
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        )
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = paths;
        Ok(vec![])
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_lsof(code: Option<i32>, stdout: &str, stderr: &str) -> Result<Vec<String>, String> {
    if !matches!(code, Some(0 | 1)) || !stderr.trim().is_empty() {
        return Err(format!(
            "Проверка открытых файлов: код {code:?}; {}",
            stderr.trim()
        ));
    }
    let mut result = Vec::new();
    let mut pid = None;
    for line in stdout.lines() {
        if let Some(value) = line.strip_prefix('p') {
            pid = Some(
                value
                    .parse::<u32>()
                    .map_err(|_| "Некорректный PID в выводе lsof")?,
            );
        } else if let Some(name) = line.strip_prefix('c') {
            if let Some(pid) = pid.take() {
                result.push(format!("{name} (PID {pid})"));
            }
        }
    }
    if !stdout.trim().is_empty() && result.is_empty() {
        return Err("Не удалось разобрать список открытых файлов".into());
    }
    result.sort();
    result.dedup();
    Ok(result)
}

#[cfg(test)]
mod mac_lock_tests {
    #[test]
    fn lsof_partial_match_is_busy_and_empty_exit_one_is_free() {
        assert_eq!(
            super::parse_lsof(Some(1), "p123\ncAntigravity Helper\np456\ncagy\n", "")
                .unwrap()
                .len(),
            2
        );
        assert!(super::parse_lsof(Some(1), "", "").unwrap().is_empty());
        assert!(super::parse_lsof(Some(1), "", "permission denied").is_err());
        assert!(super::parse_lsof(Some(0), "unexpected output", "").is_err());
    }
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn cli_and_helpers_are_scoped_to_the_selected_installation() {
        use std::path::Path;
        let paths = vec![
            "C:/Apps/Antigravity/resources/bin/language_server.exe".into(),
            "C:/Tools/agy.exe".into(),
        ];
        for path in [
            "C:/Tools/agy.exe",
            "C:/Apps/Antigravity/resources/node.exe",
            "C:/Apps/Antigravity/crashpad_handler.exe",
        ] {
            assert!(super::owned_application(Path::new(path), &paths), "{path}");
        }
        for path in [
            "C:/Other/agy.exe",
            "C:/Program Files/nodejs/node.exe",
            "C:/Apps/Antigravity-other/node.exe",
            "C:/Apps/Antigravity/antigravity-bypass-russia.exe",
            "C:/Windows/System32/cmd.exe",
        ] {
            assert!(!super::owned_application(Path::new(path), &paths), "{path}");
        }
    }

    #[test]
    #[ignore = "requires Windows .NET Framework compiler; launches isolated hidden fixtures"]
    fn closes_ide_cli_and_server_without_stopping_unrelated_process() {
        use std::{
            fs,
            os::windows::process::CommandExt,
            process::Command,
            time::{Duration, Instant},
        };
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("Fixture.cs");
        let exe = dir.path().join("Antigravity.exe");
        fs::write(&source, r#"using System; using System.IO;
class P { static void Main(string[] args) { File.WriteAllText(args[0], "ready"); System.Threading.Thread.Sleep(-1); } }"#).unwrap();
        let compiler = std::path::PathBuf::from(std::env::var_os("WINDIR").unwrap())
            .join("Microsoft.NET/Framework64/v4.0.30319/csc.exe");
        let output = Command::new(compiler)
            .creation_flags(0x08000000)
            .args(["/nologo", "/target:exe"])
            .arg(format!("/out:{}", exe.display()))
            .arg(&source)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        struct Fixture(std::process::Child);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let unrelated_dir = tempfile::tempdir().unwrap();
        let executables = [
            exe.clone(),
            dir.path().join("agy.exe"),
            dir.path().join("language_server.exe"),
            unrelated_dir.path().join("Antigravity.exe"),
        ];
        let mut children = Vec::new();
        let mut ready_files = Vec::new();
        for (index, path) in executables.iter().enumerate() {
            if path != &exe {
                fs::copy(&exe, path).unwrap();
            }
            let ready = dir.path().join(format!("ready-{index}"));
            children.push(Fixture(
                Command::new(path)
                    .arg(&ready)
                    .creation_flags(0x08000000)
                    .spawn()
                    .unwrap(),
            ));
            ready_files.push(ready);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready_files.iter().all(|p| p.exists()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(ready_files.iter().all(|p| p.exists()));
        assert!(!super::holders(&[exe.clone()]).unwrap().is_empty());
        assert_eq!(
            super::running_applications(&executables[..3])
                .unwrap()
                .len(),
            3
        );
        super::close_application(&executables[..3]).unwrap();
        for child in &mut children[..3] {
            assert!(child.0.try_wait().unwrap().is_some());
        }
        assert!(children[3].0.try_wait().unwrap().is_none());
    }
    #[test]
    fn automatic_close_refuses_unrelated_process_without_stopping_it() {
        assert!(super::close_application(&[std::env::current_exe().unwrap()]).is_err());
        assert!(super::holders(&[std::env::current_exe().unwrap()])
            .unwrap()
            .iter()
            .any(|s| s.contains(&format!("PID {}", std::process::id()))));
    }
    #[test]
    fn shutdown_scope_excludes_other_editors_and_similar_directories() {
        use std::path::Path;
        let paths = vec!["C:/Apps/Antigravity/resources/bin/language_server.exe".into()];
        assert!(super::owned_application(
            Path::new("C:/Apps/Antigravity/Antigravity.exe"),
            &paths
        ));
        assert!(super::owned_application(
            Path::new("C:/Apps/Antigravity/resources/bin/language_server.exe"),
            &paths
        ));
        assert!(!super::owned_application(
            Path::new("C:/Apps/Antigravity/Code.exe"),
            &paths
        ));
        assert!(!super::owned_application(
            Path::new("C:/Apps/Anti/Antigravity.exe"),
            &paths
        ));
        assert!(!super::owned_application(
            Path::new("C:/Other/language_server.exe"),
            &paths
        ));
    }
    #[test]
    fn identifies_running_executable_without_terminating_it() {
        let list = super::holders(&[std::env::current_exe().unwrap()]).unwrap();
        assert!(list
            .iter()
            .any(|s| s.contains(&format!("PID {}", std::process::id()))));
    }
}
