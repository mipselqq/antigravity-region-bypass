#![allow(dead_code)]

use crate::system::process::no_window;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const FORWARDER_FLAG: &str = "--dns-forwarder";
pub const TASK_NAME: &str = "AntigravityBypassRussia";
pub const LAUNCHD_LABEL: &str = "com.antigravity.bypass.russia";
pub const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/com.antigravity.bypass.russia.plist";
pub const EXE_NAME: &str = if cfg!(target_os = "windows") {
    "ag_dns.exe"
} else {
    "ag_dns"
};

pub fn install_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(p) = std::env::var("ProgramData") {
            return PathBuf::from(p).join("AntigravityBypassRussia");
        }
        PathBuf::from("C:\\ProgramData\\AntigravityBypassRussia")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/AntigravityBypassRussia")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("/var/lib/antigravity_bypass_russia")
    }
}

pub fn installed_exe() -> PathBuf {
    install_dir().join(EXE_NAME)
}

#[cfg(any(target_os = "macos", test))]
fn classify_launchd_query(success: bool, code: Option<i32>, stderr: &str) -> Result<bool, String> {
    if success {
        return Ok(true);
    }
    if code == Some(113) || stderr.contains("Could not find service") {
        return Ok(false);
    }
    Err(format!(
        "Проверка launchd (код {code:?}): {}",
        stderr.trim()
    ))
}

#[cfg(target_os = "macos")]
fn mac_job_loaded() -> Result<bool, String> {
    let output = Command::new("/bin/launchctl")
        .args(["print", &format!("system/{LAUNCHD_LABEL}")])
        .output()
        .map_err(|e| format!("launchctl print: {e}"))?;
    classify_launchd_query(
        output.status.success(),
        output.status.code(),
        &String::from_utf8_lossy(&output.stderr),
    )
}

#[cfg(target_os = "macos")]
fn unload_mac_job() -> Result<(), String> {
    if !mac_job_loaded()? {
        return Ok(());
    }
    let output = Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{LAUNCHD_LABEL}")])
        .output()
        .map_err(|e| format!("launchctl bootout: {e}"))?;
    if !output.status.success() && mac_job_loaded()? {
        return Err(format!(
            "Не выгрузить DNS-службу: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if mac_job_loaded()? {
        return Err("DNS-служба ещё зарегистрирована в launchd; повторите отключение".into());
    }
    Ok(())
}

#[cfg(test)]
mod launchd_tests {
    #[test]
    fn absent_job_is_idempotent_but_query_failure_blocks_cleanup() {
        assert_eq!(
            super::classify_launchd_query(false, Some(113), "Could not find service").unwrap(),
            false
        );
        assert_eq!(
            super::classify_launchd_query(true, Some(0), "").unwrap(),
            true
        );
        assert!(super::classify_launchd_query(false, Some(1), "Operation not permitted").is_err());
        assert!(super::classify_launchd_query(false, None, "").is_err());
    }
}

fn same_file_bytes(a: &Path, b: &Path) -> bool {
    let (Ok(meta_a), Ok(meta_b)) = (fs::metadata(a), fs::metadata(b)) else {
        return false;
    };
    if meta_a.len() != meta_b.len() {
        return false;
    }
    let (Ok(mut fa), Ok(mut fb)) = (File::open(a), File::open(b)) else {
        return false;
    };
    let mut buf_a = [0u8; 64 * 1024];
    let mut buf_b = [0u8; 64 * 1024];
    loop {
        let n_a = fa.read(&mut buf_a).unwrap_or(0);
        let n_b = fb.read(&mut buf_b).unwrap_or(0);
        if n_a != n_b || buf_a[..n_a] != buf_b[..n_b] {
            return false;
        }
        if n_a == 0 {
            return true;
        }
    }
}

pub fn is_enabled() -> bool {
    #[cfg(target_os = "windows")]
    {
        let out = no_window(&mut Command::new("schtasks"))
            .args(["/Query", "/TN", TASK_NAME])
            .output();
        out.map(|o| o.status.success()).unwrap_or(false)
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from(LAUNCHD_PLIST).exists() || mac_job_loaded().unwrap_or(true)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    false
}

pub fn is_running() -> bool {
    #[cfg(target_os = "windows")]
    {
        let out = no_window(&mut Command::new("tasklist"))
            .args(["/FI", &format!("IMAGENAME eq {}", EXE_NAME)])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            return s.contains(EXE_NAME);
        }
        false
    }
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("pgrep")
            .args(["-f", &format!("{} {}", EXE_NAME, FORWARDER_FLAG)])
            .output();
        out.map(|o| o.status.success()).unwrap_or(false)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let out = Command::new("pgrep").arg(EXE_NAME).output();
        out.map(|o| o.status.success()).unwrap_or(false)
    }
}

pub fn enable() -> Result<(), String> {
    let dir = install_dir();
    fs::create_dir_all(&dir).map_err(|e| {
        format!(
            "Не удалось создать директорию службы {}: {}",
            dir.display(),
            e
        )
    })?;

    let src = std::env::current_exe()
        .map_err(|e| format!("Не удалось определить путь к текущему exe: {}", e))?;
    let dst = installed_exe();

    if !dst.exists() || !same_file_bytes(&src, &dst) {
        #[cfg(target_os = "windows")]
        {
            let _ = no_window(&mut Command::new("schtasks"))
                .args(["/End", "/TN", TASK_NAME])
                .output();
            let _ = no_window(&mut Command::new("taskkill"))
                .args(["/F", "/T", "/IM", EXE_NAME])
                .output();
        }
        #[cfg(target_os = "macos")]
        {
            unload_mac_job()?;
        }

        crate::system::process::stop_process_by_name(EXE_NAME);

        let mut copy_res = Err(std::io::Error::new(std::io::ErrorKind::Other, "init"));
        for attempt in 0..20 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let _ = fs::remove_file(&dst);
            copy_res = fs::copy(&src, &dst);
            if copy_res.is_ok() {
                break;
            }
            if attempt % 5 == 0 {
                #[cfg(target_os = "windows")]
                {
                    let _ = no_window(&mut Command::new("schtasks"))
                        .args(["/End", "/TN", TASK_NAME])
                        .output();
                    let _ = no_window(&mut Command::new("taskkill"))
                        .args(["/F", "/T", "/IM", EXE_NAME])
                        .output();
                }
                crate::system::process::stop_process_by_name(EXE_NAME);
            }
        }

        copy_res.map_err(|e| {
            format!(
                "Не удалось скопировать бинарник службы ({} -> {}): {}",
                src.display(),
                dst.display(),
                e
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dst, fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
        }
        crate::system::fs_utils::post_write_hook(&dst)?;
    }

    #[cfg(target_os = "windows")]
    {
        let task_xml = format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Antigravity Bypass Russia DNS Forwarder (Local Relay)</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{}"</Command>
      <Arguments>{}</Arguments>
    </Exec>
  </Actions>
</Task>"#,
            dst.display(),
            FORWARDER_FLAG
        );

        let xml_path = dir.join("task.xml");
        let mut file =
            File::create(&xml_path).map_err(|e| format!("Не удалось создать XML задачи: {}", e))?;
        use std::io::Write;
        file.write_all(&[0xFF, 0xFE]).map_err(|e| e.to_string())?;
        for unit in task_xml.encode_utf16() {
            file.write_all(&unit.to_le_bytes())
                .map_err(|e| e.to_string())?;
        }
        drop(file);

        let _ = no_window(&mut Command::new("schtasks"))
            .args(["/Delete", "/TN", TASK_NAME, "/F"])
            .output();

        let out = no_window(&mut Command::new("schtasks"))
            .args([
                "/Create",
                "/TN",
                TASK_NAME,
                "/XML",
                &xml_path.to_string_lossy(),
                "/F",
            ])
            .output()
            .map_err(|e| format!("Не удалось запустить schtasks /Create: {}", e))?;

        let _ = fs::remove_file(&xml_path);
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(format!("schtasks /Create завершился ошибкой: {}", err));
        }

        let started = no_window(&mut Command::new("schtasks"))
            .args(["/Run", "/TN", TASK_NAME])
            .output()
            .map_err(|e| format!("Запуск DNS-службы: {e}"))?;
        if !started.status.success() {
            return Err(format!(
                "Не запустить DNS-службу ({}): {} {}",
                started.status,
                String::from_utf8_lossy(&started.stderr).trim(),
                String::from_utf8_lossy(&started.stdout).trim()
            ));
        }
    }

    #[cfg(target_os = "macos")]
    {
        unload_mac_job()?;
        let plist_path = LAUNCHD_PLIST;
        let stderr_log = dir.join("stderr.log");
        let stdout_log = dir.join("stdout.log");
        let plist_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>
    <key>ProcessType</key>
    <string>Background</string>
    <key>Nice</key>
    <integer>10</integer>
    <key>LowPriorityIO</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>30</integer>
    <key>StandardErrorPath</key>
    <string>{}</string>
    <key>StandardOutPath</key>
    <string>{}</string>
</dict>
</plist>"#,
            LAUNCHD_LABEL,
            dst.display(),
            FORWARDER_FLAG,
            stderr_log.display(),
            stdout_log.display()
        );

        crate::system::fs_utils::robust_write_file(Path::new(plist_path), plist_content.as_bytes())
            .map_err(|e| format!("Не удалось записать plist демона: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(plist_path, fs::Permissions::from_mode(0o644))
                .map_err(|e| e.to_string())?;
            use std::os::fd::AsRawFd;
            let file = File::open(plist_path).map_err(|e| e.to_string())?;
            if unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } != 0 {
                return Err(format!(
                    "Владелец plist: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        let out = Command::new("launchctl")
            .args(["bootstrap", "system", plist_path])
            .output();
        if out.map(|o| !o.status.success()).unwrap_or(true) {
            let fallback = Command::new("launchctl")
                .args(["load", "-w", plist_path])
                .output()
                .map_err(|e| format!("launchctl load failed: {}", e))?;
            if !fallback.status.success() {
                return Err("Не удалось загрузить LaunchDaemon через launchctl".to_string());
            }
        }
    }

    Ok(())
}

pub fn start() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let out = no_window(&mut Command::new("schtasks"))
            .args(["/Run", "/TN", TASK_NAME])
            .output()
            .map_err(|e| format!("Ошибка запуска службы: {}", e))?;
        if out.status.success() {
            for _ in 0..10 {
                std::thread::sleep(std::time::Duration::from_millis(50));
                if is_running() {
                    return Ok(());
                }
            }
        }
        Err("Служба не перешла в состояние выполнения".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("launchctl")
            .args(["start", LAUNCHD_LABEL])
            .output()
            .map_err(|e| format!("Ошибка launchctl: {}", e))?;
        if out.status.success() {
            Ok(())
        } else {
            Err("launchctl start failed".to_string())
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    Ok(())
}

pub fn disable() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let _ = no_window(&mut Command::new("schtasks"))
            .args(["/End", "/TN", TASK_NAME])
            .output();
        let _ = no_window(&mut Command::new("schtasks"))
            .args(["/Delete", "/TN", TASK_NAME, "/F"])
            .output();
        let _ = no_window(&mut Command::new("taskkill"))
            .args(["/F", "/T", "/IM", EXE_NAME])
            .output();
    }
    #[cfg(target_os = "macos")]
    {
        unload_mac_job()?;
        if Path::new(LAUNCHD_PLIST).exists() {
            fs::remove_file(LAUNCHD_PLIST).map_err(|e| format!("Удаление plist: {e}"))?;
        }
    }

    crate::system::process::stop_process_by_name(EXE_NAME);

    for _ in 0..20 {
        if !is_running() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if is_running() || is_enabled() {
        return Err(
            "Служба ещё активна; восстановление сетевых файлов отменено до её остановки".into(),
        );
    }

    // Keep state/backups until their owners have verified restoration. Never delete this tree.
    let installed = installed_exe();
    if std::env::current_exe().ok().as_ref() != Some(&installed) && installed.exists() {
        fs::remove_file(&installed).map_err(|e| format!("Не удалить бинарник службы: {e}"))?;
    }
    Ok(())
}
