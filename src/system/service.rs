#![allow(dead_code)]

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

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
    let output =
        crate::system::command::output("launchctl", ["print", &format!("system/{LAUNCHD_LABEL}")])
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
    let output = crate::system::command::output(
        "launchctl",
        ["bootout", &format!("system/{LAUNCHD_LABEL}")],
    )
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

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn task_xml_preserves_spaces_unicode_ampersands_and_quotes_in_paths() {
        let path = Path::new(r"D:\Данные & John's Apps\ag_dns.exe");
        let xml = windows_task_xml(path).replace('\'', "''");
        let script = format!("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; $task=[xml]'{xml}'; ConvertTo-Json -Compress -InputObject ([string]$task.Task.Actions.Exec.Command)");
        let out = crate::system::powershell::output(&script).unwrap();
        assert!(out.status.success(), "{out:?}");
        let command: String = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(command, format!("\"{}\"", path.display()));
    }

    #[test]
    fn task_query_distinguishes_absence_from_scheduler_failure() {
        for (body, expected) in [
            ("return @()", Some(false)),
            (
                "[pscustomobject]@{TaskPath='\\other\\';TaskName='AntigravityBypassRussia'}",
                Some(false),
            ),
            (
                "[pscustomobject]@{TaskPath='\\';TaskName='AntigravityBypassRussia'}",
                Some(true),
            ),
            ("throw 'Служба планировщика недоступна'", None),
        ] {
            let script = format!(
                "function Get-ScheduledTask {{ {body} }}\n{}",
                registered_query()
            );
            let result = registered_response(crate::system::powershell::output(&script).unwrap());
            match expected {
                Some(value) => assert_eq!(result.unwrap(), value),
                None => assert!(result
                    .unwrap_err()
                    .contains("Служба планировщика недоступна")),
            }
        }
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
        let (Ok(n_a), Ok(n_b)) = (fa.read(&mut buf_a), fb.read(&mut buf_b)) else {
            return false;
        };
        if n_a != n_b || buf_a[..n_a] != buf_b[..n_b] {
            return false;
        }
        if n_a == 0 {
            return true;
        }
    }
}

fn xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(windows)]
fn registered_query() -> String {
    format!(
        r#"
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$ErrorActionPreference='Stop'
try {{
    $tasks = @(Get-ScheduledTask | Where-Object {{ $_.TaskPath -eq '\' -and $_.TaskName -eq '{TASK_NAME}' }})
    ConvertTo-Json -Compress -InputObject ($tasks.Count -gt 0)
}} catch {{
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}}
"#
    )
}

#[cfg(windows)]
fn registered_response(output: std::process::Output) -> Result<bool, String> {
    if !output.status.success() {
        return Err(format!(
            "Не удалось проверить задачу DNS-службы: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Некорректный ответ при проверке DNS-службы: {e}"))
}

pub fn registered_state() -> Result<bool, String> {
    #[cfg(windows)]
    {
        registered_response(
            crate::system::powershell::output(&registered_query())
                .map_err(|e| format!("Проверка задачи DNS-службы: {e}"))?,
        )
    }
    #[cfg(target_os = "macos")]
    {
        if Path::new(LAUNCHD_PLIST).exists() {
            Ok(true)
        } else {
            mac_job_loaded()
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Ok(false)
    }
}

pub fn running_state() -> Result<bool, String> {
    #[cfg(windows)]
    {
        let out = crate::system::command::output(
            "tasklist",
            [
                "/FI",
                &format!("IMAGENAME eq {}", EXE_NAME),
                "/FO",
                "CSV",
                "/NH",
            ],
        )
        .map_err(|e| format!("Проверка процесса DNS-службы: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "Не удалось проверить процесс DNS-службы ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).lines().any(|line| {
            line.split(',')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .eq_ignore_ascii_case(EXE_NAME)
        }))
    }
    #[cfg(unix)]
    {
        #[cfg(target_os = "macos")]
        let args = vec!["-f".to_string(), format!("{} {}", EXE_NAME, FORWARDER_FLAG)];
        #[cfg(not(target_os = "macos"))]
        let args = vec![EXE_NAME.to_string()];
        let out = crate::system::command::output("pgrep", &args)
            .map_err(|e| format!("Проверка процесса DNS-службы: {e}"))?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(format!(
                "Не удалось проверить процесс DNS-службы: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )),
        }
    }
}

#[cfg(windows)]
fn windows_task_xml(dst: &Path) -> String {
    format!(
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
        xml_text(&dst.to_string_lossy()),
        FORWARDER_FLAG
    )
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
            let _ = crate::system::command::output("schtasks", ["/End", "/TN", TASK_NAME]);
            let _ = crate::system::command::output("taskkill", ["/F", "/T", "/IM", EXE_NAME]);
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
                    let _ = crate::system::command::output("schtasks", ["/End", "/TN", TASK_NAME]);
                    let _ =
                        crate::system::command::output("taskkill", ["/F", "/T", "/IM", EXE_NAME]);
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
        let task_xml = windows_task_xml(&dst);

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

        // /Create /F updates an existing task; keep it registered if validation fails.
        let out = crate::system::command::output(
            "schtasks",
            [
                "/Create",
                "/TN",
                TASK_NAME,
                "/XML",
                &xml_path.to_string_lossy(),
                "/F",
            ],
        )
        .map_err(|e| format!("Не удалось запустить schtasks /Create: {}", e))?;

        let _ = fs::remove_file(&xml_path);
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(format!("schtasks /Create завершился ошибкой: {}", err));
        }

        let started = crate::system::command::output("schtasks", ["/Run", "/TN", TASK_NAME])
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
            xml_text(&dst.to_string_lossy()),
            FORWARDER_FLAG,
            xml_text(&stderr_log.to_string_lossy()),
            xml_text(&stdout_log.to_string_lossy())
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

        let out = crate::system::command::output("launchctl", ["bootstrap", "system", plist_path]);
        if out.map(|o| !o.status.success()).unwrap_or(true) {
            let fallback = crate::system::command::output("launchctl", ["load", "-w", plist_path])
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
        let out = crate::system::command::output("schtasks", ["/Run", "/TN", TASK_NAME])
            .map_err(|e| format!("Ошибка запуска службы: {}", e))?;
        if out.status.success() {
            for _ in 0..10 {
                std::thread::sleep(std::time::Duration::from_millis(50));
                if running_state()? {
                    return Ok(());
                }
            }
        }
        Err("Служба не перешла в состояние выполнения".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        let out = crate::system::command::output("launchctl", ["start", LAUNCHD_LABEL])
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
    // Unknown state must not authorize removal of the service or DNS settings.
    registered_state()?;
    running_state()?;
    #[cfg(target_os = "windows")]
    {
        let _ = crate::system::command::output("schtasks", ["/End", "/TN", TASK_NAME]);
        let _ = crate::system::command::output("schtasks", ["/Delete", "/TN", TASK_NAME, "/F"]);
        let _ = crate::system::command::output("taskkill", ["/F", "/T", "/IM", EXE_NAME]);
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
        if !running_state()? {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if running_state()? || registered_state()? {
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
