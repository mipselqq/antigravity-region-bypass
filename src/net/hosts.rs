#![allow(dead_code)]

use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

const START_MARK: &str = "# BEGIN ANTIGRAVITY-BYPASS-RUSSIA";
const END_MARK: &str = "# END ANTIGRAVITY-BYPASS-RUSSIA";

pub fn hosts_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        PathBuf::from(root)
            .join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc/hosts")
    }
}

pub fn write_entries(entries: &[(String, Ipv4Addr)]) -> Result<(), String> {
    let p = hosts_path();
    let original = if p.exists() {
        fs::read_to_string(&p).map_err(|e| format!("Чтение hosts: {}", e))?
    } else {
        String::new()
    };

    let stripped = strip_block(&original)?;
    let mut block = String::new();
    block.push_str(START_MARK);
    block.push('\n');
    for (host, ip) in entries {
        block.push_str(&format!("{} {}\n", ip, host));
    }
    block.push_str(END_MARK);
    block.push('\n');

    // Prepending needs no separator added to the user's bytes, even without
    // an existing final newline. Rollback removes exactly our complete block.
    let combined = format!("{block}{stripped}");
    if combined == original {
        return Ok(());
    }

    safe_write_hosts(&p, original.as_bytes(), combined.as_bytes())
}

pub fn remove_entries() -> Result<(), String> {
    let p = hosts_path();
    if !p.exists() {
        return Ok(());
    }
    let original = fs::read_to_string(&p).map_err(|e| format!("Чтение hosts: {}", e))?;
    let stripped = strip_block(&original)?;
    if stripped != original {
        safe_write_hosts(&p, original.as_bytes(), stripped.as_bytes())?;
    }
    Ok(())
}

pub fn owned_entries() -> Result<Vec<(String, Ipv4Addr)>, String> {
    match fs::read_to_string(hosts_path()) {
        Ok(text) => parse_owned_entries(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(format!("Чтение hosts: {e}")),
    }
}

fn parse_owned_entries(text: &str) -> Result<Vec<(String, Ipv4Addr)>, String> {
    strip_block(text)?; // Refuse damaged boundaries rather than guessing ownership.
    let mut entries = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        match line.trim() {
            START_MARK => inside = true,
            END_MARK => inside = false,
            _ if inside => {
                let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
                let Some(ip) = fields.next().and_then(|ip| ip.parse::<Ipv4Addr>().ok()) else {
                    continue;
                };
                for host in fields {
                    let host = super::route_health::host_name(host);
                    if !super::provider::NRPT_AGENT.contains(&host.as_str()) {
                        continue;
                    }
                    if entries
                        .iter()
                        .any(|(name, previous)| name == &host && previous != &ip)
                    {
                        return Err(format!("Неоднозначные адреса {host} в блоке hosts"));
                    }
                    if !entries.contains(&(host.clone(), ip)) {
                        entries.push((host, ip));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(entries)
}

fn strip_block(text: &str) -> Result<String, String> {
    let mut result = String::new();
    let mut in_block = false;
    for line in text.split_inclusive('\n') {
        match line.trim() {
            START_MARK if !in_block => in_block = true,
            END_MARK if in_block => in_block = false,
            START_MARK | END_MARK => {
                return Err("Повреждены границы блока hosts; файл сохранён".into())
            }
            _ if !in_block => result.push_str(line),
            _ => {}
        }
    }
    if in_block {
        return Err("Нет конца блока hosts; файл сохранён".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_unambiguous_owned_agent_entries_can_identify_a_refused_route() {
        let unmanaged = "192.0.2.9 cloudcode-pa.googleapis.com\n";
        assert!(parse_owned_entries(unmanaged).unwrap().is_empty());
        let text = format!("{unmanaged}{START_MARK}\n192.0.2.1 CLOUDCODE-PA.GOOGLEAPIS.COM # keep\n192.0.2.2 unrelated.test\n{END_MARK}\n");
        assert_eq!(
            parse_owned_entries(&text).unwrap(),
            vec![(
                "cloudcode-pa.googleapis.com".into(),
                "192.0.2.1".parse().unwrap()
            )]
        );
        let conflicting = text.replace(
            END_MARK,
            &format!("192.0.2.3 cloudcode-pa.googleapis.com\n{END_MARK}"),
        );
        assert!(parse_owned_entries(&conflicting).is_err());
        assert!(parse_owned_entries(&text.replace(END_MARK, "")).is_err());
    }

    #[test]
    fn stale_hosts_update_preserves_concurrent_edit_on_every_platform() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        fs::write(&path, "user changed this").unwrap();
        assert!(safe_write_hosts(&path, b"old", b"replacement").is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "user changed this");
    }
    #[test]
    fn removing_owned_block_preserves_unmanaged_bytes_and_user_additions() {
        for original in [
            "# user\r\n127.0.0.1 localhost\r\n",
            "# user without final newline",
            "",
        ] {
            let text = format!("{START_MARK}\n127.0.0.2 example.com\n{END_MARK}\n{original}");
            assert_eq!(strip_block(&text).unwrap(), original);
            assert_eq!(strip_block(original).unwrap(), original);
        }
        assert!(strip_block(&format!("{START_MARK}\n# user lines")).is_err());
        assert!(strip_block(END_MARK).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn removes_owned_entries_when_windows_denies_replacement() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        let unmanaged = "127.0.0.1 localhost\r\n# other application's entries\r\n";
        let original = format!("{START_MARK}\n127.0.0.2 example.com\n{END_MARK}\n{unmanaged}");
        fs::write(&path, &original).unwrap();
        // A reader that shares writes but not deletion reproduces the failure.
        let _reader = fs::OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(&path)
            .unwrap();
        assert!(crate::system::fs_utils::robust_write_file(&path, unmanaged.as_bytes()).is_err());
        assert_eq!(fs::read(&path).unwrap(), original.as_bytes());
        safe_write_hosts(&path, original.as_bytes(), unmanaged.as_bytes()).unwrap();
        assert_eq!(fs::read(&path).unwrap(), unmanaged.as_bytes());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn fallback_preserves_concurrent_changes_and_refuses_active_writers() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        fs::write(&path, b"user addition").unwrap();
        assert!(write_hosts_in_place(&path, b"stale content", b"replacement").is_err());
        let _writer = fs::OpenOptions::new()
            .write(true)
            .share_mode(3)
            .open(&path)
            .unwrap();
        assert!(safe_write_hosts(&path, b"user addition", b"replacement").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"user addition");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

fn safe_write_hosts(path: &Path, _expected: &[u8], data: &[u8]) -> Result<(), String> {
    let current = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && _expected.is_empty() => vec![],
        Err(e) => return Err(e.to_string()),
    };
    if current != _expected {
        return Err("hosts изменён другой программой; повторите операцию".into());
    }
    let result = crate::system::fs_utils::robust_write_file(path, data);
    #[cfg(windows)]
    if let Err(atomic_error) = result {
        return write_hosts_in_place(path, _expected, data)
            .map_err(|e| format!("{atomic_error}. Обновление hosts на месте: {e}"));
    }
    result
}

/// Windows can allow writing hosts while denying replacement of its directory
/// entry. Keep its identity/ACL and a flushed recovery copy before modifying it.
/// This fallback is deliberately restricted to hosts, not application binaries.
#[cfg(windows)]
fn write_hosts_in_place(path: &Path, expected: &[u8], data: &[u8]) -> Result<(), String> {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::windows::fs::OpenOptionsExt;

    // Allow readers but exclude other writers/deletion throughout read and write.
    // No truncate on open: a failed open must leave the original untouched.
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(1) // FILE_SHARE_READ
        .open(path)
        .map_err(|e| e.to_string())?;
    let mut original = Vec::new();
    file.read_to_end(&mut original).map_err(|e| e.to_string())?;
    if original != expected {
        return Err("hosts изменён другой программой; повторите операцию".into());
    }
    let mut backup = tempfile::Builder::new()
        .prefix("hosts.antigravity-recovery-")
        .tempfile_in(path.parent().unwrap_or_else(|| Path::new(".")))
        .map_err(|e| e.to_string())?;
    backup.write_all(&original).map_err(|e| e.to_string())?;
    backup.as_file().sync_all().map_err(|e| e.to_string())?;
    let (backup_file, backup_path) = backup.keep().map_err(|e| e.to_string())?;
    drop(backup_file);

    let mut replace = |bytes: &[u8]| -> std::io::Result<()> {
        file.seek(SeekFrom::Start(0))?;
        file.write_all(bytes)?;
        file.set_len(bytes.len() as u64)?;
        file.sync_all()
    };
    if let Err(error) = replace(data) {
        let restored = replace(&original);
        return Err(format!(
            "{error}; восстановление исходного файла: {}; резервная копия: {}",
            match restored {
                Ok(()) => "выполнено".to_string(),
                Err(e) => e.to_string(),
            },
            backup_path.display()
        ));
    }
    let _ = fs::remove_file(backup_path);
    Ok(())
}
