#[allow(unused_imports)]
use std::process::Command;
use std::{fs, io::Write, path::Path};

/// Never truncate the destination on a failed replacement.
pub fn robust_write_file(path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp =
        tempfile::NamedTempFile::new_in(parent).map_err(|e| format!("Временный файл: {e}"))?;
    temp.write_all(data).map_err(|e| e.to_string())?;
    if let Ok(metadata) = fs::metadata(path) {
        temp.as_file()
            .set_permissions(metadata.permissions())
            .map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::{fs::MetadataExt, io::AsRawFd};
            if unsafe { libc::fchown(temp.as_file().as_raw_fd(), metadata.uid(), metadata.gid()) }
                != 0
            {
                return Err(format!(
                    "Не сохранить владельца: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
    }
    temp.as_file().sync_all().map_err(|e| e.to_string())?;
    temp.persist(path).map_err(|e| {
        let holders = super::file_lock::holders(&[path.to_path_buf()]).unwrap_or_default();
        let action = if holders.is_empty() {
            "Проверьте права на файл, атрибут «только чтение» и защиту антивируса".to_string()
        } else { format!("Файл используется: {}. Сохраните работу, закройте эти приложения и повторите откат", holders.join(", ")) };
        format!(
            "Атомарная замена {} не удалась: {}. {}",
            path.display(),
            e.error, action
        )
    })?;
    Ok(())
}

pub fn post_write_hook(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let is_macho_target = path.extension().map_or(true, |ext| {
            ext != "js" && ext != "json" && ext != "asar" && ext != "bak"
        });
        let path_str = path.to_str().unwrap_or_default();
        if is_macho_target {
            let res = Command::new("codesign")
                .args([
                    "--force",
                    "--sign",
                    "-",
                    "--preserve-metadata=entitlements,requirements,flags",
                    path_str,
                ])
                .output();
            let res = res.map_err(|e| format!("codesign: {e}"))?;
            if !res.status.success() {
                return Err(format!(
                    "codesign: {}",
                    String::from_utf8_lossy(&res.stderr).trim()
                ));
            }
            let verify = Command::new("/usr/bin/codesign")
                .args(["--verify", "--strict", path_str])
                .output()
                .map_err(|e| e.to_string())?;
            if !verify.status.success() {
                return Err(format!(
                    "Проверка подписи службы: {}",
                    String::from_utf8_lossy(&verify.stderr).trim()
                ));
            }
        }
        let _ = Command::new("xattr")
            .args(["-d", "com.apple.quarantine", path_str])
            .output();

        // Clear quarantine recursively without re-signing the entire .app with --deep
        let mut curr = path.parent();
        while let Some(p) = curr {
            if p.extension().and_then(|e| e.to_str()) == Some("app") {
                let app_str = p.to_str().unwrap_or_default();
                let _ = Command::new("xattr").args(["-cr", app_str]).output();
                break;
            }
            curr = p.parent();
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = path;
    Ok(())
}
