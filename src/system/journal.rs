//! Exact, content-addressed backups. A changed upstream file is never overwritten on rollback.
use super::fs_utils::robust_write_file;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    schema: u32,
    original: String,
    modified: String,
    #[serde(default)]
    previous: Option<String>,
    existed: bool,
    profile: String,
}

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn directory(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".ag-backups");
    path.with_file_name(name)
}
fn record_path(path: &Path) -> PathBuf {
    directory(path).join("current.json")
}

pub fn apply(
    path: &Path,
    before: Option<&[u8]>,
    after: &[u8],
    profile: &str,
) -> Result<(), String> {
    let current = read_optional(path)?;
    if current.as_deref() != before {
        return Err("Файл изменён другим процессом; повторите проверку".into());
    }
    let dir = directory(path);
    fs::create_dir_all(&dir).map_err(|e| format!("Backup: {e}"))?;
    let old_record = read_optional(&record_path(path))?
        .map(|bytes| parse_record(&bytes))
        .transpose()?;
    let continuation = old_record.as_ref().filter(|r| {
        current.as_ref().is_some_and(|b| {
            let hash = digest(b);
            hash == r.modified || r.previous.as_ref() == Some(&hash)
        })
    });
    let original = continuation
        .map(|r| r.original.clone())
        .unwrap_or_else(|| digest(before.unwrap_or_default()));
    let backup = dir.join(format!("{original}.bin"));
    if !backup.exists() && continuation.is_none() {
        robust_write_file(&backup, before.unwrap_or_default())?;
    }
    if digest(&fs::read(&backup).map_err(|e| e.to_string())?) != original {
        return Err("Повреждена резервная копия; запись отменена".into());
    }
    let record = Record {
        schema: 1,
        original,
        modified: digest(after),
        previous: continuation.map(|_| digest(before.unwrap_or_default())),
        existed: continuation.map(|r| r.existed).unwrap_or(before.is_some()),
        profile: profile.into(),
    };
    // A crash before replacement is recoverable: restore accepts either hash.
    robust_write_file(
        &record_path(path),
        &serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?,
    )?;
    if read_optional(path)?.as_deref() != before {
        return Err("Файл изменился во время подготовки backup".into());
    }
    robust_write_file(path, after)
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::read(path) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn parse_record(bytes: &[u8]) -> Result<Record, String> {
    let record: Record =
        serde_json::from_slice(bytes).map_err(|e| format!("Журнал повреждён: {e}"))?;
    if record.schema != 1
        || [&record.original, &record.modified]
            .into_iter()
            .chain(record.previous.iter())
            .any(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err("Неподдерживаемый журнал backup".into());
    }
    Ok(record)
}
pub fn has_record(path: &Path) -> bool {
    record_path(path).is_file()
}

pub fn verify_recorded_file(path: &Path) -> Result<bool, String> {
    let Some(bytes) = read_optional(&record_path(path))? else {
        return Ok(false);
    };
    let record = parse_record(&bytes)?;
    let current = read_optional(path)?;
    if current.as_ref().is_some_and(|bytes| {
        let hash = digest(bytes);
        hash == record.modified
            || hash == record.original
            || record.previous.as_ref() == Some(&hash)
    }) || (!record.existed && current.is_none())
    {
        Ok(true)
    } else {
        Err(format!(
            "{} изменён после настройки; пользовательские изменения сохранены",
            path.display()
        ))
    }
}

/// Preserve legacy configuration before removing a known override. This is an
/// archive, not an active patch record: another rollback must not reapply it.
pub fn archive_legacy(path: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    if read_optional(path)?.as_deref() != Some(bytes) {
        return Err("Настройки изменились; очистка отменена".into());
    }
    let dir = directory(path);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let backup = dir.join(format!("legacy-{}.bin", digest(bytes)));
    if !backup.exists() {
        robust_write_file(&backup, bytes)?;
    }
    if fs::read(&backup).map_err(|e| e.to_string())? != bytes {
        return Err("Архив старых настроек повреждён; очистка отменена".into());
    }
    Ok(backup)
}

pub fn restore(path: &Path) -> Result<bool, String> {
    let Some(bytes) = read_optional(&record_path(path))? else {
        return Ok(false);
    };
    let record = parse_record(&bytes)?;
    let current = read_optional(path)?;
    if (record.existed
        && current
            .as_ref()
            .is_some_and(|b| digest(b) == record.original))
        || (!record.existed && current.is_none())
    {
        fs::remove_file(record_path(path)).map_err(|e| e.to_string())?;
        return Ok(true);
    }
    if !current.as_ref().is_some_and(|b| {
        let hash = digest(b);
        hash == record.modified || record.previous.as_ref() == Some(&hash)
    }) {
        return Err("Файл обновлён/отредактирован после патча; старая копия не применена".into());
    }
    let backup = fs::read(directory(path).join(format!("{}.bin", record.original)))
        .map_err(|e| format!("Backup недоступен: {e}"))?;
    if digest(&backup) != record.original {
        return Err("Хеш backup не совпадает; откат отменён".into());
    }
    if record.existed {
        robust_write_file(path, &backup)?;
    } else {
        fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    fs::remove_file(record_path(path)).map_err(|e| e.to_string())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_edits_keep_original_baseline_and_failed_write_is_recoverable() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        fs::write(&p, b"original").unwrap();
        apply(&p, Some(b"original"), b"first", "settings").unwrap();
        apply(&p, Some(b"first"), b"second", "settings").unwrap();
        // Simulate a crash after the second journal write, before file replacement.
        fs::write(&p, b"first").unwrap();
        restore(&p).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"original");
    }
    #[test]
    fn rollback_rejects_updated_binary_and_preserves_backup() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("app");
        fs::write(&p, b"v1").unwrap();
        apply(&p, Some(b"v1"), b"patched v1", "test").unwrap();
        fs::write(&p, b"v2").unwrap();
        assert!(restore(&p).is_err());
        assert_eq!(fs::read(&p).unwrap(), b"v2");
        assert!(has_record(&p));
        apply(&p, Some(b"v2"), b"patched v2", "test").unwrap();
        restore(&p).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"v2");
    }
    #[test]
    fn corruption_and_concurrent_changes_never_overwrite_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("app");
        fs::write(&p, b"original").unwrap();
        assert!(apply(&p, Some(b"stale"), b"patched", "test").is_err());
        apply(&p, Some(b"original"), b"patched", "test").unwrap();
        fs::write(
            directory(&p).join(format!("{}.bin", digest(b"original"))),
            b"wrong",
        )
        .unwrap();
        assert!(restore(&p).is_err());
        assert_eq!(fs::read(&p).unwrap(), b"patched");
    }
    #[test]
    fn new_file_is_removed_and_original_bytes_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        apply(&p, None, b"new", "settings").unwrap();
        restore(&p).unwrap();
        assert!(!p.exists());
        fs::write(&p, b"// comment\r\n{}").unwrap();
        apply(&p, Some(b"// comment\r\n{}"), b"changed", "settings").unwrap();
        restore(&p).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"// comment\r\n{}");
    }
}
