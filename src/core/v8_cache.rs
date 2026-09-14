use std::fs;
use std::path::{Path, PathBuf};

use crate::system::env::{get_user_homes, mask_path};

const PRODUCTS: &[&str] = &["Antigravity", "Antigravity IDE", "Google Antigravity"];

fn product_caches(roots: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    roots
        .into_iter()
        .flat_map(|root| {
            PRODUCTS.iter().flat_map(move |product| {
                ["CachedData", "Code Cache"].map(|cache| root.join(product).join(cache))
            })
        })
        .collect()
}

pub fn clear_ide_v8_caches() -> Result<usize, String> {
    let homes = get_user_homes();
    let mut dirs = Vec::new();

    #[cfg(windows)]
    {
        let mut roots: Vec<_> = homes
            .iter()
            .map(|home| home.join("AppData/Roaming"))
            .collect();
        if let Some(appdata) = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
        {
            roots.push(appdata);
        }
        dirs.extend(product_caches(roots));
        for home in &homes {
            for package in ["antigravity", "antigravity-ide"] {
                let root = home
                    .join("scoop/persist")
                    .join(package)
                    .join("data/user-data");
                dirs.extend(["CachedData", "Code Cache"].map(|cache| root.join(cache)));
            }
        }
    }
    #[cfg(target_os = "macos")]
    for home in &homes {
        dirs.extend(product_caches([home.join("Library/Application Support")]));
        for cache in [
            "com.google.antigravity/Cache",
            "Antigravity",
            "Antigravity IDE",
        ] {
            dirs.push(home.join("Library/Caches").join(cache));
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    dirs.extend(product_caches(
        homes.iter().map(|home| home.join(".config")),
    ));

    dirs.sort();
    dirs.dedup();
    clear_directories(&dirs)
}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Includes junctions as well as symbolic links.
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn clear_directory(dir: &Path) -> Result<usize, String> {
    let describe = |error: &dyn std::fmt::Display| format!("{}: {error}", mask_path(dir));
    let metadata = match fs::symlink_metadata(dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(describe(&error)),
    };
    if !metadata.is_dir() || is_link(&metadata) {
        return Err(describe(&"ожидался обычный каталог кэша"));
    }
    let root = fs::canonicalize(dir).map_err(|error| describe(&error))?;
    let entries = fs::read_dir(&root).map_err(|error| describe(&error))?;
    let mut cleared = 0;
    let mut errors = Vec::new();
    for entry in entries {
        let result = (|| -> Result<(), String> {
            let entry = entry.map_err(|error| describe(&error))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| describe(&error))?;
            if is_link(&metadata) {
                return Err(describe(&"в кэше обнаружена ссылка; она сохранена"));
            }
            // Resolve and check the destination before any recursive removal.
            let resolved = fs::canonicalize(&path).map_err(|error| describe(&error))?;
            if resolved == root || !resolved.starts_with(&root) {
                return Err(describe(&"путь выходит за пределы каталога кэша"));
            }
            let removal = if metadata.is_dir() {
                fs::remove_dir_all(&resolved)
            } else {
                fs::remove_file(&resolved)
            };
            removal.map_err(|error| describe(&error))
        })();
        match result {
            Ok(()) => cleared += 1,
            Err(error) => errors.push(error),
        }
    }
    if errors.is_empty() {
        Ok(cleared)
    } else {
        Err(errors.join("; "))
    }
}

fn clear_directories(dirs: &[PathBuf]) -> Result<usize, String> {
    let mut cleared = 0;
    let mut errors = Vec::new();
    for dir in dirs {
        match clear_directory(dir) {
            Ok(count) => cleared += count,
            Err(error) => errors.push(error),
        }
    }
    if errors.is_empty() {
        Ok(cleared)
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_all_product_caches_without_removing_settings() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("Redirected App Data");
        let dirs = product_caches([root.clone()]);
        assert_eq!(dirs.len(), 6);
        for dir in &dirs {
            fs::create_dir_all(dir.join("nested")).unwrap();
            fs::write(dir.join("nested/stale.bin"), b"stale").unwrap();
        }
        for product in PRODUCTS {
            fs::write(root.join(product).join("settings.json"), b"keep").unwrap();
        }
        assert_eq!(clear_directories(&dirs).unwrap(), 6);
        for dir in dirs {
            assert_eq!(fs::read_dir(dir).unwrap().count(), 0);
        }
        for product in PRODUCTS {
            assert_eq!(
                fs::read(root.join(product).join("settings.json")).unwrap(),
                b"keep"
            );
        }
    }

    #[test]
    fn reports_failure_but_still_clears_other_caches() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        let invalid = temp.path().join("invalid");
        let valid = temp.path().join("valid");
        fs::write(&invalid, b"keep").unwrap();
        fs::create_dir(&valid).unwrap();
        fs::write(valid.join("stale.bin"), b"stale").unwrap();
        assert_eq!(clear_directory(&missing).unwrap(), 0);
        assert!(clear_directories(&[missing, invalid.clone(), valid.clone()]).is_err());
        assert_eq!(fs::read(invalid).unwrap(), b"keep");
        assert_eq!(fs::read_dir(valid).unwrap().count(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn reports_locked_cache_file() {
        use std::os::windows::fs::OpenOptionsExt;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("locked.bin");
        fs::write(&path, b"keep").unwrap();
        let locked = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .unwrap();
        assert!(clear_directory(temp.path()).is_err());
        assert!(path.exists());
        drop(locked);
        assert_eq!(clear_directory(temp.path()).unwrap(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn preserves_linked_cache_and_external_target() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep.bin"), b"keep").unwrap();
        let linked_cache = temp.path().join("linked-cache");
        symlink(&outside, &linked_cache).unwrap();
        assert!(clear_directory(&linked_cache).is_err());
        let cache = temp.path().join("cache");
        fs::create_dir(&cache).unwrap();
        symlink(&outside, cache.join("linked-entry")).unwrap();
        assert!(clear_directory(&cache).is_err());
        assert_eq!(fs::read(outside.join("keep.bin")).unwrap(), b"keep");
        assert!(fs::symlink_metadata(cache.join("linked-entry")).is_ok());
    }
}
