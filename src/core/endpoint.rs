use crate::core::detector::find_installations;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

pub const DAILY_ENDPOINT: &str = "https://daily-cloudcode-pa.googleapis.com";
pub const IDE_SETTING: &str = "jetski.cloudCodeUrl";

pub fn apply_all() -> Vec<Result<String, String>> {
    match crate::net::rank::endpoint_choice() {
        crate::net::rank::EndpointChoice::Uncertain => {
            return vec![Ok(
                "Endpoint сохранён: нет свежего подтверждения альтернативного пути".into(),
            )]
        }
        crate::net::rank::EndpointChoice::Native => return restore_automatic_overrides(),
        crate::net::rank::EndpointChoice::Daily => {}
    }
    let mut notes = Vec::new();
    for inst in find_installations() {
        match apply_ide(&inst) {
            Ok(msg) => notes.push(Ok(format!("{}: {}", inst.display(), msg))),
            Err(e) => notes.push(Err(format!("{}: {}", inst.display(), e))),
        }
    }
    // Fresh installs keep settings under APPDATA even if we missed the folder.
    for folder in ["Antigravity", "Antigravity IDE"] {
        if let Some(path) = appdata_settings(folder) {
            if find_installations()
                .iter()
                .any(|p| ide_settings_path(p).as_ref() == Some(&path))
            {
                continue;
            }
            match apply_daily_settings(&path) {
                Ok(msg) => notes.push(Ok(format!("{}: {}", path.display(), msg))),
                Err(e) => notes.push(Err(format!("{}: {}", path.display(), e))),
            }
        }
    }
    notes.push(super::endpoint_env::apply_if_default());
    notes
}

fn restore_automatic_overrides() -> Vec<Result<String, String>> {
    let mut paths: Vec<_> = find_installations()
        .iter()
        .filter_map(|p| ide_settings_path(p))
        .collect();
    for folder in ["Antigravity", "Antigravity IDE", "Google Antigravity"] {
        if let Some(path) = appdata_settings(folder) {
            paths.push(path);
        }
    }
    paths.sort();
    paths.dedup();
    let mut notes = vec![Ok(
        "Основной Cloud Code имеет проверенный путь; принудительный daily-endpoint не нужен".into(),
    )];
    for path in paths {
        if crate::system::journal::has_record(&path) {
            notes.push(
                remove_settings_file(&path)
                    .map(|_| "Прежние настройки endpoint восстановлены по журналу".into()),
            );
        }
    }
    notes.push(
        super::endpoint_env::restore()
            .map(|_| "CLI: собственный override снят, пользовательское значение сохранено".into()),
    );
    notes
}

pub fn remove_all() -> Vec<String> {
    let mut errors = Vec::new();
    let mut paths = Vec::new();
    for inst in find_installations() {
        if let Some(p) = ide_settings_path(&inst) {
            paths.push(p);
        }
    }
    for folder in ["Antigravity", "Antigravity IDE", "Google Antigravity"] {
        if let Some(p) = appdata_settings(folder) {
            paths.push(p);
        }
    }
    paths.sort();
    paths.dedup();
    for path in paths {
        if let Err(e) = remove_settings_file(&path) {
            errors.push(e);
        }
    }
    if let Err(e) = super::endpoint_env::restore() {
        errors.push(e);
    }
    errors
}

fn appdata_settings(folder: &str) -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").ok()?;
        Some(
            PathBuf::from(appdata)
                .join(folder)
                .join("User")
                .join("settings.json"),
        )
    }
    #[cfg(target_os = "macos")]
    {
        for home in crate::system::env::get_user_homes() {
            let p = home
                .join("Library")
                .join("Application Support")
                .join(folder)
                .join("User")
                .join("settings.json");
            if p.parent().map(|d| d.exists()).unwrap_or(false) || p.exists() {
                return Some(p);
            }
        }
        let home = crate::system::env::expand_env_vars("~");
        Some(
            home.join("Library")
                .join("Application Support")
                .join(folder)
                .join("User")
                .join("settings.json"),
        )
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for home in crate::system::env::get_user_homes() {
            let p = home
                .join(".config")
                .join(folder)
                .join("User")
                .join("settings.json");
            if p.parent().map(|d| d.exists()).unwrap_or(false) || p.exists() {
                return Some(p);
            }
        }
        let home = crate::system::env::expand_env_vars("~");
        Some(
            home.join(".config")
                .join(folder)
                .join("User")
                .join("settings.json"),
        )
    }
}

fn ide_settings_path(install: &Path) -> Option<PathBuf> {
    let product_candidates = [
        install.join("resources").join("app").join("product.json"),
        install
            .join("Contents")
            .join("Resources")
            .join("app")
            .join("product.json"),
        install.join("product.json"),
    ];
    let re = Regex::new(r#""nameShort"[ \t\r\n]*:[ \t\r\n]*"([^"]+)""#).ok();
    for product in product_candidates {
        if let Ok(text) = fs::read_to_string(&product) {
            if let Some(ref re) = re {
                if let Some(cap) = re.captures(&text) {
                    let name = cap.get(1)?.as_str();
                    return appdata_settings(name);
                }
            }
        }
    }
    let fallbacks = ["Antigravity", "Antigravity IDE", "Google Antigravity"];
    for f in fallbacks {
        if let Some(p) = appdata_settings(f) {
            if p.exists() {
                return Some(p);
            }
        }
    }
    appdata_settings("Antigravity")
}

pub fn apply_ide(install: &Path) -> Result<String, String> {
    let path = ide_settings_path(install)
        .ok_or_else(|| "не удалось найти settings.json IDE".to_string())?;
    apply_daily_settings(&path)
}

fn apply_daily_settings(path: &Path) -> Result<String, String> {
    if let Ok(text) = fs::read_to_string(path) {
        let value = jsonc_parser::parse_to_serde_value(
            text.trim_start_matches('\u{feff}'),
            &Default::default(),
        )
        .map_err(|e| format!("settings.json не изменён: {e}"))?;
        if let Some(value) = value.and_then(|v| v.get(IDE_SETTING).cloned()) {
            if !value.is_null()
                && value.as_str() != Some(DAILY_ENDPOINT)
                && value.as_str() != Some("")
            {
                return Ok("Пользовательский jetski.cloudCodeUrl сохранён".into());
            }
        }
    }
    upsert_settings_file(path)
}

fn upsert_settings_file(path: &Path) -> Result<String, String> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("не прочитать {}: {}", path.display(), e)),
    };
    let updated = upsert_key(&text, IDE_SETTING, DAILY_ENDPOINT)?;
    if updated == text {
        return Ok("endpoint уже настроен".into());
    }
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
    }
    crate::system::journal::apply(
        path,
        if path.exists() {
            Some(text.as_bytes())
        } else {
            None
        },
        updated.as_bytes(),
        "settings-jsonc",
    )?;
    Ok(format!("jetski.cloudCodeUrl → {}", DAILY_ENDPOINT))
}

fn remove_settings_file(path: &Path) -> Result<(), String> {
    if crate::system::journal::restore(path)? {
        return Ok(());
    }
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    if let Some(updated) = remove_legacy_daily(&text)? {
        let archive = crate::system::journal::archive_legacy(path, text.as_bytes())?;
        if fs::read(path).map_err(|e| e.to_string())? != text.as_bytes() {
            return Err("Настройки изменились; очистка отменена".into());
        }
        crate::system::fs_utils::robust_write_file(path, updated.as_bytes())?;
        crate::net::relay::log_event(&format!(
            "{}: старый daily-override снят; копия {}",
            path.display(),
            archive.display()
        ));
    }
    Ok(())
}

fn remove_legacy_daily(text: &str) -> Result<Option<String>, String> {
    let clean = text.trim_start_matches('\u{feff}');
    if clean.trim().is_empty() {
        return Ok(None);
    }
    let value = jsonc_parser::parse_to_serde_value(clean, &Default::default())
        .map_err(|e| e.to_string())?;
    if value
        .as_ref()
        .and_then(|v| v.get(IDE_SETTING))
        .and_then(|v| v.as_str())
        != Some(DAILY_ENDPOINT)
    {
        return Ok(None);
    }
    let root = jsonc_parser::cst::CstRootNode::parse(clean, &Default::default())
        .map_err(|e| e.to_string())?;
    let object = root
        .value()
        .and_then(|v| v.as_object())
        .ok_or("settings.json должен быть объектом")?;
    if object
        .properties()
        .iter()
        .filter(|p| p.name().and_then(|n| n.decoded_value().ok()).as_deref() == Some(IDE_SETTING))
        .count()
        != 1
    {
        return Err("Повторный jetski.cloudCodeUrl: неоднозначные настройки сохранены".into());
    }
    if let Some(prop) = object.get(IDE_SETTING) {
        prop.remove();
    }
    Ok(Some(format!(
        "{}{}",
        if text.starts_with('\u{feff}') {
            "\u{feff}"
        } else {
            ""
        },
        root
    )))
}

fn upsert_key(text: &str, key: &str, value: &str) -> Result<String, String> {
    use jsonc_parser::{cst::CstRootNode, ParseOptions};
    let bom = text.starts_with('\u{feff}');
    let text = text.trim_start_matches('\u{feff}');
    let options = ParseOptions {
        allow_comments: true,
        allow_trailing_commas: true,
        allow_loose_object_property_names: false,
        ..Default::default()
    };
    let root = CstRootNode::parse(if text.trim().is_empty() { "{}" } else { text }, &options)
        .map_err(|e| format!("settings.json не изменён: {e}"))?;
    let object = root
        .value()
        .and_then(|v| v.as_object())
        .ok_or("settings.json должен быть объектом")?;
    if let Some(prop) = object.get(key) {
        prop.set_value(value.into());
    } else {
        object.append(key, value.into());
    }
    let output = root.to_string();
    CstRootNode::parse(&output, &options).map_err(|e| e.to_string())?;
    Ok(format!("{}{}", if bom { "\u{feff}" } else { "" }, output))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_daily_cleanup_is_archived_idempotent_and_preserves_other_settings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = format!("\u{feff}{{ // preserve\n \"jetski.cloudCodeUrl\": \"{DAILY_ENDPOINT}\",\n \"editor.fontSize\": 19, }}");
        fs::write(&path, &original).unwrap();
        remove_settings_file(&path).unwrap();
        let cleaned = fs::read_to_string(&path).unwrap();
        assert!(
            cleaned.contains("// preserve")
                && cleaned.contains("19")
                && cleaned.starts_with('\u{feff}')
        );
        assert!(!cleaned.contains(IDE_SETTING));
        assert!(!crate::system::journal::has_record(&path));
        remove_settings_file(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), cleaned);
        assert_eq!(
            fs::read(dir.path().join("settings.json.ag-backups").join(format!(
                "legacy-{}.bin",
                crate::system::journal::digest(original.as_bytes())
            )))
            .unwrap(),
            original.as_bytes()
        );
        assert!(
            remove_legacy_daily("{\"jetski.cloudCodeUrl\":\"https://custom.test\"}")
                .unwrap()
                .is_none()
        );
        assert!(remove_legacy_daily("{broken").is_err());
        assert!(remove_legacy_daily(&format!("{{\"jetski.cloudCodeUrl\":\"https://custom.test\",\"jetski.cloudCodeUrl\":\"{DAILY_ENDPOINT}\"}}")).is_err());
    }
    #[test]
    fn automatic_daily_policy_preserves_explicit_user_endpoint_and_keeps_exact_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let user = "{ // keep\n \"jetski.cloudCodeUrl\": \"https://custom.example\", }";
        fs::write(&path, user).unwrap();
        apply_daily_settings(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), user);
        assert!(!crate::system::journal::has_record(&path));
        let native = "{ // keep\n \"editor.fontSize\": 17, }";
        fs::write(&path, native).unwrap();
        apply_daily_settings(&path).unwrap();
        assert!(fs::read_to_string(&path).unwrap().contains(DAILY_ENDPOINT));
        remove_settings_file(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), native);
    }
    #[test]
    fn settings_roundtrip_and_user_edits_are_protected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = "{\r\n // my preferences\r\n \"jetski.cloudCodeUrl\": \"https://custom.example\",\r\n \"editor.fontSize\": 17,\r\n}";
        fs::write(&path, original).unwrap();
        upsert_settings_file(&path).unwrap();
        upsert_settings_file(&path).unwrap();
        remove_settings_file(&path).unwrap();
        remove_settings_file(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        upsert_settings_file(&path).unwrap();
        let user_edit = fs::read_to_string(&path).unwrap().replace("17", "19");
        fs::write(&path, &user_edit).unwrap();
        assert!(remove_settings_file(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), user_edit);
    }
    #[test]
    fn comments_bom_trailing_comma_and_other_settings_survive() {
        let text = "\u{feff}{\n \"http.proxy\": \"http://localhost:1234\", // keep proxy\n}";
        let updated = upsert_key(text, IDE_SETTING, DAILY_ENDPOINT).unwrap();
        assert!(updated.starts_with('\u{feff}'));
        assert!(updated.contains("// keep proxy"));
        assert!(updated.contains("http://localhost:1234"));
        assert_eq!(
            upsert_key(&updated, IDE_SETTING, DAILY_ENDPOINT).unwrap(),
            updated
        );
    }
    #[test]
    fn malformed_settings_are_not_replaced_with_empty_object() {
        assert!(upsert_key("{broken", IDE_SETTING, DAILY_ENDPOINT).is_err());
        assert!(upsert_key("[]", IDE_SETTING, DAILY_ENDPOINT).is_err());
    }
}
