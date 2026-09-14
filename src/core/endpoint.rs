use crate::core::detector::find_installations;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

pub const DAILY_ENDPOINT: &str = "https://daily-cloudcode-pa.googleapis.com";
pub const IDE_SETTING: &str = "jetski.cloudCodeUrl";

pub fn apply_all() -> Vec<Result<String, String>> {
    if let Err(error) = migrate_gateway_settings() {
        return vec![Err(error)];
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

/// Restore the settings journalled by 2.3.0/2.3.1 before stopping their gateway.
fn migrate_gateway_settings() -> Result<(), String> {
    super::endpoint_env::restore_gateway()?;
    for path in settings_paths() {
        restore_gateway_profile(&path)?;
    }
    Ok(())
}
fn restore_gateway_profile(path: &Path) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let value = jsonc_parser::parse_to_serde_value(
        text.trim_start_matches('\u{feff}'),
        &Default::default(),
    )
    .map_err(|e| e.to_string())?;
    let local = value
        .as_ref()
        .and_then(|v| v.get(IDE_SETTING))
        .and_then(|v| v.as_str())
        .is_some_and(super::endpoint_env::is_gateway_endpoint);
    if local && !crate::system::journal::restore(path)? {
        return Err(format!(
            "{}: отсутствует исходная копия настройки локального шлюза",
            path.display()
        ));
    }
    Ok(())
}
#[cfg(test)]
fn apply_automatic_settings(path: &Path, endpoint: &str) -> Result<String, String> {
    let Some(text) = automatic_settings_text(path)? else {
        return Ok("Собственный endpoint профиля сохранён".into());
    };
    let updated = upsert_key(&text, IDE_SETTING, endpoint)?;
    if updated != text {
        crate::system::journal::apply(
            path,
            Some(text.as_bytes()),
            updated.as_bytes(),
            "automatic-endpoint-jsonc",
        )?;
    }
    Ok("Профиль подключён к автоматическому выбору маршрутов".into())
}
#[cfg(test)]
fn automatic_settings_text(path: &Path) -> Result<Option<String>, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let value = jsonc_parser::parse_to_serde_value(
        text.trim_start_matches('\u{feff}'),
        &Default::default(),
    )
    .map_err(|e| e.to_string())?;
    if let Some(setting) = value
        .as_ref()
        .and_then(|v| v.get(IDE_SETTING))
        .filter(|v| !v.is_null())
    {
        let Some(setting) = setting.as_str() else {
            return Err("Некорректный jetski.cloudCodeUrl; настройка сохранена".into());
        };
        if !super::endpoint_env::managed_endpoint(setting) {
            return Ok(None);
        }
    }
    // Also validate the object shape and duplicate keys before writing env.
    upsert_key(&text, IDE_SETTING, DAILY_ENDPOINT)?;
    Ok(Some(text))
}

pub fn settings_paths() -> Vec<PathBuf> {
    let mut paths: Vec<_> = find_installations()
        .iter()
        .filter_map(|p| ide_settings_path(p))
        .collect();
    for folder in ["Antigravity", "Antigravity IDE", "Google Antigravity"] {
        if let Some(path) = appdata_settings(folder) {
            if path.exists() {
                paths.push(path);
            }
        }
    }
    paths.sort();
    paths.dedup();
    // Standalone Antigravity has no VS Code User/settings.json. Its endpoint is
    // configured through CLOUD_CODE_URL; a missing IDE profile is not an error.
    paths.retain(|path| path.exists());
    paths
}

#[cfg(test)]
pub fn selected_host(path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let value = jsonc_parser::parse_to_serde_value(
        text.trim_start_matches('\u{feff}'),
        &Default::default(),
    )
    .map_err(|e| e.to_string())?;
    let setting = value.as_ref().and_then(|v| v.get(IDE_SETTING));
    let endpoint = match setting {
        None | Some(serde_json::Value::Null) => "",
        Some(serde_json::Value::String(value)) => value.as_str(),
        _ => return Err("Некорректный jetski.cloudCodeUrl; настройки не изменены".into()),
    };
    match endpoint {
        "" | "https://cloudcode-pa.googleapis.com" => Ok("cloudcode-pa.googleapis.com".into()),
        DAILY_ENDPOINT => Ok("daily-cloudcode-pa.googleapis.com".into()),
        _ => Err("В этом профиле задан собственный endpoint. Выберите профиль со стандартным Cloud Code.".into()),
    }
}

/// An explicit test selection; native and daily are both journalled, so switching
/// repeatedly still restores the original settings on rollback.
#[cfg(test)]
pub fn select_for_test(path: &Path, host: &str) -> Result<(), String> {
    selected_host(path)?;
    if !matches!(
        host,
        "cloudcode-pa.googleapis.com" | "daily-cloudcode-pa.googleapis.com"
    ) {
        return Err("Неизвестный endpoint".into());
    }
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let updated = upsert_key(&text, IDE_SETTING, &format!("https://{host}"))?;
    if updated != text {
        crate::system::journal::apply(
            path,
            Some(text.as_bytes()),
            updated.as_bytes(),
            "settings-jsonc",
        )?;
    }
    Ok(())
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
    if let Err(error) = super::endpoint_env::restore_gateway() {
        errors.push(error);
    }
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
                && !value
                    .as_str()
                    .is_some_and(super::endpoint_env::managed_endpoint)
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
    if object
        .properties()
        .iter()
        .filter(|p| p.name().and_then(|n| n.decoded_value().ok()).as_deref() == Some(key))
        .count()
        > 1
    {
        return Err("Повторный ключ endpoint: неоднозначные настройки сохранены".into());
    }
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
    #[test]
    fn classic_migration_removes_loopback_and_preserves_original_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        let original = "{ // original\n \"editor.fontSize\": 18, }";
        std::fs::write(&path, original).unwrap();
        super::apply_automatic_settings(&path, "http://127.0.0.1:18443").unwrap();
        super::restore_gateway_profile(&path).unwrap();
        super::apply_daily_settings(&path).unwrap();
        let classic = std::fs::read_to_string(&path).unwrap();
        assert!(classic.contains(super::DAILY_ENDPOINT));
        assert!(!classic.contains("127.0.0.1"));
        assert!(classic.contains("// original") && classic.contains("18"));
        super::restore_gateway_profile(&path).unwrap();
        super::remove_settings_file(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }
    #[test]
    fn automatic_endpoint_is_reversible_and_preserves_custom_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = "{\n // keep\n \"editor.fontSize\":19,\n}";
        std::fs::write(&path, original).unwrap();
        super::apply_automatic_settings(&path, "http://127.0.0.1:18443").unwrap();
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("http://127.0.0.1:18443"));
        super::remove_settings_file(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        let custom = "{\"jetski.cloudCodeUrl\":\"https://custom.example\"}";
        std::fs::write(&path, custom).unwrap();
        assert!(super::automatic_settings_text(&path).unwrap().is_none());
        super::apply_automatic_settings(&path, "http://127.0.0.1:18443").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), custom);
        for invalid in [
            "[]",
            "{broken",
            "{\"jetski.cloudCodeUrl\":5}",
            "{\"jetski.cloudCodeUrl\":\"\",\"jetski.cloudCodeUrl\":\"\"}",
        ] {
            std::fs::write(&path, invalid).unwrap();
            assert!(super::automatic_settings_text(&path).is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), invalid);
        }
    }
    #[test]
    fn explicit_endpoint_comparison_preserves_jsonc_and_original_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = "{\n // user setting\n \"editor.fontSize\": 15,\n}\n";
        std::fs::write(&path, original).unwrap();
        super::select_for_test(&path, "daily-cloudcode-pa.googleapis.com").unwrap();
        assert_eq!(
            super::selected_host(&path).unwrap(),
            "daily-cloudcode-pa.googleapis.com"
        );
        super::select_for_test(&path, "cloudcode-pa.googleapis.com").unwrap();
        assert_eq!(
            super::selected_host(&path).unwrap(),
            "cloudcode-pa.googleapis.com"
        );
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("// user setting"));
        super::remove_settings_file(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        for custom in [
            r#"{"jetski.cloudCodeUrl":"https://custom.example"}"#,
            r#"{"jetski.cloudCodeUrl":123}"#,
            "{broken",
        ] {
            std::fs::write(&path, custom).unwrap();
            assert!(super::select_for_test(&path, "cloudcode-pa.googleapis.com").is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), custom);
        }
    }
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
