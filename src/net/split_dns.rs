//! macOS /etc/resolver files, with one transaction per normalized domain.
use std::{collections::BTreeMap, fs, path::Path};

const MARKER: &str = "# ANTIGRAVITY-BYPASS-RUSSIA";

pub fn preflight(directory: &Path, domains: &[&str]) -> Result<(), String> {
    for domain in domains {
        let path = directory.join(domain.trim_start_matches('.'));
        match fs::metadata(&path) {
            Ok(_) if !crate::system::journal::has_record(&path) => {
                return Err(format!("Уже существует DNS-настройка {}. Файл сохранён; устраните конфликт перед включением обхода.", path.display()));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    Ok(())
}

fn normalized_rules(rules: &[(String, String)]) -> Result<BTreeMap<String, String>, String> {
    let mut normalized = BTreeMap::new();
    for (domain, servers) in rules {
        let domain = domain.trim_start_matches('.').to_ascii_lowercase();
        if domain.is_empty() || domain.contains(['/', '\\']) || domain == ".." {
            return Err("Некорректное имя DNS-домена".into());
        }
        if normalized
            .insert(domain.clone(), servers.clone())
            .is_some_and(|old| old != *servers)
        {
            return Err(format!("Разные DNS-серверы для {domain}"));
        }
    }
    Ok(normalized)
}

pub fn apply(directory: &Path, rules: &[(String, String)]) -> Result<(), String> {
    let rules = normalized_rules(rules)?;
    preflight(
        directory,
        &rules.keys().map(String::as_str).collect::<Vec<_>>(),
    )?;
    fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    for (domain, servers) in rules {
        let path = directory.join(&domain);
        let before = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.to_string()),
        };
        let mut content = format!("{MARKER}\ndomain {domain}\n");
        for server in servers.split(';').filter(|s| !s.is_empty()) {
            let ip: std::net::IpAddr = server.parse().map_err(|_| "Некорректный DNS-сервер")?;
            content.push_str(&format!("nameserver {ip}\n"));
        }
        content.push_str("port 53\nsearch_order 1\ntimeout 2\n");
        crate::system::journal::apply(&path, before.as_deref(), content.as_bytes(), "split-dns")?;
        #[cfg(unix)]
        if before.is_none() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

pub fn remove(directory: &Path, domains: &[&str]) -> Vec<String> {
    let mut errors = Vec::new();
    let unique: std::collections::BTreeSet<_> =
        domains.iter().map(|d| d.trim_start_matches('.')).collect();
    for domain in unique {
        let path = directory.join(domain);
        match crate::system::journal::restore(&path) {
            Ok(false) if fs::read_to_string(&path).is_ok_and(|s| s.contains(MARKER)) => errors
                .push(format!(
                    "{}: старый resolver без backup сохранён",
                    path.display()
                )),
            Err(error) => errors.push(format!("{}: {error}", path.display())),
            _ => {}
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalized_domains_roundtrip_once_and_keep_user_files() {
        let dir = tempfile::tempdir().unwrap();
        let domains = [".example.test", "example.test"];
        preflight(dir.path(), &domains).unwrap();
        let rules = domains
            .iter()
            .map(|d| (d.to_string(), "127.0.0.53".into()))
            .collect::<Vec<_>>();
        apply(dir.path(), &rules).unwrap();
        preflight(dir.path(), &domains).unwrap();
        apply(dir.path(), &rules).unwrap();
        assert!(fs::read_to_string(dir.path().join("example.test"))
            .unwrap()
            .contains("domain example.test"));
        assert!(remove(dir.path(), &domains).is_empty());
        assert!(!dir.path().join("example.test").exists());
        assert!(remove(dir.path(), &domains).is_empty());
        fs::write(dir.path().join("example.test"), "nameserver 192.0.2.1\n").unwrap();
        assert!(preflight(dir.path(), &domains).is_err());
        assert!(apply(dir.path(), &rules).is_err());
        assert!(remove(dir.path(), &domains).is_empty());
        assert_eq!(
            fs::read_to_string(dir.path().join("example.test")).unwrap(),
            "nameserver 192.0.2.1\n"
        );
    }
    #[test]
    fn conflicting_duplicate_domains_fail_before_writing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(apply(
            dir.path(),
            &[
                ("example.test".into(), "127.0.0.53".into()),
                (".example.test".into(), "192.0.2.1".into())
            ]
        )
        .is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    #[cfg(unix)]
    #[test]
    fn new_resolver_is_readable_by_the_system_resolver() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        apply(dir.path(), &[("example.test".into(), "127.0.0.53".into())]).unwrap();
        assert_eq!(
            fs::metadata(dir.path().join("example.test"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }
}
