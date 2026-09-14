use crate::core::{
    detector::{FoundTarget, TargetKind},
    opcodes::*,
};
use crate::system::journal;
use object::{Architecture, Object, ObjectSection, SectionKind};
use std::{
    fs,
    path::Path,
    sync::{Mutex, MutexGuard},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryState {
    Patched,
    PartiallyPatched,
    Stock,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOutcome {
    Changed(usize),
    AlreadyPatched,
    Restored,
    AlreadyStock,
    NotApplicable,
}
impl std::fmt::Display for PatchOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Changed(n) => write!(f, "Изменено {n} проверенных участков; backup сохранён"),
            Self::AlreadyPatched => write!(f, "Все поддерживаемые участки уже пропатчены"),
            Self::Restored => write!(f, "Точные исходные байты восстановлены"),
            Self::AlreadyStock => write!(f, "Исходное состояние; изменений нет"),
            Self::NotApplicable => write!(
                f,
                "Поддерживаемых участков патча нет; файл оставлен без изменений"
            ),
        }
    }
}
static OPERATIONS: Mutex<()> = Mutex::new(());
pub fn operation_guard() -> MutexGuard<'static, ()> {
    OPERATIONS.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) struct Plan {
    pub data: Vec<u8>,
    pub changes: usize,
    pub existing: usize,
    pub profile: String,
}
pub(crate) fn state_from_counts(stock: usize, patched: usize) -> BinaryState {
    match (stock > 0, patched > 0) {
        (true, true) => BinaryState::PartiallyPatched,
        (true, false) => BinaryState::Stock,
        (false, true) => BinaryState::Patched,
        _ => BinaryState::Unknown,
    }
}
pub(crate) fn plan_js(data: &[u8]) -> Result<Plan, String> {
    let text = std::str::from_utf8(data).map_err(|_| "JavaScript не в UTF-8")?;
    let mut output = data.to_vec();
    let re = regex_ide_main_js_stock();
    let spans: Vec<_> = re
        .captures_iter(text)
        .map(|c| (c.get(1).unwrap().end(), c.get(0).unwrap().end()))
        .collect();
    let existing = regex_ide_js_patched().find_iter(text).count();
    for (start, end) in &spans {
        output[*start..*end].fill(b' ');
        output[*start..*start + 4].copy_from_slice(b"true");
    }
    Ok(Plan {
        data: output,
        changes: spans.len(),
        existing,
        profile: "ide-reset-tier-v1".into(),
    })
}

fn apply_pattern(
    bytes: &mut [u8],
    original: &regex::bytes::Regex,
    patched: &regex::bytes::Regex,
    fix: &[u8],
) -> Result<(usize, usize), String> {
    let offsets: Vec<_> = original.find_iter(bytes).map(|m| m.start()).collect();
    let existing = patched.find_iter(bytes).count();
    if offsets.len() + existing > 1 {
        return Err("Неоднозначная машинная сигнатура; файл не изменён".into());
    }
    for offset in &offsets {
        bytes[*offset..*offset + fix.len()].copy_from_slice(fix);
    }
    Ok((offsets.len(), existing))
}

fn plan_binary(data: &[u8], kind: TargetKind) -> Result<Plan, String> {
    let file = object::File::parse(data)
        .map_err(|e| format!("Неподдерживаемый executable (PE/ELF/Mach-O): {e}"))?;
    let (original, patched, fix, profile) = match (kind, file.architecture()) {
        (TargetKind::LanguageServer, Architecture::X86_64) => (
            regex_mgr_x64_orig(),
            regex_mgr_x64_patched(),
            MGR_GATE_X64_FIX,
            "core-x64-v1",
        ),
        (TargetKind::LanguageServer, Architecture::Aarch64) => (
            regex_mgr_arm64_orig(),
            regex_mgr_arm64_patched(),
            MGR_GATE_ARM64_FIX,
            "core-arm64-v1",
        ),
        (TargetKind::AgyCli, Architecture::X86_64) => (
            regex_cli_x64_long_orig(),
            regex_cli_x64_long_patched(),
            CLI_GATE_X64_LONG_FIX,
            "agy-x64-long-v1",
        ),
        (TargetKind::AgyCli, Architecture::Aarch64) => (
            regex_mgr_arm64_orig(),
            regex_mgr_arm64_patched(),
            MGR_GATE_ARM64_FIX,
            "agy-arm64-v1",
        ),
        _ => return Err("Нет профиля патча для этой архитектуры/компонента".into()),
    };
    let mut output = data.to_vec();
    let (mut changes, mut existing) = (0, 0);
    for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
        let Some((offset, size)) = section.file_range() else {
            continue;
        };
        let start = usize::try_from(offset).map_err(|_| "Некорректное смещение секции")?;
        let end = start
            .checked_add(usize::try_from(size).map_err(|_| "Некорректная секция")?)
            .ok_or("Переполнение секции")?;
        let section_bytes = output
            .get_mut(start..end)
            .ok_or("Секция за пределами файла")?;
        let (c, p) = apply_pattern(section_bytes, original, patched, fix)?;
        changes += c;
        existing += p;
    }
    if changes + existing != 1 {
        return Err(format!(
            "Версия не поддерживается профилем {profile}: совпадений {}. SHA-256 {}",
            changes + existing,
            journal::digest(data)
        ));
    }
    Ok(Plan {
        data: output,
        changes,
        existing,
        profile: profile.into(),
    })
}

fn plan(data: &[u8], kind: TargetKind) -> Result<Plan, String> {
    match kind {
        TargetKind::IdeMainJs => plan_js(data),
        TargetKind::IdeAsar => crate::core::asar::plan_asar(data),
        _ => plan_binary(data, kind),
    }
}
fn inferred_kind(path: &Path) -> TargetKind {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    if name.ends_with(".asar") {
        TargetKind::IdeAsar
    } else if name.ends_with(".js") {
        TargetKind::IdeMainJs
    } else if name == "agy" || name == "agy.exe" {
        TargetKind::AgyCli
    } else {
        TargetKind::LanguageServer
    }
}
pub fn check_binary_state(path: &Path) -> BinaryState {
    state_for_kind(path, inferred_kind(path))
}

pub fn check_target_state(target: &FoundTarget) -> BinaryState {
    state_for_kind(&target.path, target.kind)
}

fn state_for_kind(path: &Path, kind: TargetKind) -> BinaryState {
    let Ok(data) = fs::read(path) else {
        return BinaryState::Unknown;
    };
    match plan(&data, kind) {
        Ok(p) => state_from_counts(p.changes, p.existing),
        Err(_) => BinaryState::Unknown,
    }
}

fn ensure_file_closed(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let holders = crate::system::file_lock::holders(&[path.to_path_buf()])?;
        if !holders.is_empty() {
            return Err(format!(
                "Закройте Antigravity перед изменением файлов: {}",
                holders.join(", ")
            ));
        }
    }
    let _ = path;
    Ok(())
}

/// Signing is done on a temporary copy, before backup metadata and replacement.
fn prepare_for_write(path: &Path, data: Vec<u8>, kind: TargetKind) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "macos")]
    if matches!(kind, TargetKind::LanguageServer | TargetKind::AgyCli) {
        use std::io::Write;
        let mut temp =
            tempfile::NamedTempFile::new_in(path.parent().unwrap()).map_err(|e| e.to_string())?;
        temp.write_all(&data).map_err(|e| e.to_string())?;
        let status = crate::system::command::output(
            "codesign",
            [
                "--force",
                "--sign",
                "-",
                "--preserve-metadata=entitlements,requirements,flags",
            ]
            .into_iter()
            .map(std::ffi::OsStr::new)
            .chain([temp.path().as_os_str()]),
        )
        .map_err(|e| e.to_string())?;
        if !status.status.success() {
            return Err(format!(
                "Не удалось подписать временную копию; оригинал сохранён: {}",
                String::from_utf8_lossy(&status.stderr).trim()
            ));
        }
        let verified = crate::system::command::output(
            "codesign",
            ["--verify", "--strict"]
                .into_iter()
                .map(std::ffi::OsStr::new)
                .chain([temp.path().as_os_str()]),
        )
        .map_err(|e| e.to_string())?;
        if !verified.status.success() {
            return Err(format!(
                "Подпись временной копии не прошла проверку: {}",
                String::from_utf8_lossy(&verified.stderr).trim()
            ));
        }
        return fs::read(temp.path()).map_err(|e| e.to_string());
    }
    let _ = (path, kind);
    Ok(data)
}

pub fn patch_target(target: &FoundTarget) -> Result<PatchOutcome, String> {
    let _guard = operation_guard();
    let before = fs::read(&target.path).map_err(|e| e.to_string())?;
    let p = plan(&before, target.kind)?;
    if p.changes == 0 {
        return if p.existing > 0 {
            Ok(PatchOutcome::AlreadyPatched)
        } else if matches!(target.kind, TargetKind::IdeAsar) {
            Ok(PatchOutcome::NotApplicable)
        } else {
            Err("Версия/сигнатура не поддерживается; файл не изменён".into())
        };
    }
    ensure_file_closed(&target.path)?;
    let after = prepare_for_write(&target.path, p.data, target.kind)?;
    journal::apply(&target.path, Some(&before), &after, &p.profile)?;
    Ok(PatchOutcome::Changed(p.changes))
}

pub fn restore_target(target: &FoundTarget) -> Result<PatchOutcome, String> {
    let _guard = operation_guard();
    ensure_file_closed(&target.path)?;
    if journal::restore(&target.path)? {
        return Ok(PatchOutcome::Restored);
    }
    let before = fs::read(&target.path).map_err(|e| e.to_string())?;
    if matches!(target.kind, TargetKind::IdeAsar | TargetKind::IdeMainJs)
        && plan(&before, target.kind).is_ok_and(|p| p.changes == 0 && p.existing == 0)
    {
        return Ok(PatchOutcome::NotApplicable);
    }
    let current_state = plan(&before, target.kind)
        .map(|p| state_from_counts(p.changes, p.existing))
        .unwrap_or(BinaryState::Unknown);
    if current_state == BinaryState::Stock {
        return Ok(PatchOutcome::AlreadyStock);
    }
    // Legacy backups are accepted only if applying this exact engine reproduces the current bytes.
    let mut candidates = vec![
        target.path.with_extension("bak"),
        target.path.with_extension("original"),
    ];
    let mut appended = target.path.as_os_str().to_os_string();
    appended.push(".bak");
    candidates.push(appended.into());
    for backup in candidates {
        if let Ok(original) = fs::read(&backup) {
            if let Ok(p) = plan(&original, target.kind) {
                if p.changes > 0 && p.existing == 0 && p.data == before {
                    crate::system::fs_utils::robust_write_file(&target.path, &original)?;
                    return Ok(PatchOutcome::Restored);
                }
            }
        }
    }
    Err("Нет backup, соответствующего текущей версии. Файл сохранён; восстановите точную версию приложения.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unrelated_valid_asar_is_skipped_but_damaged_archive_is_not_called_restored() {
        let dir = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: dir.path().join("app.asar"),
            kind: TargetKind::IdeAsar,
            name: "fixture".into(),
        };
        let header = b"{\"files\":{}}";
        let mut bytes = vec![];
        for value in [4u32, 20, 16, header.len() as u32] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend(header);
        bytes.resize(28, 0);
        fs::write(&target.path, &bytes).unwrap();
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::NotApplicable);
        assert_eq!(
            restore_target(&target).unwrap(),
            PatchOutcome::NotApplicable
        );
        assert_eq!(fs::read(&target.path).unwrap(), bytes);
        fs::write(&target.path, b"broken archive").unwrap();
        assert!(restore_target(&target).is_err());
    }
    fn macho_fixture(code: &[u8], cpu: u32) -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        // mach_header_64 + LC_SEGMENT_64 + one executable __text section.
        for (offset, value) in [
            (0, 0xfeedfacfu32),
            (4, cpu),
            (12, 2),
            (16, 1),
            (20, 152),
            (32, 0x19),
            (36, 152),
            (88, 7),
            (92, 5),
            (96, 1),
            (152, 512),
            (156, 2),
            (168, 0x80000400),
        ] {
            data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(64, 1024u64), (80, 1024), (144, code.len() as u64)] {
            data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        data[40..46].copy_from_slice(b"__TEXT");
        data[104..110].copy_from_slice(b"__text");
        data[120..126].copy_from_slice(b"__TEXT");
        data[512..512 + code.len()].copy_from_slice(code);
        data
    }

    #[test]
    fn macho_core_profiles_support_both_architectures_and_reject_unknown_x64_cli() {
        let x64 = b"\x80\x78\x08\x00\x74\x0a\x48\x8b\x44\x24\x20\x48\x89\x44\x60";
        let arm64 = b"\x03\x20\x40\x39\x03\x00\x00\x36\x00\x00\x00\x00\x03\x10\x06\xa9";
        for (code, cpu) in [(x64.as_slice(), 0x01000007), (arm64.as_slice(), 0x0100000c)] {
            let original = macho_fixture(code, cpu);
            let patched = plan_binary(&original, TargetKind::LanguageServer).unwrap();
            assert_eq!((patched.changes, patched.existing), (1, 0));
            assert_eq!(&patched.data[..512], &original[..512]);
            let repeated = plan_binary(&patched.data, TargetKind::LanguageServer).unwrap();
            assert_eq!((repeated.changes, repeated.existing), (0, 1));
            assert_eq!(repeated.data, patched.data);
        }
        assert!(plan_binary(&macho_fixture(x64, 0x01000007), TargetKind::AgyCli).is_err());
        let cli = b"\x48\x85\xc0\x0f\x84\x0a\x00\x00\x00\x80\x78\x08\x00\x0f\x85";
        assert_eq!(
            plan_binary(&macho_fixture(cli, 0x01000007), TargetKind::AgyCli)
                .unwrap()
                .changes,
            1
        );
    }

    #[test]
    fn macho_arm64_cli_patch_is_exact_and_idempotent() {
        // Exercise both supported instruction gaps and every TBZ immediate prefix.
        for branch in [0x03, 0x23, 0x43, 0x63, 0x83, 0xa3, 0xc3, 0xe3] {
            for gap in [1, 2] {
                let mut code = vec![0x03, 0x20, 0x40, 0x39, branch, 0x0a, 0x00, 0x36];
                for _ in 0..gap {
                    code.extend_from_slice(b"\x1f\x20\x03\xd5"); // NOP
                }
                code.extend_from_slice(b"\x03\x10\x06\xa9");
                let mut original = macho_fixture(&code, 0x0100000c);
                // A matching sequence outside __text must remain untouched.
                original[800..800 + code.len()].copy_from_slice(&code);
                let patched = plan_binary(&original, TargetKind::AgyCli).unwrap();
                assert_eq!(patched.profile, "agy-arm64-v1");
                assert_eq!((patched.changes, patched.existing), (1, 0));
                let mut expected = original;
                expected[512..520].copy_from_slice(b"\x23\x00\x80\x52\x03\x20\x00\x39");
                assert_eq!(patched.data, expected);
                let repeated = plan_binary(&patched.data, TargetKind::AgyCli).unwrap();
                assert_eq!((repeated.changes, repeated.existing), (0, 1));
                assert_eq!(repeated.data, patched.data);
            }
        }
    }

    #[test]
    fn macho_arm64_cli_rejects_missing_ambiguous_and_wrong_architecture_gates() {
        let code = b"\x03\x20\x40\x39\x03\x00\x00\x36\x1f\x20\x03\xd5\x03\x10\x06\xa9";
        let stock = macho_fixture(code, 0x0100000c);
        let patched = plan_binary(&stock, TargetKind::AgyCli).unwrap();
        let patched_code = &patched.data[512..512 + code.len()];
        for unsupported in [
            vec![0u8; code.len()],
            code[..code.len() - 1].to_vec(),
            [code.as_slice(), code.as_slice()].concat(),
            [code.as_slice(), patched_code].concat(),
            [patched_code, patched_code].concat(),
        ] {
            assert!(
                plan_binary(&macho_fixture(&unsupported, 0x0100000c), TargetKind::AgyCli).is_err()
            );
        }
        assert!(plan_binary(&macho_fixture(code, 0x01000007), TargetKind::AgyCli).is_err());
    }

    fn pe_fixture(code: &[u8], machine: u16) -> Vec<u8> {
        let mut data = vec![0u8; 1536];
        data[..2].copy_from_slice(b"MZ");
        data[60..64].copy_from_slice(&128u32.to_le_bytes());
        data[128..132].copy_from_slice(b"PE\0\0");
        for (offset, value) in [
            (132, machine),
            (134, 2),
            (148, 240),
            (150, 0x22),
            (152, 0x20b),
            (220, 3),
        ] {
            data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [
            (156, 512u32),
            (168, 0x1000),
            (172, 0x1000),
            (184, 0x1000),
            (188, 512),
            (208, 0x3000),
            (212, 512),
            (260, 16),
        ] {
            data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (section, name, raw, address, flags) in [
            (392, b".text\0\0\0", 512u32, 0x1000u32, 0x60000020u32),
            (432, b".rdata\0\0", 1024, 0x2000, 0x40000040),
        ] {
            data[section..section + 8].copy_from_slice(name);
            for (offset, value) in [(8, 512), (12, address), (16, 512), (20, raw), (36, flags)] {
                data[section + offset..section + offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            data[raw as usize..raw as usize + code.len()].copy_from_slice(code);
        }
        data
    }
    #[test]
    fn pe_architecture_code_sections_and_exact_rollback() {
        let code = b"\x80\x78\x08\x00\x74\x0a\x48\x8b\x44\x24\x20\x48\x89\x44\x60";
        let original = pe_fixture(code, 0x8664);
        let p = plan_binary(&original, TargetKind::LanguageServer).unwrap();
        assert_eq!((p.changes, p.existing), (1, 0));
        assert_eq!(&p.data[1024..], &original[1024..]); // Identical marker in data is untouched.
        assert!(plan_binary(&pe_fixture(code, 0xaa64), TargetKind::LanguageServer).is_err());
        assert!(plan_binary(
            &pe_fixture(&[code.as_slice(), code.as_slice()].concat(), 0x8664),
            TargetKind::LanguageServer
        )
        .is_err());
        // Synthetic PE can be used for planner tests on every platform. A JS
        // target exercises filesystem transactions without invoking macOS signing.
        let dir = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: dir.path().join("main.js"),
            kind: TargetKind::IdeMainJs,
            name: "fixture".into(),
        };
        let original = b"x.resetIsTierGCPTos(),x.isGoogleInternal;";
        fs::write(&target.path, original).unwrap();
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::Changed(1));
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::AlreadyPatched);
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
        assert_eq!(fs::read(&target.path).unwrap(), original);
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::AlreadyStock);
    }
    #[test]
    fn binary_wildcards_match_linefeed_but_ambiguous_gates_are_rejected() {
        let bytes = b"\x48\x85\xc0\x0f\x84\x0a\x00\x00\x00\x80\x78\x08\x00\x0f\x85";
        assert!(regex_cli_x64_long_orig().is_match(bytes));
        let mut duplicate = [bytes.as_slice(), bytes.as_slice()].concat();
        assert!(apply_pattern(
            &mut duplicate,
            regex_cli_x64_long_orig(),
            regex_cli_x64_long_patched(),
            CLI_GATE_X64_LONG_FIX
        )
        .is_err());
    }
    #[test]
    fn partial_js_is_completed_and_unrelated_text_is_unsupported() {
        let p = plan_js(b"x.resetIsTierGCPTos(),true; y.resetIsTierGCPTos(),y.isGoogleInternal")
            .unwrap();
        assert_eq!(
            state_from_counts(p.changes, p.existing),
            BinaryState::PartiallyPatched
        );
        let next = plan_js(&p.data).unwrap();
        assert_eq!((next.changes, next.existing), (0, 2));
        assert_eq!(plan_js(b"object.isGoogleInternal").unwrap().changes, 0);
    }
    #[test]
    fn raw_bytes_and_generic_cli_gate_do_not_authorize_a_binary_patch() {
        assert!(plan_binary(
            b"\x48\x85\xc0\x74\x0a\x48\x8b ineligible",
            TargetKind::AgyCli
        )
        .is_err());
    }
}
