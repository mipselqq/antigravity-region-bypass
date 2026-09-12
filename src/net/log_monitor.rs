//! Watches only newly written language-server log data. No log text or account data is persisted.
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime},
};

const MAX_READ: u64 = 256 * 1024;
const MAX_LINE: usize = 16 * 1024;
const REFUSAL: &str = "user location is not supported";

#[derive(Debug)]
pub struct Refusal {
    pub id: String,
    pub host: Option<String>,
    pub route: Option<String>,
}

fn parse_refusal(line: &[u8], id: String) -> Option<Refusal> {
    let line = String::from_utf8_lossy(line).to_ascii_lowercase();
    if !line.contains(REFUSAL) {
        return None;
    }
    let hosts: Vec<_> = super::provider::NRPT_AGENT
        .iter()
        .filter(|h| {
            line.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '.')))
                .any(|word| word == **h)
        })
        .collect();
    let host = if hosts.len() == 1 {
        Some(hosts[0].to_string())
    } else {
        None
    };
    // Only explicitly labelled remote endpoints are evidence. Arbitrary IPs may describe the client.
    let route = ["remote=", "upstream=", "peer="].iter().find_map(|label| {
        let rest = line.split_once(label)?.1;
        let value = rest
            .split(|c: char| c.is_whitespace() || matches!(c, ',' | '"' | '\''))
            .next()?;
        value
            .parse::<std::net::SocketAddr>()
            .ok()
            .map(|a| a.to_string())
    });
    Some(Refusal { id, host, route })
}

struct Tail {
    offset: u64,
    created: Option<SystemTime>,
    anchor: Vec<u8>,
    pending: Vec<u8>,
    line_start: u64,
    emitted_line: Option<u64>,
}
impl Tail {
    fn open(path: &Path, skip_existing: bool) -> std::io::Result<Self> {
        let mut file = File::open(path)?;
        let meta = file.metadata()?;
        let mut anchor = vec![0; meta.len().min(128) as usize];
        file.read_exact(&mut anchor)?;
        let offset = if skip_existing { meta.len() } else { 0 };
        Ok(Self {
            offset,
            created: meta.created().ok(),
            anchor,
            pending: vec![],
            line_start: offset,
            emitted_line: None,
        })
    }
    fn poll(&mut self, path: &Path) -> std::io::Result<Vec<Refusal>> {
        let mut file = File::open(path)?;
        let meta = file.metadata()?;
        let mut anchor = vec![0; self.anchor.len().min(meta.len() as usize)];
        file.read_exact(&mut anchor)?;
        if meta.len() < self.offset || meta.created().ok() != self.created || anchor != self.anchor
        {
            *self = Self::open(path, false)?;
            file = File::open(path)?;
        }
        file.seek(SeekFrom::Start(self.offset))?;
        let mut bytes = Vec::new();
        file.take(MAX_READ).read_to_end(&mut bytes)?;
        let mut events = Vec::new();
        for byte in bytes {
            self.pending.push(byte);
            self.offset += 1;
            if byte == b'\n' || self.pending.len() == MAX_LINE {
                self.emit(path, &mut events);
                // Keep enough overlap when a single oversized line is split.
                if byte == b'\n' {
                    self.pending.clear();
                } else {
                    self.pending.drain(..self.pending.len() - REFUSAL.len());
                }
                self.line_start = self.offset - self.pending.len() as u64;
            }
        }
        // A log writer need not flush the final newline. The event id deduplicates this later.
        self.emit(path, &mut events);
        Ok(events)
    }
    fn emit(&mut self, path: &Path, events: &mut Vec<Refusal>) {
        if self.emitted_line == Some(self.line_start) {
            return;
        }
        // The same file/offset has the same id in the DNS service and proxy processes.
        let id = crate::system::journal::digest(
            format!("{}|{:?}|{}", path.display(), self.created, self.line_start).as_bytes(),
        );
        if let Some(event) = parse_refusal(&self.pending, id) {
            self.emitted_line = Some(self.line_start);
            events.push(event);
        }
    }
}

#[derive(Default)]
pub struct Watcher {
    tails: HashMap<PathBuf, Tail>,
    started: Option<SystemTime>,
}
impl Watcher {
    pub fn poll(&mut self, roots: &[PathBuf]) -> Vec<Refusal> {
        let first = self.started.is_none();
        let started = *self.started.get_or_insert_with(SystemTime::now);
        let files = discover(roots);
        self.tails.retain(|path, _| files.contains(path));
        let mut events = Vec::new();
        for path in files {
            if !self.tails.contains_key(&path) {
                let old = fs::metadata(&path)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .is_some_and(|t| t < started);
                if let Ok(tail) = Tail::open(&path, first || old) {
                    self.tails.insert(path.clone(), tail);
                }
            }
            if let Some(tail) = self.tails.get_mut(&path) {
                if let Ok(found) = tail.poll(&path) {
                    events.extend(found);
                }
            }
        }
        events
    }
}

fn discover(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut pending: Vec<_> = roots.iter().cloned().map(|p| (p, 0)).collect();
    let mut found = Vec::new();
    let mut visited = 0;
    while let Some((path, depth)) = pending.pop() {
        visited += 1;
        if visited > 4096 || found.len() >= 64 {
            break;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                continue;
            }
        }
        if meta.is_dir() && depth < 8 {
            if let Ok(entries) = fs::read_dir(&path) {
                let mut children: Vec<_> = entries.flatten().take(512).map(|e| e.path()).collect();
                children.sort(); // Most recent timestamp-named session is popped first.
                pending.extend(children.into_iter().map(|p| (p, depth + 1)));
            }
        } else if meta.is_file()
            && path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                matches!(
                    n,
                    "language_server.log" | "language-server.log" | "ls-main.log"
                )
            })
        {
            found.push(path);
        }
    }
    found
}

pub fn spawn_background() {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(|| {
        let mut watcher = Watcher::default();
        let mut config_error = String::new();
        loop {
            match super::config::load() {
                Ok(config) => {
                    config_error.clear();
                    if config.watch_region_errors {
                        for event in watcher.poll(&config.log_roots) {
                            let outcome = super::route_health::store().update(|state| {
                                let before = state.revision;
                                let route = state.region_refusal(
                                    &event.id,
                                    event.host.as_deref(),
                                    event.route.as_deref(),
                                    super::route_health::now_ms(),
                                );
                                (state.revision != before, route)
                            });
                            match outcome {
                                Ok((true, route)) => {
                                    super::resolvers::invalidate_network_caches();
                                    super::relay::log_event(&format!("Региональный отказ: {}; {}. Запрошен повторный выбор DNS/маршрутов.",
                                        event.host.as_deref().unwrap_or("хост не указан"),
                                        if route.is_some() { "однозначно определённый маршрут временно исключён" } else { "маршрут не определён, штраф не назначен" }));
                                }
                                Err(e) => super::relay::log_event(&e),
                                _ => {}
                            }
                        }
                    } else {
                        watcher = Watcher::default();
                    }
                }
                Err(e) if e != config_error => {
                    super::relay::log_event(&e);
                    config_error = e;
                }
                Err(_) => {}
            }
            std::thread::sleep(Duration::from_secs(3));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn tails_skip_history_handle_split_writes_and_truncation_without_copying_log_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ls-main.log");
        fs::write(&path, "User location is not supported\n").unwrap();
        let mut w = Watcher::default();
        let roots = [dir.path().to_path_buf()];
        assert!(w.poll(&roots).is_empty());
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        write!(file, "cloudcode-pa.googleapis.com User location is not ").unwrap();
        assert!(w.poll(&roots).is_empty());
        writeln!(file, "supported remote=127.0.0.1:443 secret=do-not-persist").unwrap();
        let events = w.poll(&roots);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].host.as_deref(),
            Some("cloudcode-pa.googleapis.com")
        );
        assert_eq!(events[0].route.as_deref(), Some("127.0.0.1:443"));
        assert!(!format!("{:?}", events).contains("secret"));
        assert!(w.poll(&roots).is_empty());
        fs::write(&path, "User location is not supported\n").unwrap();
        assert_eq!(w.poll(&roots).len(), 1);
    }
    #[test]
    fn ignores_generic_400_and_does_not_guess_a_host_from_similar_domain() {
        assert!(parse_refusal(b"HTTP 400 invalid request", "id".into()).is_none());
        let e = parse_refusal(
            b"fakecloudcode-pa.googleapis.com User location is not supported",
            "id".into(),
        )
        .unwrap();
        assert!(e.host.is_none());
        let e = parse_refusal(b"cloudcode-pa.googleapis.com daily-cloudcode-pa.googleapis.com User location is not supported", "id".into()).unwrap();
        assert!(e.host.is_none());
    }
    #[test]
    fn two_watchers_identify_the_same_event_and_replacement_with_larger_file_is_seen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("language_server.log");
        fs::write(&path, "old header\n").unwrap();
        let roots = [dir.path().to_path_buf()];
        let mut a = Watcher::default();
        let mut b = Watcher::default();
        a.poll(&roots);
        b.poll(&roots);
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"User location is not supported")
            .unwrap();
        let ea = a.poll(&roots);
        let eb = b.poll(&roots);
        assert_eq!(ea[0].id, eb[0].id);
        assert!(a.poll(&roots).is_empty());
        fs::write(
            &path,
            "NEW header long enough to exceed the previous size\nUser location is not supported\n",
        )
        .unwrap();
        assert_eq!(a.poll(&roots).len(), 1);
    }
}
