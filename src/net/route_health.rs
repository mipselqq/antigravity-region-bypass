//! One host/route score table for DNS, IP ranking and CONNECT, including separate processes.
//! Probe failures and application region refusals have deliberately different lifetimes.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    net::SocketAddr,
    path::PathBuf,
    sync::OnceLock,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const FRESH_MS: u64 = 20_000;
const REGION_MS: u64 = 10 * 60_000;
const MAX_ENTRIES: usize = 512;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
pub fn host_name(host: &str) -> String {
    host.trim_matches('.').to_ascii_lowercase()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub host: String,
    pub route: String,
}
impl Key {
    pub fn ip(host: &str, addr: SocketAddr) -> Self {
        Self {
            host: host_name(host),
            route: addr.to_string(),
        }
    }
    fn id(&self) -> String {
        format!("{}|{}", self.host, self.route)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Entry {
    pub host: String,
    pub route: String,
    pub latency_ms: u64,
    pub checked_ms: u64,
    pub ok: bool,
    failures: u32,
    retry_ms: u64,
    region_until_ms: u64,
}
impl Entry {
    fn blocked(&self, now: u64) -> bool {
        self.retry_ms > now || self.region_until_ms > now
    }
    fn fresh(&self, now: u64) -> bool {
        self.checked_ms <= now && now - self.checked_ms < FRESH_MS
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Used {
    key: Key,
    at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    version: u32,
    entries: BTreeMap<String, Entry>,
    leaders: BTreeMap<String, String>,
    used: Vec<Used>,
    events: BTreeMap<String, u64>,
    pub revision: u64,
    pub refused_hosts: BTreeMap<String, u64>,
    #[serde(default)]
    region_actions: BTreeMap<String, u64>,
    #[serde(default)]
    region_episodes: BTreeMap<String, u64>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            entries: BTreeMap::new(),
            leaders: BTreeMap::new(),
            used: vec![],
            events: BTreeMap::new(),
            revision: 0,
            refused_hosts: BTreeMap::new(),
            region_actions: BTreeMap::new(),
            region_episodes: BTreeMap::new(),
        }
    }
}
impl State {
    pub fn known_addresses(&self, host: &str) -> Vec<SocketAddr> {
        self.entries
            .values()
            .filter(|e| e.host == host_name(host))
            .filter_map(|e| e.route.parse().ok())
            .collect()
    }
    pub fn latency(&self, key: &Key) -> Option<u64> {
        self.entries.get(&key.id()).map(|e| e.latency_ms)
    }
    pub fn region_blocked(&self, key: &Key, now: u64) -> bool {
        self.entries
            .get(&key.id())
            .is_some_and(|e| e.region_until_ms > now)
    }
    pub fn cached(&self, key: &Key, now: u64) -> Option<bool> {
        let e = self.entries.get(&key.id())?;
        if e.blocked(now) {
            Some(false)
        } else if e.fresh(now) {
            Some(e.ok)
        } else {
            None
        }
    }
    pub fn blocked(&self, key: &Key, now: u64) -> bool {
        self.entries.get(&key.id()).is_some_and(|e| e.blocked(now))
    }
    pub fn record(&mut self, key: &Key, result: Result<u128, ()>, now: u64) {
        let e = self.entries.entry(key.id()).or_insert_with(|| Entry {
            host: key.host.clone(),
            route: key.route.clone(),
            ..Default::default()
        });
        // Concurrent failures of an already benched route must not extend its exclusion.
        if e.retry_ms > now && result.is_err() {
            return;
        }
        e.checked_ms = now;
        match result {
            Ok(ms) => {
                let ms = ms.clamp(1, 3_600_000) as u64;
                e.latency_ms = if e.latency_ms == 0 {
                    ms
                } else {
                    (e.latency_ms.saturating_mul(3).saturating_add(ms)) / 4
                };
                e.ok = true;
                e.failures = 0;
                e.retry_ms = 0;
                // A valid TLS/HTTP probe says nothing about an account's region refusal.
            }
            Err(()) => {
                e.ok = false;
                e.failures = e.failures.saturating_add(1).min(8);
                e.retry_ms = now
                    + if e.failures < 2 {
                        2_000
                    } else {
                        (15_000u64 << (e.failures - 2)).min(300_000)
                    };
            }
        }
        if self.entries.len() > MAX_ENTRIES {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.checked_ms)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.entries.remove(&k);
            }
        }
    }
    pub fn order(&mut self, keys: &[Key], now: u64) -> Vec<Key> {
        let mut seen = std::collections::BTreeSet::new();
        let mut keys: Vec<_> = keys
            .iter()
            .filter(|k| seen.insert(k.id()) && self.cached(k, now) == Some(true))
            .cloned()
            .collect();
        keys.sort_by_key(|k| {
            self.entries
                .get(&k.id())
                .map(|e| e.latency_ms)
                .unwrap_or(u64::MAX)
        });
        if let Some(first) = keys.first().cloned() {
            if let Some(old) = self.leaders.get(&first.host) {
                if let Some(pos) = keys.iter().position(|k| &k.route == old) {
                    let new_ms = self.entries[&first.id()].latency_ms;
                    let old_ms = self.entries[&keys[pos].id()].latency_ms;
                    // Keep the existing route until the challenger is at least 15% faster.
                    if new_ms.saturating_mul(100) > old_ms.saturating_mul(85) {
                        let leader = keys.remove(pos);
                        keys.insert(0, leader);
                    }
                }
            }
            self.leaders.insert(first.host, keys[0].route.clone());
        }
        keys
    }
    pub fn note_used(&mut self, key: &Key, now: u64) {
        self.used
            .retain(|u| now.saturating_sub(u.at) < 120_000 && u.key != *key);
        self.used.push(Used {
            key: key.clone(),
            at: now,
        });
        if self.used.len() > MAX_ENTRIES {
            self.used.remove(0);
        }
    }
    /// Penalise only an unambiguous, host-specific route. No global "last connection" guess.
    pub fn region_refusal(
        &mut self,
        event_id: &str,
        host: Option<&str>,
        route: Option<&str>,
        now: u64,
    ) -> Option<Key> {
        self.events
            .retain(|_, at| now.saturating_sub(*at) < REGION_MS);
        if self.events.contains_key(event_id) {
            return None;
        }
        self.events.insert(event_id.into(), now);
        if self.events.len() > MAX_ENTRIES {
            if let Some(old) = self
                .events
                .iter()
                .min_by_key(|(_, t)| **t)
                .map(|(k, _)| k.clone())
            {
                self.events.remove(&old);
            }
        }
        let hosts: Vec<String> = host.map(|h| vec![host_name(h)]).unwrap_or_else(|| {
            super::provider::NRPT_AGENT
                .iter()
                .map(|h| host_name(h))
                .collect()
        });
        if hosts.iter().any(|h| {
            self.region_actions
                .get(h)
                .is_none_or(|at| now.saturating_sub(*at) >= 30_000)
        }) {
            self.revision = self.revision.wrapping_add(1);
            for h in &hosts {
                self.region_actions.insert(h.clone(), now);
            }
        }
        for h in &hosts {
            self.refused_hosts.insert(h.clone(), now + REGION_MS);
        }
        let host = host?;
        let host = host_name(host);
        if route.is_none()
            && self
                .region_episodes
                .get(&host)
                .is_some_and(|until| *until > now)
        {
            return None;
        }
        let candidates: Vec<_> = self
            .used
            .iter()
            .filter(|u| {
                u.key.host == host
                    && now.saturating_sub(u.at) < 120_000
                    && route.is_none_or(|r| u.key.route == r)
            })
            .collect();
        if candidates.len() != 1 {
            return None;
        }
        let key = candidates[0].key.clone();
        let e = self.entries.get_mut(&key.id())?;
        // A sequence of retries on a pooled tunnel must not continually prolong the penalty.
        if e.region_until_ms <= now {
            e.region_until_ms = now + REGION_MS;
        }
        self.region_episodes.insert(host, now + 180_000);
        Some(key)
    }
    pub fn host_refused(&self, host: &str, now: u64) -> bool {
        self.refused_hosts
            .get(&host_name(host))
            .is_some_and(|until| *until > now)
    }
}

pub struct Store {
    path: PathBuf,
}
impl Store {
    pub fn new(directory: PathBuf) -> Self {
        Self {
            path: directory.join("route-health.json"),
        }
    }
    fn read(&self) -> Result<State, String> {
        match fs::read(&self.path) {
            Ok(b) if b.len() <= 1024 * 1024 => {
                let s: State =
                    serde_json::from_slice(&b).map_err(|e| format!("route-health.json: {e}"))?;
                if s.version != 1 || s.entries.len() > MAX_ENTRIES || s.used.len() > MAX_ENTRIES {
                    return Err("Некорректный формат состояния маршрутов".into());
                }
                Ok(s)
            }
            Ok(_) => Err("Состояние маршрутов превышает 1 MiB".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e.to_string()),
        }
    }
    fn lock(&self) -> Result<File, String> {
        fs::create_dir_all(self.path.parent().unwrap()).map_err(|e| e.to_string())?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.path.with_extension("lock"))
            .map_err(|e| e.to_string())?;
        super::config::inherit_directory_owner(&self.path.with_extension("lock"))?;
        let start = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(file),
                Err(fs::TryLockError::WouldBlock) if start.elapsed() < Duration::from_secs(2) => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(e) => return Err(format!("Блокировка состояния маршрутов: {e}")),
            }
        }
    }
    pub fn snapshot(&self) -> Result<State, String> {
        self.read()
    }
    pub fn update<T>(&self, change: impl FnOnce(&mut State) -> T) -> Result<T, String> {
        let _lock = self.lock()?;
        let mut state = self.read()?;
        let result = change(&mut state);
        let data = serde_json::to_vec(&state).map_err(|e| e.to_string())?;
        crate::system::fs_utils::robust_write_file(&self.path, &data)?;
        super::config::inherit_directory_owner(&self.path)?;
        Ok(result)
    }
}

pub fn store() -> &'static Store {
    static STORE: OnceLock<Store> = OnceLock::new();
    STORE.get_or_init(|| Store::new(super::config::directory()))
}
pub fn record(key: &Key, result: Result<u128, ()>) -> Result<(), String> {
    store().update(|s| s.record(key, result, now_ms()))
}
pub fn note_used(key: &Key) {
    if let Err(e) = store().update(|s| s.note_used(key, now_ms())) {
        super::relay::log_event(&e);
    }
}
pub fn order(keys: &[Key]) -> Result<Vec<Key>, String> {
    store().update(|s| s.order(keys, now_ms()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(host: &str, n: u8) -> Key {
        Key::ip(host, format!("127.0.0.{n}:443").parse().unwrap())
    }
    #[test]
    fn freshness_backoff_and_region_failure_are_independent_per_host_and_route() {
        let mut s = State::default();
        let a = key("a.test", 1);
        let b = key("b.test", 1);
        s.record(&a, Ok(100), 1);
        assert_eq!(s.cached(&b, 2), None);
        assert_eq!(s.cached(&a, FRESH_MS + 1), None);
        s.record(&a, Err(()), 3);
        s.record(&a, Err(()), 2004);
        s.record(&b, Ok(100), 2004);
        assert_eq!(s.cached(&b, 2005), Some(true));
        assert_eq!(s.cached(&a, 2005), Some(false));
        s.record(&a, Ok(90), 3000);
        s.note_used(&a, 3001);
        assert_eq!(
            s.region_refusal("evt", Some("a.test"), None, 3002),
            Some(a.clone())
        );
        s.record(&a, Ok(80), 3003);
        assert_eq!(s.cached(&a, 3004), Some(false));
        assert_eq!(s.region_refusal("evt", Some("a.test"), None, 3005), None);
    }
    #[test]
    fn ambiguous_sessions_and_small_latency_noise_do_not_switch_routes() {
        let mut s = State::default();
        let a = key("a.test", 1);
        let b = key("a.test", 2);
        s.record(&a, Ok(100), 1);
        s.record(&b, Ok(110), 1);
        assert_eq!(s.order(&[a.clone(), b.clone()], 2)[0], a);
        s.record(&b, Ok(50), 3);
        assert_eq!(s.order(&[a.clone(), b.clone()], 4)[0], a);
        s.note_used(&a, 5);
        s.note_used(&b, 6);
        assert_eq!(s.region_refusal("multi", Some("a.test"), None, 7), None);
        assert!(!s.blocked(&a, 8) && !s.blocked(&b, 8));
        assert_eq!(
            s.region_refusal("specific", Some("a.test"), Some(&b.route), 9),
            Some(b)
        );
    }
    #[test]
    fn separate_store_handles_merge_concurrent_updates_and_preserve_corrupt_state() {
        let dir = tempfile::tempdir().unwrap();
        std::thread::scope(|scope| {
            for n in 1..9 {
                let path = dir.path().to_path_buf();
                scope.spawn(move || {
                    Store::new(path)
                        .update(|s| s.record(&key("a.test", n), Ok(100), 1))
                        .unwrap();
                });
            }
        });
        let store = Store::new(dir.path().to_path_buf());
        assert_eq!(store.snapshot().unwrap().entries.len(), 8);
        fs::write(&store.path, b"broken").unwrap();
        assert!(store.update(|s| s.revision += 1).is_err());
        assert_eq!(fs::read(&store.path).unwrap(), b"broken");
    }
    #[test]
    #[ignore = "launched only by the isolated multiprocess regression test"]
    fn child_writer() {
        let dir = PathBuf::from(
            std::env::var_os("AG_TEST_ROUTE_DIRECTORY").expect("isolated test directory"),
        );
        let offset: u8 = std::env::var("AG_TEST_ROUTE_OFFSET")
            .unwrap()
            .parse()
            .unwrap();
        let store = Store::new(dir);
        for n in 1..5 {
            store
                .update(|s| s.record(&key("process.test", offset + n), Ok(100), 1))
                .unwrap();
        }
    }
    #[test]
    fn independent_processes_do_not_lose_route_updates() {
        let dir = tempfile::tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let mut children = Vec::new();
        for offset in [0, 10] {
            children.push(
                std::process::Command::new(&executable)
                    .args([
                        "--exact",
                        "net::route_health::tests::child_writer",
                        "--ignored",
                    ])
                    .env("AG_TEST_ROUTE_DIRECTORY", dir.path())
                    .env("AG_TEST_ROUTE_OFFSET", offset.to_string())
                    .stdout(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            );
        }
        for mut child in children {
            assert!(child.wait().unwrap().success());
        }
        assert_eq!(
            Store::new(dir.path().into())
                .snapshot()
                .unwrap()
                .entries
                .len(),
            8
        );
    }
}
