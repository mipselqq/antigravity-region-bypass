use crate::net::client::{nodata_response, question_name, question_type};
use crate::net::resolvers;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

// Darwin requires a locally assigned address; do not require a lo0 alias.
#[cfg(target_os = "macos")]
pub const LISTEN_IP: &str = "127.0.0.1";
#[cfg(not(target_os = "macos"))]
pub const LISTEN_IP: &str = "127.0.0.53";
pub const LISTEN_PORT: u16 = 53;
pub const HEALTH_PORT: u16 = 15353;
pub const HEALTH_NAME: &str = "antigravity-relay-health.invalid";

/// Check local port 53 independently of Internet DNS or the relay's startup.
pub fn local_dns_available() -> Result<bool, String> {
    let receiver =
        UdpSocket::bind("127.0.0.254:53").map_err(|e| format!("Проверка локального DNS: {e}"))?;
    receiver
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|e| e.to_string())?;
    let sender = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let packet = crate::net::client::build_query(HEALTH_NAME, 0xA657);
    sender
        .send_to(&packet, receiver.local_addr().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut bytes = [0u8; 512];
    match receiver.recv_from(&mut bytes) {
        Ok((n, peer)) => {
            Ok(peer == sender.local_addr().map_err(|e| e.to_string())? && bytes[..n] == packet)
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e.to_string()),
    }
}
const WORKER_THREADS: usize = 4;
const MAX_PENDING: usize = 32;
const MAX_WAITERS: usize = 64;

type Waiter = (u16, std::net::SocketAddr);
#[derive(Default)]
struct Pending {
    // Keep the complete question/options; requests differing only by ID share work.
    jobs: std::collections::HashMap<Vec<u8>, Vec<Waiter>>,
}
impl Pending {
    fn add(
        &mut self,
        query: &[u8],
        peer: Option<std::net::SocketAddr>,
    ) -> Result<(Vec<u8>, bool), ()> {
        if query.len() < 12 {
            return Err(());
        }
        let id = u16::from_be_bytes([query[0], query[1]]);
        let mut key = query.to_vec();
        key[..2].fill(0);
        let new = !self.jobs.contains_key(&key);
        if new && self.jobs.len() >= MAX_PENDING {
            return Err(());
        }
        let waiters = self.jobs.entry(key.clone()).or_default();
        if let Some(peer) = peer {
            if !waiters.contains(&(id, peer)) {
                if waiters.len() >= MAX_WAITERS {
                    return Err(());
                }
                waiters.push((id, peer));
            }
        }
        Ok((key, new))
    }
}

fn usage_recorder() -> mpsc::SyncSender<super::route_health::Key> {
    let (tx, rx) = mpsc::sync_channel::<super::route_health::Key>(512);
    thread::spawn(move || loop {
        let Ok(first) = rx.recv() else { break };
        let mut keys = std::collections::BTreeSet::from([first]);
        // Batch metadata writes outside DNS response delivery.
        for key in rx.try_iter().take(511) {
            keys.insert(key);
        }
        if let Err(error) = super::route_health::store().update(|s| {
            for key in &keys {
                s.note_used(key, super::route_health::now_ms());
            }
        }) {
            log_event(&error);
        }
        thread::sleep(Duration::from_millis(250));
    });
    tx
}

fn note_answer(query: &[u8], reply: &[u8], usage: &mpsc::SyncSender<super::route_health::Key>) {
    if let Some(host) = question_name(query) {
        for ip in super::client::answer_addrs(reply) {
            let _ = usage.try_send(super::route_health::Key::ip(&host, (ip, 443).into()));
        }
    }
}

fn deliver(
    query: &[u8],
    client_addr: std::net::SocketAddr,
    cached: Option<resolvers::ResolveHit>,
    socket: &UdpSocket,
    pending: &Mutex<Pending>,
    tx: &mpsc::SyncSender<Vec<u8>>,
    usage: &mpsc::SyncSender<super::route_health::Key>,
) -> Result<(), String> {
    if let Some(ref hit) = cached {
        let _ = socket.send_to(&hit.reply, client_addr);
        note_answer(query, &hit.reply, usage);
        if !resolvers::refresh_due(query) {
            return Ok(());
        }
    }
    let peer = if cached.is_some() {
        None
    } else {
        Some(client_addr)
    };
    let job = pending
        .lock()
        .map_err(|_| "DNS queue poisoned")?
        .add(query, peer);
    match job {
        Ok((key, true)) => {
            if tx.try_send(key.clone()).is_err() {
                if let Ok(mut p) = pending.lock() {
                    p.jobs.remove(&key);
                }
                if peer.is_some() {
                    let _ = socket.send_to(&super::client::servfail_response(query), client_addr);
                }
            }
        }
        Err(()) if peer.is_some() => {
            let _ = socket.send_to(&super::client::servfail_response(query), client_addr);
        }
        _ => {}
    }
    Ok(())
}

static UPSTREAM_CACHE: std::sync::RwLock<Option<Vec<Ipv4Addr>>> = std::sync::RwLock::new(None);
static IF_INDEX_CACHE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

pub fn detach_console() {
    #[cfg(target_os = "windows")]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn FreeConsole() -> i32;
        }
        unsafe {
            FreeConsole();
        }
    }
}

pub fn log_dir() -> PathBuf {
    crate::system::service::install_dir()
}

pub fn upstream_conf_path() -> PathBuf {
    log_dir().join("upstream.conf")
}

pub fn iface_conf_path() -> PathBuf {
    log_dir().join("iface.conf")
}

fn mode_conf_path() -> PathBuf {
    log_dir().join("mode.conf")
}

pub fn save_upstream_config(servers: &[String]) {
    let dir = log_dir();
    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(upstream_conf_path(), servers.join("\n"));
    if let Ok(mut lock) = UPSTREAM_CACHE.write() {
        *lock = None;
    }
}

pub fn clear_custom_mode() {
    let _ = fs::remove_file(mode_conf_path());
}

pub fn save_if_index(idx: u32) {
    let dir = log_dir();
    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(iface_conf_path(), idx.to_string());
    IF_INDEX_CACHE.store(idx, std::sync::atomic::Ordering::SeqCst);
}

pub fn load_if_index() -> u32 {
    let cached = IF_INDEX_CACHE.load(std::sync::atomic::Ordering::SeqCst);
    if cached > 0 {
        return cached;
    }
    let p = iface_conf_path();
    if p.exists() {
        if let Ok(c) = fs::read_to_string(&p) {
            if let Ok(idx) = c.trim().parse::<u32>() {
                IF_INDEX_CACHE.store(idx, std::sync::atomic::Ordering::SeqCst);
                return idx;
            }
        }
    }
    0
}

pub fn load_upstream_servers() -> Vec<Ipv4Addr> {
    if let Ok(lock) = UPSTREAM_CACHE.read() {
        if let Some(cached) = lock.as_ref() {
            return cached.clone();
        }
    }

    let mut list = Vec::new();
    let p = upstream_conf_path();
    if p.exists() {
        if let Ok(c) = fs::read_to_string(&p) {
            for line in c.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
                    if !list.contains(&ip) {
                        list.push(ip);
                    }
                }
            }
        }
    }

    if list.is_empty() {
        for ip in crate::net::resolvers::all_provider_v4() {
            if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                if !list.contains(&addr) {
                    list.push(addr);
                }
            }
        }
    }

    if let Ok(mut lock) = UPSTREAM_CACHE.write() {
        *lock = Some(list.clone());
    }
    list
}

pub fn log_path() -> PathBuf {
    log_dir().join("dns_relay.log")
}

pub(crate) fn log_line(msg: &str) {
    #[cfg(debug_assertions)]
    {
        let p = log_path();
        let _ = fs::create_dir_all(log_dir());
        if fs::metadata(&p)
            .map(|m| m.len() > 64 * 1024)
            .unwrap_or(false)
        {
            let _ = fs::remove_file(&p);
        }
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(p) {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let _ = writeln!(f, "[{}] {}", ts, msg);
        }
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = msg;
    }
}

/// Operational recovery events are retained in release builds, without client log contents.
pub fn log_event(msg: &str) {
    let dir = super::config::directory();
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("network-events.log");
    if fs::metadata(&path).is_ok_and(|m| m.len() > 256 * 1024) {
        let _ = fs::rename(&path, dir.join("network-events.previous.log"));
    }
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = super::config::inherit_directory_owner(&path);
        let _ = writeln!(
            file,
            "[{}] {}",
            super::route_health::now_ms(),
            msg.replace(['\r', '\n'], " ")
        );
    }
}

pub fn log_fatal(msg: &str) {
    let p = log_path();
    let _ = fs::create_dir_all(log_dir());
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(p) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "[{}] FATAL: {}", ts, msg);
    }
}

pub fn run() -> Result<(), String> {
    let _ = load_if_index();
    let addr = format!("{}:{}", LISTEN_IP, LISTEN_PORT);
    let socket =
        UdpSocket::bind(&addr).map_err(|e| format!("Не удалось занять {}: {}", addr, e))?;
    let health = UdpSocket::bind((LISTEN_IP, HEALTH_PORT))
        .map_err(|e| format!("Проверка готовности DNS: {e}"))?;
    let _ = crate::net::socket::set_socket_buffers(&socket, 512 * 1024);
    log_line(&format!("start {}", addr));
    resolvers::warmup(load_if_index());
    crate::net::rank::spawn_background(true);
    super::log_monitor::spawn_background();
    let sock_arc = Arc::new(socket);

    let usage = usage_recorder();
    let pending = Arc::new(Mutex::new(Pending::default()));
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(MAX_PENDING);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..WORKER_THREADS {
        let rx_c = Arc::clone(&rx);
        let sock_c = Arc::clone(&sock_arc);
        let pending_c = Arc::clone(&pending);
        let usage_c = usage.clone();
        thread::spawn(move || loop {
            let job = {
                let guard = match rx_c.lock() {
                    Ok(g) => g,
                    Err(_) => break,
                };
                guard.recv()
            };
            match job {
                Ok(query) => {
                    let mut reply = resolvers::refresh_answer(&query, load_if_index())
                        .map(|h| h.reply)
                        .unwrap_or_else(|| super::client::servfail_response(&query));
                    let waiters = pending_c
                        .lock()
                        .ok()
                        .and_then(|mut p| p.jobs.remove(&query))
                        .unwrap_or_default();
                    for (id, peer) in &waiters {
                        reply[..2].copy_from_slice(&id.to_be_bytes());
                        let _ = sock_c.send_to(&reply, peer);
                    }
                    if !waiters.is_empty() {
                        note_answer(&query, &reply, &usage_c);
                    }
                }
                Err(_) => break,
            }
        });
    }

    // Startup readiness must never wait for external DNS or queued TLS probes.
    thread::spawn(move || {
        let mut bytes = [0u8; 512];
        while let Ok((n, peer)) = health.recv_from(&mut bytes) {
            let query = &bytes[..n];
            if question_name(query).as_deref() == Some(HEALTH_NAME) {
                if let Some(reply) =
                    crate::net::client::address_response(query, &[Ipv4Addr::LOCALHOST])
                {
                    let _ = health.send_to(&reply, peer);
                }
            }
        }
    });

    let mut buf = [0u8; 1500];
    let mut backoff_ms = 100;
    loop {
        match sock_arc.recv_from(&mut buf) {
            Ok((n, client_addr)) => {
                backoff_ms = 100;
                if n >= 12 {
                    let query = buf[..n].to_vec();
                    // This lane never queues behind external DNS/TLS work.
                    if question_type(&query) == Some(28) {
                        let _ = sock_arc.send_to(&nodata_response(&query), client_addr);
                        continue;
                    }
                    let cached = resolvers::resolve_cached(&query);
                    deliver(
                        &query,
                        client_addr,
                        cached,
                        &sock_arc,
                        &pending,
                        &tx,
                        &usage,
                    )?;
                }
            }
            Err(e) => {
                log_fatal(&format!("Socket recv error: {}", e));
                thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = (backoff_ms * 2).min(2000);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn saturated_discovery_and_metadata_queues_do_not_delay_cached_udp_answers() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let pending = Mutex::new(Pending::default());
        let (tx, _rx) = mpsc::sync_channel(MAX_PENDING);
        let (usage, _usage_rx) = mpsc::sync_channel(0);
        for n in 0..MAX_PENDING {
            let query = super::super::client::build_query(&format!("busy-{n}.test"), 1);
            let (key, _) = pending.lock().unwrap().add(&query, None).unwrap();
            tx.try_send(key).unwrap();
        }
        let started = std::time::Instant::now();
        for id in 0..100 {
            let query = super::super::client::build_query("cached-ready.test", id);
            let reply =
                super::super::client::address_response(&query, &[Ipv4Addr::new(192, 0, 2, 1)])
                    .unwrap();
            deliver(
                &query,
                client.local_addr().unwrap(),
                Some(resolvers::ResolveHit {
                    reply,
                    provider: "fixture".into(),
                    verdict: resolvers::Verdict::Substituted,
                }),
                &socket,
                &pending,
                &tx,
                &usage,
            )
            .unwrap();
            let mut buffer = [0u8; 512];
            let (size, _) = client.recv_from(&mut buffer).unwrap();
            assert!(super::super::client::response_matches(
                &query,
                &buffer[..size]
            ));
            assert_eq!(buffer[3] & 0xf, 0);
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        eprintln!(
            "100 cached UDP answers with stalled queues: {:?}",
            started.elapsed()
        );
    }
    #[test]
    fn cold_queries_coalesce_without_losing_ids_and_queue_is_bounded() {
        let mut pending = Pending::default();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let query = super::super::client::build_query("example.test", 1);
        let (key, new) = pending.add(&query, Some(peer)).unwrap();
        assert!(new);
        let mut retry = query.clone();
        retry[..2].copy_from_slice(&2u16.to_be_bytes());
        assert!(!pending.add(&retry, Some(peer)).unwrap().1);
        assert!(!pending.add(&retry, Some(peer)).unwrap().1);
        assert!(!pending.add(&retry, None).unwrap().1);
        assert_eq!(pending.jobs[&key], vec![(1, peer), (2, peer)]);
        for n in 1..MAX_PENDING {
            pending
                .add(
                    &super::super::client::build_query(&format!("{n}.test"), 1),
                    None,
                )
                .unwrap();
        }
        assert!(pending
            .add(&super::super::client::build_query("overflow.test", 1), None)
            .is_err());
        assert!(!pending.add(&query, Some(peer)).unwrap().1);
    }
}
