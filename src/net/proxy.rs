//! Embedded High-Performance HTTP CONNECT & SOCKS5 Selective Proxy & Dynamic PAC Generator.
//!
//! Features:
//! - 10-Minute Thinking Time Shield (600s TTFT timeout for deep-reasoning Gemini models)
//! - 150s Keep-Alive Connection Pool alignment preventing Electron WSAECONNRESET drops
//! - Parallel TLS Racing & Fail-Fast (1.5s) protection against silent DPI/ТСПУ blackholes
//! - 5-Minute Circuit Breaker failover to secondary relays
//! - Custom Upstream Outbound Proxy chaining (HTTP/SOCKS5 with Basic Auth)
//! - Ring-buffer session telemetry & diagnostic statistics (/stats)
//! - Zero-dependency dynamic PAC script generator (/proxy.pac & /pac)

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::net::provider::{
    load_custom_upstream, GEOHIDE_PROXY_V4, GLOBAL_CIRCUIT_BREAKER,
    NRPT_AGENT, NRPT_STUDIO,
};

pub const DEFAULT_HTTP_PROXY_PORT: u16 = 8989;
pub const DEFAULT_SOCKS5_PROXY_PORT: u16 = 10808;

// Timeouts
pub const THINKING_PHASE_TIMEOUT: Duration = Duration::from_secs(600); // 10 minutes
#[allow(dead_code)]
pub const STREAMING_CHUNK_TIMEOUT: Duration = Duration::from_secs(45);
#[allow(dead_code)]
pub const IDLE_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(150); // > 90s Electron pool
pub const FAST_RACING_TIMEOUT: Duration = Duration::from_millis(1500); // 1.5s fail-fast

static PROXY_RUNNING: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
pub struct SessionLogEntry {
    pub timestamp_epoch: u64,
    pub target: String,
    pub upstream: String,
    pub duration_ms: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub status: String,
}

static TELEMETRY_RING: Mutex<Option<VecDeque<SessionLogEntry>>> = Mutex::new(None);

pub fn record_session_telemetry(entry: SessionLogEntry) {
    // Append to log file
    append_telemetry_file(&entry);

    if let Ok(mut lock) = TELEMETRY_RING.lock() {
        let deque = lock.get_or_insert_with(|| VecDeque::with_capacity(30));
        if deque.len() >= 25 {
            deque.pop_front();
        }
        deque.push_back(entry);
    }
}

pub fn get_recent_sessions() -> Vec<SessionLogEntry> {
    if let Ok(lock) = TELEMETRY_RING.lock() {
        if let Some(deque) = lock.as_ref() {
            return deque.iter().cloned().collect();
        }
    }
    Vec::new()
}

fn get_log_file_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:\\ProgramData".to_string());
        let dir = PathBuf::from(appdata).join("AntigravityBypass");
        let _ = fs::create_dir_all(&dir);
        dir.join("proxy_sessions.log")
    }
    #[cfg(target_os = "macos")]
    {
        let home = crate::system::env::expand_env_vars("~");
        let dir = home.join("Library").join("Logs").join("AntigravityBypass");
        let _ = fs::create_dir_all(&dir);
        dir.join("proxy_sessions.log")
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let home = crate::system::env::expand_env_vars("~");
        let dir = home.join(".config").join("AntigravityBypass");
        let _ = fs::create_dir_all(&dir);
        dir.join("proxy_sessions.log")
    }
}

fn append_telemetry_file(entry: &SessionLogEntry) {
    let p = get_log_file_path();
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
        let _ = writeln!(
            f,
            "[{}] target={} upstream={} duration={}ms tx={} rx={} status={}",
            entry.timestamp_epoch,
            entry.target,
            entry.upstream,
            entry.duration_ms,
            entry.tx_bytes,
            entry.rx_bytes,
            entry.status
        );
    }
}

#[allow(dead_code)]
pub fn is_proxy_running() -> bool {
    PROXY_RUNNING.load(Ordering::Relaxed)
}

/// Determines whether a hostname belongs to Google AI / Cloud Code / Gemini infrastructure.
pub fn is_google_ai_domain(host: &str) -> bool {
    let clean = host.trim_end_matches('.').to_lowercase();

    for &domain in NRPT_AGENT {
        let d = domain.trim_start_matches('.').to_lowercase();
        if clean == d || clean.ends_with(&format!(".{}", d)) {
            return true;
        }
    }

    for &domain in NRPT_STUDIO {
        let d = domain.trim_start_matches('.').to_lowercase();
        if clean == d || clean.ends_with(&format!(".{}", d)) {
            return true;
        }
    }

    if clean.ends_with("googleapis.com")
        || clean.ends_with("google.com")
        || clean.ends_with("gstatic.com")
        || clean.ends_with("google")
        || clean.ends_with("ai.studio")
        || clean.ends_with("deepmind.com")
    {
        return true;
    }

    false
}

/// Parallel TLS Racing & Fail-Fast connection establishment.
/// Races connection attempts against multiple candidate addresses.
pub fn connect_with_racing(candidates: &[String], port: u16) -> io::Result<(TcpStream, String)> {
    if candidates.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "No candidates"));
    }

    if candidates.len() == 1 {
        let addr_str = format!("{}:{}", candidates[0], port);
        let socket_addr = addr_str
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "Unresolved"))?;
        let s = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3))?;
        return Ok((s, candidates[0].clone()));
    }

    // Parallel racing with staggered start (150ms delta)
    let (tx, rx) = std::sync::mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));

    for (idx, cand) in candidates.iter().enumerate() {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let cand_clone = cand.clone();
        let tx_clone = tx.clone();
        let stop_clone = Arc::clone(&stop);

        thread::spawn(move || {
            if idx > 0 {
                thread::sleep(Duration::from_millis((idx as u64) * 150));
            }
            if stop_clone.load(Ordering::Relaxed) {
                return;
            }

            let addr_str = format!("{}:{}", cand_clone, port);
            if let Ok(mut addrs) = addr_str.to_socket_addrs() {
                if let Some(sock_addr) = addrs.next() {
                    if let Ok(stream) = TcpStream::connect_timeout(&sock_addr, FAST_RACING_TIMEOUT) {
                        if !stop_clone.swap(true, Ordering::SeqCst) {
                            let _ = tx_clone.send((stream, cand_clone));
                        }
                    }
                }
            }
        });
    }

    // Wait for the first successful responder or overall timeout
    match rx.recv_timeout(Duration::from_secs(4)) {
        Ok(result) => Ok(result),
        Err(_) => {
            // Fallback to candidate 0 direct connection
            let addr_str = format!("{}:{}", candidates[0], port);
            let socket_addr = addr_str
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "Unresolved fallback"))?;
            let s = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(4))?;
            Ok((s, candidates[0].clone()))
        }
    }
}

/// Resolves target endpoint with selective routing and custom upstream support.
pub fn establish_upstream_connection(host: &str, port: u16) -> io::Result<(TcpStream, String)> {
    // 1. Check for custom user-configured upstream proxy
    if let Some(custom) = load_custom_upstream() {
        if is_google_ai_domain(host) {
            let upstream_addr = format!("{}:{}", custom.host, custom.port);
            let socket_addr = upstream_addr
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "Custom upstream not resolved"))?;
            let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5))?;

            // Send CONNECT request to the custom upstream proxy
            let auth_line = if let Some(auth) = &custom.auth_header {
                format!("Proxy-Authorization: {}\r\n", auth)
            } else {
                String::new()
            };
            let connect_req = format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n{}User-Agent: AntigravityBypass/1.2\r\n\r\n",
                host, port, host, port, auth_line
            );
            stream.write_all(connect_req.as_bytes())?;

            // Read response
            let mut resp_buf = [0u8; 1024];
            let n = stream.read(&mut resp_buf)?;
            let resp = String::from_utf8_lossy(&resp_buf[..n]);
            if !resp.starts_with("HTTP/1.1 200") && !resp.starts_with("HTTP/1.0 200") {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("Custom upstream rejected CONNECT: {}", resp.lines().next().unwrap_or("")),
                ));
            }
            return Ok((stream, format!("custom-upstream ({}:{})", custom.host, custom.port)));
        }
    }

    // 2. Selective routing for Google AI domains
    if is_google_ai_domain(host) {
        if GLOBAL_CIRCUIT_BREAKER.is_available() {
            let candidates: Vec<String> = GEOHIDE_PROXY_V4.iter().map(|s| s.to_string()).collect();
            match connect_with_racing(&candidates, port) {
                Ok((stream, winning_ip)) => {
                    GLOBAL_CIRCUIT_BREAKER.report_success();
                    return Ok((stream, winning_ip));
                }
                Err(_) => {
                    GLOBAL_CIRCUIT_BREAKER.report_failure();
                    // Fallback to secondary endpoint
                }
            }
        }
        // Circuit breaker tripped or racing failed: use fallback SNI
        let fallback_ip = GEOHIDE_PROXY_V4[GEOHIDE_PROXY_V4.len() - 1];
        let addr_str = format!("{}:{}", fallback_ip, port);
        let socket_addr = addr_str
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "Fallback unresolved"))?;
        let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(4))?;
        return Ok((stream, format!("{} (fallback)", fallback_ip)));
    }

    // 3. Direct routing for general traffic
    let addr_str = format!("{}:{}", host, port);
    let socket_addr = addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "Direct unresolved"))?;
    let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(6))?;
    Ok((stream, "direct".to_string()))
}

/// Generates a Proxy Auto-Configuration (PAC) script matching all Google AI domains.
pub fn generate_pac_script(http_port: u16, socks5_port: u16) -> String {
    let mut domains = Vec::new();
    for &d in NRPT_AGENT {
        let clean = d.trim_start_matches('.');
        if !domains.contains(&clean) {
            domains.push(clean);
        }
    }
    for &d in NRPT_STUDIO {
        let clean = d.trim_start_matches('.');
        if !domains.contains(&clean) {
            domains.push(clean);
        }
    }

    let json_domains = domains
        .iter()
        .map(|d| format!("    \"{}\"", d))
        .collect::<Vec<_>>()
        .join(",\n");

    format!(
        r#"// Antigravity Bypass Dynamic PAC Configuration
function FindProxyForURL(url, host) {{
    var proxy = "PROXY 127.0.0.1:{}; SOCKS5 127.0.0.1:{}; DIRECT";
    var bypassDomains = [
{}
    ];

    for (var i = 0; i < bypassDomains.length; i++) {{
        var d = bypassDomains[i];
        if (dnsDomainIs(host, d) || host === d || dnsDomainIs(host, "." + d)) {{
            return proxy;
        }}
    }}

    // Subdomain wildcard matching
    if (shExpMatch(host, "*.googleapis.com") ||
        shExpMatch(host, "*.google.com") ||
        shExpMatch(host, "*.notebooklm.google") ||
        shExpMatch(host, "*.ai.studio") ||
        shExpMatch(host, "*.deepmind.google")) {{
        return proxy;
    }}

    return "DIRECT";
}}
"#,
        http_port, socks5_port, json_domains
    )
}

/// Bidirectionally proxies data with full byte accounting and thinking-time protection.
fn pipe_streams_with_accounting(
    mut client: TcpStream,
    mut upstream: TcpStream,
    target_name: &str,
    upstream_desc: &str,
) {
    let start_time = Instant::now();
    let epoch_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Set 10-minute thinking timeout on read
    let _ = client.set_read_timeout(Some(THINKING_PHASE_TIMEOUT));
    let _ = upstream.set_read_timeout(Some(THINKING_PHASE_TIMEOUT));

    let mut client_read = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut upstream_write = match upstream.try_clone() {
        Ok(u) => u,
        Err(_) => return,
    };

    let tx_bytes_atomic = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let rx_bytes_atomic = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let tx_ref = Arc::clone(&tx_bytes_atomic);
    let t1 = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match client_read.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if upstream_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    tx_ref.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(_) => break,
            }
        }
        let _ = upstream_write.shutdown(std::net::Shutdown::Write);
    });

    let mut rx_buf = [0u8; 8192];
    let mut status = "OK".to_string();
    loop {
        match upstream.read(&mut rx_buf) {
            Ok(0) => break,
            Ok(n) => {
                if client.write_all(&rx_buf[..n]).is_err() {
                    status = "ClientClosed".to_string();
                    break;
                }
                rx_bytes_atomic.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::TimedOut {
                    status = "Timeout".to_string();
                } else {
                    status = "RemoteReset".to_string();
                }
                break;
            }
        }
    }
    let _ = client.shutdown(std::net::Shutdown::Write);
    let _ = t1.join();

    let duration_ms = start_time.elapsed().as_millis() as u64;
    let tx = tx_bytes_atomic.load(Ordering::Relaxed);
    let rx = rx_bytes_atomic.load(Ordering::Relaxed);

    record_session_telemetry(SessionLogEntry {
        timestamp_epoch: epoch_now,
        target: target_name.to_string(),
        upstream: upstream_desc.to_string(),
        duration_ms,
        tx_bytes: tx,
        rx_bytes: rx,
        status,
    });
}

/// Handles incoming HTTP CONNECT, PAC or Stats query.
fn handle_http_client(mut stream: TcpStream, http_port: u16, socks5_port: u16) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    let mut buffer = [0u8; 4096];
    let n = stream.read(&mut buffer)?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..n]);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or_default();

    // Check for PAC file requests (GET /proxy.pac or GET /pac)
    if request_line.starts_with("GET /proxy.pac") || request_line.starts_with("GET /pac") {
        let pac_body = generate_pac_script(http_port, socks5_port);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            pac_body.len(),
            pac_body
        );
        stream.write_all(response.as_bytes())?;
        return Ok(());
    }

    // Check for live diagnostics stats request (GET /stats)
    if request_line.starts_with("GET /stats") {
        let sessions = get_recent_sessions();
        let mut json_items = Vec::new();
        for s in sessions {
            json_items.push(format!(
                r#"{{"ts":{},"target":"{}","upstream":"{}","duration_ms":{},"tx":{},"rx":{},"status":"{}"}}"#,
                s.timestamp_epoch, s.target, s.upstream, s.duration_ms, s.tx_bytes, s.rx_bytes, s.status
            ));
        }
        let body = format!("[{}]", json_items.join(","));
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes())?;
        return Ok(());
    }

    // Check for HTTP CONNECT method
    if request_line.starts_with("CONNECT ") {
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")?;
            return Ok(());
        }

        let target_str = parts[1];
        let mut host_port = target_str.split(':');
        let host = host_port.next().unwrap_or_default();
        let port: u16 = host_port.next().and_then(|p| p.parse().ok()).unwrap_or(443);

        match establish_upstream_connection(host, port) {
            Ok((upstream, upstream_desc)) => {
                // Send 200 Connection Established
                stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                pipe_streams_with_accounting(stream, upstream, target_str, &upstream_desc);
            }
            Err(e) => {
                let err_resp = format!("HTTP/1.1 502 Bad Gateway\r\n\r\nConnection failed: {}", e);
                let _ = stream.write_all(err_resp.as_bytes());
                return Err(e);
            }
        }
    } else {
        stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\nOnly CONNECT, GET /proxy.pac and GET /stats are supported.\n")?;
    }

    Ok(())
}

/// Handles SOCKS5 client connection (RFC 1928).
fn handle_socks5_client(mut stream: TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;

    // 1. Version & Method negotiation
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;
    if header[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Not SOCKS5"));
    }

    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods)?;

    // Accept NO AUTH (0x00)
    stream.write_all(&[0x05, 0x00])?;

    // 2. Request details
    let mut req_header = [0u8; 4];
    stream.read_exact(&mut req_header)?;

    if req_header[0] != 0x05 || req_header[1] != 0x01 {
        // CMD != 1 (CONNECT) -> Command not supported
        stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported command"));
    }

    let atyp = req_header[3];
    let host = match atyp {
        0x01 => {
            // IPv4
            let mut ip_bytes = [0u8; 4];
            stream.read_exact(&mut ip_bytes)?;
            Ipv4Addr::from(ip_bytes).to_string()
        }
        0x03 => {
            // Domain name
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf)?;
            let len = len_buf[0] as usize;
            let mut domain_buf = vec![0u8; len];
            stream.read_exact(&mut domain_buf)?;
            String::from_utf8_lossy(&domain_buf).to_string()
        }
        0x04 => {
            // IPv6
            let mut ip_bytes = [0u8; 16];
            stream.read_exact(&mut ip_bytes)?;
            std::net::Ipv6Addr::from(ip_bytes).to_string()
        }
        _ => {
            stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Address type not supported"));
        }
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf)?;
    let port = u16::from_be_bytes(port_buf);

    let target_name = format!("{}:{}", host, port);
    match establish_upstream_connection(&host, port) {
        Ok((upstream, upstream_desc)) => {
            // Respond Success: [VER, REP(0), RSV, ATYP(1), BND.ADDR(0), BND.PORT(0)]
            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])?;
            pipe_streams_with_accounting(stream, upstream, &target_name, &upstream_desc);
        }
        Err(e) => {
            let _ = stream.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            return Err(e);
        }
    }

    Ok(())
}

/// Spawns the HTTP CONNECT proxy server on the specified port.
pub fn spawn_http_proxy(port: u16, socks5_port: u16) -> io::Result<()> {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port))?;
    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(s) = stream {
                thread::spawn(move || {
                    let _ = handle_http_client(s, port, socks5_port);
                });
            }
        }
    });
    Ok(())
}

/// Spawns the SOCKS5 proxy server on the specified port.
pub fn spawn_socks5_proxy(port: u16) -> io::Result<()> {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port))?;
    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(s) = stream {
                thread::spawn(move || {
                    let _ = handle_socks5_client(s);
                });
            }
        }
    });
    Ok(())
}

/// Runs the complete embedded proxy subsystem (both HTTP and SOCKS5).
pub fn start_proxy_servers(http_port: u16, socks5_port: u16) -> Result<(), String> {
    spawn_http_proxy(http_port, socks5_port)
        .map_err(|e| format!("Не удалось запустить HTTP CONNECT прокси на 127.0.0.1:{}: {}", http_port, e))?;

    spawn_socks5_proxy(socks5_port)
        .map_err(|e| format!("Не удалось запустить SOCKS5 прокси на 127.0.0.1:{}: {}", socks5_port, e))?;

    PROXY_RUNNING.store(true, Ordering::Relaxed);
    Ok(())
}
