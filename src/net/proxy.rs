//! Embedded HTTP CONNECT & SOCKS5 Selective Proxy & Dynamic PAC Generator.
//!
//! Provides a zero-dependency local proxy server (default: 127.0.0.1:8989 for HTTP CONNECT,
//! 127.0.0.1:10808 for SOCKS5) that selectively routes Google AI/Gemini/Cloud Code domains
//! through ranked overseas SNI proxies while routing general traffic directly.
//! Also generates and serves dynamic PAC (Proxy Auto-Configuration) scripts.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::net::provider::{GEOHIDE_PROXY_V4, NRPT_AGENT, NRPT_STUDIO};

pub const DEFAULT_HTTP_PROXY_PORT: u16 = 8989;
pub const DEFAULT_SOCKS5_PROXY_PORT: u16 = 10808;

static PROXY_RUNNING: AtomicBool = AtomicBool::new(false);

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

/// Resolves target endpoint with selective routing:
/// Returns (Upstream Address, Target Hostname).
pub fn resolve_upstream_target(host: &str, port: u16) -> (String, u16) {
    if is_google_ai_domain(host) {
        // Route through foreign SNI proxy frontend (Geohide / Comss)
        let proxy_ip = GEOHIDE_PROXY_V4[0];
        (proxy_ip.to_string(), port)
    } else {
        // Direct routing
        (host.to_string(), port)
    }
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
        r#"// Antigravity Bypass Russia Dynamic PAC Configuration
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

    // Fallback for subdomains of googleapis.com and gemini
    if (shExpMatch(host, "*.googleapis.com") ||
        shExpMatch(host, "*.google.com") ||
        shExpMatch(host, "*.notebooklm.google") ||
        shExpMatch(host, "*.ai.studio")) {{
        return proxy;
    }}

    return "DIRECT";
}}
"#,
        http_port, socks5_port, json_domains
    )
}

/// Bidirectionally proxies data between client and upstream TCP streams.
fn pipe_streams(mut client: TcpStream, mut upstream: TcpStream) {
    let mut client_read = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut upstream_write = match upstream.try_clone() {
        Ok(u) => u,
        Err(_) => return,
    };

    // Client -> Upstream thread
    let t1 = thread::spawn(move || {
        let _ = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(std::net::Shutdown::Write);
    });

    // Upstream -> Client in current thread
    let _ = io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(std::net::Shutdown::Write);

    let _ = t1.join();
}

/// Handles incoming HTTP CONNECT or PAC query.
fn handle_http_client(mut stream: TcpStream, http_port: u16, socks5_port: u16) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
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

        let (target_addr, target_port) = resolve_upstream_target(host, port);
        let upstream_addr = format!("{}:{}", target_addr, target_port);

        let upstream = match TcpStream::connect_timeout(
            &upstream_addr.parse().unwrap_or_else(|_| {
                use std::net::ToSocketAddrs;
                upstream_addr
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut a| a.next())
                    .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), target_port))
            }),
            Duration::from_secs(6),
        ) {
            Ok(s) => s,
            Err(e) => {
                let err_resp = format!("HTTP/1.1 502 Bad Gateway\r\n\r\nConnection failed: {}", e);
                let _ = stream.write_all(err_resp.as_bytes());
                return Err(e);
            }
        };

        // Send 200 Connection Established
        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        stream.set_read_timeout(None)?;

        // Pipe bidirectional streams
        pipe_streams(stream, upstream);
    } else {
        stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\nOnly CONNECT and GET /proxy.pac are supported.\n")?;
    }

    Ok(())
}

/// Handles SOCKS5 client connection (RFC 1928).
fn handle_socks5_client(mut stream: TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

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

    let (target_addr, target_port) = resolve_upstream_target(&host, port);
    let upstream_addr = format!("{}:{}", target_addr, target_port);

    let upstream = match TcpStream::connect_timeout(
        &upstream_addr.parse().unwrap_or_else(|_| {
            use std::net::ToSocketAddrs;
            upstream_addr
                .to_socket_addrs()
                .ok()
                .and_then(|mut a| a.next())
                .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), target_port))
        }),
        Duration::from_secs(6),
    ) {
        Ok(s) => s,
        Err(e) => {
            // Host unreachable
            let _ = stream.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            return Err(e);
        }
    };

    // Respond Success: [VER, REP(0), RSV, ATYP(1), BND.ADDR(0), BND.PORT(0)]
    stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])?;
    stream.set_read_timeout(None)?;

    // Pipe streams
    pipe_streams(stream, upstream);

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
