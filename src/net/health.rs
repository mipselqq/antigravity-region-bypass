use super::route_health::{self, Key};
use native_tls::{TlsConnector, TlsStream};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

pub const PROBE_BUDGET: Duration = Duration::from_millis(2500);

/// The same certificate/HTTP probe is used by the resolver and the CONNECT proxy.
/// The socket is consumed: the real client always receives a fresh, unmodified tunnel.
pub fn probe_connected(stream: TcpStream, host: &str, deadline: Instant) -> Result<u16, String> {
    let connector = TlsConnector::new().map_err(|e| e.to_string())?;
    probe_with_connector(stream, host, deadline, &connector)
}

fn probe_with_connector(
    stream: TcpStream,
    host: &str,
    deadline: Instant,
    connector: &TlsConnector,
) -> Result<u16, String> {
    stream.set_nonblocking(true).map_err(|e| e.to_string())?;
    let mut handshake = connector.connect(host, stream);
    let mut tls = loop {
        if Instant::now() >= deadline {
            return Err("TLS: общий срок проверки истёк".into());
        }
        match handshake {
            Ok(tls) => break tls,
            Err(native_tls::HandshakeError::Failure(e)) => {
                return Err(format!("TLS/certificate: {e}"))
            }
            Err(native_tls::HandshakeError::WouldBlock(mid)) => {
                std::thread::sleep(Duration::from_millis(2));
                handshake = mid.handshake();
            }
        }
    };
    let request = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let mut sent = 0;
    while sent < request.len() {
        if Instant::now() >= deadline {
            return Err("HTTP write: timeout".into());
        }
        match tls.write(&request.as_bytes()[sent..]) {
            Ok(0) => return Err("HTTP write: EOF".into()),
            Ok(n) => sent += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    // Incremental parsing also enforces the total deadline for a trickling peer.
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    while header.len() < 16 * 1024 {
        if Instant::now() >= deadline {
            return Err("HTTP header: timeout".into());
        }
        match tls.read(&mut byte) {
            Ok(0) => return Err("HTTP header: EOF".into()),
            Ok(_) => {
                header.push(byte[0]);
                if header.ends_with(b"\r\n\r\n") {
                    let status = read_http_status(&mut header.as_slice())?;
                    return if status < 500 {
                        Ok(status)
                    } else {
                        Err(format!("HTTP {status}"))
                    };
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("HTTP header exceeds 16 KiB".into())
}

pub fn probe_ip(addr: SocketAddr, host: &str) -> Result<u128, String> {
    let start = Instant::now();
    probe_address(addr, host, start + PROBE_BUDGET)?;
    Ok(start.elapsed().as_millis().max(1))
}

fn probe_address(addr: SocketAddr, host: &str, deadline: Instant) -> Result<u16, String> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or("TCP/TLS/HTTP: общий срок проверки истёк")?;
    let stream = TcpStream::connect_timeout(&addr, left).map_err(|e| format!("TCP: {e}"))?;
    probe_connected(stream, host, deadline)
}

pub fn check_ip(addr: SocketAddr, host: &str, refresh: bool) -> Result<u128, String> {
    let key = Key::ip(host, addr);
    let state = route_health::store().snapshot()?;
    let now = route_health::now_ms();
    if state.region_blocked(&key, now) {
        return Err("Маршрут отложен после регионального отказа".into());
    }
    if state.blocked(&key, now) {
        return Err("Маршрут ожидает повторной проверки".into());
    }
    if !refresh {
        match state.cached(&key, now) {
            Some(true) => return Ok(state.latency(&key).unwrap_or(1) as u128),
            Some(false) => return Err("Маршрут ожидает повторной проверки".into()),
            None => {}
        }
    }
    let result = probe_ip(addr, host);
    route_health::record(&key, result.as_ref().map(|ms| *ms).map_err(|_| ()))?;
    result
}

#[derive(Debug, Default)]
pub struct ConnReport {
    pub host: String,
    pub resolved: Vec<String>,
    pub connected: Option<String>,
    pub latency_ms: u128,
    pub used_ipv6: bool,
    pub looks_like_google: bool,
    pub http_status: Option<u16>,
    pub error: Option<String>,
}

/// Complete TLS handshake with the OS trust store and hostname verification.
pub fn connect_tls(
    addr: SocketAddr,
    host: &str,
    budget: Duration,
) -> Result<TlsStream<TcpStream>, String> {
    let start = Instant::now();
    let stream = TcpStream::connect_timeout(&addr, budget).map_err(|e| format!("TCP: {e}"))?;
    let left = budget
        .checked_sub(start.elapsed())
        .filter(|d| !d.is_zero())
        .ok_or("TLS: timeout")?;
    stream
        .set_read_timeout(Some(left))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(left))
        .map_err(|e| e.to_string())?;
    let connector = TlsConnector::new().map_err(|e| format!("TLS trust store: {e}"))?;
    connector
        .connect(host, stream)
        .map_err(|e| format!("TLS/certificate: {e}"))
}

fn read_http_status(reader: &mut impl Read) -> Result<u16, String> {
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    while header.len() < 16 * 1024 {
        reader
            .read_exact(&mut byte)
            .map_err(|e| format!("HTTP header: {e}"))?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            let line = std::str::from_utf8(&header)
                .map_err(|_| "HTTP: invalid header")?
                .lines()
                .next()
                .unwrap_or("");
            let mut fields = line.split_whitespace();
            if !matches!(fields.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
                return Err("HTTP: invalid status line".into());
            }
            return fields
                .next()
                .and_then(|s| s.parse::<u16>().ok())
                .filter(|s| (200..=599).contains(s))
                .ok_or_else(|| "HTTP: invalid final status".into());
        }
    }
    Err("HTTP: header exceeds 16 KiB".into())
}

pub fn probe_host(host: &str) -> ConnReport {
    let mut report = ConnReport {
        host: host.into(),
        ..Default::default()
    };
    let start = Instant::now();
    let addrs: Vec<_> = match (host, 443).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(e) => {
            report.error = Some(format!("DNS: {e}"));
            return report;
        }
    };
    report.resolved = addrs.iter().map(|a| a.ip().to_string()).collect();
    let mut last_error = "DNS: нет A/AAAA".to_string();
    for addr in addrs {
        // Share one deadline across every address and each byte of TLS/HTTP.
        let result = probe_address(addr, host, start + Duration::from_secs(4));
        match result {
            Ok(status) => {
                report.http_status = Some(status);
                report.latency_ms = start.elapsed().as_millis();
                report.connected = Some(addr.to_string());
                report.used_ipv6 = addr.is_ipv6();
                report.looks_like_google = super::resolvers::looks_google(&addr.ip());
                if status >= 500 {
                    report.error = Some(format!("HTTP {status}: сервер недоступен"));
                }
                return report;
            }
            Err(e) => last_error = e,
        }
    }
    report.error = Some(last_error);
    report
}

pub fn probe_all() -> Vec<ConnReport> {
    std::thread::scope(|scope| {
        let jobs: Vec<_> = super::provider::NRPT_AGENT
            .iter()
            .map(|host| scope.spawn(move || probe_host(host)))
            .collect();
        jobs.into_iter()
            .map(|j| {
                j.join().unwrap_or_else(|_| ConnReport {
                    error: Some("Проверка прервана".into()),
                    ..Default::default()
                })
            })
            .collect()
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    // Generate a short-lived localhost identity for this test process only.
    // No OS trust changes, committed private key, or future expiry date to maintain.
    pub(crate) fn identity() -> &'static (Vec<u8>, Vec<u8>) {
        static IDENTITY: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
        IDENTITY.get_or_init(|| {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
            let now = time::OffsetDateTime::now_utc();
            params.not_before = now - time::Duration::days(1);
            params.not_after = now + time::Duration::days(14);
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
            params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
            let cert = params.self_signed(&key).unwrap();
            (cert.der().to_vec(), key.serialize_der())
        })
    }
    pub(crate) fn server(
        reply: Vec<u8>,
        delay: Duration,
    ) -> (SocketAddr, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let cert = rustls::pki_types::CertificateDer::from(identity().0.clone());
            let key = rustls::pki_types::PrivatePkcs8KeyDer::from(identity().1.clone());
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key.into())
                .unwrap();
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let conn = rustls::ServerConnection::new(std::sync::Arc::new(config)).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, socket);
            let mut request = vec![];
            let mut b = [0; 1];
            while request.len() < 8192 && !request.ends_with(b"\r\n\r\n") {
                if tls.read_exact(&mut b).is_err() {
                    return;
                }
                request.push(b[0]);
            }
            let length = String::from_utf8_lossy(&request)
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|n| n.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            if length > 65_535 {
                return;
            }
            if tls.read_exact(&mut vec![0; length]).is_err() {
                return;
            }
            for chunk in reply.chunks(3) {
                if tls.write_all(chunk).and_then(|_| tls.flush()).is_err() {
                    break;
                }
                std::thread::sleep(delay);
            }
        });
        (addr, handle)
    }
    #[test]
    fn real_tls_fragmented_http_and_total_deadline_are_checked_without_os_trust_changes() {
        let cert = native_tls::Certificate::from_der(&identity().0).unwrap();
        let trusted = TlsConnector::builder()
            .add_root_certificate(cert)
            .build()
            .unwrap();
        for status in [401, 503] {
            let (addr, server) = server(
                format!("HTTP/1.1 {status} Test\r\nX: y\r\n\r\n").into_bytes(),
                Duration::ZERO,
            );
            let result = probe_with_connector(
                TcpStream::connect(addr).unwrap(),
                "localhost",
                Instant::now() + Duration::from_secs(3),
                &trusted,
            );
            assert_eq!(result.is_ok(), status == 401, "{result:?}");
            server.join().unwrap();
        }
        let (addr, server) = server(b"HTTP/1.1 200 OK\r\n\r\n".to_vec(), Duration::ZERO);
        assert!(probe_with_connector(
            TcpStream::connect(addr).unwrap(),
            "wrong-host.invalid",
            Instant::now() + Duration::from_secs(3),
            &trusted
        )
        .is_err());
        server.join().unwrap();
        let (addr, server) = self::server(
            b"HTTP/1.1 200 OK\r\nLong: header-value\r\n\r\n".to_vec(),
            Duration::from_millis(70),
        );
        let start = Instant::now();
        assert!(probe_with_connector(
            TcpStream::connect(addr).unwrap(),
            "localhost",
            start + Duration::from_millis(350),
            &trusted
        )
        .is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
        server.join().unwrap();
    }
    #[test]
    fn tls_alert_and_plain_http_are_not_valid_handshakes() {
        for reply in [
            b"\x15\x03\x03\x00\x02\x02\x28".as_slice(),
            b"HTTP/1.1 200 OK\r\n\r\n",
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let reply = reply.to_vec();
            let server = std::thread::spawn(move || {
                let (mut s, _) = listener.accept().unwrap();
                s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                let _ = s.read(&mut [0u8; 4096]);
                let _ = s.write_all(&reply);
            });
            assert!(connect_tls(address, "localhost", Duration::from_secs(1)).is_err());
            server.join().unwrap();
        }
    }
    #[test]
    fn http_status_is_distinct_from_authorization_and_requires_complete_header() {
        for status in [200, 401, 403, 404, 429, 503] {
            assert_eq!(
                read_http_status(&mut format!("HTTP/1.1 {status} test\r\nX: y\r\n\r\n").as_bytes())
                    .unwrap(),
                status
            );
        }
        assert!(read_http_status(&mut b"HTTP/1.1 200 OK\r\n".as_slice()).is_err());
    }
}
