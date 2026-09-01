use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::net::provider::GEOHIDE_PROXY_V4;
use crate::net::resolvers::looks_google;

#[derive(Debug, Default)]
pub struct ConnReport {
    pub resolved: Vec<String>,
    pub connected: Option<String>,
    pub latency_ms: u128,
    pub used_ipv6: bool,
    pub looks_like_google: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub name: String,
    pub ip: String,
    pub handshake_ms: u128,
    pub ttft_ms: u128,
    pub status: String,
}

pub fn probe_google_api() -> ConnReport {
    let mut report = ConnReport::default();
    let host = "daily-cloudcode-pa.googleapis.com";
    let target = format!("{}:443", host);
    let start = Instant::now();

    let addrs: Vec<SocketAddr> = match target.to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(e) => {
            report.error = Some(format!("DNS: {}", e));
            return report;
        }
    };

    if addrs.is_empty() {
        report.error = Some(format!("Нет A/AAAA для {}", host));
        return report;
    }

    for addr in &addrs {
        report.resolved.push(addr.ip().to_string());
        if looks_google(&addr.ip()) {
            report.looks_like_google = true;
        }
    }

    let mut last_err = String::new();
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, Duration::from_millis(3000)) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                report.latency_ms = start.elapsed().as_millis();
                report.connected = Some(format!("{} ({})", host, addr.ip()));
                report.used_ipv6 = addr.is_ipv6();
                return report;
            }
            Err(e) => last_err = e.to_string(),
        }
    }

    report.error = Some(format!("TCP 443: {}", last_err));
    report
}

/// Runs a real-time latency & TTFT benchmark across all multi-provider SNI edges.
pub fn benchmark_all_relays() -> Vec<BenchmarkResult> {
    let mut results = Vec::new();
    let host = "daily-cloudcode-pa.googleapis.com";

    for &ip_str in GEOHIDE_PROXY_V4 {
        let Ok(ip) = ip_str.parse::<Ipv4Addr>() else { continue };
        let sock_addr = SocketAddr::new(IpAddr::V4(ip), 443);

        let provider_name = match ip_str {
            "83.220.169.155" => "Comss.one (Frankfurt Anycast 10G)",
            "111.88.96.50" => "Xbox-DNS (Primary Anycast)",
            "212.109.195.93" => "Comss.one (Amsterdam High-Speed)",
            "111.88.96.51" => "Xbox-DNS (Secondary Anycast)",
            "195.133.25.16" => "Comss.one (Helsinki Edge)",
            "45.155.204.190" => "Geohide (Cloud Edge)",
            "37.230.192.51" => "Geohide (Secondary)",
            _ => "Custom SNI Relay",
        };

        let start = Instant::now();
        match TcpStream::connect_timeout(&sock_addr, Duration::from_millis(1500)) {
            Ok(mut stream) => {
                let _ = stream.set_nodelay(true);
                let _ = stream.set_read_timeout(Some(Duration::from_millis(2000)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(2000)));
                let handshake_ms = start.elapsed().as_millis().max(1);

                // Send synthetic TLS 1.3 / 1.2 ClientHello
                let hello = synthetic_client_hello(host);
                if stream.write_all(&hello).is_ok() {
                    let mut hdr = [0u8; 5];
                    if stream.read_exact(&mut hdr).is_ok() && (hdr[0] == 0x16 || hdr[0] == 0x15) {
                        let ttft_ms = start.elapsed().as_millis();
                        results.push(BenchmarkResult {
                            name: provider_name.to_string(),
                            ip: ip_str.to_string(),
                            handshake_ms,
                            ttft_ms,
                            status: "Отлично".to_string(),
                        });
                        continue;
                    }
                }
                results.push(BenchmarkResult {
                    name: provider_name.to_string(),
                    ip: ip_str.to_string(),
                    handshake_ms,
                    ttft_ms: 0,
                    status: "TCP OK, TLS Drop".to_string(),
                });
            }
            Err(_) => {
                results.push(BenchmarkResult {
                    name: provider_name.to_string(),
                    ip: ip_str.to_string(),
                    handshake_ms: 0,
                    ttft_ms: 0,
                    status: "Таймаут".to_string(),
                });
            }
        }
    }

    results.sort_by_key(|r| if r.handshake_ms > 0 { r.handshake_ms } else { 99999 });
    results
}

fn synthetic_client_hello(sni: &str) -> Vec<u8> {
    let host = sni.as_bytes();
    let mut ext = Vec::new();

    let mut sni_name = Vec::new();
    sni_name.push(0x00);
    sni_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_name.extend_from_slice(host);
    let mut sni_list = Vec::new();
    sni_list.extend_from_slice(&(sni_name.len() as u16).to_be_bytes());
    sni_list.extend(sni_name);
    ext.extend_from_slice(&0x0000u16.to_be_bytes());
    ext.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    ext.extend(sni_list);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy version
    body.extend_from_slice(&[0u8; 32]); // Random
    body.push(0x00); // Session ID len
    body.extend_from_slice(&2u16.to_be_bytes()); // Cipher suites len
    body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    body.extend_from_slice(&[0x01, 0x00]); // Compression methods len + null
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend(ext);

    let mut record = Vec::new();
    record.push(0x16); // Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record layer
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend(body);
    record
}
