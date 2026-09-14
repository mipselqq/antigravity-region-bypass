//! Rank substituted proxy IPs by TLS speed and keep a short fallback list.
//!
//! Version 2.0 selection, run only when the user enables the bypass.
//! No scheduled rescans or model-response measurements.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::net::client::{answer_addrs, build_query};
use crate::net::hosts::write_entries as write_hosts_entries;
use crate::net::provider::NRPT_AGENT;
use crate::net::relay;
use crate::net::resolvers::{self, Verdict};
use crate::net::routes;

const MAX_FALLBACKS: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RankedHost {
    pub host: String,
    pub ips: Vec<(Ipv4Addr, u128)>,
}

pub fn rank_path() -> PathBuf {
    relay::log_dir().join("proxy_rank.conf")
}

pub fn rescan_agent(if_index: u32) -> Result<Vec<RankedHost>, String> {
    let previous = load();
    let mut ranked = Vec::new();
    for name in NRPT_AGENT {
        let host = name.trim_start_matches('.').to_string();
        let mut candidates: Vec<IpAddr> = Vec::new();
        let q = build_query(&host, 0x524B);
        if let Some(hit) = resolvers::resolve_best(&q, if_index) {
            if hit.verdict == Verdict::Substituted {
                for a in answer_addrs(&hit.reply) {
                    if !candidates.contains(&a) {
                        candidates.push(a);
                    }
                }
            }
        }
        if let Some(old) = previous.iter().find(|h| h.host == host) {
            for (ip, _) in &old.ips {
                let a = IpAddr::V4(*ip);
                if !candidates.contains(&a) {
                    candidates.push(a);
                }
            }
        }
        for seed in crate::net::provider::GEOHIDE_PROXY_V4 {
            if let Ok(v4) = seed.parse::<Ipv4Addr>() {
                let a = IpAddr::V4(v4);
                if !candidates.contains(&a) {
                    candidates.push(a);
                }
            }
        }
        let mut ips = resolvers::rank_tls_v4(&candidates, &host);
        if ips.is_empty() {
            if let Some(old) = previous.iter().find(|h| h.host == host) {
                ranked.push(old.clone());
            }
            continue;
        }
        if ips.len() > MAX_FALLBACKS {
            ips.truncate(MAX_FALLBACKS);
        }
        ranked.push(RankedHost { host, ips });
    }
    if ranked.iter().any(|h| !h.ips.is_empty()) {
        routes::sync_physical_hosts(&ranked_ips(&ranked))?;
        save(&ranked)?;
        apply_hosts(&ranked)?;
    }
    if ranked.iter().all(|h| h.ips.is_empty()) {
        return Err("Нет доступных маршрутов; прежние настройки сохранены".into());
    }
    Ok(ranked)
}

pub fn format_notes(ranked: &[RankedHost]) -> Vec<String> {
    ranked
        .iter()
        .map(|h| {
            let list = h
                .ips
                .iter()
                .map(|(ip, ms)| format!("{ip} {ms}мс"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} → {}", h.host, list)
        })
        .collect()
}

fn ranked_ips(ranked: &[RankedHost]) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for h in ranked {
        for (ip, _) in &h.ips {
            if !out.contains(ip) {
                out.push(*ip);
            }
        }
    }
    out
}

fn apply_hosts(ranked: &[RankedHost]) -> Result<(), String> {
    let mut entries: Vec<(String, Ipv4Addr)> = Vec::new();
    for h in ranked {
        // Pin ONLY the single fastest leader IP for each host into hosts file.
        // This prevents Windows getaddrinfo and Electron Happy Eyeballs from attempting
        // slower fallback IPs and causing 1-3s connection stalling.
        if let Some((best_ip, _)) = h.ips.first() {
            entries.push((h.host.clone(), *best_ip));
        }
    }
    if !entries.is_empty() {
        write_hosts_entries(&entries)?;
    }
    Ok(())
}

fn save(ranked: &[RankedHost]) -> Result<(), String> {
    let dir = relay::log_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut out = format!("# antigravity-proxy-rank 1\n# ts={ts}\n");
    for h in ranked {
        for (ip, ms) in &h.ips {
            out.push_str(&format!("{} {} {}\n", h.host, ip, ms));
        }
    }
    crate::system::fs_utils::robust_write_file(&rank_path(), out.as_bytes())
}

fn load() -> Vec<RankedHost> {
    let Ok(text) = fs::read_to_string(rank_path()) else {
        return Vec::new();
    };
    let mut ranked: Vec<RankedHost> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(host) = parts.next() else { continue };
        let Some(ip) = parts.next().and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
            continue;
        };
        let ms = parts
            .next()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        if let Some(existing) = ranked.iter_mut().find(|h| h.host == host) {
            if !existing.ips.iter().any(|(x, _)| *x == ip) {
                existing.ips.push((ip, ms));
            }
        } else {
            ranked.push(RankedHost {
                host: host.to_string(),
                ips: vec![(ip, ms)],
            });
        }
    }
    ranked
}
