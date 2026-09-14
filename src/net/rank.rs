//! Rank substituted proxy IPs by TLS/HTTP latency and keep a short fallback list.
//!
//! Discovery runs at unlock and in the background. The relay serves fresh
//! ranked routes immediately and probes stale candidates before using them.
//! Verified agent hosts pins keep IDE/CLI independent of loopback DNS interception.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::net::hosts::write_entries as write_hosts_entries;
use crate::net::provider::NRPT_AGENT;
use crate::net::relay::{self, load_if_index};
use crate::net::resolvers;
use crate::net::routes;

const FULL_EVERY: Duration = Duration::from_secs(5 * 60);
const WATCH_EVERY: Duration = Duration::from_secs(15);
const START_DELAY: Duration = Duration::from_secs(20);
const MIN_RESCAN_AFTER_DEAD: Duration = Duration::from_secs(60);
const MAX_FALLBACKS: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RankedHost {
    pub host: String,
    pub ips: Vec<(Ipv4Addr, u128)>,
}

pub fn rank_path() -> PathBuf {
    super::config::directory().join("proxy_rank.conf")
}

pub fn spawn_background(manage_system: bool) {
    thread::spawn(move || {
        thread::sleep(START_DELAY);
        let mut last_full = Instant::now()
            .checked_sub(FULL_EVERY)
            .unwrap_or_else(Instant::now);
        let mut seen_revision = 0;
        let mut last_network = None;
        loop {
            let configuration = match super::configuration_lock() {
                Ok(lock) => lock,
                Err(e) => {
                    relay::log_event(&e);
                    thread::sleep(WATCH_EVERY);
                    continue;
                }
            };
            let changed_network = refresh_interface(&mut last_network);
            let stale = file_age().map(|a| a >= FULL_EVERY).unwrap_or(true);
            let leader_dead = any_path_dead();
            let revision = super::route_health::store()
                .snapshot()
                .map(|s| s.revision)
                .unwrap_or(0);
            let refused = revision != seen_revision;
            let since = last_full.elapsed();
            let run = changed_network
                || refused
                || (leader_dead && since >= MIN_RESCAN_AFTER_DEAD)
                || (stale && since >= WATCH_EVERY)
                || (stale && !rank_path().exists());
            if run {
                let why = if leader_dead { "path-down" } else { "periodic" };
                let ranked = rescan(load_if_index(), manage_system);
                match ranked {
                    Ok(r) => {
                        seen_revision = revision;
                        last_full = Instant::now();
                        relay::log_event(&format!("rank {} {}", why, format_notes(&r).join("; ")))
                    }
                    Err(e) => {
                        if manage_system {
                            if let Err(e) = prune_refused_pins() {
                                relay::log_fatal(&e);
                            }
                        }
                        relay::log_fatal(&format!("rank: {e}"));
                        relay::log_event(&format!("Повторный выбор маршрута не завершён: {e}"));
                    }
                }
                if refused && manage_system {
                    #[cfg(windows)]
                    let _ = crate::system::process::no_window(&mut std::process::Command::new(
                        "ipconfig",
                    ))
                    .arg("/flushdns")
                    .output();
                    #[cfg(target_os = "macos")]
                    let _ = std::process::Command::new("dscacheutil")
                        .arg("-flushcache")
                        .output();
                }
            } else if manage_system {
                // VPN may have wiped /32s; cheap to re-pin current proxy IPs.
                refresh_routes_from_disk();
            }
            drop(configuration);
            for host in NRPT_AGENT {
                let _ = resolvers::resolve_best(
                    &super::client::build_query(host, 0xB712),
                    load_if_index(),
                );
            }
            thread::sleep(WATCH_EVERY);
        }
    });
}

fn refresh_interface(last: &mut Option<(u32, Option<String>)>) -> bool {
    let Some(egress) = super::egress::detect() else {
        return false;
    };
    let current = (egress.if_index, egress.gateway);
    if egress.if_index == 0 || last.as_ref() == Some(&current) {
        return false;
    }
    #[cfg(target_os = "macos")]
    if egress.vpn_active {
        return false;
    }
    *last = Some(current);
    relay::save_if_index(egress.if_index);
    resolvers::invalidate_network_caches();
    if let Err(e) = super::route_health::store().update(|s| s.invalidate_probes()) {
        relay::log_fatal(&e);
    }
    true
}

pub fn rescan_agent(if_index: u32) -> Result<Vec<RankedHost>, String> {
    // The caller holds configuration_lock across all foreground setup stages.
    rescan(if_index, true)
}

fn rescan(if_index: u32, manage_system: bool) -> Result<Vec<RankedHost>, String> {
    resolvers::invalidate_network_caches();
    let previous = load();
    let candidates = thread::scope(|scope| {
        let jobs: Vec<_> = NRPT_AGENT
            .iter()
            .map(|name| {
                let previous = &previous;
                scope.spawn(move || {
                    let host = name.trim_start_matches('.').to_string();
                    let mut addresses = resolvers::substituted_ips(&host, if_index);
                    if let Some(old) = previous.iter().find(|h| h.host == host) {
                        for (ip, _) in &old.ips {
                            if !addresses.contains(&IpAddr::V4(*ip)) {
                                addresses.push(IpAddr::V4(*ip));
                            }
                        }
                    }
                    for seed in crate::net::provider::GEOHIDE_PROXY_V4 {
                        if let Ok(ip) = seed.parse() {
                            if !addresses.contains(&ip) {
                                addresses.push(ip);
                            }
                        }
                    }
                    addresses.truncate(32);
                    (host, addresses)
                })
            })
            .collect();
        jobs.into_iter()
            .filter_map(|j| j.join().ok())
            .collect::<Vec<_>>()
    });
    if manage_system {
        let all: Vec<_> = candidates
            .iter()
            .flat_map(|(_, ips)| ips.iter())
            .filter_map(|ip| {
                if let IpAddr::V4(ip) = ip {
                    Some(*ip)
                } else {
                    None
                }
            })
            .collect();
        routes::sync_physical_hosts(&all)?;
    }
    let ranked = thread::scope(|scope| {
        let jobs: Vec<_> = candidates
            .into_iter()
            .map(|(host, candidates)| {
                scope.spawn(move || {
                    let measured = resolvers::rank_paths_v4(&candidates, &host);
                    let keys: Vec<_> = measured
                        .iter()
                        .map(|(ip, _)| super::route_health::Key::ip(&host, (*ip, 443).into()))
                        .collect();
                    let order = super::route_health::order(&keys)?;
                    let ips = order
                        .iter()
                        .filter_map(|k| k.route.parse::<std::net::SocketAddr>().ok())
                        .filter_map(|a| {
                            measured
                                .iter()
                                .find(|(ip, _)| IpAddr::V4(*ip) == a.ip())
                                .copied()
                        })
                        .take(MAX_FALLBACKS)
                        .collect();
                    Ok::<_, String>(RankedHost { host, ips })
                })
            })
            .collect();
        jobs.into_iter()
            .map(|j| j.join().map_err(|_| "Прервано ранжирование".to_string())?)
            .collect::<Result<Vec<_>, String>>()
    })?;
    validate_ranked(&ranked)?;
    save(&ranked)?;
    if manage_system {
        apply_hosts(&ranked)?;
        routes::sync_physical_hosts(&ranked_ips(&ranked))?;
    }
    Ok(ranked)
}

fn validate_ranked(ranked: &[RankedHost]) -> Result<(), String> {
    if ranked
        .iter()
        .filter(|h| {
            h.host == "cloudcode-pa.googleapis.com" || h.host == "daily-cloudcode-pa.googleapis.com"
        })
        .all(|h| h.ips.is_empty())
    {
        return Err("Нет проверенного TLS/HTTP-пути к Cloud Code; прежние пользовательские настройки сохранены".into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointChoice {
    Native,
    Daily,
    Uncertain,
}

pub fn endpoint_choice() -> EndpointChoice {
    if file_age().is_none_or(|age| age > Duration::from_secs(60)) {
        return EndpointChoice::Uncertain;
    }
    let Ok(state) = super::route_health::store().snapshot() else {
        return EndpointChoice::Uncertain;
    };
    let mut ranked = load();
    for host in &mut ranked {
        host.ips.retain(|(ip, _)| {
            let key = super::route_health::Key::ip(&host.host, (*ip, 443).into());
            match state.cached(&key, super::route_health::now_ms()) {
                Some(ok) => ok,
                None => super::health::check_ip((*ip, 443).into(), &host.host, false).is_ok(),
            }
        });
    }
    choose_endpoint(&ranked)
}
fn choose_endpoint(ranked: &[RankedHost]) -> EndpointChoice {
    let has = |name: &str| ranked.iter().any(|h| h.host == name && !h.ips.is_empty());
    if has("cloudcode-pa.googleapis.com") {
        EndpointChoice::Native
    } else if has("daily-cloudcode-pa.googleapis.com") {
        EndpointChoice::Daily
    } else {
        EndpointChoice::Uncertain
    }
}

pub fn candidates_for(host: &str) -> Vec<Ipv4Addr> {
    load()
        .into_iter()
        .filter(|h| h.host == super::route_health::host_name(host))
        .flat_map(|h| h.ips.into_iter().map(|(ip, _)| ip))
        .collect()
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

fn file_age() -> Option<Duration> {
    let meta = fs::metadata(rank_path()).ok()?;
    let modified = meta.modified().ok()?;
    SystemTime::now().duration_since(modified).ok()
}

fn any_path_dead() -> bool {
    let ranked = load();
    let outcomes = thread::scope(|scope| {
        let jobs: Vec<_> = ranked
            .iter()
            .flat_map(|h| h.ips.iter().map(move |(ip, _)| (*ip, h.host.clone())))
            .map(|(ip, host)| {
                scope.spawn(move || {
                    let ok = super::health::check_ip((ip, 443).into(), &host, true).is_ok();
                    (ip, host, ok)
                })
            })
            .collect();
        jobs.into_iter()
            .filter_map(|j| j.join().ok())
            .collect::<Vec<_>>()
    });
    needs_refresh(&ranked, |ip, host| {
        outcomes
            .iter()
            .any(|(a, h, ok)| *a == ip && h == host && *ok)
    })
}

fn needs_refresh(ranked: &[RankedHost], mut probe: impl FnMut(Ipv4Addr, &str) -> bool) -> bool {
    if ranked.len() != NRPT_AGENT.len() {
        return true;
    }
    let mut failed = false;
    for host in ranked {
        if host.ips.is_empty() {
            failed = true;
        }
        for (ip, _) in &host.ips {
            if !probe(*ip, &host.host) {
                failed = true;
            }
        }
    }
    failed
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

fn refresh_routes_from_disk() {
    let ips = ranked_ips(&load());
    if !ips.is_empty() {
        if let Err(e) = routes::sync_physical_hosts(&ips) {
            relay::log_fatal(&e);
        }
    }
}

fn hosts_entries(ranked: &[RankedHost]) -> Vec<(String, Ipv4Addr)> {
    ranked
        .iter()
        // Match 2.0.0: one verified leader per host, avoiding slow fallback races.
        .filter_map(|h| h.ips.first().map(|(ip, _)| (h.host.clone(), *ip)))
        .collect()
}

fn apply_hosts(ranked: &[RankedHost]) -> Result<(), String> {
    let entries = hosts_entries(ranked);
    install_pins(&entries)
}

fn install_pins(entries: &[(String, Ipv4Addr)]) -> Result<(), String> {
    if entries.is_empty() {
        crate::net::hosts::remove_entries()?;
    } else {
        write_hosts_entries(entries)?;
    }
    let keys: Vec<_> = entries
        .iter()
        .map(|(host, ip)| super::route_health::Key::ip(host, (*ip, 443).into()))
        .collect();
    super::route_health::store().update(|s| s.set_pinned(&keys, super::route_health::now_ms()))
}

fn prune_refused_pins() -> Result<(), String> {
    let state = super::route_health::store().snapshot()?;
    let original = super::hosts::owned_entries()?;
    let keep = retained_pins(&original, &state, super::route_health::now_ms());
    if keep != original {
        install_pins(&keep)?;
    }
    Ok(())
}

fn retained_pins(
    entries: &[(String, Ipv4Addr)],
    state: &super::route_health::State,
    now: u64,
) -> Vec<(String, Ipv4Addr)> {
    entries
        .iter()
        .filter(|(host, ip)| {
            !state.region_blocked(&super::route_health::Key::ip(host, (*ip, 443).into()), now)
        })
        .cloned()
        .collect()
}

fn save(ranked: &[RankedHost]) -> Result<(), String> {
    let dir = super::config::directory();
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
    crate::system::fs_utils::robust_write_file(&rank_path(), out.as_bytes())?;
    super::config::inherit_directory_owner(&rank_path())
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_rescan_removes_region_refused_pins_but_preserves_temporarily_offline_hosts() {
        use super::super::route_health::{Key, State};
        let mut state = State::default();
        let a = (
            "cloudcode-pa.googleapis.com".to_string(),
            "192.0.2.1".parse().unwrap(),
        );
        let b = (
            "generativelanguage.googleapis.com".to_string(),
            "192.0.2.2".parse().unwrap(),
        );
        let key = Key::ip(&a.0, (a.1, 443).into());
        state.set_pinned(&[key.clone()], 1);
        state.region_refusal("region", Some(&a.0), None, 2);
        state.record(&Key::ip(&b.0, (b.1, 443).into()), Err(()), 2);
        assert_eq!(retained_pins(&[a, b.clone()], &state, 3), vec![b]);
    }
    #[test]
    fn hosts_pins_follow_verified_leaders_and_skip_unreachable_hosts() {
        let first = Ipv4Addr::new(192, 0, 2, 1);
        let second = Ipv4Addr::new(192, 0, 2, 2);
        let mut ranked = vec![
            RankedHost {
                host: "daily-cloudcode-pa.googleapis.com".into(),
                ips: vec![(first, 10), (second, 20)],
            },
            RankedHost {
                host: "cloudcode-pa.googleapis.com".into(),
                ips: vec![],
            },
        ];
        assert_eq!(
            hosts_entries(&ranked),
            vec![(ranked[0].host.clone(), first)]
        );
        ranked[0].ips.remove(0);
        assert_eq!(
            hosts_entries(&ranked),
            vec![(ranked[0].host.clone(), second)]
        );
        ranked[0].ips.clear();
        assert!(hosts_entries(&ranked).is_empty());
    }

    #[test]
    fn failed_cloudcode_scan_is_rejected_before_persistence() {
        assert!(validate_ranked(&[]).is_err());
        let mut hosts = vec![
            RankedHost {
                host: "cloudcode-pa.googleapis.com".into(),
                ips: vec![],
            },
            RankedHost {
                host: "generativelanguage.googleapis.com".into(),
                ips: vec![(Ipv4Addr::LOCALHOST, 1)],
            },
        ];
        assert!(validate_ranked(&hosts).is_err());
        hosts.push(RankedHost {
            host: "daily-cloudcode-pa.googleapis.com".into(),
            ips: vec![(Ipv4Addr::LOCALHOST, 1)],
        });
        assert!(validate_ranked(&hosts).is_ok());
    }
    #[test]
    fn native_endpoint_is_preferred_and_daily_requires_a_verified_alternative() {
        let row = |host: &str| RankedHost {
            host: host.into(),
            ips: vec![(Ipv4Addr::LOCALHOST, 1)],
        };
        assert_eq!(choose_endpoint(&[]), EndpointChoice::Uncertain);
        assert_eq!(
            choose_endpoint(&[row("daily-cloudcode-pa.googleapis.com")]),
            EndpointChoice::Daily
        );
        assert_eq!(
            choose_endpoint(&[
                row("daily-cloudcode-pa.googleapis.com"),
                row("cloudcode-pa.googleapis.com")
            ]),
            EndpointChoice::Native
        );
        assert_eq!(
            choose_endpoint(&[row("generativelanguage.googleapis.com")]),
            EndpointChoice::Uncertain
        );
    }
    #[test]
    fn every_host_and_fallback_is_checked_even_if_the_first_host_is_healthy() {
        let ranked: Vec<_> = NRPT_AGENT
            .iter()
            .map(|h| RankedHost {
                host: h.to_string(),
                ips: vec![(Ipv4Addr::LOCALHOST, 1), (Ipv4Addr::new(127, 0, 0, 2), 2)],
            })
            .collect();
        let mut calls = 0;
        assert!(needs_refresh(&ranked, |_, h| {
            calls += 1;
            h != NRPT_AGENT[1]
        }));
        assert_eq!(calls, 6);
        assert!(!needs_refresh(&ranked, |_, _| true));
        assert!(needs_refresh(&[], |_, _| true));
    }
}
