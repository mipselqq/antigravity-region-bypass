use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::net::client::{
    answer_addrs, build_query, is_successful_response, query_raw_via, question_name, question_type,
    without_addrs,
};

/// SmartDNS that *substitutes* Google AI names with their SNI-proxy IPs.
/// A passthrough (real Google anycast) is a failure for the region gate.
pub struct Provider {
    pub name: &'static str,
    pub v4: &'static [&'static str],
}

pub const PROVIDERS: &[Provider] = &[
    Provider {
        name: "xbox-dns.ru",
        v4: &["111.88.96.50", "111.88.96.51"],
    },
    Provider {
        name: "comss.one",
        v4: &["83.220.169.155", "212.109.195.93", "195.133.25.16"],
    },
    Provider {
        name: "geohide.ru",
        v4: &["45.155.204.190", "37.230.192.51"],
    },
];

const REFERENCE_V4: &[&str] = &["8.8.8.8", "1.1.1.1"];
const REFERENCE_STUBS: [Ipv4Addr; 2] = [Ipv4Addr::new(8, 6, 112, 0), Ipv4Addr::new(8, 47, 69, 0)];

const CONTROL_NAMES: &[&str] = &[
    "chatgpt.com",
    "api.openai.com",
    "claude.ai",
    "gemini.google.com",
    "ai.google.dev",
];

const PROXY_SET_TTL: Duration = Duration::from_secs(30 * 60);
const RACE_BUDGET: Duration = Duration::from_millis(2800);
const QUERY_TIMEOUT: Duration = Duration::from_millis(800);
static PROXY_SET: Mutex<Option<(HashMap<usize, Vec<IpAddr>>, Instant)>> = Mutex::new(None);
const DNS_PACKET_CACHE_TTL: Duration = Duration::from_secs(20);
static DNS_PACKET_CACHE: Mutex<
    Option<HashMap<(String, u16), (Vec<u8>, String, Verdict, Instant)>>,
> = Mutex::new(None);
static NETWORK_REVISION: AtomicU64 = AtomicU64::new(0);
static ROTATION: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Substituted,
    Sibling,
    Passthrough,
    Unknown,
}

pub struct ResolveHit {
    pub reply: Vec<u8>,
    pub provider: String,
    pub verdict: Verdict,
}

pub fn all_provider_v4() -> Vec<&'static str> {
    PROVIDERS
        .iter()
        .flat_map(|p| p.v4.iter().copied())
        .collect()
}

pub fn fallback_v4() -> Vec<&'static str> {
    all_provider_v4()
}

fn parse_v4(s: &str) -> Option<Ipv4Addr> {
    s.parse().ok()
}

fn netblock(addr: &IpAddr) -> (u8, u32) {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (4, u32::from_be_bytes([o[0], o[1], 0, 0]))
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            (6, u32::from_be_bytes([o[0], o[1], o[2], o[3]]))
        }
    }
}

pub fn classify(candidate: &[IpAddr], reference: &[IpAddr], proxy: &[IpAddr]) -> Verdict {
    if candidate.is_empty() {
        return Verdict::Unknown;
    }
    let reference: Vec<&IpAddr> = reference
        .iter()
        .filter(|a| match a {
            IpAddr::V4(v4) => !REFERENCE_STUBS.contains(v4),
            IpAddr::V6(_) => true,
        })
        .collect();
    if reference.is_empty() {
        return Verdict::Unknown;
    }

    let fam: Vec<u8> = candidate.iter().map(|a| netblock(a).0).collect();
    let comparable: Vec<&&IpAddr> = reference
        .iter()
        .filter(|a| fam.contains(&netblock(a).0))
        .collect();
    if comparable.is_empty() {
        return Verdict::Unknown;
    }

    let ref_blocks: Vec<(u8, u32)> = comparable.iter().map(|a| netblock(a)).collect();
    if candidate.iter().any(|a| ref_blocks.contains(&netblock(a))) {
        return Verdict::Passthrough;
    }
    if !proxy.is_empty() && candidate.iter().any(|a| proxy.contains(a)) {
        return Verdict::Substituted;
    }
    if proxy.is_empty() {
        return Verdict::Substituted;
    }
    Verdict::Sibling
}

fn query_a(name: &str, server: Ipv4Addr, if_index: u32, timeout: Duration) -> Option<Vec<u8>> {
    let id = (Instant::now().elapsed().as_nanos() as u16).wrapping_add(server.octets()[3] as u16);
    let pkt = build_query(name, id);
    match query_raw_via(&pkt, server, if_index, timeout) {
        Ok(resp) if is_successful_response(&resp) => Some(resp),
        _ => None,
    }
}

pub fn warmup(if_index: u32) {
    thread::spawn(move || {
        let _ = learn_proxy_addrs(if_index);
    });
}

fn cached_proxy() -> HashMap<usize, Vec<IpAddr>> {
    if let Ok(guard) = PROXY_SET.lock() {
        if let Some((map, at)) = guard.as_ref() {
            if at.elapsed() < PROXY_SET_TTL {
                return map.clone();
            }
        }
    }
    HashMap::new()
}

fn learn_proxy_addrs(if_index: u32) -> HashMap<usize, Vec<IpAddr>> {
    if let Ok(guard) = PROXY_SET.lock() {
        if let Some((map, at)) = guard.as_ref() {
            if at.elapsed() < PROXY_SET_TTL {
                return map.clone();
            }
        }
    }

    let mut map: HashMap<usize, Vec<IpAddr>> = HashMap::new();

    for (idx, provider) in PROVIDERS.iter().enumerate() {
        let mut learned = Vec::new();
        for name in CONTROL_NAMES {
            let reference = reference_addrs(name, if_index);
            for address in provider.v4 {
                let Some(server) = parse_v4(address) else {
                    continue;
                };
                if let Some(resp) = query_a(name, server, if_index, QUERY_TIMEOUT) {
                    let addrs = answer_addrs(&resp);
                    let v = classify(&addrs, &reference, &[]);
                    if v == Verdict::Substituted {
                        for a in addrs {
                            if !learned.contains(&a) {
                                learned.push(a);
                            }
                        }
                    }
                }
            }
        }
        map.insert(idx, learned);
    }

    if let Ok(mut guard) = PROXY_SET.lock() {
        *guard = Some((map.clone(), Instant::now()));
    }
    map
}

fn reference_addrs(name: &str, if_index: u32) -> Vec<IpAddr> {
    for ns in REFERENCE_V4 {
        if let Ok(ip) = ns.parse::<Ipv4Addr>() {
            if let Some(resp) = query_a(name, ip, if_index, QUERY_TIMEOUT) {
                let addrs: Vec<IpAddr> = answer_addrs(&resp)
                    .into_iter()
                    .filter(|a| match a {
                        IpAddr::V4(v4) => !REFERENCE_STUBS.contains(v4),
                        _ => true,
                    })
                    .collect();
                if !addrs.is_empty() {
                    return addrs;
                }
            }
        }
    }
    let _ = if_index;
    Vec::new()
}

/// TLS-ok IPv4s, fastest first. TCP-open is not enough: a proxy can accept
/// SYN and still RST or stall the handshake.
pub fn rank_paths_v4(addrs: &[IpAddr], sni: &str) -> Vec<(Ipv4Addr, u128)> {
    let candidates: Vec<IpAddr> = addrs.iter().copied().filter(|a| a.is_ipv4()).collect();
    if candidates.is_empty() {
        return Vec::new();
    }
    let (tx, rx) = mpsc::channel();
    for addr in candidates {
        let sni = sni.to_string();
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send((addr, path_latency_ms(addr, &sni)));
        });
    }
    drop(tx);
    let mut out = Vec::new();
    while let Ok((addr, ms)) = rx.recv() {
        let Some(ms) = ms else {
            continue;
        };
        let IpAddr::V4(v4) = addr else {
            continue;
        };
        out.push((v4, ms));
    }
    out.sort_by_key(|(_, ms)| *ms);
    out
}

pub(crate) fn path_latency_ms(addr: IpAddr, sni: &str) -> Option<u128> {
    crate::net::health::check_ip(SocketAddr::new(addr, 443), sni, false).ok()
}

pub fn invalidate_network_caches() {
    if let Ok(mut g) = DNS_PACKET_CACHE.lock() {
        *g = None;
    }
}

fn drop_dead(reply: &[u8], host: &str) -> Option<Vec<u8>> {
    let addrs = answer_addrs(reply);
    if addrs.is_empty() {
        return Some(reply.to_vec());
    }
    let dead = probe_dead(&addrs, host);
    if dead.len() == addrs.len() {
        return None;
    }
    if dead.is_empty() {
        return Some(reply.to_vec());
    }
    without_addrs(reply, &dead)
}

fn probe_dead(addrs: &[IpAddr], host: &str) -> Vec<IpAddr> {
    thread::scope(|scope| {
        let jobs: Vec<_> = addrs
            .iter()
            .take(32)
            .map(|addr| {
                (
                    *addr,
                    scope.spawn(move || {
                        crate::net::health::check_ip(SocketAddr::new(*addr, 443), host, false)
                            .is_ok()
                    }),
                )
            })
            .collect();
        let mut dead: Vec<_> = jobs
            .into_iter()
            .filter_map(|(addr, j)| (!j.join().unwrap_or(false)).then_some(addr))
            .collect();
        dead.extend(addrs.iter().skip(32));
        dead
    })
}

struct RaceResult {
    idx: usize,
    provider: String,
    reply: Vec<u8>,
    addrs: Vec<IpAddr>,
}

enum RaceMsg {
    Provider(RaceResult),
    Reference(Vec<IpAddr>),
}

fn race_providers(query: &[u8], if_index: u32) -> (Vec<RaceResult>, Vec<IpAddr>) {
    let (tx, rx) = mpsc::channel();
    for (idx, provider) in PROVIDERS.iter().enumerate() {
        for server in provider.v4 {
            let q = query.to_vec();
            let tx = tx.clone();
            let Ok(ip) = server.parse::<Ipv4Addr>() else {
                continue;
            };
            thread::spawn(move || {
                if let Ok(resp) = query_raw_via(&q, ip, if_index, QUERY_TIMEOUT) {
                    if is_successful_response(&resp) && !answer_addrs(&resp).is_empty() {
                        let addrs = answer_addrs(&resp);
                        let _ = tx.send(RaceMsg::Provider(RaceResult {
                            idx,
                            provider: provider.name.into(),
                            reply: resp,
                            addrs,
                        }));
                    }
                }
            });
        }
    }
    match super::config::load() {
        Ok(config) => {
            for (offset, provider) in config.extra_udp.into_iter().enumerate() {
                for ip in provider.addresses {
                    let q = query.to_vec();
                    let tx = tx.clone();
                    let name = provider.name.clone();
                    thread::spawn(move || {
                        if let Ok(reply) = query_raw_via(&q, ip, if_index, QUERY_TIMEOUT) {
                            let addrs = answer_addrs(&reply);
                            if is_successful_response(&reply) && !addrs.is_empty() {
                                let _ = tx.send(RaceMsg::Provider(RaceResult {
                                    idx: PROVIDERS.len() + offset,
                                    provider: name,
                                    reply,
                                    addrs,
                                }));
                            }
                        }
                    });
                }
            }
            for (offset, provider) in config.doh.into_iter().enumerate() {
                let q = query.to_vec();
                let tx = tx.clone();
                thread::spawn(move || {
                    if let Ok(reply) = super::dns_https::query(&provider, &q, if_index) {
                        let addrs = answer_addrs(&reply);
                        if is_successful_response(&reply) && !addrs.is_empty() {
                            let _ = tx.send(RaceMsg::Provider(RaceResult {
                                idx: PROVIDERS.len() + 8 + offset,
                                provider: provider.name,
                                reply,
                                addrs,
                            }));
                        }
                    }
                });
            }
        }
        Err(e) => super::relay::log_event(&e),
    }
    for ns in REFERENCE_V4 {
        let q = query.to_vec();
        let tx = tx.clone();
        let Ok(ip) = ns.parse::<Ipv4Addr>() else {
            continue;
        };
        thread::spawn(move || {
            if let Ok(resp) = query_raw_via(&q, ip, if_index, QUERY_TIMEOUT) {
                let addrs: Vec<IpAddr> = answer_addrs(&resp)
                    .into_iter()
                    .filter(|a| match a {
                        IpAddr::V4(v4) => !REFERENCE_STUBS.contains(v4),
                        _ => true,
                    })
                    .collect();
                if !addrs.is_empty() {
                    let _ = tx.send(RaceMsg::Reference(addrs));
                }
            }
        });
    }
    drop(tx);
    let deadline = Instant::now() + RACE_BUDGET;
    let mut out = Vec::new();
    let mut reference = Vec::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(RaceMsg::Provider(hit)) => out.push(hit),
            Ok(RaceMsg::Reference(addrs)) => {
                for addr in addrs {
                    if !reference.contains(&addr) {
                        reference.push(addr);
                    }
                }
            }
            Err(_) => break,
        }
    }
    (out, reference)
}

/// Gather independent candidates from every responding nameserver, not just
/// the DNS race winner. TLS ranking below decides which endpoints are usable.
pub fn substituted_ips(name: &str, if_index: u32) -> Vec<IpAddr> {
    let (hits, reference) = race_providers(&build_query(name, 0xA652), if_index);
    let proxy = cached_proxy();
    collect_substituted(&hits, &reference, &proxy)
}
fn collect_substituted(
    hits: &[RaceResult],
    reference: &[IpAddr],
    proxy: &HashMap<usize, Vec<IpAddr>>,
) -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    for hit in hits {
        if classify(
            &hit.addrs,
            reference,
            proxy.get(&hit.idx).map(Vec::as_slice).unwrap_or(&[]),
        ) == Verdict::Substituted
        {
            for ip in &hit.addrs {
                if !addresses.contains(ip) {
                    addresses.push(*ip);
                }
            }
        }
    }
    addresses
}

pub(crate) fn looks_google(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            matches!(
                (o[0], o[1]),
                (64, 233)
                    | (66, 102)
                    | (66, 249)
                    | (72, 14)
                    | (74, 125)
                    | (142, 250)
                    | (142, 251)
                    | (172, 217)
                    | (173, 194)
                    | (192, 178)
                    | (216, 58)
                    | (216, 239)
            )
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            o[0] == 0x20 && o[1] == 0x01 && o[2] == 0x48 && o[3] == 0x60
        }
    }
}

fn pick_winner(hits: &[RaceResult], reference: &[IpAddr], if_index: u32) -> Option<usize> {
    if hits.is_empty() {
        return None;
    }
    let proxy = cached_proxy();
    let rot = ROTATION.fetch_add(1, Ordering::Relaxed);
    let mut best_sub: Vec<usize> = Vec::new();
    let mut rest: Vec<usize> = Vec::new();
    for (i, hit) in hits.iter().enumerate() {
        let proxy_addrs = proxy.get(&hit.idx).cloned().unwrap_or_default();
        if hit.idx == usize::MAX
            || classify(&hit.addrs, reference, &proxy_addrs) == Verdict::Substituted
            || (reference.is_empty() && hit.addrs.iter().any(|a| !looks_google(a)))
        {
            best_sub.push(i);
        } else {
            rest.push(i);
        }
    }
    let pool = if !best_sub.is_empty() { best_sub } else { rest };
    let _ = if_index;
    if pool.is_empty() {
        return Some(rot % hits.len());
    }
    Some(pool[rot % pool.len()])
}

fn cache_dns_packet(name: String, qtype: u16, reply: Vec<u8>, provider: &str, verdict: Verdict) {
    if verdict != Verdict::Substituted {
        return;
    }
    if let Ok(mut cguard) = DNS_PACKET_CACHE.lock() {
        let cmap = cguard.get_or_insert_with(HashMap::new);
        if cmap.len() >= 64 {
            cmap.retain(|_, (_, _, _, at)| at.elapsed() < DNS_PACKET_CACHE_TTL);
            if cmap.len() >= 64 {
                if let Some(oldest) = cmap
                    .iter()
                    .min_by_key(|(_, (_, _, _, at))| *at)
                    .map(|(key, _)| key.clone())
                {
                    cmap.remove(&oldest);
                }
            }
        }
        cmap.insert(
            (name, qtype),
            (reply, provider.to_string(), verdict, Instant::now()),
        );
    }
}

/// No network calls or state writes. Cold resolution is scheduled separately
/// by the relay, so occupied discovery workers cannot delay a cached answer.
pub fn resolve_cached(query: &[u8]) -> Option<ResolveHit> {
    let name = question_name(query)?.to_ascii_lowercase();
    let state = super::route_health::store().snapshot().ok()?;
    let revision = state.revision;
    if NETWORK_REVISION.swap(revision, Ordering::SeqCst) != revision {
        invalidate_network_caches();
    }
    let ranked = if super::provider::NRPT_AGENT.contains(&name.as_str()) {
        super::rank::candidates_for(&name)
    } else {
        vec![]
    };
    cached_answer(query, &state, &ranked, super::route_health::now_ms())
}

fn cached_answer(
    query: &[u8],
    state: &super::route_health::State,
    ranked: &[Ipv4Addr],
    now: u64,
) -> Option<ResolveHit> {
    let name = question_name(query)?.to_ascii_lowercase();
    let qtype = question_type(query)?;
    let cached = DNS_PACKET_CACHE.lock().ok().and_then(|g| {
        g.as_ref()
            .and_then(|m| m.get(&(name.clone(), qtype)).cloned())
    });
    if let Some((mut reply, provider, verdict, at)) = cached {
        if at.elapsed() < DNS_PACKET_CACHE_TTL {
            reply[..2].copy_from_slice(&query[..2]);
            let addresses = answer_addrs(&reply);
            if let Some(reply) = (!addresses.is_empty()
                && addresses.iter().all(|ip| {
                    state.usable(
                        &super::route_health::Key::ip(&name, (*ip, 443).into()),
                        now,
                        120_000,
                    )
                }))
            .then(|| super::client::age_ttls(&reply, at.elapsed().as_secs() as u32, 20))
            .flatten()
            {
                return Some(ResolveHit {
                    reply,
                    provider,
                    verdict,
                });
            }
        }
        if let Ok(mut g) = DNS_PACKET_CACHE.lock() {
            if let Some(m) = g.as_mut() {
                m.remove(&(name.clone(), qtype));
            }
        }
    }
    if qtype == 1 {
        let keys: Vec<_> = ranked
            .iter()
            .map(|ip| super::route_health::Key::ip(&name, (*ip, 443).into()))
            .filter(|key| state.usable(key, now, 120_000))
            .collect();
        if !keys.is_empty() {
            if let Some(key) = keys.first() {
                if let Ok(SocketAddr::V4(addr)) = key.route.parse::<SocketAddr>() {
                    let reply = super::client::address_response(query, &[*addr.ip()])?;
                    cache_dns_packet(
                        name,
                        qtype,
                        reply.clone(),
                        "ranked-sni",
                        Verdict::Substituted,
                    );
                    return Some(ResolveHit {
                        reply,
                        provider: "ranked-sni".into(),
                        verdict: Verdict::Substituted,
                    });
                }
            }
        }
    }
    None
}

pub fn refresh_due(query: &[u8]) -> bool {
    let Some(name) = question_name(query) else {
        return false;
    };
    let Some(qtype) = question_type(query) else {
        return false;
    };
    DNS_PACKET_CACHE
        .lock()
        .ok()
        .and_then(|g| {
            g.as_ref()
                .and_then(|m| m.get(&(name.to_ascii_lowercase(), qtype)))
                .map(|(_, _, _, at)| at.elapsed() >= Duration::from_secs(10))
        })
        .unwrap_or(true)
}

/// Only background discovery workers call this path.
pub fn refresh_answer(query: &[u8], if_index: u32) -> Option<ResolveHit> {
    let name = question_name(query)?.to_ascii_lowercase();
    let qtype = question_type(query)?;
    let ranked = super::rank::candidates_for(&name);
    // Refresh the current path before contacting every DNS provider.
    if qtype == 1 {
        for ip in &ranked {
            if super::health::check_ip((*ip, 443).into(), &name, false).is_ok() {
                let reply = super::client::address_response(query, &[*ip])?;
                cache_dns_packet(
                    name,
                    qtype,
                    reply.clone(),
                    "ranked-sni",
                    Verdict::Substituted,
                );
                return Some(ResolveHit {
                    reply,
                    provider: "ranked-sni".into(),
                    verdict: Verdict::Substituted,
                });
            }
        }
    }
    let (mut hits, reference) = race_providers(query, if_index);
    // Direct relay queries also use verified seed routes when SmartDNS returns
    // ordinary Google addresses (for example behind a VPN).
    if super::provider::NRPT_AGENT.contains(&name.as_str()) {
        if let Some(hit) = ranked_hit(query, &ranked) {
            hits.push(hit);
        }
    }
    // Probe unique addresses once, in parallel, regardless of how many DNS servers returned them.
    let mut addresses = Vec::new();
    for hit in &hits {
        for addr in &hit.addrs {
            if !addresses.contains(addr) {
                addresses.push(*addr);
            }
        }
    }
    let dead = probe_dead(&addresses, &name);
    let hits: Vec<_> = hits
        .into_iter()
        .filter_map(|mut h| {
            if h.addrs.iter().all(|a| dead.contains(a)) {
                return None;
            }
            if h.addrs.iter().any(|a| dead.contains(a)) {
                h.reply = without_addrs(&h.reply, &dead)?;
            }
            h.addrs = answer_addrs(&h.reply);
            Some(h)
        })
        .collect();
    if let Some(initial) = pick_winner(&hits, &reference, if_index) {
        let proxy = cached_proxy();
        let verdict_of = |h: &RaceResult| {
            if h.idx == usize::MAX {
                Verdict::Substituted
            } else {
                classify(
                    &h.addrs,
                    &reference,
                    proxy.get(&h.idx).map(Vec::as_slice).unwrap_or(&[]),
                )
            }
        };
        let wanted = verdict_of(&hits[initial]);
        let keys: Vec<_> = hits
            .iter()
            .filter(|h| verdict_of(h) == wanted)
            .flat_map(|h| {
                h.addrs
                    .iter()
                    .map(|ip| super::route_health::Key::ip(&name, SocketAddr::new(*ip, 443)))
            })
            .collect();
        let order = super::route_health::order(&keys).ok()?;
        let win = order
            .first()
            .and_then(|key| key.route.parse::<SocketAddr>().ok())
            .and_then(|addr| {
                hits.iter()
                    .position(|h| verdict_of(h) == wanted && h.addrs.contains(&addr.ip()))
            })
            .unwrap_or(initial);
        let hit = &hits[win];
        // Prefer one measured address so a subsequent refusal can be tied to this answer.
        // The remaining verified IPs stay in the route table for failover on the next query.
        let primary = order
            .first()
            .and_then(|key| key.route.parse::<SocketAddr>().ok())
            .map(|a| a.ip());
        let other: Vec<_> = hit
            .addrs
            .iter()
            .filter(|a| Some(**a) != primary)
            .copied()
            .collect();
        let selected = if qtype == 1 && primary.is_some() && !other.is_empty() {
            without_addrs(&hit.reply, &other).unwrap_or_else(|| hit.reply.clone())
        } else {
            hit.reply.clone()
        };
        let reply = super::client::age_ttls(&selected, 0, 20)?;
        cache_dns_packet(name, qtype, reply.clone(), &hit.provider, wanted);
        return Some(ResolveHit {
            reply,
            provider: hit.provider.clone(),
            verdict: wanted,
        });
    }
    // A regular answer is not a successful bypass; the caller can still distinguish it.
    for ns in REFERENCE_V4 {
        let Ok(ip) = ns.parse::<Ipv4Addr>() else {
            continue;
        };
        if let Ok(reply) = query_raw_via(query, ip, if_index, QUERY_TIMEOUT) {
            if is_successful_response(&reply) && !answer_addrs(&reply).is_empty() {
                let reply = super::client::age_ttls(&drop_dead(&reply, &name)?, 0, 20)?;
                return Some(ResolveHit {
                    reply,
                    provider: "reference".into(),
                    verdict: Verdict::Passthrough,
                });
            }
        }
    }
    None
}

fn ranked_hit(query: &[u8], addresses: &[Ipv4Addr]) -> Option<RaceResult> {
    let reply = super::client::address_response(query, addresses)?;
    Some(RaceResult {
        idx: usize::MAX,
        provider: "ranked-sni".into(),
        addrs: answer_addrs(&reply),
        reply,
    })
}

#[cfg(test)]
fn fresh_ranked_keys(
    name: &str,
    addresses: &[Ipv4Addr],
    state: &super::route_health::State,
    now: u64,
) -> Vec<super::route_health::Key> {
    addresses
        .iter()
        .map(|ip| super::route_health::Key::ip(name, (*ip, 443).into()))
        .filter(|key| state.cached(key, now) == Some(true))
        .collect()
}

/// Nameserver IPs (not the relay) that currently substitute `name`.
/// Asked one provider at a time so a slow substituter is not lost to the race.
pub fn substituting_addrs(name: &str, if_index: u32) -> Vec<&'static str> {
    let reference = reference_addrs(name, if_index);
    let proxy = {
        let cached = cached_proxy();
        if cached.is_empty() {
            learn_proxy_addrs(if_index)
        } else {
            cached
        }
    };
    let mut out = Vec::new();
    for (idx, provider) in PROVIDERS.iter().enumerate() {
        for address in provider.v4 {
            let Some(server) = parse_v4(address) else {
                continue;
            };
            let Some(resp) = query_a(name, server, if_index, QUERY_TIMEOUT) else {
                continue;
            };
            let addrs = answer_addrs(&resp);
            let proxy_addrs = proxy.get(&idx).cloned().unwrap_or_default();
            let substituted = classify(&addrs, &reference, &proxy_addrs) == Verdict::Substituted
                || (reference.is_empty() && addrs.iter().any(|a| !looks_google(a)));
            if substituted && !out.contains(address) {
                out.push(*address);
            }
        }
    }
    out
}

pub fn verdict_tag(v: Verdict) -> &'static str {
    match v {
        Verdict::Substituted => "substituted",
        Verdict::Sibling => "sibling",
        Verdict::Passthrough => "PASSTHROUGH",
        Verdict::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_dns_never_waits_for_a_stale_tls_probe_and_honours_failures() {
        let name = "cached-fast-lane.test";
        let query = build_query(name, 0x1234);
        let ip = Ipv4Addr::new(192, 0, 2, 10);
        let key = super::super::route_health::Key::ip(name, (ip, 443).into());
        let mut state = super::super::route_health::State::default();
        state.record(&key, Ok(30), 1000);
        // Transport freshness expired; bounded last-good DNS grace still applies.
        assert_eq!(state.cached(&key, 30_000), None);
        let (tx, rx) = mpsc::channel();
        let fixture = state.clone();
        thread::spawn(move || {
            let result = cached_answer(&query, &fixture, &[ip], 30_000).unwrap();
            assert_eq!(&result.reply[..2], &0x1234u16.to_be_bytes());
            tx.send(result.reply).unwrap();
        });
        let reply = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("cached DNS waited for network work");
        assert_eq!(answer_addrs(&reply), vec![IpAddr::V4(ip)]);
        let query = build_query(name, 0x5678);
        let cached = cached_answer(&query, &state, &[ip], 30_001).unwrap();
        assert_eq!(&cached.reply[..2], &0x5678u16.to_be_bytes());
        state.record(&key, Err(()), 30_002);
        assert!(cached_answer(&query, &state, &[ip], 30_003).is_none());
        state.record(&key, Ok(20), 40_000);
        state.note_used(&key, 40_000);
        state.region_refusal("fixture", Some(name), Some(&key.route), 40_001);
        assert!(cached_answer(&query, &state, &[ip], 40_002).is_none());
    }

    #[test]
    fn dns_grace_expires_and_never_crosses_host_or_network_invalidation() {
        let ip = Ipv4Addr::new(192, 0, 2, 11);
        let name = "bounded-dns-grace.test";
        let key = super::super::route_health::Key::ip(name, (ip, 443).into());
        let mut state = super::super::route_health::State::default();
        state.record(&key, Ok(20), 1000);
        assert!(cached_answer(&build_query("other-host.test", 1), &state, &[ip], 1001).is_none());
        let query = build_query(name, 1);
        assert!(cached_answer(&query, &state, &[ip], 121_000).is_none());
        state.invalidate_probes();
        assert!(cached_answer(&query, &state, &[ip], 1001).is_none());
    }

    #[test]
    fn relay_keeps_ranked_routes_when_external_dns_only_passes_through() {
        let query = build_query("cloudcode-pa.googleapis.com", 9);
        let ranked = ranked_hit(&query, &["37.230.192.51".parse().unwrap()]).unwrap();
        assert!(super::super::client::response_matches(
            &query,
            &ranked.reply
        ));
        let hits = vec![
            RaceResult {
                idx: 0,
                provider: "fixture".into(),
                reply: vec![],
                addrs: vec![v4(142, 250, 1, 1)],
            },
            ranked,
        ];
        assert_eq!(pick_winner(&hits, &[v4(142, 250, 1, 1)], 0), Some(1));
    }

    #[test]
    fn fast_dns_answer_requires_fresh_host_specific_route_without_region_penalty() {
        let ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let key =
            super::super::route_health::Key::ip("cloudcode-pa.googleapis.com", (ip, 443).into());
        let mut state = super::super::route_health::State::default();
        state.record(&key, Ok(100), 1);
        assert_eq!(
            fresh_ranked_keys(&key.host, &[ip], &state, 2),
            vec![key.clone()]
        );
        assert!(
            fresh_ranked_keys("daily-cloudcode-pa.googleapis.com", &[ip], &state, 2).is_empty()
        );
        assert!(fresh_ranked_keys(&key.host, &[ip], &state, 20_002).is_empty());
        state.note_used(&key, 2);
        state.region_refusal("event", Some(&key.host), None, 3);
        assert!(fresh_ranked_keys(&key.host, &[ip], &state, 4).is_empty());
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn fallback_keeps_all_seven_nameservers_and_ranking_keeps_each_provider() {
        assert_eq!(fallback_v4().len(), 7);
        let hits = vec![
            RaceResult {
                idx: 0,
                provider: "fixture".into(),
                reply: vec![],
                addrs: vec![v4(142, 250, 1, 1)],
            },
            RaceResult {
                idx: 1,
                provider: "fixture".into(),
                reply: vec![],
                addrs: vec![v4(45, 155, 204, 190)],
            },
            RaceResult {
                idx: 2,
                provider: "fixture".into(),
                reply: vec![],
                addrs: vec![v4(37, 230, 192, 51), v4(45, 155, 204, 190)],
            },
        ];
        assert_eq!(
            collect_substituted(&hits, &[v4(142, 250, 1, 1)], &HashMap::new()),
            vec![v4(45, 155, 204, 190), v4(37, 230, 192, 51)]
        );
    }
    #[test]
    fn passthrough_packets_are_not_cached() {
        let name = "passthrough-regression.invalid".to_string();
        cache_dns_packet(name.clone(), 1, vec![0; 12], "test", Verdict::Passthrough);
        let guard = DNS_PACKET_CACHE.lock().unwrap();
        assert!(guard.as_ref().map_or(true, |m| !m.contains_key(&(name, 1))));
    }

    #[test]
    fn same_slash16_is_passthrough() {
        let cand = [v4(172, 217, 22, 14)];
        let refer = [v4(172, 217, 0, 1)];
        assert_eq!(classify(&cand, &refer, &[]), Verdict::Passthrough);
    }

    #[test]
    fn slower_substitution_wins_over_first_passthrough() {
        let hits = vec![
            RaceResult {
                idx: 0,
                provider: "fixture".into(),
                reply: vec![],
                addrs: vec![v4(142, 250, 1, 1)],
            },
            RaceResult {
                idx: 2,
                provider: "fixture".into(),
                reply: vec![],
                addrs: vec![v4(45, 155, 204, 190)],
            },
        ];
        assert_eq!(pick_winner(&hits, &[v4(142, 250, 1, 1)], 0), Some(1));
    }

    #[test]
    fn only_substitution_is_cached() {
        for (label, verdict) in [
            ("unknown", Verdict::Unknown),
            ("sibling", Verdict::Sibling),
            ("substituted", Verdict::Substituted),
        ] {
            let name = format!("{label}-cache-regression.invalid");
            cache_dns_packet(name.clone(), 1, vec![0; 12], "test", verdict);
            let mut guard = DNS_PACKET_CACHE.lock().unwrap();
            let present = guard
                .as_ref()
                .is_some_and(|m| m.contains_key(&(name.clone(), 1)));
            if let Some(map) = guard.as_mut() {
                map.remove(&(name, 1));
            }
            drop(guard);
            assert_eq!(present, verdict == Verdict::Substituted);
        }
    }

    #[test]
    fn different_from_reference_without_proxy_set_is_substituted() {
        let cand = [v4(87, 228, 47, 204)];
        let refer = [v4(142, 250, 1, 1)];
        assert_eq!(classify(&cand, &refer, &[]), Verdict::Substituted);
    }

    #[test]
    fn known_proxy_ip_is_substituted() {
        let cand = [v4(45, 155, 204, 190)];
        let refer = [v4(142, 250, 1, 1)];
        let proxy = [v4(45, 155, 204, 190)];
        assert_eq!(classify(&cand, &refer, &proxy), Verdict::Substituted);
    }

    #[test]
    fn other_google_edge_with_proxy_knowledge_is_sibling() {
        let cand = [v4(64, 233, 161, 1)];
        let refer = [v4(142, 250, 1, 1)];
        let proxy = [v4(45, 155, 204, 190)];
        assert_eq!(classify(&cand, &refer, &proxy), Verdict::Sibling);
    }
}
