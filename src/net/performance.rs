//! Operator-measured application responses, kept separately from transport probes.
//! No prompts, responses, credentials or model API calls are collected here.
use serde::{Deserialize, Serialize};
use std::{fs, net::Ipv4Addr};

const MAX_AGE_MS: u64 = 6 * 60 * 60_000;
const MAX_SAMPLES: usize = 120;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Route {
    pub host: String,
    pub ip: Ipv4Addr,
}
impl Route {
    pub fn valid(&self) -> bool {
        matches!(
            self.host.as_str(),
            "cloudcode-pa.googleapis.com" | "daily-cloudcode-pa.googleapis.com"
        ) && !self.ip.is_unspecified()
            && !self.ip.is_multicast()
            && !self.ip.is_loopback()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Preference {
    pub route: Route,
    pub at: u64,
    pub network: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sample {
    pub route: Route,
    pub first_ms: u64,
    pub total_ms: u64,
    pub characters: u32,
    pub retries: u32,
    pub ok: bool,
}
impl Sample {
    fn valid(&self) -> bool {
        self.route.valid()
            && self.retries <= 100
            && self.characters <= 1_000_000
            && ((!self.ok && self.first_ms == 0 && self.total_ms == 0 && self.characters == 0)
                || (self.ok
                    && self.first_ms > 0
                    && self.total_ms >= self.first_ms
                    && self.total_ms <= 3_600_000))
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Comparison {
    pub started: u64,
    pub network: String,
    pub profile: String,
    pub samples: Vec<Sample>,
    pub preference: Option<Preference>,
}
pub fn path() -> std::path::PathBuf {
    super::config::directory().join("response-comparison.json")
}
pub fn network() -> Option<String> {
    let egress = super::egress::detect()?;
    Some(crate::system::journal::digest(
        format!(
            "{}|{:?}|{}",
            egress.if_index, egress.gateway, egress.vpn_active
        )
        .as_bytes(),
    ))
}
pub fn load() -> Result<Comparison, String> {
    match fs::read(path()) {
        Ok(bytes) if bytes.len() <= 128 * 1024 => {
            let value: Comparison = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            if value.samples.len() > MAX_SAMPLES
                || value.samples.iter().any(|s| !s.valid())
                || value.preference.as_ref().is_some_and(|p| !p.route.valid())
            {
                return Err("Повреждены результаты сравнения".into());
            }
            Ok(value)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Comparison::default()),
        Err(e) => Err(e.to_string()),
        _ => Err("Файл сравнения слишком большой".into()),
    }
}
pub fn save(value: &Comparison) -> Result<(), String> {
    if value.samples.len() > MAX_SAMPLES || value.samples.iter().any(|s| !s.valid()) {
        return Err(
            "Некорректные результаты или достигнут лимит 120 измерений; начните новое сравнение"
                .into(),
        );
    }
    fs::create_dir_all(super::config::directory()).map_err(|e| e.to_string())?;
    crate::system::fs_utils::robust_write_file(
        &path(),
        &serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?,
    )?;
    super::config::inherit_directory_owner(&path())
}
pub fn active_preference() -> Option<Preference> {
    let preference = load().ok()?.preference?;
    let now = super::route_health::now_ms();
    if now < preference.at || now - preference.at >= MAX_AGE_MS || network()? != preference.network
    {
        return None;
    }
    let key =
        super::route_health::Key::ip(&preference.route.host, (preference.route.ip, 443).into());
    super::route_health::store()
        .snapshot()
        .ok()?
        .usable(&key, now, 120_000)
        .then_some(preference)
}
pub fn prioritize(ranked: &mut [super::rank::RankedHost]) {
    if let Some(preference) = active_preference() {
        if let Some(row) = ranked.iter_mut().find(|h| h.host == preference.route.host) {
            if let Some(pos) = row
                .ips
                .iter()
                .position(|(ip, _)| *ip == preference.route.ip)
            {
                let selected = row.ips.remove(pos);
                row.ips.insert(0, selected);
            }
        }
    }
}

pub struct Score {
    pub route: Route,
    pub count: usize,
    pub failures: usize,
    pub retry_sum: u64,
    pub first_ms: u64,
    pub total_ms: u64,
    pub chars_per_second: Option<u64>,
}
fn median(mut values: Vec<u64>) -> u64 {
    values.sort_unstable();
    if values.is_empty() {
        return u64::MAX;
    }
    let mid = values.len() / 2;
    if values.len() % 2 == 0 {
        values[mid - 1] + (values[mid] - values[mid - 1]) / 2
    } else {
        values[mid]
    }
}
pub fn scores(samples: &[Sample]) -> Vec<Score> {
    let mut routes = Vec::new();
    for sample in samples.iter().filter(|s| s.valid()) {
        if !routes.contains(&sample.route) {
            routes.push(sample.route.clone());
        }
    }
    routes
        .into_iter()
        .map(|route| {
            let rows: Vec<_> = samples
                .iter()
                .filter(|s| s.route == route && s.valid())
                .collect();
            let good: Vec<_> = rows.iter().filter(|s| s.ok).collect();
            let speeds: Vec<_> = good
                .iter()
                .filter(|s| s.characters > 0 && s.total_ms > s.first_ms)
                .map(|s| u64::from(s.characters) * 1000 / (s.total_ms - s.first_ms))
                .collect();
            Score {
                route,
                count: rows.len(),
                failures: rows.len() - good.len(),
                retry_sum: rows.iter().map(|s| u64::from(s.retries)).sum(),
                first_ms: median(good.iter().map(|s| s.first_ms).collect()),
                total_ms: median(good.iter().map(|s| s.total_ms).collect()),
                chars_per_second: (!speeds.is_empty()).then(|| median(speeds)),
            }
        })
        .collect()
}
/// Compare only sufficiently sampled alternatives in the same controlled session.
/// Reliability comes first, then retries, then first response and completion.
pub fn recommendation(samples: &[Sample]) -> Option<Route> {
    let mut scores = scores(samples);
    if scores.len() < 2 || scores.iter().any(|s| s.count < 3) {
        return None;
    }
    scores.sort_by(|a, b| {
        (a.failures * b.count)
            .cmp(&(b.failures * a.count))
            .then((a.retry_sum * b.count as u64).cmp(&(b.retry_sum * a.count as u64)))
            .then(a.first_ms.cmp(&b.first_ms))
            .then(a.total_ms.cmp(&b.total_ms))
    });
    scores
        .first()
        .filter(|s| s.failures < s.count)
        .map(|s| s.route.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(ip: u8, first_ms: u64) -> Sample {
        Sample {
            route: Route {
                host: "cloudcode-pa.googleapis.com".into(),
                ip: Ipv4Addr::new(192, 0, 2, ip),
            },
            first_ms,
            total_ms: first_ms + 2000,
            characters: 400,
            retries: 0,
            ok: true,
        }
    }
    #[test]
    fn actual_response_medians_select_route_and_do_not_reward_failures() {
        let mut rows = vec![
            sample(1, 100),
            sample(1, 10_000),
            sample(1, 100),
            sample(2, 300),
            sample(2, 300),
            sample(2, 300),
        ];
        assert_eq!(recommendation(&rows), Some(rows[0].route.clone()));
        assert_eq!(scores(&rows)[0].chars_per_second, Some(200));
        rows[0].ok = false;
        rows[0].first_ms = 0;
        rows[0].total_ms = 0;
        rows[0].characters = 0;
        assert_eq!(recommendation(&rows), Some(rows[3].route.clone()));
        assert!(recommendation(&rows[..5]).is_none());
    }
    #[test]
    fn malformed_timings_are_rejected_and_errors_are_not_fast_successes() {
        let mut row = sample(1, 100);
        row.total_ms = 50;
        assert!(!row.valid());
        row = sample(1, 100);
        row.ok = false;
        assert!(!row.valid());
        row.first_ms = 0;
        row.total_ms = 0;
        row.characters = 0;
        assert!(row.valid());
        assert_eq!(scores(&[row])[0].first_ms, u64::MAX);
    }
}
