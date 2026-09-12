//! RFC 8484 transport using reqwest's HTTP/2 implementation and certificate validation.
use super::{client, config::DohProvider};
use reqwest::blocking::Client;
use std::{
    collections::HashMap,
    io::Read,
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

pub const TIMEOUT: Duration = Duration::from_millis(2500);

fn source_address(if_index: u32) -> Result<Option<IpAddr>, String> {
    if if_index == 0 {
        return Ok(None);
    }
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    super::socket::bind_socket_to_interface(&socket, if_index)?;
    // UDP connect selects a source address; it sends no DNS packet.
    socket.connect("8.8.8.8:443").map_err(|e| e.to_string())?;
    let ip = socket.local_addr().map_err(|e| e.to_string())?.ip();
    if ip.is_unspecified() {
        Err("DoH: исходящий адрес не определён".into())
    } else {
        Ok(Some(ip))
    }
}

fn http_client(provider: &DohProvider, source: Option<IpAddr>) -> Result<Client, String> {
    static CLIENTS: OnceLock<Mutex<HashMap<String, Client>>> = OnceLock::new();
    let key = format!("{}|{:?}|{:?}", provider.url, provider.bootstrap, source);
    let mut clients = CLIENTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|e| e.to_string())?;
    if let Some(client) = clients.get(&key) {
        return Ok(client.clone());
    }
    let url = reqwest::Url::parse(&provider.url).map_err(|e| e.to_string())?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err("DoH требует HTTPS без credentials".into());
    }
    let host = url.host_str().ok_or("DoH: отсутствует hostname")?;
    let port = url.port_or_known_default().ok_or("DoH: отсутствует порт")?;
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(TIMEOUT)
        .timeout(TIMEOUT)
        .pool_idle_timeout(Duration::from_secs(20));
    if let Some(ip) = source {
        builder = builder.local_address(ip);
    }
    if !provider.bootstrap.is_empty() {
        let addresses: Vec<_> = provider
            .bootstrap
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();
        builder = builder.resolve_to_addrs(host, &addresses);
    }
    let client = builder
        .build()
        .map_err(|e| format!("DoH client: {}", e.without_url()))?;
    if clients.len() >= 32 {
        clients.clear();
    }
    clients.insert(key, client.clone());
    Ok(client)
}

fn exchange(client: &Client, url: &str, query: &[u8]) -> Result<Vec<u8>, String> {
    let response = client
        .post(url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(query.to_vec())
        .send()
        .map_err(|e| format!("DoH transport: {}", e.without_url()))?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mut body = Vec::new();
    response
        .take(65_536)
        .read_to_end(&mut body)
        .map_err(|e| format!("DoH body: {e}"))?;
    validate_answer(query, status, &content_type, &body)?;
    Ok(body)
}

pub fn query(provider: &DohProvider, query: &[u8], if_index: u32) -> Result<Vec<u8>, String> {
    let source = source_address(if_index)?;
    let candidates: Vec<_> = if provider.bootstrap.is_empty() {
        vec![provider.clone()]
    } else {
        provider
            .bootstrap
            .iter()
            .map(|ip| {
                let mut candidate = provider.clone();
                candidate.bootstrap = vec![*ip];
                candidate
            })
            .collect()
    };
    let (tx, rx) = std::sync::mpsc::channel();
    // Race complete DNS exchanges, not TCP connects: a silent TLS peer cannot consume the other address's budget.
    for candidate in candidates {
        let tx = tx.clone();
        let query = query.to_vec();
        std::thread::spawn(move || {
            let result = http_client(&candidate, source)
                .and_then(|client| exchange(&client, &candidate.url, &query));
            let _ = tx.send(result);
        });
    }
    drop(tx);
    let deadline = Instant::now() + TIMEOUT + Duration::from_millis(100);
    let mut error = "DoH: deadline expired".to_string();
    while let Ok(result) = rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        match result {
            Ok(answer) => return Ok(answer),
            Err(e) => error = e,
        }
    }
    Err(error)
}

fn validate_answer(
    query: &[u8],
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    if status != 200 {
        return Err(format!("DoH HTTP {status}"));
    }
    if !content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/dns-message")
    {
        return Err("DoH: неверный Content-Type".into());
    }
    if body.len() > 65_535 || !client::response_matches(query, body) {
        return Err("DoH: ответ не соответствует DNS-запросу".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn doh_posts_wire_dns_over_verified_tls_and_checks_the_binary_response() {
        let query = client::build_query("example.test", 71);
        let answer = client::nodata_response(&query);
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", answer.len()).into_bytes();
        response.extend_from_slice(&answer);
        let (addr, server) = super::super::health::tests::server(response, Duration::ZERO);
        let cert =
            reqwest::Certificate::from_der(&super::super::health::tests::identity().0).unwrap();
        let client = Client::builder()
            .no_proxy()
            .add_root_certificate(cert)
            .resolve("localhost", addr)
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let result = exchange(
            &client,
            &format!("https://localhost:{}/dns-query", addr.port()),
            &query,
        );
        assert_eq!(result.unwrap(), answer);
        server.join().unwrap();
    }
    #[test]
    fn rejects_http_error_wrong_question_transaction_and_oversized_payload() {
        let query = client::build_query("example.test", 42);
        let reply = client::nodata_response(&query);
        assert!(validate_answer(&query, 200, "application/dns-message", &reply).is_ok());
        for (status, mime) in [(503, "application/dns-message"), (200, "text/html")] {
            assert!(validate_answer(&query, status, mime, &reply).is_err());
        }
        let mut wrong = reply.clone();
        wrong[1] ^= 1;
        assert!(validate_answer(&query, 200, "application/dns-message", &wrong).is_err());
        let other = client::nodata_response(&client::build_query("other.test", 42));
        assert!(validate_answer(&query, 200, "application/dns-message", &other).is_err());
        let mut big = reply;
        big.resize(65_536, 0);
        assert!(validate_answer(&query, 200, "application/dns-message", &big).is_err());
    }
}
