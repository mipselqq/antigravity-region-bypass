use super::terminal::prompt;
use crate::{
    core::endpoint,
    net::{
        self,
        performance::{self, Comparison, Preference, Route, Sample},
    },
};
use std::path::Path;

pub fn run() -> bool {
    match compare() {
        Ok(()) => true,
        Err(error) => {
            eprintln!("Сравнение скорости: {error}");
            false
        }
    }
}

fn compare() -> Result<(), String> {
    println!("\n  СРАВНЕНИЕ СКОРОСТИ ОТВЕТОВ В ANTIGRAVITY");
    println!("  Время измеряется вами в приложении: это не автоматический замер токенов.");
    println!("  Используйте одну модель, одинаковый запрос и новый чат для каждого прогона.");
    println!("  Сеть и VPN должны оставаться одинаковыми. Между маршрутами полностью перезапускайте Antigravity.");
    println!("  Для рекомендации нужны минимум 3 прогона каждого из хотя бы двух маршрутов.");
    let paths = endpoint::settings_paths();
    if paths.is_empty() {
        return Err(
            "Не найден профиль Antigravity. Сначала запустите приложение и включите обход.".into(),
        );
    }
    for (i, path) in paths.iter().enumerate() {
        println!("  {}. {}", i + 1, path.display());
    }
    let index = if paths.len() == 1 {
        0
    } else {
        number("Профиль Antigravity (номер): ", paths.len() as u64)?
            .checked_sub(1)
            .ok_or("Неверный номер")? as usize
    };
    let path = &paths[index];
    endpoint::selected_host(path)?;
    let profile = crate::system::journal::digest(path.to_string_lossy().as_bytes());
    let network = performance::network().ok_or("Не удалось определить сеть")?;
    let mut data = performance::load()?;
    let now = net::route_health::now_ms();
    if data.profile != profile
        || data.network != network
        || now < data.started
        || now - data.started >= 6 * 60 * 60_000
    {
        data = Comparison {
            started: now,
            network,
            profile,
            ..Default::default()
        };
        performance::save(&data)?;
        println!("  Начато новое сравнение для этого профиля и подключения.");
    }
    loop {
        println!("\n  [1] Выбрать маршрут для следующего теста");
        println!("  [2] Внести результат реального запроса");
        println!("  [3] Сравнить результаты и применить рекомендуемый маршрут");
        println!("  [4] Начать заново (другая модель или запрос)");
        println!("  [5] Снять закрепление маршрута");
        println!("  [0] Вернуться");
        let action = prompt("Действие: ");
        if action == "0" {
            return Ok(());
        }
        if performance::network().as_ref() != Some(&data.network) {
            return Err("Подключение изменилось. Откройте сравнение заново; результаты разных сетей не смешиваются.".into());
        }
        let result = match action.as_str() {
            "1" => choose(path, &mut data),
            "2" => record(path, &mut data),
            "3" => recommend(path, &mut data),
            "4" => {
                data.samples.clear();
                data.started = net::route_health::now_ms();
                performance::save(&data)
            }
            "5" => {
                data.preference = None;
                let result = performance::save(&data);
                println!("  Закрепление снято. Текущий endpoint сохранён; недоступный маршрут заменит фоновая проверка.");
                result
            }
            _ => Err("Неверное действие".into()),
        };
        if let Err(error) = result {
            eprintln!("  {error}");
        }
    }
}

fn routes() -> Vec<Route> {
    [
        "cloudcode-pa.googleapis.com",
        "daily-cloudcode-pa.googleapis.com",
    ]
    .into_iter()
    .flat_map(|host| {
        net::rank::candidates_for(host)
            .into_iter()
            .map(move |ip| Route {
                host: host.into(),
                ip,
            })
    })
    .collect()
}
fn choose(path: &Path, data: &mut Comparison) -> Result<(), String> {
    let routes = routes();
    if routes.is_empty() {
        return Err("Сначала включите обход для поиска доступных маршрутов".into());
    }
    for (i, route) in routes.iter().enumerate() {
        println!("  {}. {} через {}", i + 1, route.host, route.ip);
    }
    let index = number("Маршрут (0 — отмена): ", routes.len() as u64)?;
    if index == 0 {
        return Ok(());
    }
    apply(path, data, &routes[index as usize - 1])
}

fn apply(path: &Path, data: &mut Comparison, route: &Route) -> Result<(), String> {
    println!("  Полностью закройте Antigravity перед переключением. После него запустите приложение заново.");
    if prompt("Enter — применить; 0 — отмена: ") == "0" {
        return Ok(());
    }
    let targets: Vec<_> = crate::core::detector::find_installations()
        .iter()
        .flat_map(|root| crate::core::detector::find_targets_in_path(root))
        .map(|t| t.path)
        .collect();
    if !crate::system::file_lock::running_applications(&targets)?.is_empty()
        || !crate::system::file_lock::holders(&targets)?.is_empty()
    {
        return Err(
            "Antigravity ещё работает. Закройте приложение полностью и повторите выбор маршрута."
                .into(),
        );
    }
    if performance::network().as_ref() != Some(&data.network) {
        return Err("Подключение изменилось. Откройте сравнение заново.".into());
    }
    endpoint::selected_host(path)?;
    let _lock = net::configuration_lock()?;
    // A transport check is only a prerequisite, never a speed measurement.
    net::rank::select_for_test(&route.host, route.ip)?;
    endpoint::select_for_test(path, &route.host)?;
    let mut next = data.clone();
    next.preference = Some(Preference {
        route: route.clone(),
        at: net::route_health::now_ms(),
        network: data.network.clone(),
    });
    performance::save(&next)?;
    *data = next;
    println!(
        "  Выбран {} через {}. Запустите Antigravity и выполните тест.",
        route.host, route.ip
    );
    println!(
        "  Измерьте секунды от отправки до первого текста и до полного ответа. Затем выберите [2]."
    );
    println!("  Закрепление действует до 6 часов, пока маршрут доступен и сеть не изменена.");
    Ok(())
}

fn current(path: &Path, data: &Comparison) -> Result<Route, String> {
    let preference = data
        .preference
        .as_ref()
        .ok_or("Сначала выберите маршрут пунктом 1")?;
    if net::route_health::now_ms().saturating_sub(preference.at) >= 6 * 60 * 60_000 {
        return Err("Время закрепления истекло. Выберите маршрут заново".into());
    }
    let route = &preference.route;
    if endpoint::selected_host(path)? != route.host
        || !net::hosts::owned_entries()?
            .iter()
            .any(|(host, ip)| host == &route.host && *ip == route.ip)
    {
        return Err("Endpoint или IP изменился во время теста. Результат не добавлен; выберите маршрут заново.".into());
    }
    Ok(route.clone())
}
fn number(label: &str, max: u64) -> Result<u64, String> {
    prompt(label)
        .parse::<u64>()
        .ok()
        .filter(|n| *n <= max)
        .ok_or("Введите целое число в указанном диапазоне".into())
}
fn seconds(label: &str) -> Result<u64, String> {
    let value = prompt(label)
        .replace(',', ".")
        .parse::<f64>()
        .map_err(|_| "Введите число секунд, например 1.25")?;
    if !value.is_finite() || !(0.001..=3600.0).contains(&value) {
        return Err("Время должно быть от 0.001 до 3600 секунд".into());
    }
    Ok((value * 1000.0).round() as u64)
}
fn record(path: &Path, data: &mut Comparison) -> Result<(), String> {
    let route = current(path, data)?;
    let ok = match prompt("Запрос завершился? 1 — полный ответ, 2 — ошибка/обрыв: ").as_str()
    {
        "1" => true,
        "2" => false,
        _ => return Err("Введите 1 или 2".into()),
    };
    let (first_ms, total_ms, characters) = if ok {
        let first = seconds("До первого текста, секунд: ")?;
        let total = seconds("До полного ответа, секунд (от отправки): ")?;
        if total < first {
            return Err("Полное время не может быть меньше ожидания первого текста".into());
        }
        let characters = number("Число символов ответа (0 — пропустить): ", 1_000_000)? as u32;
        (first, total, characters)
    } else {
        (0, 0, 0)
    };
    let retries = number("Замеченные повторы запроса (0–100): ", 100)? as u32;
    // Recheck after input: automatic recovery may have changed the route meanwhile.
    if current(path, data)? != route || performance::network().as_ref() != Some(&data.network) {
        return Err("Маршрут или подключение изменилось; повторите тест".into());
    }
    let mut next = data.clone();
    next.samples.push(Sample {
        route,
        first_ms,
        total_ms,
        characters,
        retries,
        ok,
    });
    performance::save(&next)?;
    *data = next;
    println!("  Результат сохранён локально. Текст запроса и ответа не сохраняется.");
    Ok(())
}
fn recommend(path: &Path, data: &mut Comparison) -> Result<(), String> {
    for score in performance::scores(&data.samples) {
        let timing = if score.failures == score.count {
            "нет успешных ответов".into()
        } else {
            format!(
                "первый текст {:.2} с; полный ответ {:.2} с",
                score.first_ms as f64 / 1000.0,
                score.total_ms as f64 / 1000.0
            )
        };
        println!(
            "  {} / {}: {} тестов, {} ошибок; {}",
            score.route.host, score.route.ip, score.count, score.failures, timing
        );
        if let Some(speed) = score.chars_per_second {
            println!("    Оценка выдачи текста: {speed} символов/с (не токенов/с)");
        }
    }
    let route = performance::recommendation(&data.samples)
        .ok_or("Нужны хотя бы два маршрута, по 3 теста каждого, и успешные ответы")?;
    println!(
        "  По вашим измерениям рекомендуется {} через {}.",
        route.host, route.ip
    );
    apply(path, data, &route)
}
