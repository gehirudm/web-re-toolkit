use base64::Engine;
use base64::engine::general_purpose::STANDARD;

const OPENER: &str = "{\"sensor_data\":\"";
const FIELD: &str = "sensor_data=";
const SEPARATOR: &str = "&&&";

pub fn extract(body: &str) -> Option<String> {
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body)
        && let Some(found) = parsed.get("sensor_data").and_then(|value| value.as_str())
    {
        return Some(found.to_string());
    }

    let start = body.find(OPENER)?;
    let from = start + OPENER.len();
    let end = body.rfind("\"}");

    match end {
        Some(end) if end > from => Some(body[from..end].to_string()),
        _ => Some(body[from..].to_string()),
    }
}

pub fn wrap(payload: &str) -> String {
    let payload = retimed(payload);
    serde_json::json!({ "sensor_data": payload }).to_string()
}

fn retimed(payload: &str) -> String {
    let mut parts: Vec<String> = payload.split(';').map(str::to_string).collect();
    if parts.len() < 8 {
        return payload.to_string();
    }

    // Field 5 is the per-load hash: fixed for a whole session, fresh for every
    // load. Derive the session constants from it.
    let fingerprint = parts
        .get(5)
        .map(|value| {
            value.bytes().fold(0u64, |acc, byte| {
                acc.wrapping_mul(1099511628211).wrapping_add(u64::from(byte))
            })
        })
        .unwrap_or(1)
        | 1;

    // A sensor payload is only valid once, and an edge scores what it contains.
    // The fields that matter here: 4 is the client id (the site keeps it fixed
    // for the whole session), 6 is the timing tuple, whose last entry is a
    // running uptime in milliseconds and whose second to last entry is a small
    // count. wred's sandbox emits a stub id and a zeroed tuple, which is not a
    // physical client, so the collection endpoint answers without promoting the
    // cookie. Rewrite those fields per the captured shape and refresh the
    // volatile ones on every wrap so no payload is ever posted twice.
    let mut state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|delta| delta.as_nanos() as u64)
        .unwrap_or(1)
        ^ fingerprint
        | 1;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    if let Ok(list) = std::env::var("WRE_AKAMAI_TIMINGS") {
        parts[6] = list;
    } else if parts[6].contains(',') {
        let mut timings: Vec<i64> = parts[6]
            .split(',')
            .map(|value| value.parse::<i64>().unwrap_or(0))
            .collect();
        let last = timings.len().saturating_sub(1);
        let uptime = 1_200 + (fingerprint % 2_400) as i64 + (next() % 180) as i64;

        for (index, timing) in timings.iter_mut().enumerate() {
            if index == last {
                *timing = uptime;
            } else if index + 1 == last && *timing <= 0 {
                *timing = (6 + next() % 23) as i64;
            } else if *timing > 1 {
                *timing += (next() % 63) as i64;
            }
        }

        parts[6] = timings
            .iter()
            .map(i64::to_string)
            .collect::<Vec<String>>()
            .join(",");
    }

    parts.join(";")
}


pub fn payload_of(header: &str) -> Option<String> {
    let field = header.split(SEPARATOR).find(|part| part.starts_with(FIELD))?;
    let encoded = field.trim_start_matches(FIELD);
    let decoded = STANDARD.decode(encoded).ok()?;

    String::from_utf8(decoded).ok()
}

pub fn with_payload(header: &str, payload: &str) -> String {
    let mut fields: Vec<String> = header
        .split(SEPARATOR)
        .filter(|part| !part.starts_with(FIELD))
        .map(str::to_string)
        .collect();

    fields.push(format!("{FIELD}{}", STANDARD.encode(payload.as_bytes())));
    fields.join(SEPARATOR)
}

pub fn looks_like_payload(body: &str) -> bool {
    body.contains("sensor_data")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_payload_comes_out_of_a_post_body() {
        let body = r#"{"sensor_data":"7a74G7m23Vrp0o5c9XJ~1~abc"}"#;
        assert_eq!(extract(body).as_deref(), Some("7a74G7m23Vrp0o5c9XJ~1~abc"));
        assert!(looks_like_payload(body));
    }

    #[test]
    fn a_payload_with_a_quote_in_it_still_comes_out() {
        let body = "{\"sensor_data\":\"abc\\\"def\"}";
        assert_eq!(extract(body).as_deref(), Some("abc\"def"));
    }

    #[test]
    fn wrapping_round_trips() {
        let payload = "7a74G7m23Vrp";
        assert_eq!(extract(&wrap(payload)).as_deref(), Some(payload));
    }

    #[test]
    fn the_telemetry_header_carries_the_payload_in_base64() {
        let header = "a=1&&&b=2&&&sensor_data=N2E3NEc3bTIzVnJw";

        assert_eq!(payload_of(header).as_deref(), Some("7a74G7m23Vrp"));

        let replaced = with_payload(header, "garbage");
        assert_eq!(replaced, "a=1&&&b=2&&&sensor_data=Z2FyYmFnZQ==");
        assert_eq!(payload_of(&replaced).as_deref(), Some("garbage"));
    }
}
