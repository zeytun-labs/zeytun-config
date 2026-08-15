use crate::error::{Error, Result};
use base64::{engine::general_purpose, Engine as _};
use percent_encoding::percent_decode_str;
use serde_json::Value;

pub fn decode_component(value: &str) -> String {
    percent_decode_str(value).decode_utf8_lossy().into_owned()
}

pub fn decode_base64_to_string(value: &str) -> Result<String> {
    let normalized = value.trim().trim_end_matches('=');
    let padded = match normalized.len() % 4 {
        0 => normalized.to_string(),
        2 => format!("{normalized}=="),
        3 => format!("{normalized}="),
        _ => normalized.to_string(),
    };

    general_purpose::STANDARD
        .decode(&padded)
        .or_else(|_| general_purpose::URL_SAFE.decode(&padded))
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(normalized))
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(normalized))
        .map_err(|err| Error::Base64(err.to_string()))
        .and_then(|bytes| String::from_utf8(bytes).map_err(|err| Error::Utf8(err.to_string())))
}

/// Decode whole blob if it looks like base64; otherwise return original.
pub fn decode_base64_if_needed(input: &str) -> String {
    let t = input.trim();
    if t.is_empty() || t.contains("://") || t.contains('\n') {
        return t.to_string();
    }
    decode_base64_to_string(t).unwrap_or_else(|_| t.to_string())
}

pub fn split_fragment(value: &str) -> (&str, Option<String>) {
    match value.split_once('#') {
        Some((main, fragment)) => (main, Some(decode_component(fragment))),
        None => (value, None),
    }
}

pub fn split_query(value: &str) -> (&str, Option<&str>) {
    value
        .split_once('?')
        .map(|(main, query)| (main, Some(query)))
        .unwrap_or((value, None))
}

pub fn parse_host_port(value: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = value.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let port = rest[(end + 1)..]
                .strip_prefix(':')
                .and_then(|port| port.parse().ok())
                .unwrap_or(default_port);
            return (host.to_string(), port);
        }
    }

    if let Some((host, port)) = value.rsplit_once(':') {
        if let Ok(port) = port.parse() {
            return (host.to_string(), port);
        }
    }

    (value.to_string(), default_port)
}

pub fn default_port_for_scheme(scheme: &str) -> u16 {
    match scheme {
        "http" | "phttp" => 80,
        "socks" | "socks4" | "socks5" => 1080,
        _ => 443,
    }
}

pub fn json_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(|value| match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    })
}

pub fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    query?.split('&').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        name.eq_ignore_ascii_case(key)
            .then(|| decode_component(value))
            .filter(|value| !value.is_empty())
    })
}

pub fn truthy(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

pub fn normalize_key(s: &str) -> String {
    s.to_ascii_lowercase()
        .replace(['_', '-'], "")
        .replace(' ', "")
}

/// Expand multi-line / comma-separated / nested base64 subscription text.
pub fn expand_configs(input: &str) -> Vec<String> {
    let decoded = decode_base64_if_needed(input);
    let mut out = Vec::new();
    for line in decoded.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        // nested base64 line without scheme
        if !line.contains("://") {
            if let Ok(inner) = decode_base64_to_string(line) {
                out.extend(expand_configs(&inner));
                continue;
            }
        }
        out.push(line.to_string());
    }
    out
}
