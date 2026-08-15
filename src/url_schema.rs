use crate::error::{Error, Result};
use crate::util::{
    decode_base64_to_string, decode_component, default_port_for_scheme, normalize_key,
};
use std::collections::BTreeMap;
use url::Url;

#[derive(Debug, Clone)]
pub struct UrlSchema {
    pub scheme: String,
    pub username: String,
    pub password: String,
    pub hostname: String,
    pub port: u16,
    pub name: String,
    /// Keys normalized: lowercased, `-`/`_`/` ` stripped (ray2sing style).
    pub params: BTreeMap<String, String>,
}

impl UrlSchema {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.params.get(&normalize_key(key)).map(String::as_str)
    }

    pub fn get_or<'a>(&'a self, default: &'a str, keys: &[&str]) -> &'a str {
        for k in keys {
            if let Some(v) = self.get(k) {
                if !v.is_empty() {
                    return v;
                }
            }
        }
        default
    }
}

pub fn parse_url(input: &str, default_port: u16) -> Result<UrlSchema> {
    let parsed = Url::parse(input).map_err(|e| Error::InvalidUrl(e.to_string()))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    let port = parsed.port().unwrap_or_else(|| {
        if default_port != 0 {
            default_port
        } else {
            default_port_for_scheme(&scheme)
        }
    });
    let hostname = parsed.host_str().ok_or(Error::MissingHost)?.to_string();

    let mut username = decode_component(parsed.username());
    let mut password = parsed.password().map(decode_component).unwrap_or_default();

    // base64 userinfo method:password (ss / some links)
    if !username.is_empty() && password.is_empty() {
        if let Ok(user_info) = decode_base64_to_string(&username) {
            if let Some((u, p)) = user_info.split_once(':') {
                username = u.to_string();
                password = p.to_string();
            }
        }
    }

    let name = parsed
        .fragment()
        .map(decode_component)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| hostname.clone());

    let mut params = BTreeMap::new();
    for (k, v) in parsed.query_pairs() {
        let key = normalize_key(&k);
        let val = v.into_owned();
        params
            .entry(key)
            .and_modify(|existing: &mut String| {
                existing.push(',');
                existing.push_str(&val);
            })
            .or_insert(val);
    }

    Ok(UrlSchema {
        scheme,
        username,
        password,
        hostname,
        port,
        name,
        params,
    })
}
