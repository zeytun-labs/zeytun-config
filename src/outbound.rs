use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Minimal sing-box outbound shape (JSON-compatible).
#[derive(Debug, Clone, Serialize)]
pub struct Outbound {
    #[serde(rename = "type")]
    pub type_name: String,
    pub tag: String,
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
}

impl Outbound {
    pub fn new(type_name: impl Into<String>, tag: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            tag: tag.into(),
            fields: BTreeMap::new(),
        }
    }

    pub fn set<T: Serialize>(&mut self, key: &str, value: T) {
        if let Ok(v) = serde_json::to_value(value) {
            if !v.is_null() {
                self.fields.insert(key.to_string(), v);
            }
        }
    }

    pub fn set_opt<T: Serialize>(&mut self, key: &str, value: Option<T>) {
        if let Some(v) = value {
            self.set(key, v);
        }
    }

    pub fn set_detour(&mut self, detour: Option<String>) {
        self.set_opt("detour", detour);
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Options {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<Outbound>,
}

pub fn tls_object(
    enabled: bool,
    server_name: Option<String>,
    insecure: bool,
    disable_sni: bool,
    alpn: Option<Vec<String>>,
    fingerprint: Option<String>,
    reality: Option<(String, String)>, // pbk, sid
) -> Value {
    let mut o = json!({ "enabled": enabled });
    if let Some(sni) = server_name {
        if !sni.is_empty() {
            o["server_name"] = json!(sni);
        }
    }
    if insecure {
        o["insecure"] = json!(true);
    }
    if disable_sni {
        o["disable_sni"] = json!(true);
    }
    if let Some(alpn) = alpn {
        if !alpn.is_empty() {
            o["alpn"] = json!(alpn);
        }
    }
    if let Some(fp) = fingerprint {
        if !fp.is_empty() {
            o["utls"] = json!({ "enabled": true, "fingerprint": fp });
        }
    }
    if let Some((pbk, sid)) = reality {
        o["reality"] = json!({
            "enabled": true,
            "public_key": pbk,
            "short_id": sid,
        });
    }
    o
}
