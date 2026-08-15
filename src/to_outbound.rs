use crate::node::{DownloadSettings, ShareProtocol, ShareProxy, Tls, Transport};
use crate::outbound::{tls_object, Outbound};
use serde_json::{json, Value};

pub fn share_to_outbound(node: &ShareProxy) -> Outbound {
    let mut out = Outbound::new(node.protocol.type_name(), node.name.clone());
    out.set("server", &node.address);
    out.set("server_port", node.port);
    if let Some(d) = &node.detour {
        out.set("detour", d);
    }

    match &node.protocol {
        ShareProtocol::Vless(v) => {
            out.set("uuid", &v.uuid);
            if let Some(f) = &v.flow {
                if !f.is_empty() {
                    out.set("flow", f);
                }
            }
            if let Some(pe) = &v.packet_encoding {
                out.set("packet_encoding", pe);
            }
            if let Some(tls) = &v.tls {
                out.set("tls", tls_to_json(tls));
            }
            if let Some(tr) = transport_to_json(v.network.as_str(), v.transport.as_ref()) {
                out.set("transport", tr);
            }
        }
        ShareProtocol::Vmess(v) => {
            out.set("uuid", &v.uuid);
            out.set("security", &v.security);
            out.set("alter_id", v.alter_id);
            if let Some(pe) = &v.packet_encoding {
                out.set("packet_encoding", pe);
            }
            if let Some(tls) = &v.tls {
                out.set("tls", tls_to_json(tls));
            }
            if let Some(tr) = transport_to_json(v.network.as_str(), v.transport.as_ref()) {
                out.set("transport", tr);
            }
        }
        ShareProtocol::Trojan(t) => {
            out.set("password", &t.password);
            if let Some(tls) = &t.tls {
                out.set("tls", tls_to_json(tls));
            }
            if let Some(tr) = transport_to_json(t.network.as_str(), t.transport.as_ref()) {
                out.set("transport", tr);
            }
        }
        ShareProtocol::Shadowsocks(s) => {
            out.set("method", &s.method);
            out.set("password", &s.password);
            if let Some(p) = &s.plugin {
                out.set("plugin", p);
            }
            if let Some(o) = &s.plugin_opts {
                out.set("plugin_opts", o);
            }
        }
        ShareProtocol::Hysteria2(h) => {
            out.set("password", &h.password);
            if h.up_mbps > 0 {
                out.set("up_mbps", h.up_mbps);
            }
            if h.down_mbps > 0 {
                out.set("down_mbps", h.down_mbps);
            }
            if let Some(obfs) = &h.obfs {
                out.set(
                    "obfs",
                    json!({
                        "type": obfs,
                        "password": h.obfs_password.clone().unwrap_or_default(),
                    }),
                );
            }
            out.set("tls", tls_to_json(&h.tls));
        }
        ShareProtocol::Tuic(t) => {
            out.set("uuid", &t.uuid);
            out.set("password", &t.password);
            out.set("congestion_control", &t.congestion_control);
            out.set("udp_relay_mode", &t.udp_relay_mode);
            out.set("tls", tls_to_json(&t.tls));
        }
        ShareProtocol::Socks(s) => {
            if !s.username.is_empty() {
                out.set("username", &s.username);
            }
            if !s.password.is_empty() {
                out.set("password", &s.password);
            }
            out.set("version", s.version.to_string());
        }
        ShareProtocol::Http(h) => {
            if !h.username.is_empty() {
                out.set("username", &h.username);
            }
            if !h.password.is_empty() {
                out.set("password", &h.password);
            }
            if let Some(p) = &h.path {
                out.set("path", p);
            }
            if let Some(tls) = &h.tls {
                out.set("tls", tls_to_json(tls));
            }
        }
    }
    out
}

fn tls_to_json(tls: &Tls) -> Value {
    let reality = match (&tls.reality_pbk, &tls.reality_sid) {
        (Some(pbk), sid) if !pbk.is_empty() => Some((pbk.clone(), sid.clone().unwrap_or_default())),
        _ => None,
    };
    tls_object(
        tls.enabled,
        tls.sni.clone(),
        tls.allow_insecure,
        tls.disable_sni,
        tls.alpn.clone(),
        tls.fingerprint.clone(),
        reality,
    )
}

/// Emit sing-box `transport` object for a network + optional knobs.
/// Shared by CLI convert and app compiler (deserialize into typed core models).
pub fn transport_to_json(network: &str, transport: Option<&Transport>) -> Option<Value> {
    let net = network.to_ascii_lowercase();
    let net = match net.as_str() {
        "websocket" => "ws",
        "http-upgrade" => "httpupgrade",
        "splithttp" | "split-http" | "split_http" | "xray-http" | "xray_http" => "xhttp",
        other => other,
    };
    if net == "tcp" || net.is_empty() {
        return None;
    }
    let t = transport.cloned().unwrap_or_default();
    let mut v = json!({ "type": net });
    match net {
        "ws" => {
            if let Some(p) = &t.path {
                v["path"] = json!(p);
            }
            if let Some(h) = &t.headers {
                v["headers"] = json!(h);
            } else if let Some(host) = &t.host {
                v["headers"] = json!({ "Host": host });
            }
            if let Some(ed) = t.max_early_data {
                v["max_early_data"] = json!(ed);
            }
            if let Some(name) = &t.early_data_header_name {
                if !name.is_empty() {
                    v["early_data_header_name"] = json!(name);
                }
            }
        }
        "httpupgrade" => {
            if let Some(p) = &t.path {
                v["path"] = json!(p);
            }
            if let Some(host) = &t.host {
                v["host"] = json!(host);
            }
            if let Some(h) = &t.headers {
                v["headers"] = json!(h);
            }
        }
        "http" => {
            if let Some(host) = &t.host {
                v["host"] = json!([host]);
            }
            v["path"] = json!(t.path.as_deref().unwrap_or("/"));
            if let Some(m) = &t.method {
                if !m.is_empty() {
                    v["method"] = json!(m);
                }
            }
            if let Some(h) = &t.headers {
                v["headers"] = json!(h);
            }
        }
        "grpc" => {
            let sn = t
                .service_name
                .clone()
                .or(t.path.clone())
                .unwrap_or_default();
            v["service_name"] = json!(sn);
        }
        "quic" => {}
        "xhttp" => {
            v["mode"] = json!(t.mode.as_deref().unwrap_or("auto"));
            if let Some(h) = &t.host {
                v["host"] = json!(h);
            }
            if let Some(p) = &t.path {
                v["path"] = json!(p);
            }
            if let Some(h) = &t.headers {
                v["headers"] = json!(h);
            }
            set_opt_str(&mut v, "xPaddingBytes", t.x_padding_bytes.as_ref());
            set_opt_str(
                &mut v,
                "scMaxEachPostBytes",
                t.sc_max_each_post_bytes.as_ref(),
            );
            set_opt_str(
                &mut v,
                "scMinPostsIntervalMs",
                t.sc_min_posts_interval_ms.as_ref(),
            );
            if let Some(b) = t.no_grpc_header {
                v["noGRPCHeader"] = json!(b);
            }
            if let Some(b) = t.no_sse_header {
                v["noSSEHeader"] = json!(b);
            }
            if let Some(b) = t.x_padding_obfs_mode {
                v["xPaddingObfsMode"] = json!(b);
            }
            set_opt_str(&mut v, "xPaddingKey", t.x_padding_key.as_ref());
            set_opt_str(&mut v, "xPaddingHeader", t.x_padding_header.as_ref());
            set_opt_str(&mut v, "xPaddingPlacement", t.x_padding_placement.as_ref());
            set_opt_str(&mut v, "xPaddingMethod", t.x_padding_method.as_ref());
            set_opt_str(&mut v, "uplinkHTTPMethod", t.uplink_http_method.as_ref());
            set_opt_str(
                &mut v,
                "sessionIDPlacement",
                t.session_id_placement.as_ref(),
            );
            set_opt_str(&mut v, "sessionIDKey", t.session_id_key.as_ref());
            set_opt_str(&mut v, "seqPlacement", t.seq_placement.as_ref());
            set_opt_str(&mut v, "seqKey", t.seq_key.as_ref());
            set_opt_str(
                &mut v,
                "uplinkDataPlacement",
                t.uplink_data_placement.as_ref(),
            );
            set_opt_str(&mut v, "uplinkDataKey", t.uplink_data_key.as_ref());
            set_opt_str(&mut v, "uplinkChunkSize", t.uplink_chunk_size.as_ref());
            set_opt_str(&mut v, "sessionIDTable", t.session_id_table.as_ref());
            set_opt_str(&mut v, "sessionIDLength", t.session_id_length.as_ref());
            if let Some(xmux) = xmux_to_json(
                t.xmux_max_concurrency.as_ref(),
                t.xmux_max_connections.as_ref(),
                t.xmux_c_max_reuse_times.as_ref(),
                t.xmux_h_max_request_times.as_ref(),
                t.xmux_h_max_reusable_secs.as_ref(),
                t.xmux_h_keep_alive_period,
            ) {
                v["xmux"] = xmux;
            }
            if let Some(dl) = &t.download {
                v["downloadSettings"] = download_to_json(dl);
            }
        }
        _ => {
            if let Some(p) = &t.path {
                v["path"] = json!(p);
            }
            if let Some(h) = &t.host {
                v["host"] = json!(h);
            }
        }
    }
    Some(v)
}

fn set_opt_str(v: &mut Value, key: &str, val: Option<&String>) {
    if let Some(s) = val {
        if !s.is_empty() {
            v[key] = json!(s);
        }
    }
}

fn xmux_to_json(
    max_concurrency: Option<&String>,
    max_connections: Option<&String>,
    c_max_reuse_times: Option<&String>,
    h_max_request_times: Option<&String>,
    h_max_reusable_secs: Option<&String>,
    h_keep_alive_period: Option<i64>,
) -> Option<Value> {
    if max_concurrency.is_none()
        && max_connections.is_none()
        && c_max_reuse_times.is_none()
        && h_max_request_times.is_none()
        && h_max_reusable_secs.is_none()
        && h_keep_alive_period.is_none()
    {
        return None;
    }
    let mut xmux = json!({});
    set_opt_str(&mut xmux, "maxConcurrency", max_concurrency);
    set_opt_str(&mut xmux, "maxConnections", max_connections);
    set_opt_str(&mut xmux, "cMaxReuseTimes", c_max_reuse_times);
    set_opt_str(&mut xmux, "hMaxRequestTimes", h_max_request_times);
    set_opt_str(&mut xmux, "hMaxReusableSecs", h_max_reusable_secs);
    if let Some(p) = h_keep_alive_period {
        xmux["hKeepAlivePeriod"] = json!(p);
    }
    Some(xmux)
}

fn download_to_json(d: &DownloadSettings) -> Value {
    let mut v = json!({});
    if let Some(addr) = &d.address {
        if !addr.is_empty() {
            v["server"] = json!(addr);
        }
    }
    if let Some(port) = d.port {
        if port > 0 {
            v["server_port"] = json!(port);
        }
    }
    set_opt_str(&mut v, "path", d.path.as_ref());
    set_opt_str(&mut v, "host", d.host.as_ref());
    set_opt_str(&mut v, "detour", d.detour.as_ref());
    set_opt_str(&mut v, "xPaddingBytes", d.x_padding_bytes.as_ref());
    set_opt_str(
        &mut v,
        "scMaxEachPostBytes",
        d.sc_max_each_post_bytes.as_ref(),
    );
    set_opt_str(
        &mut v,
        "scMinPostsIntervalMs",
        d.sc_min_posts_interval_ms.as_ref(),
    );
    if let Some(b) = d.no_grpc_header {
        v["noGRPCHeader"] = json!(b);
    }
    if let Some(b) = d.no_sse_header {
        v["noSSEHeader"] = json!(b);
    }
    if let Some(xmux) = xmux_to_json(
        d.xmux_max_concurrency.as_ref(),
        d.xmux_max_connections.as_ref(),
        d.xmux_c_max_reuse_times.as_ref(),
        d.xmux_h_max_request_times.as_ref(),
        d.xmux_h_max_reusable_secs.as_ref(),
        d.xmux_h_keep_alive_period,
    ) {
        v["xmux"] = xmux;
    }
    let sec = d.security.as_deref().unwrap_or("").to_ascii_lowercase();
    if sec == "tls" || sec == "reality" || d.sni.is_some() || d.reality_pbk.is_some() {
        let reality = if sec == "reality" || d.reality_pbk.is_some() {
            Some((
                d.reality_pbk.clone().unwrap_or_default(),
                d.reality_sid.clone().unwrap_or_default(),
            ))
        } else {
            None
        };
        v["tls"] = tls_object(
            true,
            d.sni.clone(),
            d.allow_insecure,
            false,
            d.alpn.clone(),
            d.fingerprint.clone(),
            reality,
        );
    }
    v
}
