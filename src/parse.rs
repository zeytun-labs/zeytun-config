use crate::error::{Error, Result};
use crate::node::{
    Http, Hysteria2, Shadowsocks, ShareProtocol, ShareProxy, Socks, Tls, Transport, Trojan, Tuic,
    Vless, Vmess,
};
use crate::url_schema::parse_url;
use crate::util::{
    decode_base64_to_string, decode_component, json_string, normalize_key, parse_host_port,
    query_param, split_fragment, split_query, truthy,
};
use serde_json::Value;
use std::collections::BTreeMap;
use url::Url;

pub fn parse_share_proxy(link: &str) -> Result<ShareProxy> {
    let link = link.trim();
    let scheme = link
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .ok_or(Error::MissingScheme)?;

    match scheme.as_str() {
        "vmess" | "svmess" => parse_vmess(link),
        "vless" | "svless" => parse_vless(link),
        "trojan" | "strojan" => parse_trojan(link),
        "ss" | "shadowsocks" => parse_shadowsocks(link),
        "hysteria2" | "hy2" => parse_hysteria2(link),
        "tuic" => parse_tuic(link),
        "socks" | "socks4" | "socks5" => parse_socks(link),
        "http" | "https" | "phttp" | "phttps" => parse_http(link),
        _ => Err(Error::UnsupportedScheme(scheme)),
    }
}

/// Back-compat alias used by convert pipeline.
pub fn parse_link(link: &str) -> Result<crate::outbound::Outbound> {
    let node = parse_share_proxy(link)?;
    Ok(crate::to_outbound::share_to_outbound(&node))
}

fn parse_vless(link: &str) -> Result<ShareProxy> {
    let u = parse_url(link, 443)?;
    let network = promote_tcp_http_header(
        &u.params,
        normalize_network(u.get_or("tcp", &["type", "net", "network"])),
    );
    let flow = u
        .get("flow")
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let pe = u
        .get("packetencoding")
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| Some("xudp".into()));
    Ok(ShareProxy {
        name: u.name,
        address: u.hostname.clone(),
        port: u.port,
        detour: None,
        protocol: ShareProtocol::Vless(Vless {
            uuid: u.username,
            flow,
            packet_encoding: pe,
            network: network.clone(),
            transport: transport_from_params(&u.params, &network),
            tls: tls_from_params(&u.params, &u.hostname, false),
        }),
    })
}

fn parse_trojan(link: &str) -> Result<ShareProxy> {
    let u = parse_url(link, 443)?;
    let network = promote_tcp_http_header(
        &u.params,
        normalize_network(u.get_or("tcp", &["type", "net", "network"])),
    );
    let force = u.get("security").is_none() && u.get("tls").is_none();
    let tls = tls_from_params(&u.params, &u.hostname, force).or_else(|| {
        force.then(|| Tls {
            enabled: true,
            sni: Some(u.hostname.clone()),
            ..Default::default()
        })
    });
    Ok(ShareProxy {
        name: u.name,
        address: u.hostname.clone(),
        port: u.port,
        detour: None,
        protocol: ShareProtocol::Trojan(Trojan {
            password: u.username,
            network: network.clone(),
            transport: transport_from_params(&u.params, &network),
            tls,
        }),
    })
}

fn parse_vmess(link: &str) -> Result<ShareProxy> {
    let payload = link
        .split_once("://")
        .map(|(_, p)| p)
        .ok_or(Error::MissingScheme)?;
    let (payload, frag) = split_fragment(payload);
    let json_str = decode_base64_to_string(payload)?;
    let value: Value =
        serde_json::from_str(&json_str).map_err(|e| Error::VmessJson(e.to_string()))?;

    let address = json_string(&value, "add").ok_or(Error::VmessMissingAdd)?;
    let port = json_string(&value, "port")
        .and_then(|p| p.parse().ok())
        .unwrap_or(443);
    let name = frag
        .or_else(|| json_string(&value, "ps"))
        .unwrap_or_else(|| address.clone());
    let params = params_from_vmess_json(&value);
    let network = promote_tcp_http_header(
        &params,
        normalize_network(&json_string(&value, "net").unwrap_or_else(|| "tcp".into())),
    );
    let pe = json_string(&value, "packetEncoding").or_else(|| Some("xudp".into()));

    Ok(ShareProxy {
        name,
        address: address.clone(),
        port,
        detour: None,
        protocol: ShareProtocol::Vmess(Vmess {
            uuid: json_string(&value, "id").unwrap_or_default(),
            alter_id: json_string(&value, "aid")
                .and_then(|a| a.parse().ok())
                .unwrap_or(0),
            security: json_string(&value, "scy")
                .or_else(|| json_string(&value, "security"))
                .unwrap_or_else(|| "auto".into()),
            packet_encoding: pe,
            network: network.clone(),
            transport: transport_from_params(&params, &network),
            tls: tls_from_params(&params, &address, false),
        }),
    })
}

fn parse_shadowsocks(link: &str) -> Result<ShareProxy> {
    let raw = link
        .split_once("://")
        .map(|(_, r)| r)
        .ok_or(Error::MissingScheme)?;
    let (without_fragment, name) = split_fragment(raw);
    let (main, query) = split_query(without_fragment);

    let (user_info, host_port) = if let Some((user_info, host_port)) = main.rsplit_once('@') {
        let user_info = decode_component(user_info);
        let user_info = if user_info.contains(':') {
            user_info
        } else {
            decode_base64_to_string(&user_info)?
        };
        (user_info, decode_component(host_port))
    } else {
        let decoded = decode_base64_to_string(main)?;
        let (user_info, host_port) = decoded.rsplit_once('@').ok_or(Error::SsMissingServer)?;
        (user_info.to_string(), host_port.to_string())
    };

    let (method, password) = user_info.split_once(':').ok_or(Error::SsMissingAuth)?;
    let (address, port) = parse_host_port(&host_port, 8388);
    let name = name.unwrap_or_else(|| address.clone());

    let (plugin, plugin_opts) = if let Some(plugin_full) = query_param(query, "plugin") {
        let (p, a) = plugin_full
            .split_once(';')
            .map(|(p, a)| (p.to_string(), Some(a.to_string())))
            .unwrap_or((plugin_full, None));
        (Some(p), a.or_else(|| query_param(query, "plugin-opts")))
    } else {
        (None, query_param(query, "plugin-opts"))
    };

    Ok(ShareProxy {
        name,
        address,
        port,
        detour: None,
        protocol: ShareProtocol::Shadowsocks(Shadowsocks {
            method: decode_component(method),
            password: decode_component(password),
            plugin,
            plugin_opts,
            udp_over_tcp: false,
        }),
    })
}

fn parse_hysteria2(link: &str) -> Result<ShareProxy> {
    let u = parse_url(link, 443)?;
    let mut pass = u.username.clone();
    if !u.password.is_empty() {
        pass = format!("{}:{}", u.username, u.password);
    }
    let sni = u
        .get("sni")
        .or_else(|| u.get("hostname"))
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let insecure = u.get("insecure").map(truthy).unwrap_or(false);
    let disable_sni = sni
        .as_ref()
        .map(|s| s.parse::<std::net::IpAddr>().is_ok())
        .unwrap_or(false);

    let up_mbps = u
        .get("upmbps")
        .or_else(|| u.get("up"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let down_mbps = u
        .get("downmbps")
        .or_else(|| u.get("down"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let server_ports = u
        .get("mport")
        .or_else(|| u.get("serverports"))
        .map(str::to_string);
    let hop_interval = u.get("hopinterval").map(str::to_string);
    let obfs = u.get("obfs").filter(|s| !s.is_empty()).map(str::to_string);
    let obfs_password = u.get("obfspassword").map(str::to_string);

    Ok(ShareProxy {
        name: u.name,
        address: u.hostname,
        port: u.port,
        detour: None,
        protocol: ShareProtocol::Hysteria2(Hysteria2 {
            password: pass,
            up_mbps,
            down_mbps,
            server_ports,
            hop_interval,
            obfs,
            obfs_password,
            tls: Tls {
                enabled: true,
                allow_insecure: insecure,
                sni,
                disable_sni,
                ..Default::default()
            },
        }),
    })
}

fn parse_tuic(link: &str) -> Result<ShareProxy> {
    let u = parse_url(link, 443)?;
    let sni = u.get("sni").filter(|s| !s.is_empty()).map(str::to_string);
    let insecure = u
        .get("allowinsecure")
        .or_else(|| u.get("insecure"))
        .map(truthy)
        .unwrap_or(false);

    let congestion_control = u.get("congestioncontrol").unwrap_or("cubic").to_string();
    let udp_relay_mode = u.get("udprelaymode").unwrap_or("native").to_string();
    let udp_over_stream = u.get("udpoverstream").map(truthy).unwrap_or(false);
    let zero_rtt_handshake = u.get("zerortthandshake").map(truthy).unwrap_or(false);
    let heartbeat = u.get("heartbeat").map(str::to_string);

    Ok(ShareProxy {
        name: u.name,
        address: u.hostname,
        port: u.port,
        detour: None,
        protocol: ShareProtocol::Tuic(Tuic {
            uuid: u.username,
            password: u.password,
            congestion_control,
            udp_relay_mode,
            udp_over_stream,
            zero_rtt_handshake,
            heartbeat,
            tls: Tls {
                enabled: true,
                allow_insecure: insecure,
                sni: sni.clone(),
                disable_sni: sni.is_none(),
                alpn: Some(vec!["h3".into(), "spdy/3.1".into()]),
                ..Default::default()
            },
        }),
    })
}

fn parse_socks(link: &str) -> Result<ShareProxy> {
    let u = parse_url(link, 1080)?;
    let version = if u.scheme == "socks4" {
        4
    } else {
        u.get("v")
            .or_else(|| u.get("ver"))
            .or_else(|| u.get("version"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(5)
    };
    Ok(ShareProxy {
        name: u.name,
        address: u.hostname,
        port: u.port,
        detour: None,
        protocol: ShareProtocol::Socks(Socks {
            version,
            username: u.username,
            password: u.password,
        }),
    })
}

fn parse_http(link: &str) -> Result<ShareProxy> {
    let u = parse_url(link, 0)?;
    let https = u.scheme == "https" || u.scheme == "phttps";
    let tls =
        if https || u.get("tls").is_some() || u.get("sni").is_some() || u.get("insecure").is_some()
        {
            Some(Tls {
                enabled: true,
                sni: u.get("sni").map(str::to_string),
                allow_insecure: u.get("insecure").map(|s| s != "0").unwrap_or(false),
                ..Default::default()
            })
        } else {
            None
        };
    let path = u.get("path").map(str::to_string);
    Ok(ShareProxy {
        name: u.name,
        address: u.hostname,
        port: u.port,
        detour: None,
        protocol: ShareProtocol::Http(Http {
            username: u.username,
            password: u.password,
            path,
            tls,
        }),
    })
}

// --- helpers ---

fn normalize_network(net: &str) -> String {
    match net.to_ascii_lowercase().as_str() {
        "raw" | "" => "tcp".into(),
        "xray-http" | "xray_http" | "splithttp" | "split-http" | "split_http" => "xhttp".into(),
        other => other.to_string(),
    }
}

/// Xray share: `type=tcp` + `headerType=http` (or vmess `type=http`) = HTTP camouflage over TCP.
/// sing-box maps that to transport `http`, not bare TCP.
fn promote_tcp_http_header(params: &BTreeMap<String, String>, network: String) -> String {
    if network == "tcp"
        && (params
            .get("headertype")
            .map(|s| s.eq_ignore_ascii_case("http"))
            .unwrap_or(false)
            || params
                .get("type")
                .map(|s| s.eq_ignore_ascii_case("http"))
                .unwrap_or(false))
    {
        "http".into()
    } else {
        network
    }
}

fn tls_from_params(params: &BTreeMap<String, String>, address: &str, force: bool) -> Option<Tls> {
    let security = params
        .get("security")
        .or_else(|| params.get("tls"))
        .map(String::as_str)
        .unwrap_or("");
    let is_reality = security.eq_ignore_ascii_case("reality");
    let is_tls = force
        || security.eq_ignore_ascii_case("tls")
        || is_reality
        || params
            .get("tls")
            .map(|s| s.eq_ignore_ascii_case("tls"))
            .unwrap_or(false);
    if !is_tls {
        return None;
    }
    let sni = params
        .get("sni")
        .or_else(|| params.get("peer"))
        .or_else(|| params.get("servername"))
        .cloned()
        .filter(|s| !s.is_empty())
        .or_else(|| Some(address.to_string()));
    let mut fp = params
        .get("fp")
        .or_else(|| params.get("fingerprint"))
        .cloned()
        .filter(|s| !s.is_empty());
    if fp.is_none() && is_reality {
        fp = Some("chrome".into());
    }
    Some(Tls {
        enabled: true,
        allow_insecure: params
            .get("insecure")
            .or_else(|| params.get("allowinsecure"))
            .map(|s| truthy(s))
            .unwrap_or(false),
        sni,
        alpn: params.get("alpn").map(|a| {
            a.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        }),
        disable_sni: params.contains_key("nosni"),
        fingerprint: fp,
        reality_pbk: if is_reality {
            params.get("pbk").cloned()
        } else {
            None
        },
        reality_sid: if is_reality {
            params.get("sid").cloned()
        } else {
            None
        },
    })
}

fn transport_from_params(params: &BTreeMap<String, String>, network: &str) -> Option<Transport> {
    let mut net = network.to_string();
    if (params.get("type").map(|s| s.as_str()) == Some("http")
        || params.get("headertype").map(|s| s.as_str()) == Some("http"))
        && net == "tcp"
    {
        net = "http".into();
    }
    if net == "tcp" {
        return None;
    }

    let host = params.get("host").cloned().filter(|s| !s.is_empty());
    let mut path = params
        .get("path")
        .or_else(|| params.get("servicename"))
        .cloned()
        .filter(|s| !s.is_empty());
    let mut t = Transport {
        host: host.clone(),
        path: path.clone(),
        mode: params.get("mode").cloned(),
        service_name: if net == "grpc" {
            path.clone()
        } else {
            params.get("servicename").cloned()
        },
        method: params.get("method").cloned(),
        ..Default::default()
    };

    match net.as_str() {
        "ws" | "httpupgrade" => {
            if let Some(ref h) = host {
                let mut headers = std::collections::HashMap::new();
                headers.insert("Host".into(), h.clone());
                t.headers = Some(headers);
            }
            if let Some(ref mut p) = path {
                if !p.starts_with('/') {
                    *p = format!("/{p}");
                }
                if net == "ws" {
                    if let Ok(path_url) = Url::parse(&format!("http://x{p}")) {
                        let mut max_early = 0u32;
                        let mut clean = path_url.path().to_string();
                        let mut q: Vec<(String, String)> = Vec::new();
                        for (k, v) in path_url.query_pairs() {
                            if k == "ed" {
                                if let Ok(n) = v.parse::<u32>() {
                                    max_early = n;
                                }
                            } else {
                                q.push((k.into_owned(), v.into_owned()));
                            }
                        }
                        if !q.is_empty() {
                            let qs = q
                                .iter()
                                .map(|(k, v)| format!("{k}={v}"))
                                .collect::<Vec<_>>()
                                .join("&");
                            clean = format!("{clean}?{qs}");
                        }
                        t.path = Some(clean);
                        t.max_early_data = Some(max_early);
                        t.early_data_header_name = Some("Sec-WebSocket-Protocol".into());
                    } else {
                        t.path = Some(p.clone());
                    }
                } else {
                    t.path = Some(p.clone());
                }
            }
        }
        "xhttp" => {
            t.mode = Some(params.get("mode").cloned().unwrap_or_else(|| "auto".into()));
            if let Some(extra) = params.get("extra") {
                if let Ok(v) = serde_json::from_str::<Value>(extra) {
                    merge_xhttp_extra(&mut t, &v);
                } else if let Ok(decoded) = decode_base64_to_string(extra) {
                    if let Ok(v) = serde_json::from_str::<Value>(&decoded) {
                        merge_xhttp_extra(&mut t, &v);
                    }
                }
            }
            // also direct query keys (normalized)
            pull_xhttp_query(&mut t, params);
        }
        _ => {}
    }
    Some(t)
}

fn pull_xhttp_query(t: &mut Transport, params: &BTreeMap<String, String>) {
    if t.x_padding_bytes.is_none() {
        t.x_padding_bytes = params.get("xpaddingbytes").cloned();
    }
    if t.sc_max_each_post_bytes.is_none() {
        t.sc_max_each_post_bytes = params.get("scmaxeachpostbytes").cloned();
    }
    if t.sc_min_posts_interval_ms.is_none() {
        t.sc_min_posts_interval_ms = params.get("scminpostsintervalms").cloned();
    }
    if t.session_id_placement.is_none() {
        t.session_id_placement = params.get("sessionidplacement").cloned();
    }
    if t.seq_placement.is_none() {
        t.seq_placement = params.get("seqplacement").cloned();
    }
    if t.uplink_data_placement.is_none() {
        t.uplink_data_placement = params.get("uplinkdataplacement").cloned();
    }
    if t.uplink_http_method.is_none() {
        t.uplink_http_method = params.get("uplinkhttpmethod").cloned();
    }
    if t.no_grpc_header.is_none() {
        t.no_grpc_header = params.get("nogrpcheader").map(|s| truthy(s));
    }
    if t.no_sse_header.is_none() {
        t.no_sse_header = params.get("nosseheader").map(|s| truthy(s));
    }
}

fn merge_xhttp_extra(t: &mut Transport, extra: &Value) {
    if t.path.is_none() {
        t.path = json_string(extra, "path");
    }
    if t.host.is_none() {
        t.host = json_string(extra, "host");
    }
    if t.mode.is_none() {
        t.mode = json_string(extra, "mode");
    }
    if t.x_padding_bytes.is_none() {
        t.x_padding_bytes = json_string(extra, "xPaddingBytes");
    }
    if t.sc_max_each_post_bytes.is_none() {
        t.sc_max_each_post_bytes = json_string(extra, "scMaxEachPostBytes");
    }
    if t.sc_min_posts_interval_ms.is_none() {
        t.sc_min_posts_interval_ms = json_string(extra, "scMinPostsIntervalMs");
    }
    if t.x_padding_obfs_mode.is_none() {
        t.x_padding_obfs_mode = extra.get("xPaddingObfsMode").and_then(|v| v.as_bool());
    }
    if t.x_padding_key.is_none() {
        t.x_padding_key = json_string(extra, "xPaddingKey");
    }
    if t.x_padding_header.is_none() {
        t.x_padding_header = json_string(extra, "xPaddingHeader");
    }
    if t.x_padding_placement.is_none() {
        t.x_padding_placement = json_string(extra, "xPaddingPlacement");
    }
    if t.x_padding_method.is_none() {
        t.x_padding_method = json_string(extra, "xPaddingMethod");
    }
    if t.uplink_http_method.is_none() {
        t.uplink_http_method = json_string(extra, "uplinkHTTPMethod");
    }
    if t.session_id_placement.is_none() {
        t.session_id_placement = json_string(extra, "sessionIDPlacement");
    }
    if t.session_id_key.is_none() {
        t.session_id_key = json_string(extra, "sessionIDKey");
    }
    if t.seq_placement.is_none() {
        t.seq_placement = json_string(extra, "seqPlacement");
    }
    if t.seq_key.is_none() {
        t.seq_key = json_string(extra, "seqKey");
    }
    if t.uplink_data_placement.is_none() {
        t.uplink_data_placement = json_string(extra, "uplinkDataPlacement");
    }
    if t.uplink_data_key.is_none() {
        t.uplink_data_key = json_string(extra, "uplinkDataKey");
    }
    if t.uplink_chunk_size.is_none() {
        t.uplink_chunk_size = json_string(extra, "uplinkChunkSize");
    }
    if t.session_id_table.is_none() {
        t.session_id_table = json_string(extra, "sessionIDTable");
    }
    if t.session_id_length.is_none() {
        t.session_id_length = json_string(extra, "sessionIDLength");
    }
    if t.no_grpc_header.is_none() {
        t.no_grpc_header = extra.get("noGRPCHeader").and_then(|v| v.as_bool());
    }
    if t.no_sse_header.is_none() {
        t.no_sse_header = extra.get("noSSEHeader").and_then(|v| v.as_bool());
    }
    if let Some(xmux) = extra.get("xmux") {
        if t.xmux_max_concurrency.is_none() {
            t.xmux_max_concurrency = json_string(xmux, "maxConcurrency");
        }
        if t.xmux_max_connections.is_none() {
            t.xmux_max_connections = json_string(xmux, "maxConnections");
        }
        if t.xmux_c_max_reuse_times.is_none() {
            t.xmux_c_max_reuse_times = json_string(xmux, "cMaxReuseTimes");
        }
        if t.xmux_h_max_request_times.is_none() {
            t.xmux_h_max_request_times = json_string(xmux, "hMaxRequestTimes");
        }
        if t.xmux_h_max_reusable_secs.is_none() {
            t.xmux_h_max_reusable_secs = json_string(xmux, "hMaxReusableSecs");
        }
        if t.xmux_h_keep_alive_period.is_none() {
            t.xmux_h_keep_alive_period = xmux
                .get("hKeepAlivePeriod")
                .and_then(|v| v.as_i64())
                .or_else(|| json_string(xmux, "hKeepAlivePeriod").and_then(|s| s.parse().ok()));
        }
    }
    if t.download.is_none() {
        if let Some(dl) = extra
            .get("downloadSettings")
            .or_else(|| extra.get("download"))
        {
            t.download = Some(parse_download_settings(dl));
        }
    }
}

fn parse_download_settings(dl: &Value) -> crate::node::DownloadSettings {
    use crate::node::DownloadSettings;
    let mut d = DownloadSettings {
        address: json_string(dl, "address").or_else(|| json_string(dl, "server")),
        port: dl
            .get("port")
            .or_else(|| dl.get("server_port"))
            .and_then(|v| {
                v.as_u64()
                    .map(|n| n as u16)
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            }),
        path: json_string(dl, "path"),
        host: json_string(dl, "host"),
        detour: json_string(dl, "detour"),
        security: json_string(dl, "security"),
        sni: None,
        allow_insecure: false,
        alpn: None,
        fingerprint: None,
        reality_pbk: None,
        reality_sid: None,
        x_padding_bytes: json_string(dl, "xPaddingBytes"),
        sc_max_each_post_bytes: json_string(dl, "scMaxEachPostBytes"),
        sc_min_posts_interval_ms: json_string(dl, "scMinPostsIntervalMs"),
        no_grpc_header: dl.get("noGRPCHeader").and_then(|v| v.as_bool()),
        no_sse_header: dl.get("noSSEHeader").and_then(|v| v.as_bool()),
        xmux_max_concurrency: None,
        xmux_max_connections: None,
        xmux_c_max_reuse_times: None,
        xmux_h_max_request_times: None,
        xmux_h_max_reusable_secs: None,
        xmux_h_keep_alive_period: None,
    };
    if let Some(xmux) = dl.get("xmux") {
        d.xmux_max_concurrency = json_string(xmux, "maxConcurrency");
        d.xmux_max_connections = json_string(xmux, "maxConnections");
        d.xmux_c_max_reuse_times = json_string(xmux, "cMaxReuseTimes");
        d.xmux_h_max_request_times = json_string(xmux, "hMaxRequestTimes");
        d.xmux_h_max_reusable_secs = json_string(xmux, "hMaxReusableSecs");
        d.xmux_h_keep_alive_period = xmux
            .get("hKeepAlivePeriod")
            .and_then(|v| v.as_i64())
            .or_else(|| json_string(xmux, "hKeepAlivePeriod").and_then(|s| s.parse().ok()));
    }
    // nested tlsSettings (xray share) or flat tls (sing-box)
    if let Some(tls) = dl.get("tlsSettings").or_else(|| dl.get("tls")) {
        d.sni = json_string(tls, "serverName")
            .or_else(|| json_string(tls, "server_name"))
            .or_else(|| json_string(tls, "sni"));
        d.allow_insecure = tls
            .get("allowInsecure")
            .or_else(|| tls.get("insecure"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        d.fingerprint = json_string(tls, "fingerprint");
        if let Some(alpn) = tls.get("alpn") {
            d.alpn = match alpn {
                Value::Array(arr) => Some(
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect(),
                ),
                Value::String(s) => Some(
                    s.split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect(),
                ),
                _ => None,
            };
        }
        if d.security.is_none() && tls.get("enabled").and_then(|v| v.as_bool()) == Some(true) {
            d.security = Some("tls".into());
        }
        if let Some(reality) = tls.get("reality") {
            if reality.get("enabled").and_then(|v| v.as_bool()) != Some(false) {
                d.security = Some("reality".into());
                d.reality_pbk = json_string(reality, "publicKey")
                    .or_else(|| json_string(reality, "public_key"));
                d.reality_sid =
                    json_string(reality, "shortId").or_else(|| json_string(reality, "short_id"));
                if d.sni.is_none() {
                    d.sni = json_string(tls, "server_name").or_else(|| json_string(tls, "serverName"));
                }
            }
        }
    }
    if let Some(reality) = dl.get("realitySettings") {
        d.security = Some("reality".into());
        d.sni = d
            .sni
            .or_else(|| json_string(reality, "serverName"))
            .or_else(|| json_string(reality, "server_name"));
        d.fingerprint = d
            .fingerprint
            .or_else(|| json_string(reality, "fingerprint"));
        d.reality_pbk = json_string(reality, "publicKey")
            .or_else(|| json_string(reality, "public_key"));
        d.reality_sid =
            json_string(reality, "shortId").or_else(|| json_string(reality, "short_id"));
    }
    d
}

fn params_from_vmess_json(value: &Value) -> BTreeMap<String, String> {
    let mut params = BTreeMap::new();
    if let Some(obj) = value.as_object() {
        for (k, v) in obj {
            if let Some(s) = match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                Value::Bool(b) => Some(b.to_string()),
                _ => None,
            } {
                params.insert(normalize_key(k), s);
            }
        }
    }
    if let Some(net) = json_string(value, "net") {
        params.insert("net".into(), net);
    }
    if let Some(path) = json_string(value, "path") {
        params.insert("path".into(), path);
    }
    if let Some(host) = json_string(value, "host") {
        params.insert("host".into(), host);
    }
    if let Some(tls) = json_string(value, "tls") {
        params.insert("security".into(), tls.clone());
        params.insert("tls".into(), tls);
    }
    if let Some(sni) = json_string(value, "sni") {
        params.insert("sni".into(), sni);
    }
    if let Some(extra) = value.get("extra").and_then(|v| {
        if let Value::String(s) = v {
            Some(s.clone())
        } else {
            serde_json::to_string(v).ok()
        }
    }) {
        params.insert("extra".into(), extra);
    }
    params
}
