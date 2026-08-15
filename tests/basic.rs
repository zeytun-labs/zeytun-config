use zeytun_config::{convert_options, parse_outbound, parse_share_proxy, share_to_link};

#[test]
fn vless_ws_tls() {
    let url = "vless://25da296e-1d96-48ae-9867-4342796cd742@172.67.149.95:443?encryption=none&fp=chrome&host=vless.example.workers.dev&path=%2F%3Fed%3D2048&security=tls&sni=vless.example.workers.dev&type=ws#tag-vless";
    let o = parse_outbound(url).expect("parse");
    assert_eq!(o.type_name, "vless");
    assert_eq!(o.tag, "tag-vless");
    assert_eq!(o.fields["server"], "172.67.149.95");
    assert_eq!(o.fields["server_port"], 443);
    assert_eq!(o.fields["uuid"], "25da296e-1d96-48ae-9867-4342796cd742");
    let tls = o.fields["tls"].as_object().unwrap();
    assert_eq!(tls["enabled"], true);
    assert_eq!(tls["server_name"], "vless.example.workers.dev");
    assert_eq!(tls["utls"]["fingerprint"], "chrome");
    let tr = o.fields["transport"].as_object().unwrap();
    assert_eq!(tr["type"], "ws");
    assert_eq!(tr["max_early_data"], 2048);
}

#[test]
fn vless_tcp_http_header() {
    // Xray: type=tcp + headerType=http → sing-box transport http (not bare tcp).
    let url = "vless://6030a5fe-b1ea-4c25-9b36-dc857d154769@104.253.18.113:42422?encryption=none&headerType=http&host=play.google.com&path=%2F&security=none&type=tcp#google%20play-me";
    let node = parse_share_proxy(url).expect("parse");
    match &node.protocol {
        zeytun_config::ShareProtocol::Vless(v) => {
            assert_eq!(v.network, "http");
            let tr = v.transport.as_ref().expect("transport");
            assert_eq!(tr.host.as_deref(), Some("play.google.com"));
            assert_eq!(tr.path.as_deref(), Some("/"));
        }
        _ => panic!("expected vless"),
    }
    let o = parse_outbound(url).expect("outbound");
    let tr = o.fields["transport"].as_object().unwrap();
    assert_eq!(tr["type"], "http");
    assert_eq!(tr["host"], serde_json::json!(["play.google.com"]));
    assert_eq!(tr["path"], "/");
}

#[test]
fn ss_sip002() {
    // method:password base64 userinfo
    let url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0cGFzcw@1.2.3.4:8388#myss";
    let o = parse_outbound(url).expect("parse");
    assert_eq!(o.type_name, "shadowsocks");
    assert_eq!(o.fields["method"], "chacha20-ietf-poly1305");
    assert_eq!(o.fields["password"], "testpass");
    assert_eq!(o.fields["server"], "1.2.3.4");
    assert_eq!(o.fields["server_port"], 8388);
}

#[test]
fn convert_wraps_outbounds() {
    let url = "socks5://user:pass@10.0.0.1:1080#s";
    let opts = convert_options(url).unwrap();
    assert_eq!(opts.outbounds.len(), 1);
    assert!(opts.outbounds[0].tag.contains("§ 0"));
}

#[test]
fn chain_sets_detour() {
    let url = "socks://a:b@1.1.1.1:1080#outer -> socks://c:d@2.2.2.2:1080#inner";
    let opts = convert_options(url).unwrap();
    assert_eq!(opts.outbounds.len(), 2);
    // reverse order: inner first, then outer with detour=inner
    assert!(opts.outbounds[0].tag.starts_with("inner"));
    assert!(opts.outbounds[1].tag.starts_with("outer"));
    assert_eq!(
        opts.outbounds[1]
            .fields
            .get("detour")
            .and_then(|v| v.as_str()),
        Some(opts.outbounds[0].tag.as_str())
    );
}

#[test]
fn xhttp_download_settings() {
    let extra = r#"{"downloadSettings":{"address":"dl.example.com","port":8443,"path":"/dl","host":"dl.example.com","security":"tls","tlsSettings":{"serverName":"dl.example.com","fingerprint":"chrome","alpn":["h2"]}}}"#;
    let url = format!(
        "vless://3179dce2-2ff9-413c-85b4-c1d53ed41668@up.example.com:443?type=xhttp&path=%2Fxhttp&host=up.example.com&mode=stream-up&security=tls&sni=up.example.com&extra={}#xhttp-dl",
        urlencoding_lite(extra)
    );
    let o = parse_outbound(&url).expect("parse");
    let tr = o.fields["transport"].as_object().unwrap();
    assert_eq!(tr["type"], "xhttp");
    let dl = tr["downloadSettings"].as_object().unwrap();
    assert_eq!(dl["server"], "dl.example.com");
    assert_eq!(dl["server_port"], 8443);
    assert_eq!(dl["path"], "/dl");
    assert_eq!(dl["tls"]["server_name"], "dl.example.com");
    assert_eq!(dl["tls"]["utls"]["fingerprint"], "chrome");
}

fn urlencoding_lite(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{:02X}", b),
        })
        .collect()
}

#[test]
fn share_to_link_vless_ws_roundtrip() {
    let url = "vless://25da296e-1d96-48ae-9867-4342796cd742@172.67.149.95:443?encryption=none&fp=chrome&host=vless.example.workers.dev&path=%2F%3Fed%3D2048&security=tls&sni=vless.example.workers.dev&type=ws#tag-vless";
    let node = parse_share_proxy(url).expect("parse");
    let out = share_to_link(&node).expect("emit");
    let again = parse_share_proxy(&out).expect("reparse");
    assert_eq!(again.address, node.address);
    assert_eq!(again.port, node.port);
    assert_eq!(again.name, node.name);
    match (&node.protocol, &again.protocol) {
        (zeytun_config::ShareProtocol::Vless(a), zeytun_config::ShareProtocol::Vless(b)) => {
            assert_eq!(a.uuid, b.uuid);
            assert_eq!(a.network, b.network);
            assert_eq!(
                a.transport.as_ref().and_then(|t| t.path.clone()),
                b.transport.as_ref().and_then(|t| t.path.clone())
            );
            assert_eq!(
                a.transport.as_ref().and_then(|t| t.max_early_data),
                b.transport.as_ref().and_then(|t| t.max_early_data)
            );
            assert_eq!(
                a.tls.as_ref().and_then(|t| t.sni.clone()),
                b.tls.as_ref().and_then(|t| t.sni.clone())
            );
        }
        _ => panic!("expected vless"),
    }
}

#[test]
fn share_to_link_ss_roundtrip() {
    let url = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0cGFzcw@1.2.3.4:8388#myss";
    let node = parse_share_proxy(url).expect("parse");
    let out = share_to_link(&node).expect("emit");
    let again = parse_share_proxy(&out).expect("reparse");
    match (&node.protocol, &again.protocol) {
        (
            zeytun_config::ShareProtocol::Shadowsocks(a),
            zeytun_config::ShareProtocol::Shadowsocks(b),
        ) => {
            assert_eq!(a.method, b.method);
            assert_eq!(a.password, b.password);
            assert_eq!(again.address, "1.2.3.4");
            assert_eq!(again.port, 8388);
            assert_eq!(again.name, "myss");
        }
        _ => panic!("expected ss"),
    }
}

#[test]
fn share_to_link_xhttp_download_roundtrip() {
    let extra = r#"{"downloadSettings":{"address":"dl.example.com","port":8443,"path":"/dl","host":"dl.example.com","security":"tls","tlsSettings":{"serverName":"dl.example.com","fingerprint":"chrome","alpn":["h2"]}}}"#;
    let url = format!(
        "vless://3179dce2-2ff9-413c-85b4-c1d53ed41668@up.example.com:443?type=xhttp&path=%2Fxhttp&host=up.example.com&mode=stream-up&security=tls&sni=up.example.com&extra={}#xhttp-dl",
        urlencoding_lite(extra)
    );
    let node = parse_share_proxy(&url).expect("parse");
    let out = share_to_link(&node).expect("emit");
    let o = parse_outbound(&out).expect("reparse outbound");
    let tr = o.fields["transport"].as_object().unwrap();
    assert_eq!(tr["type"], "xhttp");
    let dl = tr["downloadSettings"].as_object().unwrap();
    assert_eq!(dl["server"], "dl.example.com");
    assert_eq!(dl["server_port"], 8443);
    assert_eq!(dl["path"], "/dl");
}
