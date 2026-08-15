use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("proxy link is missing scheme")]
    MissingScheme,
    #[error("unsupported proxy scheme `{0}`")]
    UnsupportedScheme(String),
    #[error("invalid proxy URL: {0}")]
    InvalidUrl(String),
    #[error("proxy URL is missing host")]
    MissingHost,
    #[error("invalid base64 payload: {0}")]
    Base64(String),
    #[error("invalid UTF-8: {0}")]
    Utf8(String),
    #[error("invalid vmess JSON: {0}")]
    VmessJson(String),
    #[error("vmess link is missing add")]
    VmessMissingAdd,
    #[error("shadowsocks link is missing server")]
    SsMissingServer,
    #[error("shadowsocks link is missing method/password")]
    SsMissingAuth,
    #[error("unknown transport type: {0}")]
    UnknownTransport(String),
    #[error("no outbounds found")]
    NoOutbounds,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
