use cln_plugin::messages;
use serde::Deserialize;
pub mod http;

#[derive(Clone, Debug, Deserialize)]
pub struct ProxyInfo {
    #[serde(flatten)]
    /// The proxy data
    inner: messages::ProxyInfo,
    /// Whether to only send data though Tor or not
    pub always_use: bool,
}

impl ProxyInfo {
    pub fn new(proxy: messages::ProxyInfo, always_use: bool) -> Self {
        Self {
            inner: proxy,
            always_use,
        }
    }

    pub fn get_socks_addr(&self) -> String {
        format!("socks5h://{}:{}", self.inner.address, self.inner.port)
    }
}
