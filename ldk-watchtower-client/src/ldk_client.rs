//! HTTP client for the ldk-server `WatchtowerStateExport` endpoint.
//!
//! The transport mirrors ldk-server's protobuf-over-HTTP API: requests are sent as
//! HTTP POSTs to `{base_url}/{ApiName}` with a protobuf-encoded body and
//! `Content-Type: application/octet-stream`.
//!
//! Authentication mirrors `validate_auth` in `ldk-server/src/service.rs`: an
//! `x-auth: HMAC {timestamp}:{hmac_hex}` header where `hmac_hex` is the hex-encoded
//! HMAC-SHA256 (keyed with the API key) of `timestamp (8 bytes, big endian) || body`.

use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use prost::Message;

use crate::proto::{
    WatchtowerStateExportRequest, WatchtowerStateExportResponse, WATCHTOWER_STATE_EXPORT_PATH,
};

/// Errors that can occur while interacting with the ldk-server API.
#[derive(Debug)]
pub enum LdkClientError {
    /// A network-level error (connection refused, timeout, ...).
    ConnectionError(String),
    /// The server returned a non-success status code.
    ApiError(u16, String),
    /// The response body could not be protobuf-decoded.
    DeserializeError(String),
    /// The system clock is set before the UNIX epoch.
    SystemTimeError,
}

impl std::fmt::Display for LdkClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LdkClientError::ConnectionError(e) => write!(f, "cannot connect to ldk-server: {e}"),
            LdkClientError::ApiError(code, msg) => {
                write!(f, "ldk-server API error ({code}): {msg}")
            }
            LdkClientError::DeserializeError(e) => {
                write!(f, "cannot decode ldk-server response: {e}")
            }
            LdkClientError::SystemTimeError => write!(f, "system time is before the UNIX epoch"),
        }
    }
}

impl std::error::Error for LdkClientError {}

impl LdkClientError {
    pub fn is_connection(&self) -> bool {
        matches!(self, LdkClientError::ConnectionError(_))
    }
}

/// Computes the authentication HMAC expected by ldk-server: HMAC-SHA256 keyed with
/// the API key over `timestamp.to_be_bytes() || body`, hex-encoded.
pub fn compute_auth_hmac(api_key: &str, timestamp: u64, body: &[u8]) -> String {
    let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(api_key.as_bytes());
    hmac_engine.input(&timestamp.to_be_bytes());
    hmac_engine.input(body);
    Hmac::<sha256::Hash>::from_engine(hmac_engine).to_string()
}

/// Blocking HTTP client for the ldk-server watchtower state export API.
pub struct LdkServerClient {
    base_url: String,
    api_key: String,
    client: reqwest::blocking::Client,
}

impl LdkServerClient {
    pub fn new(base_url: String, api_key: String) -> Self {
        LdkServerClient {
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_key,
            client: reqwest::blocking::Client::new(),
        }
    }

    /// Performs a protobuf-encoded, HMAC-authenticated POST to the given endpoint and
    /// protobuf-decodes the response.
    fn post<Req: Message, Res: Message + Default>(
        &self,
        path: &str,
        request: &Req,
    ) -> Result<Res, LdkClientError> {
        let body = request.encode_to_vec();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| LdkClientError::SystemTimeError)?
            .as_secs();
        let auth_header = format!(
            "HMAC {}:{}",
            timestamp,
            compute_auth_hmac(&self.api_key, timestamp, &body)
        );

        let response = self
            .client
            .post(format!("{}/{}", self.base_url, path))
            .header("content-type", "application/octet-stream")
            .header("x-auth", auth_header)
            .body(body)
            .send()
            .map_err(|e| {
                log::debug!("Error sending request to ldk-server: {e}");
                LdkClientError::ConnectionError(format!("{e}"))
            })?;

        let status = response.status();
        let response_body = response
            .bytes()
            .map_err(|e| LdkClientError::ConnectionError(format!("{e}")))?;

        if !status.is_success() {
            return Err(LdkClientError::ApiError(
                status.as_u16(),
                String::from_utf8_lossy(&response_body).into_owned(),
            ));
        }

        Res::decode(response_body.as_ref())
            .map_err(|e| LdkClientError::DeserializeError(format!("{e}")))
    }

    /// Exports the watchtower state of a single channel (if `user_channel_id` is set)
    /// or of all channels (if `None`).
    pub fn watchtower_state_export(
        &self,
        user_channel_id: Option<String>,
    ) -> Result<WatchtowerStateExportResponse, LdkClientError> {
        self.post(
            WATCHTOWER_STATE_EXPORT_PATH,
            &WatchtowerStateExportRequest { user_channel_id },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_auth_hmac() {
        // Cross-checked against the algorithm in ldk-server's `compute_auth_hmac`:
        // HMAC-SHA256(key = api_key, msg = timestamp.to_be_bytes() || body), hex-encoded.
        let hmac = compute_auth_hmac("secret-api-key", 1_700_000_000, b"watchtower");
        assert_eq!(hmac.len(), 64);
        assert!(hmac.chars().all(|c| c.is_ascii_hexdigit()));

        // Deterministic for the same inputs, different for different bodies/keys/timestamps.
        assert_eq!(
            hmac,
            compute_auth_hmac("secret-api-key", 1_700_000_000, b"watchtower")
        );
        assert_ne!(
            hmac,
            compute_auth_hmac("secret-api-key", 1_700_000_001, b"watchtower")
        );
        assert_ne!(
            hmac,
            compute_auth_hmac("secret-api-key", 1_700_000_000, b"other")
        );
        assert_ne!(
            hmac,
            compute_auth_hmac("other-key", 1_700_000_000, b"watchtower")
        );
    }
}
