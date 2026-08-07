//! Blocking HTTP(S) client for the teos (Eye of Satoshi) tower API.
//!
//! This mirrors `watchtower-plugin/src/net/http.rs`, adapted to a blocking
//! `reqwest` client. Towers behind onion addresses are reached through a local
//! Tor SOCKS5 proxy (`socks5h://`); onion addresses without a proxy are refused.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use teos_common::appointment::{Appointment, Locator};
use teos_common::cryptography;
use teos_common::net::http::Endpoint;
use teos_common::net::NetAddr;
use teos_common::protos as common_msgs;
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::{TowerId, UserId};

/// SOCKS5 proxy information used to reach (onion) towers.
#[derive(Clone, Debug)]
pub struct ProxyInfo {
    /// The proxy address in `host:port` form (e.g. `127.0.0.1:9050`).
    address: String,
}

impl ProxyInfo {
    pub fn new(address: String) -> Self {
        ProxyInfo { address }
    }

    pub fn get_socks_addr(&self) -> String {
        format!("socks5h://{}", self.address)
    }
}

/// Proof that a tower has misbehaved: the returned appointment receipt was signed
/// by a key that does not match the tower id we were given.
#[derive(Clone, Serialize, Debug)]
pub struct MisbehaviorProof {
    #[serde(with = "hex::serde")]
    pub locator: Locator,
    pub appointment_receipt: AppointmentReceipt,
    pub recovered_id: TowerId,
}

impl MisbehaviorProof {
    pub fn new(
        locator: Locator,
        appointment_receipt: AppointmentReceipt,
        recovered_id: TowerId,
    ) -> Self {
        Self {
            locator,
            appointment_receipt,
            recovered_id,
        }
    }
}

/// Represents a generic tower API response.
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum ApiResponse<T> {
    Response(T),
    Error(ApiError),
}

/// API errors that can be received when interacting with the tower.
/// Error codes match `teos_common::errors`.
#[derive(Serialize, Deserialize, Debug)]
pub struct ApiError {
    pub error: String,
    pub error_code: u8,
}

/// Errors related to requests sent to the tower.
#[derive(Debug, PartialEq, Eq)]
pub enum RequestError {
    ConnectionError(String),
    DeserializeError(String),
    Unexpected(String),
}

impl RequestError {
    pub fn is_connection(&self) -> bool {
        matches!(self, RequestError::ConnectionError(_))
    }
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestError::ConnectionError(e) => write!(f, "connection error: {e}"),
            RequestError::DeserializeError(e) => write!(f, "deserialize error: {e}"),
            RequestError::Unexpected(e) => write!(f, "unexpected error: {e}"),
        }
    }
}

/// Errors related to the `add_appointment` requests to the tower.
#[derive(Debug)]
pub enum AddAppointmentError {
    RequestError(RequestError),
    ApiError(ApiError),
    SignatureError(MisbehaviorProof),
}

impl From<RequestError> for AddAppointmentError {
    fn from(r: RequestError) -> Self {
        AddAppointmentError::RequestError(r)
    }
}

impl std::fmt::Display for AddAppointmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddAppointmentError::RequestError(e) => write!(f, "{e}"),
            AddAppointmentError::ApiError(e) => {
                write!(f, "tower API error ({}): {}", e.error_code, e.error)
            }
            AddAppointmentError::SignatureError(_) => write!(
                f,
                "tower misbehaved: receipt signature does not match tower id"
            ),
        }
    }
}

/// Builds a reqwest client honoring the Tor proxy rules: requests to onion
/// addresses go through the proxy; onion addresses without a proxy are refused.
fn build_client(
    net_addr: &NetAddr,
    proxy: &Option<ProxyInfo>,
) -> Result<reqwest::blocking::Client, RequestError> {
    match proxy {
        Some(proxy) if net_addr.is_onion() => reqwest::blocking::Client::builder()
            .proxy(
                reqwest::Proxy::http(proxy.get_socks_addr())
                    .map_err(|e| RequestError::ConnectionError(format!("{e}")))?,
            )
            .build()
            .map_err(|e| RequestError::ConnectionError(format!("{e}"))),
        None if net_addr.is_onion() => Err(RequestError::ConnectionError(
            "Cannot connect to an onion address without a proxy".to_owned(),
        )),
        _ => Ok(reqwest::blocking::Client::new()),
    }
}

/// Sends a protobuf-typed (JSON-serialized) POST request to a tower endpoint.
pub fn post_request<S: Serialize>(
    tower_net_addr: &NetAddr,
    endpoint: Endpoint,
    data: &S,
    proxy: &Option<ProxyInfo>,
) -> Result<reqwest::blocking::Response, RequestError> {
    let client = build_client(tower_net_addr, proxy)?;
    client
        .post(format!("{}{}", tower_net_addr.net_addr(), endpoint.path()))
        .json(data)
        .send()
        .map_err(|e| {
            log::debug!("An error occurred when sending data to the tower: {e}");
            if e.is_connect() || e.is_timeout() {
                RequestError::ConnectionError(
                    "Cannot connect to the tower. Connection refused".to_owned(),
                )
            } else {
                RequestError::Unexpected(
                    "Unexpected error occurred (see logs for more info)".to_owned(),
                )
            }
        })
}

/// Generic function to process the response of a given post request.
pub fn process_post_response<T: DeserializeOwned>(
    post_request: Result<reqwest::blocking::Response, RequestError>,
) -> Result<T, RequestError> {
    match post_request {
        Ok(r) => r.json().map_err(|e| {
            RequestError::DeserializeError(format!("Unexpected response body. Error: {e}"))
        }),
        Err(e) => Err(e),
    }
}

/// Handles the logic of interacting with the `register` endpoint of the tower.
pub fn register(
    tower_id: TowerId,
    user_id: UserId,
    tower_net_addr: &NetAddr,
    proxy: &Option<ProxyInfo>,
) -> Result<RegistrationReceipt, RequestError> {
    log::info!("Registering with the Eye of Satoshi (tower_id={tower_id})");
    process_post_response(post_request(
        tower_net_addr,
        Endpoint::Register,
        &common_msgs::RegisterRequest {
            user_id: user_id.to_vec(),
        },
        proxy,
    ))
    .map(|r: common_msgs::RegisterResponse| {
        RegistrationReceipt::with_signature(
            user_id,
            r.available_slots,
            r.subscription_start,
            r.subscription_expiry,
            r.subscription_signature,
        )
    })
}

/// Handles the logic of interacting with the `add_appointment` endpoint of the tower.
///
/// On a successful response the receipt signature is verified against the given
/// tower id; a mismatch yields a [MisbehaviorProof].
pub fn send_appointment(
    tower_id: TowerId,
    tower_net_addr: &NetAddr,
    proxy: &Option<ProxyInfo>,
    appointment: &Appointment,
    signature: &str,
) -> Result<(common_msgs::AddAppointmentResponse, AppointmentReceipt), AddAppointmentError> {
    log::debug!(
        "Sending appointment {} to tower {tower_id}",
        appointment.locator
    );
    let request_data = common_msgs::AddAppointmentRequest {
        appointment: Some(appointment.clone().into()),
        signature: signature.to_owned(),
    };

    match process_post_response(post_request(
        tower_net_addr,
        Endpoint::AddAppointment,
        &request_data,
        proxy,
    ))? {
        ApiResponse::Response::<common_msgs::AddAppointmentResponse>(r) => {
            let receipt = AppointmentReceipt::with_signature(
                signature.to_owned(),
                r.start_block,
                r.signature.clone(),
            );
            let recovered_id = TowerId(
                cryptography::recover_pk(&receipt.to_vec(), &receipt.signature().unwrap()).unwrap(),
            );
            if recovered_id == tower_id {
                log::debug!(
                    "Appointment accepted and signed by {tower_id} (start block: {})",
                    r.start_block
                );
                Ok((r, receipt))
            } else {
                Err(AddAppointmentError::SignatureError(MisbehaviorProof::new(
                    appointment.locator,
                    receipt,
                    recovered_id,
                )))
            }
        }
        ApiResponse::Error(e) => Err(AddAppointmentError::ApiError(e)),
    }
}
