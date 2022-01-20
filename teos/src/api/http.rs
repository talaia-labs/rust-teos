use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::error::Error;
use std::net::SocketAddr;
use tonic::{transport::Channel, Code};
use triggered::Listener;
use warp::{http::StatusCode, reply, Filter, Rejection, Reply};

use teos_common::appointment::{AppointmentStatus, LOCATOR_LEN};
use teos_common::errors;
use teos_common::USER_ID_LEN;

use crate::protos as msgs;
use crate::protos::public_tower_services_client::PublicTowerServicesClient;

// REQUEST TYPES
#[derive(Serialize, Deserialize, Debug)]
struct RegisterData {
    #[serde(with = "hex::serde")]
    user_id: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct AddAppointmentData {
    appointment: Appointment,
    signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Appointment {
    #[serde(with = "hex::serde")]
    locator: Vec<u8>,
    #[serde(with = "hex::serde")]
    encrypted_blob: Vec<u8>,
    to_self_delay: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct GetAppointmentData {
    #[serde(with = "hex::serde")]
    locator: Vec<u8>,
    signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct GetSubscriptionInfoData {
    signature: String,
}

// RESPONSE TYPES
#[derive(Serialize, Deserialize, Debug)]
struct RegisterResponse {
    #[serde(with = "hex::serde")]
    user_id: Vec<u8>,
    available_slots: u32,
    subscription_expiry: u32,
    subscription_signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AddAppointmentResponse {
    #[serde(with = "hex::serde")]
    locator: Vec<u8>,
    start_block: u32,
    signature: String,
    available_slots: u32,
    subscription_expiry: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct GetAppointmentResponse {
    #[serde(flatten)]
    appointment: AppointmentOrTracker,
    status: String,
}

#[derive(Serialize, Deserialize, Debug)]
enum AppointmentOrTracker {
    #[serde(rename = "appointment")]
    Appointment(Appointment),
    #[serde(rename = "appointment")]
    Tracker(Tracker),
}

#[derive(Serialize, Deserialize, Debug)]
struct Tracker {
    #[serde(with = "hex::serde")]
    locator: Vec<u8>,
    #[serde(with = "hex::serde")]
    dispute_txid: Vec<u8>,
    #[serde(with = "hex::serde")]
    penalty_txid: Vec<u8>,
    #[serde(with = "hex::serde")]
    penalty_rawtx: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SubscriptionInfoResponse {
    available_slots: u32,
    subscription_expiry: u32,
    locators: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub(crate) struct ApiError {
    error: String,
    error_code: u8,
}

impl ApiError {
    fn new(error: String, error_code: u8) -> Self {
        ApiError { error, error_code }
    }
}

fn with_grpc(
    grpc_endpoint: PublicTowerServicesClient<Channel>,
) -> impl Filter<Extract = (PublicTowerServicesClient<Channel>,), Error = Infallible> + Clone {
    warp::any().map(move || grpc_endpoint.clone())
}

fn empty_field(field_name: &str) -> reply::WithStatus<reply::Json> {
    reply::with_status(
        reply::json(&ApiError::new(
            format!("{} field is empty", field_name),
            errors::EMPTY_FIELD,
        )),
        StatusCode::BAD_REQUEST,
    )
}

fn wrong_field_length(
    field_name: &str,
    field_size: usize,
    expected_size: usize,
) -> reply::WithStatus<reply::Json> {
    reply::with_status(
        warp::reply::json(&ApiError::new(
            format!(
                "Wrong {} field size. Expected {}, received {}",
                field_name, expected_size, field_size
            ),
            errors::WRONG_FIELD_SIZE,
        )),
        StatusCode::BAD_REQUEST,
    )
}

async fn register(
    data: RegisterData,
    mut grpc_conn: PublicTowerServicesClient<Channel>,
) -> std::result::Result<impl Reply, Rejection> {
    let user_id = data.user_id;
    if user_id.is_empty() {
        return Ok(empty_field("user_id"));
    }
    if user_id.len() != USER_ID_LEN {
        return Ok(wrong_field_length("user_id", user_id.len(), USER_ID_LEN));
    }

    let (body, status) = match grpc_conn
        .register(msgs::RegisterRequest {
            user_id: user_id.to_vec(),
        })
        .await
    {
        Ok(r) => {
            let body = r.into_inner();
            (
                warp::reply::json(&RegisterResponse {
                    user_id: body.user_id,
                    available_slots: body.available_slots,
                    subscription_expiry: body.subscription_expiry,
                    subscription_signature: body.subscription_signature,
                }),
                StatusCode::OK,
            )
        }
        Err(s) => {
            let error_code = match s.code() {
                Code::InvalidArgument => errors::WRONG_FIELD_FORMAT,
                Code::ResourceExhausted => errors::REGISTRATION_RESOURCE_EXHAUSTED,
                _ => {
                    log::debug!("Unexpected error ocurred: {}", s.message());
                    errors::UNEXPECTED_ERROR
                }
            };
            (
                warp::reply::json(&ApiError::new(s.message().into(), error_code)),
                StatusCode::BAD_REQUEST,
            )
        }
    };

    Ok(reply::with_status(body, status))
}

async fn add_appointment(
    data: AddAppointmentData,
    mut grpc_conn: PublicTowerServicesClient<Channel>,
) -> std::result::Result<impl Reply, Rejection> {
    let locator = data.appointment.locator;
    if locator.is_empty() {
        return Ok(empty_field("locator"));
    }
    if locator.len() != LOCATOR_LEN {
        return Ok(wrong_field_length("locator", locator.len(), LOCATOR_LEN));
    }
    if data.signature.is_empty() {
        return Ok(empty_field("signature"));
    }

    let (body, status) = match grpc_conn
        .add_appointment(msgs::AddAppointmentRequest {
            appointment: Some(msgs::Appointment {
                locator: locator.to_vec(),
                encrypted_blob: data.appointment.encrypted_blob,
                to_self_delay: data.appointment.to_self_delay,
            }),
            signature: data.signature,
        })
        .await
    {
        Ok(r) => {
            let body = r.into_inner();
            (
                warp::reply::json(&AddAppointmentResponse {
                    locator: body.locator,
                    start_block: body.start_block,
                    signature: body.signature,
                    available_slots: body.available_slots,
                    subscription_expiry: body.subscription_expiry,
                }),
                StatusCode::OK,
            )
        }
        Err(s) => {
            let error_code = match s.code() {
                Code::Unauthenticated => errors::INVALID_SIGNATURE_OR_SUBSCRIPTION_ERROR,
                Code::AlreadyExists => errors::APPOINTMENT_ALREADY_TRIGGERED,
                _ => {
                    log::debug!("Unexpected error ocurred: {}", s.message());
                    errors::UNEXPECTED_ERROR
                }
            };
            (
                warp::reply::json(&ApiError::new(s.message().into(), error_code)),
                StatusCode::BAD_REQUEST,
            )
        }
    };

    Ok(reply::with_status(body, status))
}

async fn get_appointment(
    data: GetAppointmentData,
    mut grpc_conn: PublicTowerServicesClient<Channel>,
) -> std::result::Result<impl Reply, Rejection> {
    let locator = data.locator;
    if locator.is_empty() {
        return Ok(empty_field("locator"));
    }
    if locator.len() != LOCATOR_LEN {
        return Ok(wrong_field_length("locator", locator.len(), LOCATOR_LEN));
    }
    if data.signature.is_empty() {
        return Ok(empty_field("signature"));
    }

    let (body, status) = match grpc_conn
        .get_appointment(msgs::GetAppointmentRequest {
            locator: locator.to_vec(),
            signature: data.signature,
        })
        .await
    {
        Ok(r) => {
            // This is a bit cumbersome but data is layered by gRPC due to it being either an Appointment or a Tracker
            let body = r.into_inner();
            let data = body.appointment_data.unwrap().appointment_data.unwrap();

            let appointment_or_tracker = match data {
                msgs::appointment_data::AppointmentData::Appointment(a) => {
                    AppointmentOrTracker::Appointment(Appointment {
                        locator,
                        encrypted_blob: a.encrypted_blob,
                        to_self_delay: a.to_self_delay,
                    })
                }
                msgs::appointment_data::AppointmentData::Tracker(t) => {
                    AppointmentOrTracker::Tracker(Tracker {
                        locator: t.locator,
                        dispute_txid: t.dispute_txid,
                        penalty_txid: t.penalty_txid,
                        penalty_rawtx: t.penalty_rawtx,
                    })
                }
            };
            (
                warp::reply::json(&GetAppointmentResponse {
                    appointment: appointment_or_tracker,
                    status: AppointmentStatus::from(body.status).to_string(),
                }),
                StatusCode::OK,
            )
        }
        Err(s) => {
            let (error_code, status_code) = match s.code() {
                Code::Unauthenticated | Code::NotFound => (
                    errors::INVALID_SIGNATURE_OR_SUBSCRIPTION_ERROR,
                    StatusCode::NOT_FOUND,
                ),
                _ => {
                    log::debug!("Unexpected error ocurred: {}", s.message());
                    (errors::UNEXPECTED_ERROR, StatusCode::BAD_REQUEST)
                }
            };
            (
                warp::reply::json(&ApiError::new(s.message().into(), error_code)),
                status_code,
            )
        }
    };

    Ok(reply::with_status(body, status))
}

async fn get_subscription_info(
    data: GetSubscriptionInfoData,
    mut grpc_conn: PublicTowerServicesClient<Channel>,
) -> std::result::Result<impl Reply, Rejection> {
    if data.signature.is_empty() {
        return Ok(empty_field("signature"));
    }

    let (body, status) = match grpc_conn
        .get_subscription_info(msgs::GetSubscriptionInfoRequest {
            signature: data.signature,
        })
        .await
    {
        Ok(r) => {
            let body = r.into_inner();
            let locators = body
                .locators
                .iter()
                .map(|locator| hex::encode(locator))
                .collect();
            (
                warp::reply::json(&SubscriptionInfoResponse {
                    available_slots: body.available_slots,
                    subscription_expiry: body.subscription_expiry,
                    locators: locators,
                }),
                StatusCode::OK,
            )
        }
        Err(s) => {
            let (error_code, status_code) = match s.code() {
                Code::Unauthenticated => (
                    errors::INVALID_SIGNATURE_OR_SUBSCRIPTION_ERROR,
                    StatusCode::NOT_FOUND,
                ),
                _ => {
                    log::debug!("Unexpected error ocurred: {}", s.message());
                    (errors::UNEXPECTED_ERROR, StatusCode::BAD_REQUEST)
                }
            };
            (
                warp::reply::json(&ApiError::new(s.message().into(), error_code)),
                status_code,
            )
        }
    };

    Ok(reply::with_status(body, status))
}

fn router(
    grpc_conn: PublicTowerServicesClient<Channel>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let register = warp::post()
        .and(warp::path("register"))
        .and(warp::body::content_length_limit(128).and(warp::body::json()))
        .and(with_grpc(grpc_conn.clone()))
        .and_then(register);

    let add_appointment = warp::post()
        .and(warp::path("add_appointment"))
        .and(warp::body::content_length_limit(1024).and(warp::body::json()))
        .and(with_grpc(grpc_conn.clone()))
        .and_then(add_appointment);

    let get_appointment = warp::post()
        .and(warp::path("get_appointment"))
        .and(warp::body::content_length_limit(192).and(warp::body::json()))
        .and(with_grpc(grpc_conn.clone()))
        .and_then(get_appointment);

    let get_subscription_info = warp::post()
        .and(warp::path("get_subscription_info"))
        .and(warp::body::content_length_limit(128).and(warp::body::json()))
        .and(with_grpc(grpc_conn))
        .and_then(get_subscription_info);

    let routes = register
        .or(add_appointment)
        .or(get_appointment)
        .or(get_subscription_info)
        .recover(|x| handle_rejection(x));

    routes
}

async fn handle_rejection(err: Rejection) -> Result<impl Reply, Rejection> {
    match err.find::<warp::body::BodyDeserializeError>() {
        Some(e) => {
            let error = e
                .source()
                .map(|cause| cause.to_string())
                .unwrap_or_else(|| "Invalid Body".to_string());

            let error_code = if error.contains("invalid type") {
                errors::WRONG_FIELD_TYPE
            } else if error.contains("missing field") {
                errors::MISSING_FIELD
            } else if error.contains("Odd number of digits") | error.contains("Invalid character") {
                errors::WRONG_FIELD_FORMAT
            } else {
                errors::INVALID_REQUEST_FORMAT
            };
            Ok(reply::with_status(
                warp::reply::json(&ApiError { error, error_code }),
                StatusCode::BAD_REQUEST,
            ))
        }
        None => Err(err),
    }
}

pub async fn serve(http_bind: SocketAddr, grpc_bind: String, shutdown_signal: Listener) {
    let grpc_conn = PublicTowerServicesClient::connect(grpc_bind).await.unwrap();
    let (_, server) = warp::serve(router(grpc_conn))
        .bind_with_graceful_shutdown(http_bind, async { shutdown_signal.await });
    server.await
}

#[cfg(test)]
mod test_helpers {
    use super::*;

    use serde::de::DeserializeOwned;
    use serde_json::Value;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tonic::transport::Server;

    use crate::api::internal::InternalAPI;
    use crate::protos::public_tower_services_server::PublicTowerServicesServer;
    use crate::test_utils::{create_api_with_config, ApiConfig};

    pub enum RequestBody<'a> {
        Jsonify(&'a str),
        DoNotJsonify(&'a str),
        Json(Value),
        Body(&'a str),
    }

    pub(crate) async fn run_tower_in_background_with_config(
        api_config: ApiConfig,
    ) -> (SocketAddr, Arc<InternalAPI>) {
        let internal_rpc_api = create_api_with_config(api_config).await;
        let cloned = internal_rpc_api.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            Server::builder()
                .add_service(PublicTowerServicesServer::new(internal_rpc_api))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        (addr, cloned)
    }

    pub(crate) async fn run_tower_in_background() -> SocketAddr {
        run_tower_in_background_with_config(ApiConfig::default())
            .await
            .0
    }

    pub(crate) async fn check_api_error<'a>(
        endpoint: &str,
        body: RequestBody<'a>,
        server_addr: SocketAddr,
    ) -> (ApiError, StatusCode) {
        let grpc_conn = PublicTowerServicesClient::connect(format!(
            "http://{}:{}",
            server_addr.ip(),
            server_addr.port()
        ))
        .await
        .unwrap();

        let req = match body {
            RequestBody::Json(j) => warp::test::request().method("POST").path(endpoint).json(&j),
            RequestBody::DoNotJsonify(j) => {
                warp::test::request().method("POST").path(endpoint).json(&j)
            }
            RequestBody::Jsonify(j) => warp::test::request()
                .method("POST")
                .path(endpoint)
                .json(&serde_json::from_str::<Value>(j).unwrap()),
            RequestBody::Body(b) => warp::test::request().method("POST").path(endpoint).body(b),
        };

        let res = req.reply(&router(grpc_conn)).await;

        (
            serde_json::from_slice::<ApiError>(res.body()).unwrap(),
            res.status(),
        )
    }

    pub(crate) async fn request_to_api<B, T>(
        endpoint: &str,
        body: B,
        server_addr: SocketAddr,
    ) -> Result<T, serde_json::Error>
    where
        B: Serialize,
        T: DeserializeOwned,
    {
        let grpc_conn = PublicTowerServicesClient::connect(format!(
            "http://{}:{}",
            server_addr.ip(),
            server_addr.port()
        ))
        .await
        .unwrap();

        let res = warp::test::request()
            .method("POST")
            .path(endpoint)
            .json(&serde_json::json!(body))
            .reply(&router(grpc_conn))
            .await;

        serde_json::from_slice::<T>(res.body())
    }
}

#[cfg(test)]
mod tests_failures {
    use super::*;

    use super::test_helpers::{check_api_error, run_tower_in_background, RequestBody};
    use crate::test_utils::get_random_user_id;

    #[tokio::test]
    async fn test_no_json_request_body() {
        let server_addr = run_tower_in_background().await;
        let (api_error, status) =
            check_api_error("/register", RequestBody::Body(""), server_addr).await;
        assert!(api_error.error.contains("EOF while parsing"));
        assert_eq!(api_error.error_code, errors::INVALID_REQUEST_FORMAT);
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_wrong_json_request_body() {
        let server_addr = run_tower_in_background().await;
        let (api_error, status) =
            check_api_error("/register", RequestBody::DoNotJsonify(""), server_addr).await;
        assert!(api_error.error.contains("expected struct"));
        // FIXME: This may need finer catching since it's the same error as if a field cannot be deserialized from being of the wrong type.
        // May not be worth the hassle though.
        assert_eq!(api_error.error_code, errors::WRONG_FIELD_TYPE);
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_empty_json_request_body() {
        let server_addr = run_tower_in_background().await;
        let (api_error, status) =
            check_api_error("/register", RequestBody::Jsonify(r#"{}"#), server_addr).await;
        assert!(api_error.error.contains("missing field"));
        assert_eq!(api_error.error_code, errors::MISSING_FIELD);
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_empty_field() {
        let server_addr = run_tower_in_background().await;
        let (api_error, status) = check_api_error(
            "/register",
            RequestBody::Jsonify(r#"{"user_id": ""}"#),
            server_addr,
        )
        .await;
        assert!(api_error.error.contains("field is empty"));
        assert_eq!(api_error.error_code, errors::EMPTY_FIELD);
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_wrong_field_hex_encoding_odd() {
        let server_addr = run_tower_in_background().await;
        let (api_error, status) = check_api_error(
            "/register",
            RequestBody::Jsonify(r#"{"user_id": "a"}"#),
            server_addr,
        )
        .await;
        assert!(api_error.error.contains("Odd number of digits"));
        assert_eq!(api_error.error_code, errors::WRONG_FIELD_FORMAT);
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_wrong_hex_encoding_character() {
        let server_addr = run_tower_in_background().await;
        let (api_error, status) =
        check_api_error("/register",  
        RequestBody::Jsonify(r#"{"user_id": "022fa2900ed7fc07b4e8ca3ea081e846245b0497944644aa78ea0b994ac22074dZ"}"#),
        server_addr
    ).await;

        assert!(api_error.error.contains("Invalid character"));
        assert_eq!(api_error.error_code, errors::WRONG_FIELD_FORMAT);
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_wrong_field_size() {
        let server_addr = run_tower_in_background().await;
        let (api_error, status) = check_api_error(
            "/register",
            RequestBody::Jsonify(r#"{"user_id": "aa"}"#),
            server_addr,
        )
        .await;

        assert!(api_error.error.contains("Wrong user_id field size"));
        assert_eq!(api_error.error_code, errors::WRONG_FIELD_SIZE);
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_wrong_field_type() {
        let server_addr = run_tower_in_background().await;
        let (api_error, status) = check_api_error(
            "/register",
            RequestBody::DoNotJsonify(r#"{"user_id": 1}"#),
            server_addr,
        )
        .await;
        assert!(api_error.error.contains("invalid type"));
        assert_eq!(api_error.error_code, errors::WRONG_FIELD_TYPE);
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_request_missing_field() {
        // We'll use a different endpoint here since we need a json object with more than one field
        let server_addr = run_tower_in_background().await;
        let (api_error, status) = check_api_error(
            "/add_appointment",
            RequestBody::Jsonify(r#"{"signature": "aa"}"#),
            server_addr,
        )
        .await;
        assert!(api_error.error.contains("missing field"));
        assert_eq!(api_error.error_code, errors::MISSING_FIELD);
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // Tests with no json body return (passed trough handle_rejection)

    #[tokio::test]
    async fn test_empty_request_body() {
        let server_addr = run_tower_in_background().await;
        let grpc_conn = PublicTowerServicesClient::connect(format!(
            "http://{}:{}",
            server_addr.ip(),
            server_addr.port()
        ))
        .await
        .unwrap();

        let res = warp::test::request()
            .method("POST")
            .path("/register")
            .reply(&router(grpc_conn))
            .await;

        assert_eq!(res.status(), StatusCode::LENGTH_REQUIRED)
    }

    #[tokio::test]
    async fn test_payload_too_large() {
        let server_addr = run_tower_in_background().await;
        let grpc_conn = PublicTowerServicesClient::connect(format!(
            "http://{}:{}",
            server_addr.ip(),
            server_addr.port()
        ))
        .await
        .unwrap();

        let res = warp::test::request()
            .method("POST")
            .path("/register")
            .json(&format!("{}{}", get_random_user_id(), get_random_user_id()))
            .reply(&router(grpc_conn))
            .await;

        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE)
    }

    #[tokio::test]
    async fn test_wrong_endpoint() {
        let server_addr = run_tower_in_background().await;
        let grpc_conn = PublicTowerServicesClient::connect(format!(
            "http://{}:{}",
            server_addr.ip(),
            server_addr.port()
        ))
        .await
        .unwrap();

        let res = warp::test::request()
            .method("POST")
            .path("/")
            .json(&"")
            .reply(&router(grpc_conn))
            .await;

        assert_eq!(res.status(), StatusCode::NOT_FOUND)
    }

    #[tokio::test]
    async fn test_wrong_method() {
        let server_addr = run_tower_in_background().await;
        let grpc_conn = PublicTowerServicesClient::connect(format!(
            "http://{}:{}",
            server_addr.ip(),
            server_addr.port()
        ))
        .await
        .unwrap();

        let res = warp::test::request()
            .path("/")
            .json(&"")
            .reply(&router(grpc_conn))
            .await;

        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED)
    }
}

#[cfg(test)]
mod tests_methods {
    use super::*;

    use super::test_helpers::{
        check_api_error, request_to_api, run_tower_in_background,
        run_tower_in_background_with_config, RequestBody,
    };
    use crate::extended_appointment::UUID;
    use crate::test_utils::{generate_dummy_appointment, get_random_user_id, ApiConfig, DURATION};
    use teos_common::{cryptography, UserId};

    impl std::convert::From<teos_common::appointment::Appointment> for Appointment {
        fn from(a: teos_common::appointment::Appointment) -> Self {
            Appointment {
                locator: a.locator.serialize(),
                encrypted_blob: a.encrypted_blob,
                to_self_delay: a.to_self_delay,
            }
        }
    }

    #[tokio::test]
    async fn test_register() {
        let server_addr = run_tower_in_background().await;
        let response = request_to_api::<RegisterData, RegisterResponse>(
            "/register",
            RegisterData {
                user_id: get_random_user_id().serialize(),
            },
            server_addr,
        )
        .await;
        assert!(matches!(response, Ok(RegisterResponse { .. })));
    }

    #[tokio::test]
    async fn test_register_max_slots() {
        let (server_addr, _) =
            run_tower_in_background_with_config(ApiConfig::new(u32::MAX, DURATION)).await;
        let user_id = get_random_user_id();

        // Register once, this should go trough and set slots to the limit
        request_to_api::<RegisterData, RegisterResponse>(
            "/register",
            RegisterData {
                user_id: user_id.serialize(),
            },
            server_addr,
        )
        .await
        .unwrap();

        // Register again to get additional slots, this should fail
        assert_eq!(
            check_api_error(
                "/register",
                RequestBody::Json(serde_json::json!(RegisterData {
                    user_id: user_id.serialize(),
                })),
                server_addr,
            )
            .await,
            (
                ApiError::new(
                    "Subscription maximum slots count reached".into(),
                    errors::REGISTRATION_RESOURCE_EXHAUSTED
                ),
                StatusCode::BAD_REQUEST
            )
        );
    }

    #[tokio::test]
    async fn test_add_appointment() {
        let server_addr = run_tower_in_background().await;

        // Register first
        let (user_sk, user_pk) = cryptography::get_random_keypair();
        request_to_api::<RegisterData, RegisterResponse>(
            "/register",
            RegisterData {
                user_id: user_pk.serialize().to_vec(),
            },
            server_addr,
        )
        .await
        .unwrap();

        // Then try to add an appointment
        let appointment = generate_dummy_appointment(None).inner;
        let signature = cryptography::sign(&appointment.serialize(), &user_sk).unwrap();

        let response = request_to_api::<AddAppointmentData, AddAppointmentResponse>(
            "/add_appointment",
            AddAppointmentData {
                appointment: appointment.into(),
                signature,
            },
            server_addr,
        )
        .await;

        assert!(matches!(response, Ok(AddAppointmentResponse { .. })));
    }

    #[tokio::test]
    async fn test_add_appointment_non_registered() {
        let server_addr = run_tower_in_background().await;
        let (user_sk, _) = cryptography::get_random_keypair();
        let appointment = generate_dummy_appointment(None).inner;
        let signature = cryptography::sign(&appointment.serialize(), &user_sk).unwrap();

        assert_eq!(
            check_api_error(
                "/add_appointment",
                RequestBody::Json(serde_json::json!(AddAppointmentData {
                    appointment: appointment.into(),
                    signature,
                })),
                server_addr,
            )
            .await,
            (
                ApiError::new(
                    "Invalid signature or user does not have enough slots available".into(),
                    errors::INVALID_SIGNATURE_OR_SUBSCRIPTION_ERROR
                ),
                StatusCode::BAD_REQUEST
            )
        );
    }

    #[tokio::test]
    async fn test_add_appointment_already_triggered() {
        // Get the InternalAPI so we can mess with the inner state
        let (server_addr, internal_api) =
            run_tower_in_background_with_config(ApiConfig::new(u32::MAX, DURATION)).await;

        // Register
        let (user_sk, user_pk) = cryptography::get_random_keypair();
        request_to_api::<RegisterData, RegisterResponse>(
            "/register",
            RegisterData {
                user_id: user_pk.serialize().to_vec(),
            },
            server_addr,
        )
        .await
        .unwrap();

        // Add the appointment to the Responder so it counts as triggered
        let appointment = generate_dummy_appointment(None).inner;
        let signature = cryptography::sign(&appointment.serialize(), &user_sk).unwrap();
        internal_api
            .get_watcher()
            .add_random_tracker_to_responder(UUID::new(appointment.locator, UserId(user_pk)));

        // Try to add it via the http API
        assert_eq!(
            check_api_error(
                "/add_appointment",
                RequestBody::Json(serde_json::json!(AddAppointmentData {
                    appointment: appointment.into(),
                    signature,
                })),
                server_addr,
            )
            .await,
            (
                ApiError::new(
                    "The provided appointment has already been triggered".into(),
                    errors::APPOINTMENT_ALREADY_TRIGGERED
                ),
                StatusCode::BAD_REQUEST
            )
        );
    }

    #[tokio::test]
    async fn test_get_appointment() {
        let server_addr = run_tower_in_background().await;

        // Register first
        let (user_sk, user_pk) = cryptography::get_random_keypair();
        request_to_api::<RegisterData, RegisterResponse>(
            "/register",
            RegisterData {
                user_id: user_pk.serialize().to_vec(),
            },
            server_addr,
        )
        .await
        .unwrap();

        // Add an appointment
        let appointment = generate_dummy_appointment(None).inner;
        let signature = cryptography::sign(&appointment.serialize(), &user_sk).unwrap();

        request_to_api::<AddAppointmentData, AddAppointmentResponse>(
            "/add_appointment",
            AddAppointmentData {
                appointment: appointment.clone().into(),
                signature,
            },
            server_addr,
        )
        .await
        .unwrap();

        // Get it back
        let response = request_to_api::<GetAppointmentData, GetAppointmentResponse>(
            "/get_appointment",
            GetAppointmentData {
                locator: appointment.locator.serialize(),
                signature: cryptography::sign(
                    format!("get appointment {}", appointment.locator).as_bytes(),
                    &user_sk,
                )
                .unwrap(),
            },
            server_addr,
        )
        .await;

        assert!(matches!(response, Ok(GetAppointmentResponse { .. })));
    }

    #[tokio::test]
    async fn test_get_appointment_non_registered() {
        let server_addr = run_tower_in_background().await;

        // User is not registered
        let (user_sk, _) = cryptography::get_random_keypair();
        // Appointment hasn't been added either, but the user check comes first
        let appointment = generate_dummy_appointment(None).inner;

        assert_eq!(
            check_api_error(
                "/get_appointment",
                RequestBody::Json(serde_json::json!(GetAppointmentData {
                    locator: appointment.locator.serialize(),
                    signature: cryptography::sign(
                        format!("get appointment {}", appointment.locator).as_bytes(),
                        &user_sk,
                    )
                    .unwrap()
                })),
                server_addr,
            )
            .await,
            (
                ApiError::new(
                    "Appointment not found".into(),
                    errors::INVALID_SIGNATURE_OR_SUBSCRIPTION_ERROR
                ),
                StatusCode::NOT_FOUND
            )
        );
    }

    #[tokio::test]
    async fn test_get_appointment_not_found() {
        let server_addr = run_tower_in_background().await;

        // Register first
        let (user_sk, user_pk) = cryptography::get_random_keypair();
        request_to_api::<RegisterData, RegisterResponse>(
            "/register",
            RegisterData {
                user_id: user_pk.serialize().to_vec(),
            },
            server_addr,
        )
        .await
        .unwrap();

        // Appointment hasn't been added
        let appointment = generate_dummy_appointment(None).inner;

        assert_eq!(
            check_api_error(
                "/get_appointment",
                RequestBody::Json(serde_json::json!(GetAppointmentData {
                    locator: appointment.locator.serialize(),
                    signature: cryptography::sign(
                        format!("get appointment {}", appointment.locator).as_bytes(),
                        &user_sk,
                    )
                    .unwrap()
                })),
                server_addr,
            )
            .await,
            (
                ApiError::new(
                    "Appointment not found".into(),
                    errors::INVALID_SIGNATURE_OR_SUBSCRIPTION_ERROR
                ),
                StatusCode::NOT_FOUND
            )
        );
    }

    #[tokio::test]
    async fn test_get_subscription_info() {
        let server_addr = run_tower_in_background().await;

        // Register first
        let (user_sk, user_pk) = cryptography::get_random_keypair();
        request_to_api::<RegisterData, RegisterResponse>(
            "/register",
            RegisterData {
                user_id: user_pk.serialize().to_vec(),
            },
            server_addr,
        )
        .await
        .unwrap();

        // Get the subscription info
        let response = request_to_api::<GetSubscriptionInfoData, SubscriptionInfoResponse>(
            "/get_subscription_info",
            GetSubscriptionInfoData {
                signature: cryptography::sign("get subscription info".as_bytes(), &user_sk)
                    .unwrap(),
            },
            server_addr,
        )
        .await;

        assert!(matches!(response, Ok(SubscriptionInfoResponse { .. })));
    }

    #[tokio::test]
    async fn test_get_subscription_info_non_registered() {
        let server_addr = run_tower_in_background().await;

        // User is not registered
        let (user_sk, _) = cryptography::get_random_keypair();

        assert_eq!(
            check_api_error(
                "/get_subscription_info",
                RequestBody::Json(serde_json::json!(GetSubscriptionInfoData {
                    signature: cryptography::sign("get subscription info".as_bytes(), &user_sk)
                        .unwrap(),
                })),
                server_addr,
            )
            .await,
            (
                ApiError::new(
                    "User not found. Have you registered?".into(),
                    errors::INVALID_SIGNATURE_OR_SUBSCRIPTION_ERROR
                ),
                StatusCode::NOT_FOUND
            )
        );
    }
}
