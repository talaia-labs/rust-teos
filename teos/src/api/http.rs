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
) -> impl Filter<Extract = impl Reply, Error = Infallible> + Clone {
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

async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    if err.is_not_found() {
        return Ok(reply::with_status(
            warp::reply::json(&"Not found"),
            StatusCode::NOT_FOUND,
        ));
    }

    let (body, status) = if let Some(e) = err.find::<warp::body::BodyDeserializeError>() {
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
        (
            warp::reply::json(&ApiError { error, error_code }),
            StatusCode::BAD_REQUEST,
        )
    } else if let Some(_) = err.find::<warp::reject::PayloadTooLarge>() {
        (
            warp::reply::json(&ApiError::new(
                "Payload too large".into(),
                errors::INVALID_REQUEST_FORMAT,
            )),
            StatusCode::PAYLOAD_TOO_LARGE,
        )
    } else if let Some(_) = err.find::<warp::reject::LengthRequired>() {
        (
            warp::reply::json(&ApiError::new(
                "Empty request body".into(),
                errors::INVALID_REQUEST_FORMAT,
            )),
            StatusCode::LENGTH_REQUIRED,
        )
    } else if let Some(_) = err.find::<warp::reject::MethodNotAllowed>() {
        (
            warp::reply::json(&ApiError::new(
                "Method not allowed".into(),
                errors::INVALID_REQUEST_FORMAT,
            )),
            StatusCode::METHOD_NOT_ALLOWED,
        )
    } else {
        (
            warp::reply::json(&ApiError::new(
                format!("Unexpected error: {:?}", err),
                errors::INVALID_REQUEST_FORMAT,
            )),
            StatusCode::BAD_REQUEST,
        )
    };

    Ok(reply::with_status(body, status))
}

pub async fn serve(http_bind: SocketAddr, grpc_bind: String, shutdown_signal: Listener) {
    let grpc_conn = PublicTowerServicesClient::connect(grpc_bind).await.unwrap();
    let (_, server) = warp::serve(router(grpc_conn))
        .bind_with_graceful_shutdown(http_bind, async { shutdown_signal.await });
    server.await
}
