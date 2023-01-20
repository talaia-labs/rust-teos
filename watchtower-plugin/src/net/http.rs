use reqwest::Response;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use teos_common::appointment::Appointment;
use teos_common::cryptography;
use teos_common::net::NetAddr;
use teos_common::protos as common_msgs;
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::{TowerId, UserId};

use crate::net::ProxyInfo;
use crate::MisbehaviorProof;

/// Represents a generic api response.
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum ApiResponse<T> {
    Response(T),
    Error(ApiError),
}

/// API errors that can be received when interacting with the tower. Error codes match `teos_common::errors`.
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

/// Handles the logic of interacting with the `register` endpoint of the tower.
pub async fn register(
    tower_id: TowerId,
    user_id: UserId,
    tower_net_addr: &NetAddr,
    proxy: &Option<ProxyInfo>,
) -> Result<RegistrationReceipt, RequestError> {
    log::info!("Registering in the Eye of Satoshi (tower_id={})", tower_id);
    process_post_response(
        post_request(
            tower_net_addr,
            "register",
            &common_msgs::RegisterRequest {
                user_id: user_id.to_vec(),
            },
            proxy,
        )
        .await,
    )
    .await
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

/// Encapsulates the logging and response parsing of sending and appointment to the tower.
pub async fn add_appointment(
    tower_id: TowerId,
    tower_net_addr: &NetAddr,
    proxy: &Option<ProxyInfo>,
    appointment: &Appointment,
    signature: &str,
) -> Result<(u32, AppointmentReceipt), AddAppointmentError> {
    log::debug!(
        "Sending appointment {} to tower {}",
        appointment.locator,
        tower_id
    );
    let (response, receipt) =
        send_appointment(tower_id, tower_net_addr, proxy, appointment, signature).await?;
    log::debug!("Appointment accepted and signed by {}", tower_id);
    log::debug!("Remaining slots: {}", response.available_slots);
    log::debug!("Start block: {}", response.start_block);

    Ok((response.available_slots, receipt))
}

/// Handles the logic of interacting with the `add_appointment` endpoint of the tower.
pub async fn send_appointment(
    tower_id: TowerId,
    tower_net_addr: &NetAddr,
    proxy: &Option<ProxyInfo>,
    appointment: &Appointment,
    signature: &str,
) -> Result<(common_msgs::AddAppointmentResponse, AppointmentReceipt), AddAppointmentError> {
    let request_data = common_msgs::AddAppointmentRequest {
        appointment: Some(appointment.clone().into()),
        signature: signature.to_owned(),
    };

    match process_post_response(
        post_request(tower_net_addr, "add_appointment", &request_data, proxy).await,
    )
    .await?
    {
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

/// Generic function to post different types of requests to the tower.
pub async fn post_request<S: Serialize>(
    tower_net_addr: &NetAddr,
    endpoint: &str,
    data: S,
    proxy: &Option<ProxyInfo>,
) -> Result<Response, RequestError> {
    let client = if let Some(proxy) = proxy {
        if proxy.always_use || tower_net_addr.is_onion() {
            reqwest::Client::builder()
                .proxy(
                    reqwest::Proxy::http(proxy.get_socks_addr())
                        .map_err(|e| RequestError::ConnectionError(format!("{}", e)))?,
                )
                .build()
                .map_err(|e| RequestError::ConnectionError(format!("{}", e)))?
        } else {
            reqwest::Client::new()
        }
    } else {
        // If there is no proxy we only build the client as long as the address is not onion
        if tower_net_addr.is_onion() {
            return Err(RequestError::ConnectionError(
                "Cannot connect to an onion address without a proxy".to_owned(),
            ));
        }
        reqwest::Client::new()
    };

    client
        .post(format!("{}/{}", tower_net_addr.net_addr(), endpoint))
        .json(&data)
        .send()
        .await
        .map_err(|e| {
            log::debug!("An error ocurred when sending data to the tower: {}", e);
            if e.is_connect() | e.is_timeout() {
                RequestError::ConnectionError(
                    "Cannot connect to the tower. Connection refused".to_owned(),
                )
            } else {
                RequestError::Unexpected(
                    "Unexpected error ocurred (see logs for more info)".to_owned(),
                )
            }
        })
}

/// Generic function to process the response of a given post request.
pub async fn process_post_response<T: DeserializeOwned>(
    post_request: Result<Response, RequestError>,
) -> Result<T, RequestError> {
    // TODO: Check if this can be switched for a map. Not sure how to handle async with maps
    match post_request {
        Ok(r) => r.json().await.map_err(|e| {
            RequestError::DeserializeError(format!("Unexpected response body. Error: {}", e))
        }),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use serde_json::json;

    use crate::test_utils::get_dummy_add_appointment_response;
    use teos_common::test_utils::{
        generate_random_appointment, get_random_appointment_receipt,
        get_random_registration_receipt, get_random_user_id,
    };

    mod request_error {
        use super::*;

        #[test]
        fn test_is_connection() {
            let error_message = "error_msg";
            for error in [
                RequestError::ConnectionError(error_message.to_owned()),
                RequestError::DeserializeError(error_message.to_owned()),
                RequestError::Unexpected(error_message.to_owned()),
            ] {
                if error == RequestError::ConnectionError(error_message.to_owned()) {
                    assert!(error.is_connection())
                } else {
                    assert!(!error.is_connection())
                }
            }
        }
    }

    #[tokio::test]
    async fn test_register() {
        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let mut registration_receipt = get_random_registration_receipt();
        registration_receipt.sign(&tower_sk);

        let server = MockServer::start();
        let api_mock = server.mock(|when, then| {
            when.method(POST).path("/register");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!(registration_receipt));
        });

        let receipt = register(
            TowerId(tower_pk),
            registration_receipt.user_id(),
            &NetAddr::new(server.base_url()),
            &None,
        )
        .await
        .unwrap();

        api_mock.assert();
        assert_eq!(receipt, registration_receipt);
    }

    #[tokio::test]
    async fn test_register_connection_error() {
        let error = register(
            get_random_user_id(),
            get_random_user_id(),
            &NetAddr::new("http://server_addr".to_owned()),
            &None,
        )
        .await
        .unwrap_err();

        assert!(matches!(error, RequestError::ConnectionError { .. }))
    }

    #[tokio::test]
    async fn test_register_deserialize_error() {
        let server = MockServer::start();
        let api_mock = server.mock(|when, then| {
            when.method(POST).path("/register");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!([]));
        });

        let error = register(
            get_random_user_id(),
            get_random_user_id(),
            &NetAddr::new(server.base_url()),
            &None,
        )
        .await
        .unwrap_err();

        api_mock.assert();
        assert!(matches!(error, RequestError::DeserializeError { .. }))
    }

    #[tokio::test]
    async fn test_add_appointment() {
        // `add_appointment` is basically a pass trough function for `send_appointment` with some logging and a parse of the outputs
        // in case there are no errors. All the error cases will be tested in `send_appointment`.
        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let appointment = generate_random_appointment(None);

        let appointment_receipt = get_random_appointment_receipt(tower_sk);
        let add_appointment_response =
            get_dummy_add_appointment_response(appointment.locator, &appointment_receipt);

        let server = MockServer::start();
        let api_mock = server.mock(|when, then| {
            when.method(POST).path("/add_appointment");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!(add_appointment_response));
        });

        let (response, receipt) = add_appointment(
            TowerId(tower_pk),
            &NetAddr::new(server.base_url()),
            &None,
            &appointment,
            appointment_receipt.user_signature(),
        )
        .await
        .unwrap();

        api_mock.assert();
        assert_eq!(response, add_appointment_response.available_slots);
        assert_eq!(receipt, appointment_receipt);
    }

    #[tokio::test]
    async fn test_send_appointment() {
        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let appointment = generate_random_appointment(None);

        let appointment_receipt = get_random_appointment_receipt(tower_sk);
        let add_appointment_response =
            get_dummy_add_appointment_response(appointment.locator, &appointment_receipt);

        let server = MockServer::start();
        let api_mock = server.mock(|when, then| {
            when.method(POST).path("/add_appointment");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!(add_appointment_response));
        });

        let (response, receipt) = send_appointment(
            TowerId(tower_pk),
            &NetAddr::new(server.base_url()),
            &None,
            &appointment,
            appointment_receipt.user_signature(),
        )
        .await
        .unwrap();

        api_mock.assert();
        assert_eq!(response, add_appointment_response);
        assert_eq!(receipt, appointment_receipt);
    }

    #[tokio::test]
    async fn test_send_appointment_misbehaving() {
        let (sybil_tower_sk, sibyl_tower_pk) = cryptography::get_random_keypair();
        let appointment = generate_random_appointment(None);

        let appointment_receipt = get_random_appointment_receipt(sybil_tower_sk);
        let add_appointment_response =
            get_dummy_add_appointment_response(appointment.locator, &appointment_receipt);

        let server = MockServer::start();
        let api_mock = server.mock(|when, then| {
            when.method(POST).path("/add_appointment");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!(add_appointment_response));
        });

        let tower_id = get_random_user_id();
        let error = send_appointment(
            tower_id,
            &NetAddr::new(server.base_url()),
            &None,
            &appointment,
            appointment_receipt.user_signature(),
        )
        .await
        .unwrap_err();

        api_mock.assert();
        if let AddAppointmentError::SignatureError(proof) = error {
            assert_eq!(
                MisbehaviorProof::new(
                    appointment.locator,
                    appointment_receipt,
                    TowerId(sibyl_tower_pk)
                ),
                proof
            )
        } else {
            panic!("SignatureError was expected")
        }
    }

    #[tokio::test]
    async fn test_send_appointment_connection_error() {
        let error = send_appointment(
            get_random_user_id(),
            &NetAddr::new("http://server_addr".to_owned()),
            &None,
            &generate_random_appointment(None),
            "user_sig",
        )
        .await
        .unwrap_err();

        if let AddAppointmentError::RequestError(e) = error {
            assert!(matches!(e, RequestError::ConnectionError { .. }))
        } else {
            panic!("ConnectionError was expected")
        }
    }

    #[tokio::test]
    async fn test_send_appointment_deserialize_error() {
        let server = MockServer::start();
        let api_mock = server.mock(|when, then| {
            when.method(POST).path("/add_appointment");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!([]));
        });

        let error = send_appointment(
            get_random_user_id(),
            &NetAddr::new(server.base_url()),
            &None,
            &generate_random_appointment(None),
            "user_sig",
        )
        .await
        .unwrap_err();

        api_mock.assert();
        if let AddAppointmentError::RequestError(e) = error {
            assert!(matches!(e, RequestError::DeserializeError { .. }))
        } else {
            panic!("DeserializeError was expected")
        }
    }

    #[tokio::test]
    async fn test_send_appointment_api_error() {
        let api_error = ApiError {
            error: "error_msg".to_owned(),
            error_code: 1,
        };

        let server = MockServer::start();
        let api_mock = server.mock(|when, then| {
            when.method(POST).path("/add_appointment");
            then.status(400)
                .header("content-type", "application/json")
                .json_body(json!(api_error));
        });

        let error = send_appointment(
            get_random_user_id(),
            &NetAddr::new(server.base_url()),
            &None,
            &generate_random_appointment(None),
            "user_sig",
        )
        .await
        .unwrap_err();

        api_mock.assert();
        assert!(matches!(error, AddAppointmentError::ApiError { .. }));
    }

    #[tokio::test]
    async fn test_post_request() {
        let server = MockServer::start();
        let api_mock = server.mock(|when, then| {
            when.method(POST);
            then.status(200).header("content-type", "application/json");
        });

        let response = post_request(&NetAddr::new(server.base_url()), "", json!(""), &None)
            .await
            .unwrap();

        api_mock.assert();
        assert!(matches!(response, Response { .. }));
    }

    #[tokio::test]
    async fn test_post_request_connection_error() {
        assert!(matches!(
            post_request(
                &NetAddr::new("http://unreachable_url".to_owned()),
                "",
                json!(""),
                &None,
            )
            .await
            .unwrap_err(),
            RequestError::ConnectionError { .. }
        ));
    }

    #[tokio::test]
    async fn test_process_post_response_json_error() {
        // `process_post_response` is a pass-trough function that maps json deserialization errors from `post_request`.
        // So just testing that specific case should be enough.
        let server = MockServer::start();
        let api_mock = server.mock(|when, then| {
            when.method(POST);
            then.status(200).header("content-type", "application/json");
        });

        // Any expected response work here as long as it cannot be properly deserialized
        let error = process_post_response::<ApiResponse<common_msgs::GetAppointmentResponse>>(
            post_request(&NetAddr::new(server.base_url()), "", json!(""), &None).await,
        )
        .await
        .unwrap_err();

        api_mock.assert();
        assert!(matches!(error, RequestError::DeserializeError { .. }));
    }
}
