use reqwest::{Method, Response};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use teos_common::appointment::Appointment;
use teos_common::cryptography;
use teos_common::net::http::Endpoint;
use teos_common::net::NetAddr;
use teos_common::protos as common_msgs;
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::{TowerId, UserId};

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
) -> Result<RegistrationReceipt, RequestError> {
    log::info!("Registering in the Eye of Satoshi (tower_id={tower_id})");
    process_post_response(
        post_request(
            tower_net_addr,
            Endpoint::Register,
            &common_msgs::RegisterRequest {
                user_id: user_id.to_vec(),
            },
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
    appointment: &Appointment,
    signature: &str,
) -> Result<(u32, AppointmentReceipt), AddAppointmentError> {
    log::debug!(
        "Sending appointment {} to tower {tower_id}",
        appointment.locator
    );
    let (response, receipt) =
        send_appointment(tower_id, tower_net_addr, appointment, signature).await?;
    log::debug!("Appointment accepted and signed by {tower_id}");
    log::debug!("Remaining slots: {}", response.available_slots);
    log::debug!("Start block: {}", response.start_block);

    Ok((response.available_slots, receipt))
}

/// Handles the logic of interacting with the `add_appointment` endpoint of the tower.
pub async fn send_appointment(
    tower_id: TowerId,
    tower_net_addr: &NetAddr,
    appointment: &Appointment,
    signature: &str,
) -> Result<(common_msgs::AddAppointmentResponse, AppointmentReceipt), AddAppointmentError> {
    let request_data = common_msgs::AddAppointmentRequest {
        appointment: Some(appointment.clone().into()),
        signature: signature.to_owned(),
    };

    match process_post_response(
        post_request(
            tower_net_addr,
            Endpoint::AddAppointment,
            &request_data,
        )
        .await,
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

/// A generic function to send a request to a tower.
async fn request<S: Serialize>(
    tower_net_addr: &NetAddr,
    endpoint: Endpoint,
    method: Method,
    data: Option<S>,
) -> Result<Response, RequestError> {
    // If there is no proxy we only build the client as long as the address is not onion
    if tower_net_addr.is_onion() {
        return Err(RequestError::ConnectionError(
            "Cannot connect to an onion address without a proxy".to_owned(),
        ));
    }
    let client = reqwest::Client::new();

    let mut request_builder = client.request(
        method,
        format!("{}{}", tower_net_addr.net_addr(), endpoint.path()),
    );

    if let Some(data) = data {
        request_builder = request_builder.json(&data);
    }

    request_builder.send().await.map_err(|e| {
        log::debug!("An error ocurred when sending data to the tower: {e}");
        if e.is_connect() | e.is_timeout() {
            RequestError::ConnectionError(
                "Cannot connect to the tower. Connection refused".to_owned(),
            )
        } else {
            RequestError::Unexpected("Unexpected error ocurred (see logs for more info)".to_owned())
        }
    })
}

pub async fn post_request<S: Serialize>(
    tower_net_addr: &NetAddr,
    endpoint: Endpoint,
    data: S,
) -> Result<Response, RequestError> {
    request(tower_net_addr, endpoint, Method::POST, Some(data)).await
}

pub async fn get_request(
    tower_net_addr: &NetAddr,
    endpoint: Endpoint,
) -> Result<Response, RequestError> {
    request::<()>(tower_net_addr, endpoint, Method::GET, None).await
}

/// Generic function to process the response of a given post request.
pub async fn process_post_response<T: DeserializeOwned>(
    post_request: Result<Response, RequestError>,
) -> Result<T, RequestError> {
    // TODO: Check if this can be switched for a map. Not sure how to handle async with maps
    match post_request {
        Ok(r) => r.json().await.map_err(|e| {
            RequestError::DeserializeError(format!("Unexpected response body. Error: {e}"))
        }),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let mut server = mockito::Server::new_async().await;
        let api_mock = server
            .mock("POST", Endpoint::Register.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(registration_receipt).to_string())
            .create_async()
            .await;

        let receipt = register(
            TowerId(tower_pk),
            registration_receipt.user_id(),
            &NetAddr::new(server.url()),
        )
        .await
        .unwrap();

        api_mock.assert_async().await;
        assert_eq!(receipt, registration_receipt);
    }

    #[tokio::test]
    async fn test_register_connection_error() {
        let error = register(
            get_random_user_id(),
            get_random_user_id(),
            &NetAddr::new("http://server_addr".to_owned()),
        )
        .await
        .unwrap_err();

        assert!(matches!(error, RequestError::ConnectionError { .. }))
    }

    #[tokio::test]
    async fn test_register_deserialize_error() {
        let mut server = mockito::Server::new_async().await;
        let api_mock = server
            .mock("POST", Endpoint::Register.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!([]).to_string())
            .create_async()
            .await;

        let error = register(
            get_random_user_id(),
            get_random_user_id(),
            &NetAddr::new(server.url()),
        )
        .await
        .unwrap_err();

        api_mock.assert_async().await;
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

        let mut server = mockito::Server::new_async().await;
        let api_mock = server
            .mock("POST", Endpoint::AddAppointment.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(add_appointment_response).to_string())
            .create_async()
            .await;

        let (response, receipt) = add_appointment(
            TowerId(tower_pk),
            &NetAddr::new(server.url()),
            &appointment,
            appointment_receipt.user_signature(),
        )
        .await
        .unwrap();

        api_mock.assert_async().await;
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

        let mut server = mockito::Server::new_async().await;
        let api_mock = server
            .mock("POST", Endpoint::AddAppointment.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(add_appointment_response).to_string())
            .create_async()
            .await;

        let (response, receipt) = send_appointment(
            TowerId(tower_pk),
            &NetAddr::new(server.url()),
            &appointment,
            appointment_receipt.user_signature(),
        )
        .await
        .unwrap();

        api_mock.assert_async().await;
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

        let mut server = mockito::Server::new_async().await;
        let api_mock = server
            .mock("POST", Endpoint::AddAppointment.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!(add_appointment_response).to_string())
            .create_async()
            .await;

        let tower_id = get_random_user_id();
        let error = send_appointment(
            tower_id,
            &NetAddr::new(server.url()),
            &appointment,
            appointment_receipt.user_signature(),
        )
        .await
        .unwrap_err();

        api_mock.assert_async().await;
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
        let mut server = mockito::Server::new_async().await;
        let api_mock = server
            .mock("POST", Endpoint::AddAppointment.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!([]).to_string())
            .create_async()
            .await;

        let error = send_appointment(
            get_random_user_id(),
            &NetAddr::new(server.url()),
            &generate_random_appointment(None),
            "user_sig",
        )
        .await
        .unwrap_err();

        api_mock.assert_async().await;
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

        let mut server = mockito::Server::new_async().await;
        let api_mock = server
            .mock("POST", Endpoint::AddAppointment.path().as_str())
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(json!(api_error).to_string())
            .create_async()
            .await;

        let error = send_appointment(
            get_random_user_id(),
            &NetAddr::new(server.url()),
            &generate_random_appointment(None),
            "user_sig",
        )
        .await
        .unwrap_err();

        api_mock.assert_async().await;
        assert!(matches!(error, AddAppointmentError::ApiError { .. }));
    }

    #[tokio::test]
    async fn test_request() {
        let mut server = mockito::Server::new_async().await;

        // Test with POST
        let api_mock_post = server
            .mock("POST", Endpoint::Register.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .create_async()
            .await;

        let response_post = request(
            &NetAddr::new(server.url()),
            Endpoint::Register,
            Method::POST,
            Some(json!("")),
        )
        .await;

        api_mock_post.assert_async().await;
        assert!(matches!(response_post, Ok(Response { .. })));

        // Test with GET
        let api_mock_get = server
            .mock("GET", Endpoint::Ping.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .create_async()
            .await;

        let response_get = request::<()>(
            &NetAddr::new(server.url()),
            Endpoint::Ping,
            Method::GET,
            None,
        )
        .await;

        api_mock_get.assert_async().await;
        assert!(matches!(response_get, Ok(Response { .. })));
    }

    #[tokio::test]
    async fn test_request_connection_error() {
        assert!(request(
            &NetAddr::new("http://unreachable_url".to_owned()),
            Endpoint::Register,
            Method::POST,
            Some(json!("")),
        )
        .await
        .unwrap_err()
        .is_connection());

        assert!(request(
            &NetAddr::new("http://unreachable_url".to_owned()),
            Endpoint::Ping,
            Method::GET,
            None::<&str>,
        )
        .await
        .unwrap_err()
        .is_connection());
    }

    #[tokio::test]
    async fn test_get_request() {
        let mut server = mockito::Server::new_async().await;
        let api_mock = server
            .mock("GET", Endpoint::Ping.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .create_async()
            .await;
        let response = get_request(&NetAddr::new(server.url()), Endpoint::Ping).await;

        api_mock.assert_async().await;

        assert!(matches!(response, Ok(Response { .. })));
    }

    #[tokio::test]
    async fn test_get_request_connection_error() {
        assert!(get_request(
            &NetAddr::new("http://unreachable_url".to_owned()),
            Endpoint::Ping,
        )
        .await
        .unwrap_err()
        .is_connection());
    }

    #[tokio::test]
    async fn test_post_request() {
        let mut server = mockito::Server::new_async().await;
        let api_mock = server
            .mock("POST", Endpoint::Register.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .create_async()
            .await;

        let response = post_request(
            &NetAddr::new(server.url()),
            Endpoint::Register,
            json!(""),
        )
        .await;

        api_mock.assert_async().await;
        assert!(matches!(response, Ok(Response { .. })));
    }

    #[tokio::test]
    async fn test_post_request_connection_error() {
        assert!(post_request(
            &NetAddr::new("http://unreachable_url".to_owned()),
            Endpoint::Register,
            json!(""),
        )
        .await
        .unwrap_err()
        .is_connection());
    }

    #[tokio::test]
    async fn test_process_post_response_json_error() {
        // `process_post_response` is a pass-trough function that maps json deserialization errors from `post_request`.
        // So just testing that specific case should be enough.

        let mut server = mockito::Server::new_async().await;
        let api_mock = server
            .mock("POST", Endpoint::GetAppointment.path().as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .create_async()
            .await;

        // Any expected response work here as long as it cannot be properly deserialized
        let error = process_post_response::<ApiResponse<common_msgs::GetAppointmentResponse>>(
            post_request(
                &NetAddr::new(server.url()),
                Endpoint::GetAppointment,
                json!(""),
            )
            .await,
        )
        .await
        .unwrap_err();

        api_mock.assert_async().await;
        assert!(matches!(error, RequestError::DeserializeError { .. }));
    }
}
