use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;

use backoff::future::retry_notify;
use backoff::{Error, ExponentialBackoff};

use teos_common::cryptography;
use teos_common::errors;
use teos_common::UserId as TowerId;

use crate::net::http::{add_appointment, AddAppointmentError};
use crate::wt_client::WTClient;
use crate::AppointmentStatus;

pub async fn manage_retry(
    mut unreachable_towers: UnboundedReceiver<TowerId>,
    wt_client: Arc<Mutex<WTClient>>,
    max_elapsed_time_secs: u16,
    max_interval_time_secs: u16,
) {
    log::info!("Starting retry manager");

    loop {
        let tower_id = unreachable_towers.recv().await.unwrap();
        wt_client
            .lock()
            .unwrap()
            .set_tower_status(tower_id, crate::TowerStatus::TemporaryUnreachable);

        log::info!("Retrying tower {}", tower_id);
        match retry_notify(
            ExponentialBackoff {
                max_elapsed_time: Some(Duration::from_secs(max_elapsed_time_secs as u64)),
                max_interval: Duration::from_secs(max_interval_time_secs as u64),
                ..ExponentialBackoff::default()
            },
            || async { retry_add_appointment(tower_id, wt_client.clone()).await },
            |err, _| {
                log::warn!("Retry error happened with {}. {}", tower_id, err);
            },
        )
        .await
        {
            Ok(_) => {
                log::info!("Retry strategy succeeded for {}", tower_id);
                wt_client
                    .lock()
                    .unwrap()
                    .set_tower_status(tower_id, crate::TowerStatus::Reachable);
            }
            Err(e) => {
                log::warn!("Retry strategy gave up for {}. {}", tower_id, e);
                // Notice we'll end up here after a permanent error. That is, either after finishing the backoff strategy
                // unsuccessfully or by manually raising such an error (like when facing a tower misbehavior)
                if wt_client
                    .lock()
                    .unwrap()
                    .towers
                    .get(&tower_id)
                    .unwrap()
                    .status
                    .is_unreachable()
                {
                    log::warn!("Setting {} as unreachable", tower_id);
                    wt_client
                        .lock()
                        .unwrap()
                        .set_tower_status(tower_id, crate::TowerStatus::Unreachable);
                }
            }
        }
    }
}

async fn retry_add_appointment(
    tower_id: TowerId,
    wt_client: Arc<Mutex<WTClient>>,
) -> Result<(), Error<&'static str>> {
    let appointments = wt_client
        .lock()
        .unwrap()
        .dbm
        .lock()
        .unwrap()
        .load_appointments(tower_id, AppointmentStatus::Pending);
    let net_addr = wt_client
        .lock()
        .unwrap()
        .towers
        .get(&tower_id)
        .unwrap()
        .net_addr
        .clone();
    let user_sk = wt_client.lock().unwrap().user_sk;

    for appointment in appointments {
        match add_appointment(
            tower_id,
            &net_addr,
            &appointment,
            &cryptography::sign(&appointment.to_vec(), &user_sk).unwrap(),
        )
        .await
        {
            Ok((slots, receipt)) => {
                let mut wt_client = wt_client.lock().unwrap();
                wt_client.add_appointment_receipt(tower_id, appointment.locator, slots, &receipt);
                wt_client.remove_pending_appointment(tower_id, appointment.locator);
                log::debug!("Response verified and data stored in the database");
            }
            Err(e) => {
                match e {
                    AddAppointmentError::RequestError(e) => {
                        if e.is_connection() {
                            log::warn!(
                                "{} cannot be reached. Tower will be retried later",
                                tower_id,
                            );
                            return Err(Error::transient("Tower cannot be reached"));
                        }
                    }
                    AddAppointmentError::ApiError(e) => match e.error_code {
                        errors::INVALID_SIGNATURE_OR_SUBSCRIPTION_ERROR => {
                            log::warn!("There is a subscription issue with {}", tower_id);
                            return Err(Error::transient("Subscription error"));
                        }
                        _ => {
                            log::warn!(
                                "{} rejected the appointment. Error: {}, error_code: {}",
                                tower_id,
                                e.error,
                                e.error_code
                            );
                            // We need to move the appointment from pending to invalid
                            // Add itn first to invalid and remove it from pending later so a cascade delete is not triggered
                            wt_client
                                .lock()
                                .unwrap()
                                .add_invalid_appointment(tower_id, &appointment);
                            wt_client
                                .lock()
                                .unwrap()
                                .remove_pending_appointment(tower_id, appointment.locator);
                        }
                    },
                    AddAppointmentError::SignatureError(proof) => {
                        log::warn!("Cannot recover known tower_id from the appointment receipt. Flagging tower as misbehaving");
                        wt_client
                            .lock()
                            .unwrap()
                            .flag_misbehaving_tower(tower_id, proof);
                        return Err(Error::permanent("Tower misbehaved"));
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use httpmock::prelude::*;
    use serde_json::json;
    use tokio::fs;
    use tokio::sync::mpsc::unbounded_channel;

    use teos_common::errors;
    use teos_common::receipts::AppointmentReceipt;
    use teos_common::test_utils::{
        generate_random_appointment, get_random_registration_receipt, get_random_user_id,
    };

    use crate::net::http::ApiError;
    use crate::test_utils::get_dummy_add_appointment_response;
    use crate::TowerStatus;

    #[tokio::test]
    // TODO: It'll be nice to toggle the mock on and off instead of having it always on. Not sure MockServer allows that though:
    // https://github.com/alexliesenfeld/httpmock/issues/67
    async fn test_manage_retry_reachable() {
        let tmp_path = &format!(".watchtower_{}/", get_random_user_id());
        let (tx, rx) = unbounded_channel();
        let wt_client = Arc::new(Mutex::new(WTClient::new(tmp_path.into(), tx.clone()).await));
        let server = MockServer::start();

        // Add a tower with pending appointments
        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt);

        // Add appointment to pending
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Prepare the mock response
        let mut add_appointment_receipt = AppointmentReceipt::new(
            cryptography::sign(&appointment.to_vec(), &wt_client.lock().unwrap().user_sk).unwrap(),
            42,
        );
        add_appointment_receipt.sign(&tower_sk);
        let add_appointment_response =
            get_dummy_add_appointment_response(appointment.locator, &add_appointment_receipt);
        let api_mock = server.mock(|when, then| {
            when.method(POST).path("/add_appointment");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!(add_appointment_response));
        });

        // Start the task and send the tower to the channel for retry
        let wt_client_clone = wt_client.clone();
        let max_elapsed_time = 2;
        let max_interval_time = 1;
        let task = tokio::spawn(async move {
            manage_retry(rx, wt_client_clone, max_elapsed_time, max_interval_time).await
        });
        tx.send(tower_id).unwrap();

        // Wait for the elapsed time and check how the tower status changed
        tokio::time::sleep(Duration::from_secs(max_elapsed_time as u64)).await;
        assert_eq!(
            wt_client
                .lock()
                .unwrap()
                .towers
                .get(&tower_id)
                .unwrap()
                .status,
            TowerStatus::Reachable
        );
        assert!(!wt_client
            .lock()
            .unwrap()
            .towers
            .get(&tower_id)
            .unwrap()
            .pending_appointments
            .contains(&appointment.locator));

        api_mock.assert();

        task.abort();
        fs::remove_dir_all(tmp_path).await.unwrap();
    }

    #[tokio::test]
    async fn test_manage_retry_unreachable() {
        let tmp_path = &format!(".watchtower_{}/", get_random_user_id());
        let (tx, rx) = unbounded_channel();
        let wt_client = Arc::new(Mutex::new(WTClient::new(tmp_path.into(), tx.clone()).await));

        // Add a tower with pending appointments
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let receipt = get_random_registration_receipt();
        wt_client.lock().unwrap().add_update_tower(
            tower_id,
            "http://unreachable.tower".into(),
            &receipt,
        );

        // Add appointment to pending
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Start the task and send the tower to the channel for retry
        let wt_client_clone = wt_client.clone();
        let max_elapsed_time = 3;
        let max_interval_time = 1;
        let task = tokio::spawn(async move {
            manage_retry(rx, wt_client_clone, max_elapsed_time, max_interval_time).await
        });
        tx.send(tower_id).unwrap();

        // Wait for the elapsed time and check how the tower status changed
        tokio::time::sleep(Duration::from_secs(max_elapsed_time as u64 / 3)).await;
        assert_eq!(
            wt_client
                .lock()
                .unwrap()
                .towers
                .get(&tower_id)
                .unwrap()
                .status,
            TowerStatus::TemporaryUnreachable
        );

        // Wait until the task gives up and check again
        tokio::time::sleep(Duration::from_secs(max_elapsed_time as u64)).await;
        assert_eq!(
            wt_client
                .lock()
                .unwrap()
                .towers
                .get(&tower_id)
                .unwrap()
                .status,
            TowerStatus::Unreachable
        );

        task.abort();
        fs::remove_dir_all(tmp_path).await.unwrap();
    }

    #[tokio::test]
    async fn test_manage_retry_rejected() {
        let tmp_path = &format!(".watchtower_{}/", get_random_user_id());
        let (tx, rx) = unbounded_channel();
        let wt_client = Arc::new(Mutex::new(WTClient::new(tmp_path.into(), tx.clone()).await));
        let server = MockServer::start();

        // Add a tower with pending appointments
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt);

        // Add appointment to pending
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Prepare the mock response
        let api_mock = server.mock(|when, then| {
            when.method(POST).path("/add_appointment");
            then.status(400)
                .header("content-type", "application/json")
                .json_body(json!(ApiError {
                    error: "error_msg".into(),
                    error_code: 1,
                }));
        });

        // Start the task and send the tower to the channel for retry
        let wt_client_clone = wt_client.clone();
        let max_elapsed_time = 2;
        let max_interval_time = 1;
        let task = tokio::spawn(async move {
            manage_retry(rx, wt_client_clone, max_elapsed_time, max_interval_time).await
        });
        tx.send(tower_id).unwrap();

        // Wait for the elapsed time and check how the tower status changed
        tokio::time::sleep(Duration::from_secs(max_elapsed_time as u64)).await;
        assert_eq!(
            wt_client
                .lock()
                .unwrap()
                .towers
                .get(&tower_id)
                .unwrap()
                .status,
            TowerStatus::Reachable
        );
        assert!(!wt_client
            .lock()
            .unwrap()
            .towers
            .get(&tower_id)
            .unwrap()
            .pending_appointments
            .contains(&appointment.locator));
        assert!(wt_client
            .lock()
            .unwrap()
            .towers
            .get(&tower_id)
            .unwrap()
            .invalid_appointments
            .contains(&appointment.locator));
        api_mock.assert();

        task.abort();
        fs::remove_dir_all(tmp_path).await.unwrap();
    }

    #[tokio::test]
    async fn test_retry_misbehaving() {
        let tmp_path = &format!(".watchtower_{}/", get_random_user_id());
        let (tx, rx) = unbounded_channel();
        let wt_client = Arc::new(Mutex::new(WTClient::new(tmp_path.into(), tx.clone()).await));
        let server = MockServer::start();

        // Add a tower with pending appointments
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt);

        // Add appointment to pending
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Prepare the mock response
        let mut add_appointment_receipt = AppointmentReceipt::new(
            cryptography::sign(&appointment.to_vec(), &wt_client.lock().unwrap().user_sk).unwrap(),
            42,
        );
        // Sign with a random key so it counts as misbehaving
        add_appointment_receipt.sign(&cryptography::get_random_keypair().0);
        let add_appointment_response =
            get_dummy_add_appointment_response(appointment.locator, &add_appointment_receipt);
        let api_mock = server.mock(|when, then| {
            when.method(POST).path("/add_appointment");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!(add_appointment_response));
        });

        // Start the task and send the tower to the channel for retry
        let wt_client_clone = wt_client.clone();
        let max_elapsed_time = 2;
        let max_interval_time = 1;
        let task = tokio::spawn(async move {
            manage_retry(rx, wt_client_clone, max_elapsed_time, max_interval_time).await
        });
        tx.send(tower_id).unwrap();

        // Wait for the elapsed time and check how the tower status changed
        tokio::time::sleep(Duration::from_secs(max_elapsed_time as u64)).await;
        assert!(wt_client
            .lock()
            .unwrap()
            .towers
            .get(&tower_id)
            .unwrap()
            .status
            .is_misbehaving());
        api_mock.assert();

        task.abort();
        fs::remove_dir_all(tmp_path).await.unwrap();
    }

    #[tokio::test]
    async fn test_retry_add_appointment() {
        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = &format!(".watchtower_{}/", get_random_user_id());
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.into(), unbounded_channel().0).await,
        ));
        let server = MockServer::start();

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt);

        // Add appointment to pending
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Prepare the mock response
        let mut add_appointment_receipt = AppointmentReceipt::new(
            cryptography::sign(&appointment.to_vec(), &wt_client.lock().unwrap().user_sk).unwrap(),
            42,
        );
        add_appointment_receipt.sign(&tower_sk);
        let add_appointment_response =
            get_dummy_add_appointment_response(appointment.locator, &add_appointment_receipt);
        let api_mock = server.mock(|when, then| {
            when.method(POST).path("/add_appointment");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!(add_appointment_response));
        });

        let r = retry_add_appointment(tower_id, wt_client.clone()).await;
        assert_eq!(r, Ok(()));
        api_mock.assert();

        fs::remove_dir_all(tmp_path).await.unwrap();
    }

    #[tokio::test]
    async fn test_retry_add_appointment_no_pending() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = &format!(".watchtower_{}/", get_random_user_id());
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.into(), unbounded_channel().0).await,
        ));
        let server = MockServer::start();

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt);

        // If there are no pending appointments the method will simply return
        let r = retry_add_appointment(tower_id, wt_client.clone()).await;
        assert_eq!(r, Ok(()));

        fs::remove_dir_all(tmp_path).await.unwrap();
    }

    #[tokio::test]
    async fn test_retry_add_appointment_misbehaving() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = &format!(".watchtower_{}/", get_random_user_id());
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.into(), unbounded_channel().0).await,
        ));
        let server = MockServer::start();

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt);

        // Add appointment to pending
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Prepare the mock response
        let mut add_appointment_receipt = AppointmentReceipt::new(
            cryptography::sign(&appointment.to_vec(), &wt_client.lock().unwrap().user_sk).unwrap(),
            42,
        );
        add_appointment_receipt.sign(&cryptography::get_random_keypair().0);
        let add_appointment_response =
            get_dummy_add_appointment_response(appointment.locator, &add_appointment_receipt);
        let api_mock = server.mock(|when, then| {
            when.method(POST).path("/add_appointment");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!(add_appointment_response));
        });

        let r = retry_add_appointment(tower_id, wt_client.clone()).await;
        assert_eq!(r, Err(Error::permanent("Tower misbehaved")));
        api_mock.assert();

        fs::remove_dir_all(tmp_path).await.unwrap();
    }

    #[tokio::test]
    async fn test_retry_add_appointment_unreachable() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = &format!(".watchtower_{}/", get_random_user_id());
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.into(), unbounded_channel().0).await,
        ));

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client.lock().unwrap().add_update_tower(
            tower_id,
            "http://unreachable.tower".into(),
            &receipt,
        );

        // Add some pending appointments and try again (with an unreachable tower).
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);
        let r = retry_add_appointment(tower_id, wt_client.clone()).await;
        assert_eq!(r, Err(Error::transient("Tower cannot be reached")));

        fs::remove_dir_all(tmp_path).await.unwrap();
    }

    #[tokio::test]
    async fn test_retry_add_appointment_subscription_error() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = &format!(".watchtower_{}/", get_random_user_id());
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.into(), unbounded_channel().0).await,
        ));
        let server = MockServer::start();

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt);

        let api_mock = server.mock(|when, then| {
            when.method(POST).path("/add_appointment");
            then.status(400)
                .header("content-type", "application/json")
                .json_body(json!(ApiError {
                    error: "error_msg".into(),
                    error_code: errors::INVALID_SIGNATURE_OR_SUBSCRIPTION_ERROR,
                }));
        });

        // Add some pending appointments and try again (with an unreachable tower).
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);
        let r = retry_add_appointment(tower_id, wt_client.clone()).await;

        assert_eq!(r, Err(Error::transient("Subscription error")));
        api_mock.assert();

        fs::remove_dir_all(tmp_path).await.unwrap();
    }

    #[tokio::test]
    async fn test_retry_add_appointment_rejected() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = &format!(".watchtower_{}/", get_random_user_id());
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.into(), unbounded_channel().0).await,
        ));
        let server = MockServer::start();

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt);

        let api_mock = server.mock(|when, then| {
            when.method(POST).path("/add_appointment");
            then.status(400)
                .header("content-type", "application/json")
                .json_body(json!(ApiError {
                    error: "error_msg".into(),
                    error_code: 1,
                }));
        });

        // Add some pending appointments and try again (with an unreachable tower).
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);
        let r = retry_add_appointment(tower_id, wt_client.clone()).await;

        assert_eq!(r, Ok(()));
        api_mock.assert();
        assert!(wt_client
            .lock()
            .unwrap()
            .towers
            .get(&tower_id)
            .unwrap()
            .invalid_appointments
            .contains(&appointment.locator));

        fs::remove_dir_all(tmp_path).await.unwrap();
    }
}
