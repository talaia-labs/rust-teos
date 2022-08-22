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

pub struct Retrier {
    wt_client: Arc<Mutex<WTClient>>,
    max_elapsed_time_secs: u16,
    max_interval_time_secs: u16,
}

impl Retrier {
    pub fn new(
        wt_client: Arc<Mutex<WTClient>>,
        max_elapsed_time_secs: u16,
        max_interval_time_secs: u16,
    ) -> Self {
        Self {
            wt_client,
            max_elapsed_time_secs,
            max_interval_time_secs,
        }
    }
    pub async fn manage_retry(&self, mut unreachable_towers: UnboundedReceiver<TowerId>) {
        log::info!("Starting retry manager");

        loop {
            let tower_id = unreachable_towers.recv().await.unwrap();
            {
                // Not start a retry if the tower has been abandoned
                let mut wt_client = self.wt_client.lock().unwrap();
                if wt_client.towers.get(&tower_id).is_none() {
                    log::info!("Skipping retrying abandoned tower {}", tower_id);
                    continue;
                }
                wt_client.set_tower_status(tower_id, crate::TowerStatus::TemporaryUnreachable);
            }

            log::info!("Retrying tower {}", tower_id);
            match retry_notify(
                ExponentialBackoff {
                    max_elapsed_time: Some(Duration::from_secs(self.max_elapsed_time_secs as u64)),
                    max_interval: Duration::from_secs(self.max_interval_time_secs as u64),
                    ..ExponentialBackoff::default()
                },
                || async { self.add_appointment(tower_id).await },
                |err, _| {
                    log::warn!("Retry error happened with {}. {}", tower_id, err);
                },
            )
            .await
            {
                Ok(_) => {
                    log::info!("Retry strategy succeeded for {}", tower_id);
                    self.wt_client
                        .lock()
                        .unwrap()
                        .set_tower_status(tower_id, crate::TowerStatus::Reachable);
                }
                Err(e) => {
                    log::warn!("Retry strategy gave up for {}. {}", tower_id, e);
                    // Notice we'll end up here after a permanent error. That is, either after finishing the backoff strategy
                    // unsuccessfully or by manually raising such an error (like when facing a tower misbehavior)
                    let mut wt_client = self.wt_client.lock().unwrap();
                    if let Some(tower) = wt_client.towers.get_mut(&tower_id) {
                        if tower.status.is_unreachable() {
                            log::warn!("Setting {} as unreachable", tower_id);
                            wt_client.set_tower_status(tower_id, crate::TowerStatus::Unreachable);
                        }
                    } else {
                        log::info!("Skipping retrying abandoned tower {}", tower_id);
                    }
                }
            }
        }
    }

    async fn add_appointment(&self, tower_id: TowerId) -> Result<(), Error<&'static str>> {
        // Create a new scope so we can get all the data only locking the WTClient once.
        let (appointments, net_addr, user_sk) = {
            let wt_client = self.wt_client.lock().unwrap();
            if wt_client.towers.get(&tower_id).is_none() {
                return Err(Error::permanent("Tower was abandoned. Skipping retry"));
            }

            let appointments = wt_client
                .dbm
                .lock()
                .unwrap()
                .load_appointments(tower_id, AppointmentStatus::Pending);
            let net_addr = wt_client.towers.get(&tower_id).unwrap().net_addr.clone();
            let user_sk = wt_client.user_sk;
            (appointments, net_addr, user_sk)
        };

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
                    let mut wt_client = self.wt_client.lock().unwrap();
                    wt_client.add_appointment_receipt(
                        tower_id,
                        appointment.locator,
                        slots,
                        &receipt,
                    );
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
                                let mut wt_client = self.wt_client.lock().unwrap();
                                wt_client.add_invalid_appointment(tower_id, &appointment);
                                wt_client.remove_pending_appointment(tower_id, appointment.locator);
                            }
                        },
                        AddAppointmentError::SignatureError(proof) => {
                            log::warn!("Cannot recover known tower_id from the appointment receipt. Flagging tower as misbehaving");
                            self.wt_client
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use httpmock::prelude::*;
    use serde_json::json;
    use tempdir::TempDir;
    use tokio::sync::mpsc::unbounded_channel;

    use teos_common::errors;
    use teos_common::receipts::AppointmentReceipt;
    use teos_common::test_utils::{
        generate_random_appointment, get_random_registration_receipt, get_random_user_id,
    };

    use crate::net::http::ApiError;
    use crate::test_utils::get_dummy_add_appointment_response;
    use crate::TowerStatus;

    const MAX_ELAPSED_TIME: u16 = 2;
    const MAX_INTERVAL_TIME: u16 = 1;

    impl Retrier {
        fn dummy(wt_client: Arc<Mutex<WTClient>>) -> Self {
            Self::new(wt_client, 0, 0)
        }
    }

    #[tokio::test]
    // TODO: It'll be nice to toggle the mock on and off instead of having it always on. Not sure MockServer allows that though:
    // https://github.com/alexliesenfeld/httpmock/issues/67
    async fn test_manage_retry_reachable() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let (tx, rx) = unbounded_channel();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), tx.clone()).await,
        ));
        let server = MockServer::start();

        // Add a tower with pending appointments
        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt)
            .unwrap();

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
        let task = tokio::spawn(async move {
            Retrier::new(wt_client_clone, MAX_ELAPSED_TIME, MAX_INTERVAL_TIME)
                .manage_retry(rx)
                .await
        });
        tx.send(tower_id).unwrap();

        // Wait for the elapsed time and check how the tower status changed
        tokio::time::sleep(Duration::from_secs(MAX_ELAPSED_TIME as u64)).await;
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
    }

    #[tokio::test]
    async fn test_manage_retry_unreachable() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let (tx, rx) = unbounded_channel();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), tx.clone()).await,
        ));

        // Add a tower with pending appointments
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, "http://unreachable.tower".into(), &receipt)
            .unwrap();

        // Add appointment to pending
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);

        // Start the task and send the tower to the channel for retry
        let wt_client_clone = wt_client.clone();

        let max_elapsed_time = MAX_ELAPSED_TIME + 1;
        let task = tokio::spawn(async move {
            Retrier::new(wt_client_clone, max_elapsed_time, MAX_INTERVAL_TIME)
                .manage_retry(rx)
                .await
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
    }

    #[tokio::test]
    async fn test_manage_retry_rejected() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let (tx, rx) = unbounded_channel();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), tx.clone()).await,
        ));
        let server = MockServer::start();

        // Add a tower with pending appointments
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt)
            .unwrap();

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
        let task = tokio::spawn(async move {
            Retrier::new(wt_client_clone, MAX_ELAPSED_TIME, MAX_INTERVAL_TIME)
                .manage_retry(rx)
                .await
        });
        tx.send(tower_id).unwrap();

        // Wait for the elapsed time and check how the tower status changed
        tokio::time::sleep(Duration::from_secs(MAX_ELAPSED_TIME as u64)).await;
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
    }

    #[tokio::test]
    async fn test_manage_retry_misbehaving() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let (tx, rx) = unbounded_channel();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), tx.clone()).await,
        ));
        let server = MockServer::start();

        // Add a tower with pending appointments
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt)
            .unwrap();

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
        let task = tokio::spawn(async move {
            Retrier::new(wt_client_clone, MAX_ELAPSED_TIME, MAX_INTERVAL_TIME)
                .manage_retry(rx)
                .await
        });
        tx.send(tower_id).unwrap();

        // Wait for the elapsed time and check how the tower status changed
        tokio::time::sleep(Duration::from_secs(MAX_ELAPSED_TIME as u64)).await;
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
    }

    #[tokio::test]
    async fn test_manage_retry_abandoned() {
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let (tx, rx) = unbounded_channel();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), tx.clone()).await,
        ));
        let server = MockServer::start();

        // Add a tower with pending appointments
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt)
            .unwrap();

        // Remove the tower (to simulate it has been abandoned)
        wt_client.lock().unwrap().remove_tower(tower_id).unwrap();

        // Start the task and send the tower to the channel for retry
        let wt_client_clone = wt_client.clone();
        let task = tokio::spawn(async move {
            Retrier::new(wt_client_clone, MAX_ELAPSED_TIME, MAX_INTERVAL_TIME)
                .manage_retry(rx)
                .await
        });

        // Send the id and check how it gets removed
        tx.send(tower_id).unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!wt_client.lock().unwrap().towers.contains_key(&tower_id));

        task.abort();
    }

    #[tokio::test]
    async fn test_add_appointment() {
        let (tower_sk, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await,
        ));
        let server = MockServer::start();

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt)
            .unwrap();

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

        let r = Retrier::dummy(wt_client).add_appointment(tower_id).await;
        assert_eq!(r, Ok(()));
        api_mock.assert();
    }

    #[tokio::test]
    async fn test_add_appointment_no_pending() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await,
        ));
        let server = MockServer::start();

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt)
            .unwrap();

        // If there are no pending appointments the method will simply return
        let r = Retrier::dummy(wt_client).add_appointment(tower_id).await;

        assert_eq!(r, Ok(()));
    }

    #[tokio::test]
    async fn test_add_appointment_misbehaving() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await,
        ));
        let server = MockServer::start();

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt)
            .unwrap();

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
        let r = Retrier::dummy(wt_client).add_appointment(tower_id).await;
        assert_eq!(r, Err(Error::permanent("Tower misbehaved")));
        api_mock.assert();
    }

    #[tokio::test]
    async fn test_add_appointment_unreachable() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await,
        ));

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, "http://unreachable.tower".into(), &receipt)
            .unwrap();

        // Add some pending appointments and try again (with an unreachable tower).
        let appointment = generate_random_appointment(None);
        wt_client
            .lock()
            .unwrap()
            .add_pending_appointment(tower_id, &appointment);
        let r = Retrier::dummy(wt_client).add_appointment(tower_id).await;
        assert_eq!(r, Err(Error::transient("Tower cannot be reached")));
    }

    #[tokio::test]
    async fn test_add_appointment_subscription_error() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await,
        ));
        let server = MockServer::start();

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt)
            .unwrap();

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
        let r = Retrier::dummy(wt_client).add_appointment(tower_id).await;

        assert_eq!(r, Err(Error::transient("Subscription error")));
        api_mock.assert();
    }

    #[tokio::test]
    async fn test_add_appointment_rejected() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await,
        ));
        let server = MockServer::start();

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt)
            .unwrap();

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
        let r = Retrier::dummy(wt_client.clone())
            .add_appointment(tower_id)
            .await;

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
    }

    #[tokio::test]
    async fn test_add_appointment_abandoned() {
        let (_, tower_pk) = cryptography::get_random_keypair();
        let tower_id = TowerId(tower_pk);
        let tmp_path = TempDir::new(&format!("watchtower_{}", get_random_user_id())).unwrap();
        let wt_client = Arc::new(Mutex::new(
            WTClient::new(tmp_path.path().to_path_buf(), unbounded_channel().0).await,
        ));
        let server = MockServer::start();

        // The tower we'd like to retry sending appointments to has to exist within the plugin
        let receipt = get_random_registration_receipt();
        wt_client
            .lock()
            .unwrap()
            .add_update_tower(tower_id, server.base_url(), &receipt)
            .unwrap();

        // Remove the tower (to simulate it has been abandoned)
        wt_client.lock().unwrap().remove_tower(tower_id).unwrap();

        // If there are no pending appointments the method will simply return
        let r = Retrier::dummy(wt_client).add_appointment(tower_id).await;

        assert_eq!(
            r,
            Err(Error::permanent("Tower was abandoned. Skipping retry"))
        );
    }
}
