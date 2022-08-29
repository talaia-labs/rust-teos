use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;

use backoff::future::retry_notify;
use backoff::{Error, ExponentialBackoff};

use teos_common::appointment::Locator;
use teos_common::cryptography;
use teos_common::errors;
use teos_common::UserId as TowerId;

use crate::net::http::{add_appointment, AddAppointmentError};
use crate::wt_client::WTClient;

pub struct RetryManager {
    wt_client: Arc<Mutex<WTClient>>,
    retriers: Arc<Mutex<HashMap<TowerId, Retrier>>>,
}

impl RetryManager {
    pub fn new(wt_client: Arc<Mutex<WTClient>>) -> Self {
        RetryManager {
            wt_client,
            retriers: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub async fn manage_retry(
        &mut self,
        max_elapsed_time_secs: u16,
        max_interval_time_secs: u16,
        mut unreachable_towers: UnboundedReceiver<(TowerId, Locator)>,
    ) {
        log::info!("Starting retry manager");

        loop {
            let (tower_id, locator) = unreachable_towers.recv().await.unwrap();
            // Not start a retry if the tower is flagged to be abandoned
            {
                let wt_client = self.wt_client.lock().unwrap();
                if !wt_client.towers.contains_key(&tower_id) {
                    log::info!("Skipping retrying abandoned tower {}", tower_id);
                    continue;
                }
            }

            if let Some(retrier) = self.add_pending_appointment(tower_id, locator) {
                log::info!("Retrying tower {}", tower_id);
                let wt_client = self.wt_client.clone();
                let retriers = self.retriers.clone();

                tokio::spawn(async move {
                    let r = retry_notify(
                        ExponentialBackoff {
                            max_elapsed_time: Some(Duration::from_secs(
                                max_elapsed_time_secs as u64,
                            )),
                            max_interval: Duration::from_secs(max_interval_time_secs as u64),
                            ..ExponentialBackoff::default()
                        },
                        || async { retrier.retry_tower(tower_id).await },
                        |err, _| {
                            log::warn!("Retry error happened with {}. {}", tower_id, err);
                        },
                    )
                    .await;

                    let mut state = wt_client.lock().unwrap();
                    let retrier = retriers.lock().unwrap().remove(&tower_id).unwrap();

                    match r {
                        Ok(_) => {
                            let pending_appointments = retrier.pending_appointments.lock().unwrap();
                            if !pending_appointments.is_empty() {
                                // If there are pending appointments by the time we remove the retrier we send them back through the channel
                                // so they are not missed. Notice this is unlikely given the map is checked before exiting `retry_tower`, but it
                                // can happen.
                                log::info!(
                                    "Some data was missed while retrying {}. Adding it back",
                                    tower_id
                                );
                                for locator in retrier.pending_appointments.lock().unwrap().drain()
                                {
                                    state.unreachable_towers.send((tower_id, locator)).unwrap();
                                }
                            } else {
                                log::info!("Retry strategy succeeded for {}", tower_id);
                                state.set_tower_status(tower_id, crate::TowerStatus::Reachable);
                            }
                        }
                        Err(e) => {
                            log::warn!("Retry strategy gave up for {}. {}", tower_id, e);
                            // Notice we'll end up here after a permanent error. That is, either after finishing the backoff strategy
                            // unsuccessfully or by manually raising such an error (like when facing a tower misbehavior)
                            if let Some(tower) = state.towers.get_mut(&tower_id) {
                                if tower.status.is_temporary_unreachable() {
                                    log::warn!("Setting {} as unreachable", tower_id);
                                    state.set_tower_status(
                                        tower_id,
                                        crate::TowerStatus::Unreachable,
                                    );
                                }
                            } else {
                                log::info!("Skipping retrying abandoned tower {}", tower_id);
                            }
                        }
                    }
                });
            }
        }
    }

    /// Adds an appointment to pending for a given tower.
    ///
    /// If the tower is not currently being retried, a new entry for it is created, otherwise, the data is appended to the existing entry.
    ///
    /// Returns true if a new entry is created, false otherwise.
    fn add_pending_appointment(&mut self, tower_id: TowerId, locator: Locator) -> Option<Retrier> {
        let mut retriers = self.retriers.lock().unwrap();
        if let std::collections::hash_map::Entry::Vacant(e) = retriers.entry(tower_id) {
            log::debug!(
                "Creating a new entry for tower {} with locator {}",
                tower_id,
                locator
            );
            self.wt_client
                .lock()
                .unwrap()
                .set_tower_status(tower_id, crate::TowerStatus::TemporaryUnreachable);

            let retrier = Retrier::new(self.wt_client.clone(), locator);
            e.insert(retrier.clone());

            Some(retrier)
        } else {
            log::debug!(
                "Adding pending appointment {} to existing tower {}",
                locator,
                tower_id
            );
            retriers
                .get(&tower_id)
                .unwrap()
                .pending_appointments
                .lock()
                .unwrap()
                .insert(locator);

            None
        }
    }
}

#[derive(Clone)]
pub struct Retrier {
    wt_client: Arc<Mutex<WTClient>>,
    pending_appointments: Arc<Mutex<HashSet<Locator>>>,
}

impl Retrier {
    pub fn new(wt_client: Arc<Mutex<WTClient>>, locator: Locator) -> Self {
        Self {
            wt_client,
            pending_appointments: Arc::new(Mutex::new(HashSet::from([locator]))),
        }
    }

    async fn retry_tower(&self, tower_id: TowerId) -> Result<(), Error<&'static str>> {
        // Create a new scope so we can get all the data only locking the WTClient once.
        let (net_addr, user_sk, proxy) = {
            let wt_client = self.wt_client.lock().unwrap();
            if wt_client.towers.get(&tower_id).is_none() {
                return Err(Error::permanent("Tower was abandoned. Skipping retry"));
            }

            if self.pending_appointments.lock().unwrap().is_empty() {
                return Err(Error::permanent("Tower has no data pending for retry"));
            }

            let net_addr = wt_client.towers.get(&tower_id).unwrap().net_addr.clone();
            let user_sk = wt_client.user_sk;
            (net_addr, user_sk, wt_client.proxy.clone())
        };

        while !self.pending_appointments.lock().unwrap().is_empty() {
            let locators = self.pending_appointments.lock().unwrap().clone();
            for locator in locators.into_iter() {
                let appointment = self
                    .wt_client
                    .lock()
                    .unwrap()
                    .dbm
                    .lock()
                    .unwrap()
                    .load_appointment(locator)
                    .unwrap();

                match add_appointment(
                    tower_id,
                    &net_addr,
                    proxy.clone(),
                    &appointment,
                    &cryptography::sign(&appointment.to_vec(), &user_sk).unwrap(),
                )
                .await
                {
                    Ok((slots, receipt)) => {
                        self.pending_appointments.lock().unwrap().remove(&locator);
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
                                    return Err(Error::permanent("Subscription error"));
                                }
                                _ => {
                                    log::warn!(
                                        "{} rejected the appointment. Error: {}, error_code: {}",
                                        tower_id,
                                        e.error,
                                        e.error_code
                                    );
                                    // We need to move the appointment from pending to invalid
                                    // Add it first to invalid and remove it from pending later so a cascade delete is not triggered
                                    self.pending_appointments.lock().unwrap().remove(&locator);
                                    let mut wt_client = self.wt_client.lock().unwrap();
                                    wt_client.add_invalid_appointment(tower_id, &appointment);
                                    wt_client
                                        .remove_pending_appointment(tower_id, appointment.locator);
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
        fn empty(wt_client: Arc<Mutex<WTClient>>) -> Self {
            Self {
                wt_client,
                pending_appointments: Arc::new(Mutex::new(HashSet::new())),
            }
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
            RetryManager::new(wt_client_clone)
                .manage_retry(MAX_ELAPSED_TIME, MAX_INTERVAL_TIME, rx)
                .await
        });
        tx.send((tower_id, appointment.locator)).unwrap();

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
            RetryManager::new(wt_client_clone)
                .manage_retry(MAX_ELAPSED_TIME, MAX_INTERVAL_TIME, rx)
                .await
        });
        tx.send((tower_id, appointment.locator)).unwrap();

        // Wait for the elapsed time and check how the tower status changed
        tokio::time::sleep(Duration::from_secs(max_elapsed_time as u64 / 3)).await;
        assert!(wt_client
            .lock()
            .unwrap()
            .towers
            .get(&tower_id)
            .unwrap()
            .status
            .is_temporary_unreachable());

        // Wait until the task gives up and check again
        tokio::time::sleep(Duration::from_secs(max_elapsed_time as u64)).await;
        assert!(wt_client
            .lock()
            .unwrap()
            .towers
            .get(&tower_id)
            .unwrap()
            .status
            .is_unreachable());

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
            RetryManager::new(wt_client_clone)
                .manage_retry(MAX_ELAPSED_TIME, MAX_INTERVAL_TIME, rx)
                .await
        });
        tx.send((tower_id, appointment.locator)).unwrap();

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
            RetryManager::new(wt_client_clone)
                .manage_retry(MAX_ELAPSED_TIME, MAX_INTERVAL_TIME, rx)
                .await
        });
        tx.send((tower_id, appointment.locator)).unwrap();

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
            RetryManager::new(wt_client_clone)
                .manage_retry(MAX_ELAPSED_TIME, MAX_INTERVAL_TIME, rx)
                .await
        });

        // Send the id and check how it gets removed
        tx.send((tower_id, generate_random_appointment(None).locator))
            .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!wt_client.lock().unwrap().towers.contains_key(&tower_id));

        task.abort();
    }

    #[tokio::test]
    async fn test_retry_tower() {
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

        // Since we are retrying manually, we need to add the data to pending appointments manually too
        let retrier = Retrier::new(wt_client, appointment.locator);
        let r = retrier.retry_tower(tower_id).await;
        assert_eq!(r, Ok(()));
        api_mock.assert();
    }

    #[tokio::test]
    async fn test_retry_tower_no_pending() {
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
        let r = Retrier::empty(wt_client).retry_tower(tower_id).await;
        assert_eq!(
            r,
            Err(Error::permanent("Tower has no data pending for retry"))
        );
    }

    #[tokio::test]
    async fn test_retry_tower_misbehaving() {
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

        // Since we are retrying manually, we need to add the data to pending appointments manually too
        let retrier = Retrier::new(wt_client, appointment.locator);
        let r = retrier.retry_tower(tower_id).await;
        assert_eq!(r, Err(Error::permanent("Tower misbehaved")));
        api_mock.assert();
    }

    #[tokio::test]
    async fn test_retry_tower_unreachable() {
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

        // Since we are retrying manually, we need to add the data to pending appointments manually too
        let retrier = Retrier::new(wt_client, appointment.locator);
        let r = retrier.retry_tower(tower_id).await;

        assert_eq!(r, Err(Error::transient("Tower cannot be reached")));
    }

    #[tokio::test]
    async fn test_retry_tower_subscription_error() {
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

        // Since we are retrying manually, we need to add the data to pending appointments manually too
        let retrier = Retrier::new(wt_client, appointment.locator);
        let r = retrier.retry_tower(tower_id).await;

        assert_eq!(r, Err(Error::permanent("Subscription error")));
        api_mock.assert();
    }

    #[tokio::test]
    async fn test_retry_tower_rejected() {
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

        // Since we are retrying manually, we need to add the data to pending appointments manually too
        let retrier = Retrier::new(wt_client.clone(), appointment.locator);
        let r = retrier.retry_tower(tower_id).await;

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
    async fn test_retry_tower_abandoned() {
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
        let r = Retrier::empty(wt_client).retry_tower(tower_id).await;

        assert_eq!(
            r,
            Err(Error::permanent("Tower was abandoned. Skipping retry"))
        );
    }
}
