use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::{error::TryRecvError, UnboundedReceiver};

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
    unreachable_towers: UnboundedReceiver<(TowerId, Locator)>,
    max_elapsed_time_secs: u16,
    max_interval_time_secs: u16,
    retriers: HashMap<TowerId, Arc<Retrier>>,
}

impl RetryManager {
    pub fn new(
        wt_client: Arc<Mutex<WTClient>>,
        unreachable_towers: UnboundedReceiver<(TowerId, Locator)>,
        max_elapsed_time_secs: u16,
        max_interval_time_secs: u16,
    ) -> Self {
        RetryManager {
            wt_client,
            unreachable_towers,
            max_elapsed_time_secs,
            max_interval_time_secs,
            retriers: HashMap::new(),
        }
    }

    /// Starts the retry manager's main logic loop.
    /// This method will keep running until the `unreachable_towers` sender disconnects.
    ///
    /// It will receive any `(tower_id, locator)` pair and try to send the appointment with `locator` to
    /// the tower with `tower_id`. This is done by spawning a tokio thread for each `tower_id` that tries
    /// to send all the pending appointments.
    pub async fn manage_retry(&mut self) {
        log::info!("Starting retry manager");

        loop {
            match self.unreachable_towers.try_recv() {
                Ok((tower_id, locator)) => {
                    // Not start a retry if the tower is flagged to be abandoned
                    if !self
                        .wt_client
                        .lock()
                        .unwrap()
                        .towers
                        .contains_key(&tower_id)
                    {
                        log::info!("Skipping retrying abandoned tower {}", tower_id);
                        continue;
                    }
                    self.add_pending_appointment(tower_id, locator);
                }
                Err(TryRecvError::Empty) => {
                    // Keep only running retriers and retriers ready to be started/re-started.
                    // This will remove failed ones and ones finished successfully and have no pending appointments.
                    //
                    // Note that a failed retrier could have received some new appointments to retry. In this case, we don't try to send
                    // them because we know that that tower is unreachable. We most likely received these new appointments while the tower
                    // was still flagged as temporarily unreachable when cleaning up after giving up retrying.
                    self.retriers.retain(|_, retrier| {
                        retrier.set_tower_status_if_failed();
                        retrier.is_running() || retrier.should_start()
                    });
                    // Start all the ready retriers.
                    for retrier in self.retriers.values() {
                        if retrier.should_start() {
                            self.start_retrying(retrier.clone());
                        }
                    }
                    // Sleep to not waste a lot of CPU cycles.
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(TryRecvError::Disconnected) => break,
            }
        }
    }

    /// Adds an appointment to pending for a given tower.
    ///
    /// If the tower is not currently being retried, a new entry for it is created, otherwise, the data is appended to the existing entry.
    fn add_pending_appointment(&mut self, tower_id: TowerId, locator: Locator) {
        if let std::collections::hash_map::Entry::Vacant(e) = self.retriers.entry(tower_id) {
            log::debug!(
                "Creating a new entry for tower {} with locator {}",
                tower_id,
                locator
            );
            e.insert(Arc::new(Retrier::new(
                self.wt_client.clone(),
                tower_id,
                locator,
            )));
        } else {
            log::debug!(
                "Adding pending appointment {} to existing tower {}",
                locator,
                tower_id
            );
            self.retriers
                .get(&tower_id)
                .unwrap()
                .pending_appointments
                .lock()
                .unwrap()
                .insert(locator);
        }
    }

    fn start_retrying(&self, retrier: Arc<Retrier>) {
        log::info!("Retrying tower {}", retrier.tower_id);
        retrier.start(self.max_elapsed_time_secs, self.max_interval_time_secs);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RetrierStatus {
    /// Retrier is stopped. This could happen if the retrier was never started or it started and
    /// finished successfully. If a retrier is stopped and has some pending appointments, it should be
    /// started/re-started, otherwise, it can be deleted safely.
    Stopped,
    /// Retrier is currently retrying the tower. If the retrier receives new appointments, it will
    /// **try** to send them along (but it might not send them).
    ///
    /// If a retrier status is `Running`, then its associated tower is temporary unreachable.
    Running,
    /// Retrier failed retrying the tower. Should not be re-started.
    ///
    /// If a retrier status is `Failed`, then its associated tower is neither reachable nor temporary unreachable.
    Failed,
}

pub struct Retrier {
    wt_client: Arc<Mutex<WTClient>>,
    tower_id: TowerId,
    pending_appointments: Mutex<HashSet<Locator>>,
    status: Mutex<RetrierStatus>,
}

impl Retrier {
    pub fn new(wt_client: Arc<Mutex<WTClient>>, tower_id: TowerId, locator: Locator) -> Self {
        Self {
            wt_client,
            tower_id,
            pending_appointments: Mutex::new(HashSet::from([locator])),
            status: Mutex::new(RetrierStatus::Stopped),
        }
    }

    fn has_pending_appointments(&self) -> bool {
        !self.pending_appointments.lock().unwrap().is_empty()
    }

    fn set_status(&self, status: RetrierStatus) {
        *self.status.lock().unwrap() = status;
    }

    pub fn is_running(&self) -> bool {
        *self.status.lock().unwrap() == RetrierStatus::Running
    }

    pub fn should_start(&self) -> bool {
        // A retrier can be started/re-started if it is stopped (i.e. not running and not failed)
        // and has some pending appointments.
        *self.status.lock().unwrap() == RetrierStatus::Stopped && self.has_pending_appointments()
    }

    pub fn start(self: Arc<Self>, max_elapsed_time_secs: u16, max_interval_time_secs: u16) {
        // We shouldn't be retrying failed and running retriers.
        debug_assert_eq!(*self.status.lock().unwrap(), RetrierStatus::Stopped);

        // Set the tower as temporary unreachable and the retrier status to running.
        self.wt_client
            .lock()
            .unwrap()
            .set_tower_status(self.tower_id, crate::TowerStatus::TemporaryUnreachable);
        self.set_status(RetrierStatus::Running);

        tokio::spawn(async move {
            let r = retry_notify(
                ExponentialBackoff {
                    max_elapsed_time: Some(Duration::from_secs(max_elapsed_time_secs as u64)),
                    max_interval: Duration::from_secs(max_interval_time_secs as u64),
                    ..ExponentialBackoff::default()
                },
                || async { self.run().await },
                |err, _| {
                    log::warn!("Retry error happened with {}. {}", self.tower_id, err);
                },
            )
            .await;

            let mut state = self.wt_client.lock().unwrap();

            match r {
                Ok(_) => {
                    log::info!("Retry strategy succeeded for {}", self.tower_id);
                    // Set the tower status now so new appointment doesn't go to the retry manager.
                    state.set_tower_status(self.tower_id, crate::TowerStatus::Reachable);
                    // Retrier succeeded and can be re-used by re-starting it.
                    self.set_status(RetrierStatus::Stopped);
                }
                Err(e) => {
                    // Notice we'll end up here after a permanent error. That is, either after finishing the backoff strategy
                    // unsuccessfully or by manually raising such an error (like when facing a tower misbehavior).
                    log::warn!("Retry strategy gave up for {}. {}", self.tower_id, e);

                    // Retrier failed and should be given up on. Avoid setting the tower status until the retrier is
                    // deleted/dropped. This way users performing manual retry will get an error as the tower will be
                    // temporary unreachable.
                    // We don't need to set the tower status now. Any new appointments we receive will not be retried anyways.
                    self.set_status(RetrierStatus::Failed);
                }
            }
        });
    }

    async fn run(&self) -> Result<(), Error<&'static str>> {
        // Create a new scope so we can get all the data only locking the WTClient once.
        let (tower_id, net_addr, user_sk, proxy) = {
            let wt_client = self.wt_client.lock().unwrap();
            if wt_client.towers.get(&self.tower_id).is_none() {
                return Err(Error::permanent("Tower was abandoned. Skipping retry"));
            }

            let net_addr = wt_client
                .towers
                .get(&self.tower_id)
                .unwrap()
                .net_addr
                .clone();
            let user_sk = wt_client.user_sk;
            (self.tower_id, net_addr, user_sk, wt_client.proxy.clone())
        };

        while self.has_pending_appointments() {
            let locators = self.pending_appointments.lock().unwrap().clone();
            for locator in locators.into_iter() {
                let appointment = self
                    .wt_client
                    .lock()
                    .unwrap()
                    .dbm
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
                                    self.wt_client.lock().unwrap().set_tower_status(
                                        tower_id,
                                        crate::TowerStatus::SubscriptionError,
                                    );
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

    /// Sets the correct tower status if the retrier status is failed.
    ///
    /// This method MUST be called before getting rid of a failed retrier, and has
    /// no effect on non-failed retriers.
    pub fn set_tower_status_if_failed(&self) {
        if *self.status.lock().unwrap() == RetrierStatus::Failed {
            let mut state = self.wt_client.lock().unwrap();
            if let Some(tower) = state.towers.get(&self.tower_id) {
                if tower.status.is_temporary_unreachable() {
                    log::warn!("Setting {} as unreachable", self.tower_id);
                    state.set_tower_status(self.tower_id, crate::TowerStatus::Unreachable);
                }
            } else {
                log::info!("Skipping retrying abandoned tower {}", self.tower_id);
            }
        }
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
        fn empty(wt_client: Arc<Mutex<WTClient>>, tower_id: TowerId) -> Self {
            Self {
                wt_client,
                tower_id,
                pending_appointments: Mutex::new(HashSet::new()),
                status: Mutex::new(RetrierStatus::Stopped),
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
            RetryManager::new(wt_client_clone, rx, MAX_ELAPSED_TIME, MAX_INTERVAL_TIME)
                .manage_retry()
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
            RetryManager::new(wt_client_clone, rx, MAX_ELAPSED_TIME, MAX_INTERVAL_TIME)
                .manage_retry()
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
            RetryManager::new(wt_client_clone, rx, MAX_ELAPSED_TIME, MAX_INTERVAL_TIME)
                .manage_retry()
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
            RetryManager::new(wt_client_clone, rx, MAX_ELAPSED_TIME, MAX_INTERVAL_TIME)
                .manage_retry()
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
            RetryManager::new(wt_client_clone, rx, MAX_ELAPSED_TIME, MAX_INTERVAL_TIME)
                .manage_retry()
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
        let retrier = Retrier::new(wt_client, tower_id, appointment.locator);
        let r = retrier.run().await;
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
        let r = Retrier::empty(wt_client, tower_id).run().await;
        assert_eq!(r, Ok(()));
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
        let retrier = Retrier::new(wt_client, tower_id, appointment.locator);
        let r = retrier.run().await;
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
        let retrier = Retrier::new(wt_client, tower_id, appointment.locator);
        let r = retrier.run().await;

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
        let retrier = Retrier::new(wt_client, tower_id, appointment.locator);
        let r = retrier.run().await;

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
        let retrier = Retrier::new(wt_client.clone(), tower_id, appointment.locator);
        let r = retrier.run().await;

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
        let r = Retrier::empty(wt_client, tower_id).run().await;

        assert_eq!(
            r,
            Err(Error::permanent("Tower was abandoned. Skipping retry"))
        );
    }
}
