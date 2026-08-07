//! The main polling loop: exports the watchtower state from ldk-server and ships
//! appointments for new signed justice transactions to the tower.

use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use teos_common::appointment::Appointment;
use teos_common::cryptography;
use teos_common::net::NetAddr;
use teos_common::{TowerId, UserId};

use crate::appointments::build_appointment;
use crate::config::Config;
use crate::dbm::{StateStatus, TrackedJustice, DBM};
use crate::ldk_client::LdkServerClient;
use crate::proto::{JusticeTransaction, WatchtowerChannelState};
use crate::retrier::{retry_with_backoff, RetryError};
use crate::tower::{register, send_appointment, ProxyInfo};

/// Cap the per-appointment retry budget so a single unreachable tower cannot
/// starve the polling loop for too long.
const MAX_RETRY_ELAPSED_SECS: u64 = 300;

/// Errors that prevent the client from starting up.
#[derive(Debug)]
pub enum ClientError {
    Db(rusqlite::Error),
    Io(std::io::Error),
    InvalidTowerId(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Db(e) => write!(f, "database error: {e}"),
            ClientError::Io(e) => write!(f, "i/o error: {e}"),
            ClientError::InvalidTowerId(e) => write!(f, "invalid tower id: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<rusqlite::Error> for ClientError {
    fn from(e: rusqlite::Error) -> Self {
        ClientError::Db(e)
    }
}

pub struct WatchtowerClient {
    cfg: Config,
    ldk: LdkServerClient,
    dbm: DBM,
    user_sk: SecretKey,
    user_id: UserId,
    tower_id: TowerId,
    tower_net_addr: NetAddr,
    proxy: Option<ProxyInfo>,
}

impl WatchtowerClient {
    pub fn new(cfg: Config) -> Result<WatchtowerClient, ClientError> {
        std::fs::create_dir_all(&cfg.data_dir).map_err(ClientError::Io)?;
        let dbm = DBM::new(&cfg.data_dir.join("watchtower_db.sql3"))?;

        // Load (or generate and persist) the keypair identifying us to the tower.
        // The user id is the compressed public key; appointments are signed with
        // the secret key, as in `watchtower-plugin/src/wt_client.rs`.
        let (user_sk, user_id) = if let Some(sk) = dbm.load_client_key() {
            (
                sk,
                UserId(PublicKey::from_secret_key(&Secp256k1::new(), &sk)),
            )
        } else {
            let (sk, pk) = cryptography::get_random_keypair();
            dbm.store_client_key(&sk)?;
            (sk, UserId(pk))
        };
        log::info!("User id = {user_id}");

        let tower_id = TowerId::from_str(&cfg.tower_id).map_err(ClientError::InvalidTowerId)?;

        // The tower API is plain HTTP(S); prepend a scheme if none was given.
        let net_addr = if cfg.tower_net_addr.starts_with("http") {
            cfg.tower_net_addr.clone()
        } else {
            format!("http://{}", cfg.tower_net_addr)
        };
        let tower_net_addr = NetAddr::new(net_addr);

        // Onion towers are only reachable through the Tor proxy.
        let proxy = if tower_net_addr.is_onion() {
            log::info!(
                "Tower is an onion address, routing through Tor proxy at {}",
                cfg.tor_proxy
            );
            Some(ProxyInfo::new(cfg.tor_proxy.clone()))
        } else {
            None
        };

        Ok(WatchtowerClient {
            ldk: LdkServerClient::new(cfg.ldk_server_url.clone(), cfg.api_key.clone()),
            cfg,
            dbm,
            user_sk,
            user_id,
            tower_id,
            tower_net_addr,
            proxy,
        })
    }

    /// Registers with the tower unless a registration receipt is already persisted.
    fn ensure_registered(&self) {
        if self
            .dbm
            .load_registration_receipt(self.tower_id, self.user_id)
            .is_some()
        {
            log::debug!("Already registered with {}", self.tower_id);
            return;
        }

        match register(
            self.tower_id,
            self.user_id,
            &self.tower_net_addr,
            &self.proxy,
        ) {
            Ok(receipt) => {
                log::info!(
                    "Registered with {} (slots: {}, expiry: {})",
                    self.tower_id,
                    receipt.available_slots(),
                    receipt.subscription_expiry()
                );
                if let Err(e) = self.dbm.store_registration_receipt(self.tower_id, &receipt) {
                    log::error!("Cannot persist registration receipt: {e}");
                }
            }
            Err(e) => log::error!("Cannot register with the tower: {e}"),
        }
    }

    /// Exports the watchtower state from ldk-server, either for all channels or
    /// filtered to the configured watch list.
    fn export_state(&self) -> Vec<WatchtowerChannelState> {
        let requests: Vec<Option<String>> = if self.cfg.watch_channels.is_empty() {
            vec![None]
        } else {
            self.cfg.watch_channels.iter().cloned().map(Some).collect()
        };

        let mut states = Vec::new();
        for user_channel_id in requests {
            match self.ldk.watchtower_state_export(user_channel_id) {
                Ok(response) => states.extend(response.channel_states),
                Err(e) => log::warn!("Cannot export watchtower state from ldk-server: {e}"),
            }
        }

        // Defensive client-side filtering in case the server ignores the filter.
        if !self.cfg.watch_channels.is_empty() {
            let watched: HashSet<&String> = self.cfg.watch_channels.iter().collect();
            states.retain(|s| watched.contains(&s.user_channel_id));
        }
        states
    }

    /// Tracks all exported justice transactions and ships appointments for the
    /// ones that are signed and not yet delivered.
    fn process_exported_states(&self) {
        let states = self.export_state();
        log::debug!(
            "Exported state for {} channel(s) from ldk-server",
            states.len()
        );

        for state in states {
            for justice in &state.justice_transactions {
                let tracked = TrackedJustice {
                    commitment_txid: justice.commitment_txid.clone(),
                    user_channel_id: state.user_channel_id.clone(),
                    commitment_number: justice.commitment_number,
                    to_local_value_sats: justice.to_local_value_sats,
                    to_self_delay: state.to_self_delay,
                    // Only signed entries carry usable transaction bytes.
                    justice_tx: if justice.signed {
                        justice.justice_tx.clone()
                    } else {
                        Vec::new()
                    },
                    status: StateStatus::Seen,
                };
                match self.dbm.track_justice(&tracked) {
                    Ok(StateStatus::Pending) => self.deliver(&justice.commitment_txid),
                    Ok(_) => {}
                    Err(e) => log::error!(
                        "Cannot persist justice state {}: {e}",
                        justice.commitment_txid
                    ),
                }
            }
        }
    }

    /// Retries delivery of every appointment still pending in the database
    /// (e.g. left over from a previous run).
    fn retry_pending(&self) {
        match self.dbm.load_pending_justices() {
            Ok(pending) => {
                for tracked in pending {
                    self.deliver(&tracked.commitment_txid);
                }
            }
            Err(e) => log::error!("Cannot load pending appointments from the database: {e}"),
        }
    }

    /// Builds, signs and sends the appointment for a tracked (pending) justice
    /// transaction to the tower, persisting the outcome.
    fn deliver(&self, commitment_txid: &str) {
        let tracked = match self.dbm.load_justice(commitment_txid) {
            Ok(Some(t)) if t.status == StateStatus::Pending => t,
            Ok(_) => return,
            Err(e) => {
                log::error!("Cannot load justice state {commitment_txid}: {e}");
                return;
            }
        };

        let appointment = match self.build_appointment(&tracked) {
            Some(a) => a,
            None => {
                log::warn!("Cannot build appointment for {commitment_txid}, flagging as invalid");
                let _ = self
                    .dbm
                    .set_justice_status(commitment_txid, StateStatus::Invalid);
                return;
            }
        };

        self.send(&tracked, appointment);
    }

    /// Builds an appointment from a tracked state. Thin wrapper around
    /// [build_appointment] so the on-disk representation maps to the proto one.
    fn build_appointment(&self, tracked: &TrackedJustice) -> Option<Appointment> {
        build_appointment(
            &JusticeTransaction {
                commitment_txid: tracked.commitment_txid.clone(),
                commitment_number: tracked.commitment_number,
                to_local_value_sats: tracked.to_local_value_sats,
                justice_tx: tracked.justice_tx.clone(),
                signed: true,
            },
            tracked.to_self_delay,
        )
    }

    fn send(&self, tracked: &TrackedJustice, appointment: Appointment) {
        // Appointments are signed with the user key, as teos expects.
        let signature = match cryptography::sign(&appointment.to_vec(), &self.user_sk) {
            Ok(sig) => sig,
            Err(e) => {
                log::error!("Cannot sign appointment {}: {e}", appointment.locator);
                return;
            }
        };

        let max_elapsed =
            Duration::from_secs(MAX_RETRY_ELAPSED_SECS.min(self.cfg.poll_interval_secs.max(10)));
        let result = retry_with_backoff(max_elapsed, || {
            send_appointment(
                self.tower_id,
                &self.tower_net_addr,
                &self.proxy,
                &appointment,
                &signature,
            )
        });

        match result {
            Ok((_, receipt)) => {
                log::info!(
                    "Appointment {} accepted by {}",
                    appointment.locator,
                    self.tower_id
                );
                if let Err(e) = self
                    .dbm
                    .store_appointment_receipt(&appointment.locator.to_string(), &receipt)
                {
                    log::error!("Cannot persist appointment receipt: {e}");
                }
                let _ = self
                    .dbm
                    .set_justice_status(&tracked.commitment_txid, StateStatus::Sent);
            }
            Err(RetryError::Misbehaving(proof)) => {
                log::error!(
                    "Tower {} misbehaved: receipt signed by {} instead. Proof stored",
                    self.tower_id,
                    proof.recovered_id
                );
                let _ = self.dbm.store_misbehaving_proof(self.tower_id, &proof);
                let _ = self
                    .dbm
                    .set_justice_status(&tracked.commitment_txid, StateStatus::Invalid);
            }
            Err(RetryError::Api(e, code)) => {
                log::warn!(
                    "Tower rejected appointment {} ({code}): {e}",
                    appointment.locator
                );
                let _ = self
                    .dbm
                    .set_justice_status(&tracked.commitment_txid, StateStatus::Invalid);
            }
            Err(RetryError::Unreachable) => {
                // Left as `pending`: retried on the next tick or after a restart.
                log::warn!(
                    "Tower unreachable, appointment {} stays pending",
                    appointment.locator
                );
            }
        }
    }

    /// A single iteration of the polling loop.
    pub fn tick(&self) {
        self.ensure_registered();
        // Retry leftovers from previous runs first, then process fresh state.
        self.retry_pending();
        self.process_exported_states();
    }
}
