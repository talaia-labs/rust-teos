//! Watchtower's Lightning interface.

use bitcoin::secp256k1::{PublicKey, SecretKey};
use triggered::Listener;

use crate::protos::public_tower_services_client::PublicTowerServicesClient;
use tonic::transport::Channel;
use tonic::Code;

use lightning::io;
use lightning::ln::msgs::{DecodeError, ErrorAction, LightningError, WarningMessage};
use lightning::ln::peer_handler::{
    CustomMessageHandler, ErroringMessageHandler, IgnoringMessageHandler, MessageHandler,
    PeerManager,
};
use lightning::ln::wire::CustomMessageReader;
use lightning::util::logger::{Level, Logger as LightningLogger, Record};
use lightning::util::ser::Readable;

use lightning_net_tokio::SocketDescriptor;

use std::convert::TryInto;
use std::mem;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use teos_common::cryptography::get_random_bytes;
use teos_common::lightning::messages::*;
use teos_common::protos as common_msgs;

// FIXME: Check if we can drop some Arcs here.
type TowerPeerManager = PeerManager<
    SocketDescriptor,
    Arc<ErroringMessageHandler>, // No channel message handler
    Arc<IgnoringMessageHandler>, // No routing message handler
    Arc<Logger>,
    Arc<TowerMessageHandler>, // Using our custom message handler
>;

/// A helper that returns an [`Err(LightningError)`] with the specified warning message.
fn warn_peer<T>(msg_to_peer: &str, msg_to_log: &str) -> Result<T, LightningError> {
    Err(LightningError {
        err: msg_to_log.to_owned(),
        action: ErrorAction::SendWarningMessage {
            msg: WarningMessage {
                // Zeros for channel id tells that the warning isn't channel specific.
                channel_id: [0; 32],
                data: msg_to_peer.to_owned(),
            },
            log_level: Level::Warn,
        },
    })
}

/// A handler to handle the incoming [`TowerMessage`]s.
pub struct TowerMessageHandler {
    /// A queue holding the response messages or errors the tower wants to send to its peers.
    msg_queue: Mutex<Vec<(PublicKey, TowerMessage)>>,
    // TODO: Will it make more sense using the watcher interface instead of the gRPC?
    // since the watcher interface is not async and it does provide richer error codes.
    /// A connection to the tower's public internal gRPC API.
    grpc_conn: PublicTowerServicesClient<Channel>,
    /// A tokio runtime handle to run gRPC async calls on.
    handle: tokio::runtime::Handle,
}

impl TowerMessageHandler {
    fn new(grpc_conn: PublicTowerServicesClient<Channel>, handle: tokio::runtime::Handle) -> Self {
        Self {
            msg_queue: Mutex::new(Vec::new()),
            grpc_conn,
            handle,
        }
    }

    /// Handles a tower request message by casting it to a gRPC message and send it to the
    /// internal API. The API's response is then casted to a tower response and returned.
    /// The argument `peer` is used for logging purposes only.
    fn handle_tower_message(
        &self,
        msg: TowerMessage,
        peer: &PublicKey,
    ) -> Result<TowerMessage, LightningError> {
        tokio::task::block_in_place(|| {
            log::info!("Received {:?} from {}", msg, peer);
            let mut grpc_conn = self.grpc_conn.clone();
            match msg {
                TowerMessage::Register(msg) => {
                    let res = self
                        .handle
                        .block_on(grpc_conn.register(common_msgs::RegisterRequest::from(msg)));
                    match res {
                        Ok(r) => Ok(r.into_inner().into()),
                        Err(e) => warn_peer(
                            e.message(),
                            &format!("Failed registering {} because {}", peer, e.message()),
                        ),
                    }
                }
                TowerMessage::AddUpdateAppointment(msg) => {
                    let res =
                        self.handle.block_on(grpc_conn.add_appointment(
                            common_msgs::AddAppointmentRequest::from(msg.clone()),
                        ));
                    match res {
                        Ok(r) => Ok(r.into_inner().into()),
                        // NOTE: The gRPC interface multiplexes the errors and doesn't let us know what they exactly
                        // were. Possible errors can be found [here](crate::watcher::AddAppointmentFailure).
                        Err(e) if e.code() == Code::Unauthenticated => Ok(AppointmentRejected {
                            locator: msg.locator,
                            rcode: Code::Unauthenticated as u16,
                            reason: e.message().into(),
                        }
                        .into()),
                        Err(e) if e.code() == Code::AlreadyExists => Ok(AppointmentRejected {
                            locator: msg.locator,
                            rcode: Code::AlreadyExists as u16,
                            reason: e.message().into(),
                        }
                        .into()),
                        Err(e) => {
                            warn_peer(
                                e.message(),
                                &format!(
                                "Failed accepting appointment from {} with locator {} because {}",
                                peer, msg.locator, e.message()
                            ),
                            )
                        }
                    }
                }
                TowerMessage::GetAppointment(msg) => {
                    let res =
                        self.handle.block_on(grpc_conn.get_appointment(
                            common_msgs::GetAppointmentRequest::from(msg.clone()),
                        ));
                    match res {
                        Ok(r) => Ok(r.into_inner().into()),
                        Err(e) if e.code() == Code::NotFound => Ok(AppointmentNotFound {
                            locator: msg.locator,
                        }
                        .into()),
                        Err(e) => warn_peer(
                            e.message(),
                            &format!(
                                "GetAppointment request from {} failed because {}",
                                peer,
                                e.message()
                            ),
                        ),
                    }
                }
                TowerMessage::GetSubscriptionInfo(msg) => {
                    let res =
                        self.handle.block_on(grpc_conn.get_subscription_info(
                            common_msgs::GetSubscriptionInfoRequest::from(msg),
                        ));
                    match res {
                        Ok(r) => Ok(r.into_inner().into()),
                        Err(e) => warn_peer(
                            e.message(),
                            &format!(
                                "GetSubscriptionInfo request from {} failed because {}",
                                peer,
                                e.message()
                            ),
                        ),
                    }
                }
                // TODO: DeleteAppointment
                // TowerMessageHandler as CustomMessageReader won't produce other than the above messages.
                _ => unreachable!(),
            }
        })
    }
}

impl CustomMessageReader for TowerMessageHandler {
    type CustomMessage = TowerMessage;

    fn read<R: io::Read>(
        &self,
        message_type: u16,
        buffer: &mut R,
    ) -> Result<Option<TowerMessage>, DecodeError> {
        match message_type {
            Register::TYPE => Ok(Some(Register::read(buffer)?.into())),
            AddUpdateAppointment::TYPE => Ok(Some(AddUpdateAppointment::read(buffer)?.into())),
            GetAppointment::TYPE => Ok(Some(GetAppointment::read(buffer)?.into())),
            GetSubscriptionInfo::TYPE => Ok(Some(GetSubscriptionInfo::read(buffer)?.into())),
            // Unknown message.
            _ => Ok(None),
        }
    }
}

impl CustomMessageHandler for TowerMessageHandler {
    fn handle_custom_message(
        &self,
        msg: TowerMessage,
        sender_node_id: &PublicKey,
    ) -> Result<(), LightningError> {
        self.msg_queue.lock().unwrap().push((
            *sender_node_id,
            self.handle_tower_message(msg, sender_node_id)?,
        ));
        Ok(())
    }

    fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, TowerMessage)> {
        mem::take(&mut self.msg_queue.lock().unwrap())
    }
}

/// A translation struct to translate LDK's logs to our logging system's logs.
pub struct Logger;

impl LightningLogger for Logger {
    fn log(&self, record: &Record) {
        #[cfg(test)]
        // Pass "-- --nocapture" flag to "cargo test" for this println to appear.
        println!(
            // "\x1B" stuff are terminal colors. Might not work in some terminals though.
            "\x1B[42m{}\x1B[0m [\x1B[33m{}:{}\x1B[0m]: {}",
            record.level, record.module_path, record.line, record.args
        );
        #[cfg(not(test))]
        match record.level {
            Level::Error => log::error!(target: record.module_path, "{}", record.args),
            Level::Warn => log::warn!(target: record.module_path, "{}", record.args),
            Level::Info => log::info!(target: record.module_path, "{}", record.args),
            Level::Debug => log::debug!(target: record.module_path, "{}", record.args),
            Level::Trace => log::trace!(target: record.module_path, "{}", record.args),
            _ => {}
        }
    }
}

pub async fn serve(
    lightning_bind: SocketAddr,
    grpc_bind: String,
    shutdown_signal: Listener,
    tower_sk: SecretKey,
) {
    let grpc_conn = loop {
        match PublicTowerServicesClient::connect(grpc_bind.clone()).await {
            Ok(conn) => break conn,
            Err(_) => {
                log::error!("Cannot connect to the gRPC server. Retrying shortly");
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    };
    let tower_message_handler = Arc::new(TowerMessageHandler::new(
        grpc_conn,
        tokio::runtime::Handle::current(),
    ));
    let message_handler = MessageHandler {
        chan_handler: Arc::new(ErroringMessageHandler::new()),
        route_handler: Arc::new(IgnoringMessageHandler {}),
    };
    let ephemeral_bytes: [u8; 32] = get_random_bytes(32).try_into().unwrap();
    let peer_manager = Arc::new(TowerPeerManager::new(
        message_handler,
        tower_sk,
        &ephemeral_bytes,
        Arc::new(Logger),
        tower_message_handler,
    ));
    // To suppress an issue similar to https://github.com/rust-lang/rust-clippy/issues/2928
    #[allow(clippy::expect_fun_call)]
    let listener = tokio::net::TcpListener::bind(lightning_bind)
        .await
        .expect(&format!(
            "Couldn't bind the lightning server to {}",
            lightning_bind
        ));
    loop {
        let tcp_stream = listener.accept().await.unwrap().0;
        if shutdown_signal.is_triggered() {
            return;
        }
        let peer_manager = peer_manager.clone();
        tokio::spawn(async move {
            lightning_net_tokio::setup_inbound(peer_manager, tcp_stream.into_std().unwrap()).await;
        });
    }
}

#[cfg(test)]
mod test_lightning_client {
    use super::*;

    use std::collections::VecDeque;

    pub(crate) type TestClientPeerManager = PeerManager<
        SocketDescriptor,
        Arc<ErroringMessageHandler>, // No channel message handler
        Arc<IgnoringMessageHandler>, // No routing message handler
        Arc<Logger>,
        Arc<TestClientMessageHandler>, // Using our custom message handler
    >;

    pub(crate) struct TestClientMessageHandler {
        msg_queue: Mutex<Vec<(PublicKey, TowerMessage)>>,
        // A vector we store the received messages in to test whether the tower sent correct responses or not.
        received_msgs: Mutex<VecDeque<TowerMessage>>,
    }

    impl TestClientMessageHandler {
        pub(crate) fn new() -> Self {
            Self {
                msg_queue: Mutex::new(Vec::new()),
                received_msgs: Mutex::new(VecDeque::new()),
            }
        }

        /// Sends a tower message to `peer`.
        /// This works by pushing the message to a pending messages queue and notifying the passed
        /// `peer_manager` that there are some events to process.
        ///
        /// You should only pass the peer manager that is holding a reference of this `TestClientMessageHandler`
        /// (`self`) as a custom message handler and not any other peer manager.
        pub(crate) fn send_msg(
            &self,
            peer_manager: &TestClientPeerManager,
            msg: TowerMessage,
            peer: &PublicKey,
        ) {
            self.msg_queue.lock().unwrap().push((*peer, msg));
            // Let the peer manager process our pending message.
            peer_manager.process_events();
            // The message queue must be empty after the peer manager has processed events.
            assert!(self.msg_queue.lock().unwrap().is_empty());
        }

        pub(crate) fn received_msgs_count(&self) -> usize {
            self.received_msgs.lock().unwrap().len()
        }

        pub(crate) fn pop_oldest_received_msg(&self) -> TowerMessage {
            self.received_msgs.lock().unwrap().pop_front().unwrap()
        }
    }

    impl CustomMessageReader for TestClientMessageHandler {
        type CustomMessage = TowerMessage;

        fn read<R: io::Read>(
            &self,
            message_type: u16,
            buffer: &mut R,
        ) -> Result<Option<TowerMessage>, DecodeError> {
            match message_type {
                Register::TYPE => Ok(Some(Register::read(buffer)?.into())), // A real client shouldn't have this
                SubscriptionDetails::TYPE => Ok(Some(SubscriptionDetails::read(buffer)?.into())),
                AddUpdateAppointment::TYPE => Ok(Some(AddUpdateAppointment::read(buffer)?.into())), // ,this
                AppointmentAccepted::TYPE => Ok(Some(AppointmentAccepted::read(buffer)?.into())),
                AppointmentRejected::TYPE => Ok(Some(AppointmentRejected::read(buffer)?.into())),
                GetAppointment::TYPE => Ok(Some(GetAppointment::read(buffer)?.into())), // ,this
                AppointmentData::TYPE => Ok(Some(AppointmentData::read(buffer)?.into())),
                TrackerData::TYPE => Ok(Some(TrackerData::read(buffer)?.into())),
                AppointmentNotFound::TYPE => Ok(Some(AppointmentNotFound::read(buffer)?.into())),
                GetSubscriptionInfo::TYPE => Ok(Some(GetSubscriptionInfo::read(buffer)?.into())), // ,and this.
                SubscriptionInfo::TYPE => Ok(Some(SubscriptionInfo::read(buffer)?.into())),
                // Unknown message.
                _ => Ok(None),
            }
        }
    }

    impl CustomMessageHandler for TestClientMessageHandler {
        fn handle_custom_message(
            &self,
            msg: TowerMessage,
            _sender_node_id: &PublicKey,
        ) -> Result<(), LightningError> {
            self.received_msgs.lock().unwrap().push_back(msg);
            Ok(())
        }

        fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, TowerMessage)> {
            mem::take(&mut self.msg_queue.lock().unwrap())
        }
    }
}

#[cfg(test)]
mod test_helpers {
    use super::test_lightning_client::*;
    use super::*;

    use bitcoin::secp256k1::Secp256k1;
    use teos_common::cryptography::get_random_keypair;

    use crate::api::internal::InternalAPI;
    use crate::test_utils::{
        get_public_grpc_conn, run_tower_in_background_with_config, ApiConfig, BitcoindStopper,
    };

    pub(crate) const WAIT_DURATION: tokio::time::Duration = tokio::time::Duration::from_millis(10);

    pub(crate) async fn get_tower_message_handler_with_config(
        conf: ApiConfig,
    ) -> (Arc<TowerMessageHandler>, Arc<InternalAPI>, BitcoindStopper) {
        let (server_addr, internal_api, bitcoind_stopper) =
            run_tower_in_background_with_config(conf).await;
        let grpc_conn = get_public_grpc_conn(server_addr).await;
        let handle = tokio::runtime::Handle::current();
        (
            Arc::new(TowerMessageHandler::new(grpc_conn, handle)),
            internal_api,
            bitcoind_stopper,
        )
    }

    pub(crate) async fn get_tower_message_handler(
    ) -> (Arc<TowerMessageHandler>, Arc<InternalAPI>, BitcoindStopper) {
        get_tower_message_handler_with_config(ApiConfig::default()).await
    }

    pub(crate) async fn request_to_tower_message_handler(
        tower: &Arc<TowerMessageHandler>,
        msg: TowerMessage,
        peer: PublicKey,
    ) -> Result<TowerMessage, LightningError> {
        let tower = tower.clone();
        // Must use `spawn_blocking` because `handle_tower_message` uses `block_on`.
        tokio::task::spawn_blocking(move || tower.handle_tower_message(msg, &peer))
            .await
            .unwrap()
    }

    /// Spawns a tower and a Lightning server that accepts tower messages.
    /// Note that the server might not be fully booted up after this function returns.
    pub(crate) async fn run_lightning_tower_with_config(
        conf: ApiConfig,
    ) -> (SocketAddr, PublicKey, BitcoindStopper) {
        let (server_addr, internal_api, bitcoind_stopper) =
            run_tower_in_background_with_config(conf).await;
        let lightning_bind = {
            let unused_port = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            unused_port.local_addr().unwrap()
        };
        let grpc_bind = format!("http://{}:{}", server_addr.ip(), server_addr.port());
        let (_, shutdown_signal) = triggered::trigger();
        let tower_sk = internal_api.get_watcher().get_signing_key();
        // To make the tests simple, we won't let the testers await on the task or hand them shutdown triggers.
        let _ = tokio::task::spawn(serve(lightning_bind, grpc_bind, shutdown_signal, tower_sk));
        (
            lightning_bind,
            PublicKey::from_secret_key(&Secp256k1::new(), &tower_sk),
            bitcoind_stopper,
        )
    }

    pub(crate) async fn run_lightning_tower() -> (SocketAddr, PublicKey, BitcoindStopper) {
        run_lightning_tower_with_config(ApiConfig::default()).await
    }

    pub(crate) fn get_test_client_peer_manager() -> (
        Arc<TestClientPeerManager>,
        Arc<TestClientMessageHandler>,
        PublicKey,
    ) {
        let client_message_handler = Arc::new(TestClientMessageHandler::new());
        let (client_sk, client_pk) = get_random_keypair();
        let ephemeral_bytes: [u8; 32] = get_random_bytes(32).try_into().unwrap();
        (
            Arc::new(TestClientPeerManager::new(
                MessageHandler {
                    chan_handler: Arc::new(ErroringMessageHandler::new()),
                    route_handler: Arc::new(IgnoringMessageHandler {}),
                },
                client_sk,
                &ephemeral_bytes,
                Arc::new(Logger),
                client_message_handler.clone(),
            )),
            client_message_handler,
            client_pk,
        )
    }

    /// Connects `client_peer_manager` to another peer manager at `tower_addr`.
    /// It keeps trying indefinitely till a connection is successful.
    pub(crate) async fn connect_to_tower(
        client_peer_manager: Arc<TestClientPeerManager>,
        tower_addr: SocketAddr,
        tower_pk: PublicKey,
    ) {
        // From https://lightningdevkit.org/payments/connecting_peers/
        loop {
            match lightning_net_tokio::connect_outbound(
                client_peer_manager.clone(),
                tower_pk,
                tower_addr,
            )
            .await
            {
                Some(connection_closed_future) => {
                    let mut connection_closed_future = Box::pin(connection_closed_future);
                    loop {
                        // Make sure the connection is still established.
                        match futures::poll!(&mut connection_closed_future) {
                            std::task::Poll::Ready(_) => {
                                panic!(
                                    "{}@{} disconnected before handshake completed",
                                    tower_pk, tower_addr
                                );
                            }
                            std::task::Poll::Pending => {}
                        }
                        // Wait for the handshake to complete.
                        match client_peer_manager
                            .get_peer_node_ids()
                            .iter()
                            .find(|id| **id == tower_pk)
                        {
                            Some(_) => return,
                            None => tokio::time::sleep(WAIT_DURATION).await,
                        }
                    }
                }
                None => {
                    // The server takes some time to boot up. Let's wait a little bit.
                    tokio::time::sleep(WAIT_DURATION).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod message_handler_tests {
    use super::test_helpers::*;
    use super::*;

    use teos_common::cryptography::{get_random_keypair, sign};
    use teos_common::test_utils::{generate_random_appointment, get_random_user_id};
    use teos_common::UserId;

    use crate::extended_appointment::UUID;
    use crate::test_utils::{ApiConfig, DURATION};

    #[tokio::test]
    async fn test_register() {
        let (tower, _, _s) = get_tower_message_handler().await;
        let user_id = get_random_user_id();
        let msg = Register {
            pubkey: user_id,
            // The tower doesn't use this info ATM.
            appointment_slots: 4024,
            subscription_period: 4002,
        }
        .into();

        assert!(matches! {
            request_to_tower_message_handler(&tower, msg, user_id.0).await,
            Ok(TowerMessage::SubscriptionDetails(SubscriptionDetails {
                ..
            }))
        })
    }

    #[tokio::test]
    async fn test_register_max_slots() {
        let (tower, _, _s) =
            get_tower_message_handler_with_config(ApiConfig::new(u32::MAX, DURATION)).await;
        let user_id = get_random_user_id();
        let msg: TowerMessage = Register {
            pubkey: user_id,
            // The tower doesn't use this info ATM.
            appointment_slots: 4024,
            subscription_period: 4002,
        }
        .into();

        // First registration should go through.
        assert!(matches!(
            request_to_tower_message_handler(&tower, msg.clone(), user_id.0).await,
            Ok(TowerMessage::SubscriptionDetails(
                SubscriptionDetails { .. }
            ))
        ));

        // Second one should fail (maximum slots count reached).
        assert!(matches!(
            request_to_tower_message_handler(&tower, msg, user_id.0).await,
            Err(LightningError { err, .. }) if err.contains("maximum slots")
        ));
    }

    #[tokio::test]
    async fn test_register_service_unavailable() {
        let (tower, _, _s) =
            get_tower_message_handler_with_config(ApiConfig::default().bitcoind_unreachable())
                .await;
        let user_id = get_random_user_id();
        let msg = Register {
            pubkey: user_id,
            // The tower doesn't use this info ATM.
            appointment_slots: 4024,
            subscription_period: 4002,
        }
        .into();

        assert!(matches!(
            request_to_tower_message_handler(&tower, msg, user_id.0).await,
            Err(LightningError { err, .. }) if err.contains("currently unavailable")
        ));
    }

    #[tokio::test]
    async fn test_add_appointment() {
        let (tower, _, _s) = get_tower_message_handler().await;
        let (user_sk, user_pk) = get_random_keypair();
        let msg = Register {
            pubkey: UserId(user_pk),
            // The tower doesn't use this info ATM.
            appointment_slots: 4024,
            subscription_period: 4002,
        }
        .into();

        // Register with the tower.
        request_to_tower_message_handler(&tower, msg, user_pk)
            .await
            .unwrap();

        let appointment = generate_random_appointment(None);
        let signature = sign(&appointment.to_vec(), &user_sk).unwrap();
        let msg = AddUpdateAppointment {
            locator: appointment.locator,
            encrypted_blob: appointment.encrypted_blob,
            signature,
            to_self_delay: Some(appointment.to_self_delay),
        }
        .into();

        assert!(matches!(
            request_to_tower_message_handler(&tower, msg, user_pk).await,
            Ok(TowerMessage::AppointmentAccepted(
                AppointmentAccepted { locator, .. }
            )) if locator == appointment.locator
        ));
    }

    #[tokio::test]
    async fn test_add_appointment_non_registered() {
        let (tower, _, _s) = get_tower_message_handler().await;
        let (user_sk, user_pk) = get_random_keypair();

        let appointment = generate_random_appointment(None);
        let signature = sign(&appointment.to_vec(), &user_sk).unwrap();
        let msg = AddUpdateAppointment {
            locator: appointment.locator,
            encrypted_blob: appointment.encrypted_blob,
            signature,
            to_self_delay: Some(appointment.to_self_delay),
        }
        .into();

        assert!(matches!(
            request_to_tower_message_handler(&tower, msg, user_pk).await,
            Ok(TowerMessage::AppointmentRejected(
                AppointmentRejected { locator, rcode, .. }
            )) if locator == appointment.locator && rcode == Code::Unauthenticated as u16
        ));
    }

    #[tokio::test]
    async fn test_add_appointment_already_triggered() {
        let (tower, internal_api, _s) = get_tower_message_handler().await;
        let (user_sk, user_pk) = get_random_keypair();
        let msg = Register {
            pubkey: UserId(user_pk),
            // The tower doesn't use this info ATM.
            appointment_slots: 4024,
            subscription_period: 4002,
        }
        .into();

        // Register with the tower.
        request_to_tower_message_handler(&tower, msg, user_pk)
            .await
            .unwrap();

        let appointment = generate_random_appointment(None);
        let signature = sign(&appointment.to_vec(), &user_sk).unwrap();
        let msg = AddUpdateAppointment {
            locator: appointment.locator,
            encrypted_blob: appointment.encrypted_blob,
            signature,
            to_self_delay: Some(appointment.to_self_delay),
        }
        .into();

        // Add the appointment to the responder so it counts as triggered.
        internal_api
            .get_watcher()
            .add_random_tracker_to_responder(UUID::new(appointment.locator, UserId(user_pk)));

        // Send the appointment to the tower and assert it rejects because of being already triggered.
        assert!(matches!(
            request_to_tower_message_handler(&tower, msg, user_pk).await,
            Ok(TowerMessage::AppointmentRejected(
                AppointmentRejected { locator, rcode, .. }
            )) if locator == appointment.locator && rcode == Code::AlreadyExists as u16
        ));
    }

    #[tokio::test]
    async fn test_add_appointment_service_unavailable() {
        let (tower, _, _s) =
            get_tower_message_handler_with_config(ApiConfig::default().bitcoind_unreachable())
                .await;
        let (user_sk, user_pk) = get_random_keypair();

        let appointment = generate_random_appointment(None);
        let signature = sign(&appointment.to_vec(), &user_sk).unwrap();
        let msg = AddUpdateAppointment {
            locator: appointment.locator,
            encrypted_blob: appointment.encrypted_blob,
            signature,
            to_self_delay: Some(appointment.to_self_delay),
        }
        .into();

        assert!(matches!(
            request_to_tower_message_handler(&tower, msg, user_pk).await,
            Err(LightningError { err, .. }) if err.contains("currently unavailable")
        ));
    }

    #[tokio::test]
    async fn test_get_appointment() {
        let (tower, _, _s) = get_tower_message_handler().await;
        let (user_sk, user_pk) = get_random_keypair();
        let msg = Register {
            pubkey: UserId(user_pk),
            // The tower doesn't use this info ATM.
            appointment_slots: 4024,
            subscription_period: 4002,
        }
        .into();

        // Register with the tower.
        request_to_tower_message_handler(&tower, msg, user_pk)
            .await
            .unwrap();

        let appointment = generate_random_appointment(None);
        let signature = sign(&appointment.to_vec(), &user_sk).unwrap();
        let msg = AddUpdateAppointment {
            locator: appointment.locator,
            encrypted_blob: appointment.encrypted_blob.clone(),
            signature,
            to_self_delay: Some(appointment.to_self_delay),
        }
        .into();

        // Send the appointment to the tower.
        request_to_tower_message_handler(&tower, msg, user_pk)
            .await
            .unwrap();

        let signature = sign(
            format!("get appointment {}", appointment.locator).as_bytes(),
            &user_sk,
        )
        .unwrap();
        let msg = GetAppointment {
            locator: appointment.locator,
            signature,
        }
        .into();

        // Assert the tower has the appointment we just sent.
        assert!(matches!(
            request_to_tower_message_handler(&tower, msg, user_pk).await,
            Ok(TowerMessage::AppointmentData(AppointmentData {
                locator, encrypted_blob
            })) if locator == appointment.locator && encrypted_blob == appointment.encrypted_blob
        ));
    }

    #[tokio::test]
    async fn test_get_appointment_non_registered() {
        let (tower, _, _s) = get_tower_message_handler().await;
        let (user_sk, user_pk) = get_random_keypair();
        let appointment = generate_random_appointment(None);
        let signature = sign(
            format!("get appointment {}", appointment.locator).as_bytes(),
            &user_sk,
        )
        .unwrap();
        let msg = GetAppointment {
            locator: appointment.locator,
            signature,
        }
        .into();

        // Assert the tower cannot authenticate us.
        assert!(matches!(
            request_to_tower_message_handler(&tower, msg, user_pk).await,
            Err(LightningError { err, .. }) if err.contains("cannot be authenticated")
        ));
    }

    #[tokio::test]
    async fn test_get_appointment_not_found() {
        let (tower, _, _s) = get_tower_message_handler().await;
        let (user_sk, user_pk) = get_random_keypair();
        let msg = Register {
            pubkey: UserId(user_pk),
            // The tower doesn't use this info ATM.
            appointment_slots: 4024,
            subscription_period: 4002,
        }
        .into();

        // Register with the tower.
        request_to_tower_message_handler(&tower, msg, user_pk)
            .await
            .unwrap();

        let appointment = generate_random_appointment(None);
        let signature = sign(
            format!("get appointment {}", appointment.locator).as_bytes(),
            &user_sk,
        )
        .unwrap();
        let msg = GetAppointment {
            locator: appointment.locator,
            signature,
        }
        .into();

        assert!(matches!(
            request_to_tower_message_handler(&tower, msg, user_pk).await,
            Ok(TowerMessage::AppointmentNotFound(AppointmentNotFound {
                locator
            })) if locator == appointment.locator
        ));
    }

    #[tokio::test]
    async fn test_get_appointment_service_unavailable() {
        let (tower, _, _s) =
            get_tower_message_handler_with_config(ApiConfig::default().bitcoind_unreachable())
                .await;
        let (user_sk, user_pk) = get_random_keypair();
        let appointment = generate_random_appointment(None);
        let signature = sign(
            format!("get appointment {}", appointment.locator).as_bytes(),
            &user_sk,
        )
        .unwrap();
        let msg = GetAppointment {
            locator: appointment.locator,
            signature,
        }
        .into();

        assert!(matches!(
            request_to_tower_message_handler(&tower, msg, user_pk).await,
            Err(LightningError { err, .. }) if err.contains("currently unavailable")
        ));
    }

    #[tokio::test]
    async fn test_get_subscription_info() {
        let (tower, _, _s) = get_tower_message_handler().await;
        let (user_sk, user_pk) = get_random_keypair();
        let msg = Register {
            pubkey: UserId(user_pk),
            // The tower doesn't use this info ATM.
            appointment_slots: 4024,
            subscription_period: 4002,
        }
        .into();

        request_to_tower_message_handler(&tower, msg, user_pk)
            .await
            .unwrap();

        let signature = sign(format!("get subscription info").as_bytes(), &user_sk).unwrap();
        let msg = GetSubscriptionInfo { signature }.into();

        assert!(matches!(
            request_to_tower_message_handler(&tower, msg, user_pk).await,
            Ok(TowerMessage::SubscriptionInfo(SubscriptionInfo { .. }))
        ));
    }

    #[tokio::test]
    async fn test_get_subscription_info_non_registered() {
        let (tower, _, _s) = get_tower_message_handler().await;
        let (user_sk, user_pk) = get_random_keypair();
        let signature = sign(format!("get subscription info").as_bytes(), &user_sk).unwrap();
        let msg = GetSubscriptionInfo { signature }.into();

        assert!(matches!(
            request_to_tower_message_handler(&tower, msg, user_pk).await,
            Err(LightningError { err, .. }) if err.contains("User not found")
        ));
    }

    #[tokio::test]
    async fn test_get_subscription_info_service_unavailable() {
        let (tower, _, _s) =
            get_tower_message_handler_with_config(ApiConfig::default().bitcoind_unreachable())
                .await;
        let (user_sk, user_pk) = get_random_keypair();
        let signature = sign(format!("get subscription info").as_bytes(), &user_sk).unwrap();
        let msg = GetSubscriptionInfo { signature }.into();

        assert!(matches!(
            request_to_tower_message_handler(&tower, msg, user_pk).await,
            Err(LightningError { err, .. }) if err.contains("currently unavailable")
        ));
    }
}

#[cfg(test)]
mod peer_manager_tests {
    use super::test_helpers::*;
    use super::*;

    use teos_common::UserId;

    // Needs to be "multi_thread" because we "block_in_place" without using "spawn_blocking".
    #[tokio::test(flavor = "multi_thread")]
    async fn simple_test() {
        let (tower_addr, tower_pk, _s) = run_lightning_tower().await;
        let (client_peer_manager, client_messenger, client_pk) = get_test_client_peer_manager();
        connect_to_tower(client_peer_manager.clone(), tower_addr, tower_pk).await;

        let msg = Register {
            pubkey: UserId(client_pk),
            appointment_slots: 8778,
            subscription_period: 6726,
        }
        .into();

        // Send the register message to the tower.
        client_messenger.send_msg(&client_peer_manager, msg, &tower_pk);
        // And wait till we get a response.
        while client_messenger.received_msgs_count() != 1 {
            tokio::time::sleep(WAIT_DURATION).await;
        }

        let received_msg = client_messenger.pop_oldest_received_msg();
        assert!(matches!(
            received_msg,
            TowerMessage::SubscriptionDetails(SubscriptionDetails { .. })
        ));
    }
}
