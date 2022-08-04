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
