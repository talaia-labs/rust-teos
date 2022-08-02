//! Watchtower's Lightning interface.

use bitcoin::secp256k1::PublicKey;
use tokio::runtime;

use crate::protos::public_tower_services_client::PublicTowerServicesClient;
use tonic::transport::Channel;
use tonic::Code;

use lightning::io;
use lightning::ln::msgs::{DecodeError, ErrorAction, LightningError, WarningMessage};
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::CustomMessageReader;
use lightning::util::logger;
use lightning::util::ser::Readable;

use std::mem;
use std::sync::Mutex;

use teos_common::lightning::messages::*;
use teos_common::protos as common_msgs;

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
            log_level: logger::Level::Warn,
        },
    })
}

/// A handler to handle the incoming [`TowerMessage`]s.
pub struct TowerMessageHandler {
    /// A queue holding the response messages or errors the tower wants to send to its peers.
    msg_queue: Mutex<Vec<(PublicKey, TowerMessage)>>,
    // TODO: Will it make more sense using the watcher interface instead of the gRPC?
    // since the watcher interface is not async and it does provide richer error codes.
    /// A connection to the tower's internal gRPC API.
    grpc_conn: PublicTowerServicesClient<Channel>,
    /// A tokio runtime handle to run gRPC async calls on.
    handle: runtime::Handle,
}

impl TowerMessageHandler {
    fn new(grpc_conn: PublicTowerServicesClient<Channel>, handle: runtime::Handle) -> Self {
        Self {
            msg_queue: Mutex::new(Vec::new()),
            grpc_conn,
            handle,
        }
    }

    fn handle_tower_message(
        &self,
        msg: TowerMessage,
        peer: &PublicKey,
    ) -> Result<TowerMessage, LightningError> {
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
                    self.handle
                        .block_on(grpc_conn.add_appointment(
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
                    Err(e) => warn_peer(
                        e.message(),
                        &format!(
                            "Failed accepting appointment from {} with locator {}",
                            peer, msg.locator
                        ),
                    ),
                }
            }
            TowerMessage::GetAppointment(msg) => {
                let res =
                    self.handle
                        .block_on(grpc_conn.get_appointment(
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
                let res = self.handle.block_on(
                    grpc_conn
                        .get_subscription_info(common_msgs::GetSubscriptionInfoRequest::from(msg)),
                );
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
