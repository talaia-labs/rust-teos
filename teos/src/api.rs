use futures::executor::block_on;
use std::convert::TryInto;
use std::sync::Arc;
use tonic::{Code, Request, Response, Status};

use crate::protos as msgs;
use crate::protos::private_tower_services_server::PrivateTowerServices;
use crate::protos::public_tower_services_server::PublicTowerServices;

use crate::watcher::{
    AddAppointmentFailure, AppointmentInfo, GetAppointmentFailure, GetSubscriptionInfoFailure,
    Watcher,
};

use teos_common::appointment::{Appointment, AppointmentStatus, Locator};
use teos_common::UserId;

/// Internal API of the tower.
/// Holds the [Watcher] (which is the single entry point of the tower's core) and offers interfaces
/// to all available methods. The [InternalAPI] has two interfaces, a public one, reachable from the [API]
/// and a private one, only accessible from the [RPCServer].
pub struct InternalAPI {
    /// A [Watcher] instance.
    watcher: Arc<Watcher>,
}

impl<'a> InternalAPI {
    /// Creates a new [InternalAPI] instance.
    pub fn new(watcher: Arc<Watcher>) -> Self {
        Self { watcher }
    }
}

/// Public tower API. Accessible by users.
#[tonic::async_trait]
impl<'a> PublicTowerServices for Arc<InternalAPI> {
    /// Register endpoint. Part of the public API. Internally calls [Watcher::register].
    async fn register(
        &self,
        request: Request<msgs::RegisterRequest>,
    ) -> Result<Response<msgs::RegisterResponse>, Status> {
        let req_data = request.into_inner();

        let user_id = UserId::deserialize(&req_data.user_id).map_err(|_| {
            Status::new(
                Code::InvalidArgument,
                "Provided public key does not match expected format (33-byte compressed key)",
            )
        })?;

        match self.watcher.register(user_id) {
            Ok(receipt) => Ok(Response::new(msgs::RegisterResponse {
                user_id: req_data.user_id,
                available_slots: receipt.available_slots(),
                subscription_expiry: receipt.subscription_expiry(),
                subscription_signature: receipt.signature().unwrap(),
            })),
            Err(_) => Err(Status::new(
                Code::ResourceExhausted,
                "Subscription maximum slots count reached",
            )),
            // FIXME: more errors are needed. e.g. ConnectionRefusedError.
        }
    }

    /// Add appointment endpoint. Part of the public API. Internally calls [Watcher::add_appointment].
    async fn add_appointment(
        &self,
        request: Request<msgs::AddAppointmentRequest>,
    ) -> Result<Response<msgs::AddAppointmentResponse>, Status> {
        let req_data = request.into_inner();
        let app_data = req_data.appointment.unwrap();

        let appointment = Appointment::new(
            Locator::deserialize(&app_data.locator).unwrap(),
            app_data.encrypted_blob.try_into().unwrap(),
            app_data.to_self_delay,
        );
        let locator = appointment.locator;

        // This is block_on because MutexGuard cannot be sent between threads safely.
        match block_on(
            self.watcher
                .add_appointment(appointment, req_data.signature),
        ) {
            Ok((receipt, available_slots, subscription_expiry)) => {
                Ok(Response::new(msgs::AddAppointmentResponse {
                    locator: locator.serialize(),
                    start_block: receipt.start_block(),
                    signature: receipt.signature().unwrap(),
                    available_slots,
                    subscription_expiry,
                }))
            }
            Err(e) => match e {
                AddAppointmentFailure::AuthenticationFailure
                | AddAppointmentFailure::NotEnoughSlots => Err(Status::new(
                    Code::Unauthenticated,
                    "Invalid signature or user does not have enough slots available",
                )),
                AddAppointmentFailure::SubscriptionExpired(x) => Err(Status::new(
                    Code::Unauthenticated,
                    format!("Your subscription expired at {}", x),
                )),
                AddAppointmentFailure::AlreadyTriggered => Err(Status::new(
                    Code::AlreadyExists,
                    "The provided appointment has already been triggered",
                )),
                // FIXME: more errors are needed. e.g. ConnectionRefusedError.
            },
        }
    }

    /// Get appointment endpoint. Part of the public API. Internally calls [Watcher::get_appointment].
    async fn get_appointment(
        &self,
        request: Request<msgs::GetAppointmentRequest>,
    ) -> Result<Response<msgs::GetAppointmentResponse>, Status> {
        let req_data = request.into_inner();
        let locator = Locator::deserialize(&req_data.locator).unwrap();

        match self.watcher.get_appointment(locator, &req_data.signature) {
            Ok(info) => {
                let (appointment_data, status) = match info {
                    AppointmentInfo::Appointment(appointment) => (
                        msgs::AppointmentData {
                            appointment_data: Some(
                                msgs::appointment_data::AppointmentData::Appointment(
                                    appointment.into(),
                                ),
                            ),
                        },
                        AppointmentStatus::BeingWatched,
                    ),
                    AppointmentInfo::Tracker(tracker) => (
                        msgs::AppointmentData {
                            appointment_data: Some(
                                msgs::appointment_data::AppointmentData::Tracker(tracker.into()),
                            ),
                        },
                        AppointmentStatus::DisputeResponded,
                    ),
                };
                Ok(Response::new(msgs::GetAppointmentResponse {
                    appointment_data: Some(appointment_data),
                    status: status as i32,
                }))
            }
            Err(e) => match e {
                GetAppointmentFailure::AuthenticationFailure | GetAppointmentFailure::NotFound => {
                    Err(Status::new(Code::NotFound, "Appointment not found"))
                }
                GetAppointmentFailure::SubscriptionExpired(x) => Err(Status::new(
                    Code::Unauthenticated,
                    format!("Your subscription expired at {}", x),
                )),
                // FIXME: more errors are needed. e.g. ConnectionRefusedError.
            },
        }
    }

    /// Get subscription info endpoint. Part of the public API. Internally calls [Watcher::get_subscription_info].
    async fn get_subscription_info(
        &self,
        request: Request<msgs::GetSubscriptionInfoRequest>,
    ) -> Result<Response<msgs::GetSubscriptionInfoResponse>, Status> {
        let (subscription_info, locators) = self
            .watcher
            .get_subscription_info(&request.into_inner().signature)
            .map_err(|e| match e {
                GetSubscriptionInfoFailure::AuthenticationFailure => {
                    Status::new(Code::NotFound, "User not found. Have you registered?")
                }
                GetSubscriptionInfoFailure::SubscriptionExpired(x) => Status::new(
                    Code::Unauthenticated,
                    format!("Your subscription expired at {}", x),
                ),
                // FIXME: more errors are needed. e.g. ConnectionRefusedError.
            })?;

        Ok(Response::new(msgs::GetSubscriptionInfoResponse {
            available_slots: subscription_info.available_slots,
            subscription_expiry: subscription_info.subscription_expiry,
            locators: locators.iter().map(|x| x.serialize()).collect(),
        }))
    }
}

/// Private tower API. Only accessible by the tower admin via RPC.
#[tonic::async_trait]
impl<'a> PrivateTowerServices for Arc<InternalAPI> {
    /// Get all appointments endpoint. Gets all appointments in the tower. Part of the private API.
    /// Internally calls [Watcher::get_all_watcher_appointments] and [Watcher::get_all_responder_trackers].
    async fn get_all_appointments(
        &self,
        _: Request<()>,
    ) -> Result<Response<msgs::GetAllAppointmentsResponse>, Status> {
        let mut all_appointments = Vec::new();

        for (_, appointment) in self.watcher.get_all_watcher_appointments().into_iter() {
            all_appointments.push(msgs::AppointmentData {
                appointment_data: Some(msgs::appointment_data::AppointmentData::Appointment(
                    appointment.inner.into(),
                )),
            })
        }

        for (_, tracker) in self.watcher.get_all_responder_trackers().into_iter() {
            all_appointments.push(msgs::AppointmentData {
                appointment_data: Some(msgs::appointment_data::AppointmentData::Tracker(
                    tracker.into(),
                )),
            })
        }

        Ok(Response::new(msgs::GetAllAppointmentsResponse {
            appointments: all_appointments,
        }))
    }

    /// Get tower info endpoint. Gets information about the tower state. Part of the private API.
    /// Internally calls [Watcher::get_registered_users_count], [Watcher::get_appointments_count]
    /// and [Watcher::get_trackers_count].
    async fn get_tower_info(
        &self,
        _: Request<()>,
    ) -> Result<Response<msgs::GetTowerInfoResponse>, Status> {
        Ok(Response::new(msgs::GetTowerInfoResponse {
            tower_id: self.watcher.tower_id.serialize(),
            n_registered_users: self.watcher.get_registered_users_count() as u32,
            n_watcher_appointments: self.watcher.get_appointments_count() as u32,
            n_responder_trackers: self.watcher.get_trackers_count() as u32,
        }))
    }

    /// Get user endpoint. Gets all users in the tower. Part of the private API.
    /// Internally calls [Watcher::get_user_ids].
    async fn get_users(&self, _: Request<()>) -> Result<Response<msgs::GetUsersResponse>, Status> {
        let user_ids = self
            .watcher
            .get_user_ids()
            .iter()
            .map(|x| x.serialize())
            .collect();

        Ok(Response::new(msgs::GetUsersResponse { user_ids }))
    }

    /// Get user endpoint. Gets information about a given user. Part of the private API.
    /// Internally calls [Watcher::get_user].
    async fn get_user(
        &self,
        request: Request<msgs::GetUserRequest>,
    ) -> Result<Response<msgs::GetUserResponse>, Status> {
        let user_id = UserId::deserialize(&request.into_inner().user_id).map_err(|_| {
            Status::new(
                Code::InvalidArgument,
                "Provided public key does not match expected format (33-byte compressed key)",
            )
        })?;

        match self.watcher.get_user_info(user_id) {
            Some(info) => Ok(Response::new(msgs::GetUserResponse {
                available_slots: info.available_slots,
                subscription_expiry: info.subscription_expiry,
                appointments: info
                    .appointments
                    .iter()
                    .map(|(uuid, _)| uuid.serialize())
                    .collect(),
            })),
            None => Err(Status::new(Code::NotFound, "User not found")),
        }
    }

    /// Stop endpoint. Stops the tower daemon. Part of the private API.
    // FIXME: Not implemented yet. Needs to perform a gentle shutdown of the whole system.
    async fn stop(&self, _: Request<()>) -> Result<Response<()>, Status> {
        Ok(Response::new(()))
    }
}
