//! Formatting logic for proto messages.

use crate::protos;
use hex;

impl std::fmt::Display for protos::GetAllAppointmentsResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.appointments.is_empty() {
            write!(f, "[]")?;
        } else {
            write!(f, "[\n")?;
            for appointment in self.appointments.iter() {
                write!(f, "\t{},\n", appointment)?;
            }
            write!(f, "\n]")?;
        }
        Ok(())
    }
}

impl std::fmt::Display for protos::AppointmentData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.appointment_data {
            Some(ref data) => match data {
                protos::appointment_data::AppointmentData::Appointment(a) => {
                    write!(f,
                        "appointment: {{\n\t\tlocator: {},\n\t\tencrypted_blob: {},\n\t\tto_self_delay: {}\n\t}}", 
                        hex::encode(a.locator.clone()), hex::encode(a.encrypted_blob.clone()), a.to_self_delay)
                }
                protos::appointment_data::AppointmentData::Tracker(t) => {
                    write!(f,
                        "tracker: {{\n\t\tlocator: {},\n\t\tdispute_txid: {},\n\t\tpenalty_txid: {},\n\t\tpenalty_rawtx: {}\n\t}}", 
                        hex::encode(t.locator.clone()), hex::encode(t.dispute_txid.clone()), hex::encode(t.penalty_txid.clone()), hex::encode(t.penalty_rawtx.clone()))
                }
            },
            None => write!(f, ""),
        }
    }
}

impl std::fmt::Display for protos::GetTowerInfoResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{\n\ttower_id: {},\n\tn_registered_users: {},\n\tn_watcher_appointments: {},\n\tn_responder_trackers: {},\n}}",
            hex::encode(&self.tower_id),
            self.n_registered_users,
            self.n_watcher_appointments,
            self.n_responder_trackers
        )
    }
}

impl std::fmt::Display for protos::GetUsersResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.user_ids.is_empty() {
            write!(f, "[]")?;
        } else {
            write!(f, "[\n")?;
            for user_id in self.user_ids.iter() {
                write!(f, "\t{},\n", hex::encode(user_id))?;
            }
            write!(f, "]")?;
        }
        Ok(())
    }
}

impl std::fmt::Display for protos::GetUserResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{\n\tavailable_slots: {},\n\tsubscription_expiry: {},\n\tappointments: {:#?},\n}}",
            self.available_slots, self.subscription_expiry, self.appointments,
        )
    }
}
