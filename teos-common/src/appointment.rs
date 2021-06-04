use serde::{Deserialize, Serialize};
use serde_json::{Error as JSONError, Value};

/// Contains data regarding an appointment between a client and the Watchtower. An appointment is requested for every new channel update.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct Appointment {
    pub locator: [u8; 16],
    pub encrypted_blob: Vec<u8>,
    pub to_self_delay: u32,
}

/// Represents all the possible states of an appointment in the system, or in a response to a client request.
pub enum AppointmentStatus {
    NotFound,
    BeingWatched,
    DisputeResponded,
}

impl Appointment {
    pub fn new(locator: [u8; 16], encrypted_blob: Vec<u8>, to_self_delay: u32) -> Self {
        Appointment {
            locator,
            encrypted_blob,
            to_self_delay,
        }
    }

    pub fn from_json(data: &str) -> Result<Self, JSONError> {
        serde_json::from_str::<Appointment>(data)
    }

    pub fn to_json(self) -> Value {
        serde_json::to_value(&self).unwrap()
    }

    /// Serializes an appointment to be signed.
    /// The serialization follows the same ordering as the fields in the appointment:
    ///
    /// locator | encrypted_blob | to_self_delay
    ///
    /// All values are big endian.
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = self.locator.to_vec();
        result.extend(&self.encrypted_blob);
        result.extend(self.to_self_delay.to_be_bytes().to_vec());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::Appointment;
    use serde_json::json;

    #[test]
    fn test_from_json() {
        let locator = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        let encrypted_blob = [1, 2, 3, 4].to_vec();
        let to_self_delay = 21;
        let appointment = Appointment::new(locator, encrypted_blob.clone(), to_self_delay);

        let data = json!(appointment).to_string();
        let a = Appointment::from_json(&data).unwrap();

        assert_eq!(a.locator, locator);
        assert_eq!(a.encrypted_blob, encrypted_blob);
        assert_eq!(a.to_self_delay, to_self_delay);
    }

    #[test]
    fn test_to_json() {
        let locator = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        let encrypted_blob = [1, 2, 3, 4].to_vec();
        let to_self_delay = 21;
        let appointment = Appointment::new(locator, encrypted_blob.clone(), to_self_delay);

        let a_json = appointment.to_json();

        assert_eq!(a_json["locator"], json!(locator));
        assert_eq!(a_json["encrypted_blob"], json!(encrypted_blob));
        assert_eq!(a_json["to_self_delay"], json!(to_self_delay));
    }
}
