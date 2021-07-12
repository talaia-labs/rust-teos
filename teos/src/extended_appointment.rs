use serde::{Deserialize, Serialize};
use serde_json::{Error as JSONError, Value};
use teos_common::appointment::{Appointment, Locator};

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct ExtendedAppointment {
    pub inner: Appointment,
    user_id: [u8; 16],
    user_signature: Vec<u8>,
    start_block: u32,
}

#[derive(Serialize, Deserialize)]
pub struct AppointmentSummary {
    locator: Locator,
    user_id: [u8; 16],
}

impl ExtendedAppointment {
    pub fn new(
        inner: Appointment,
        user_id: [u8; 16],
        user_signature: Vec<u8>,
        start_block: u32,
    ) -> Self {
        ExtendedAppointment {
            inner,
            user_id,
            user_signature,
            start_block,
        }
    }

    pub fn get_summary(&self) -> AppointmentSummary {
        AppointmentSummary {
            locator: self.inner.locator.clone(),
            user_id: self.user_id,
        }
    }

    pub fn from_json(data: &str) -> Result<Self, JSONError> {
        serde_json::from_str::<ExtendedAppointment>(data)
    }

    pub fn to_json(self) -> Value {
        serde_json::to_value(&self).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::ExtendedAppointment;
    use serde_json::json;
    use teos_common::appointment::Appointment;

    #[test]
    fn test_get_summary() {
        let locator = [1; 16];
        let user_id = [3; 16];

        let a = Appointment::new(locator, [2; 32].to_vec(), 42);
        let e = ExtendedAppointment::new(a, user_id, [4; 32].to_vec(), 21);

        let s = e.get_summary();

        assert_eq!(e.inner.locator, s.locator);
        assert_eq!(e.user_id, s.user_id);
    }

    #[test]
    fn test_from_json() {
        let locator = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        let encrypted_blob = [1, 2, 3, 4].to_vec();
        let to_self_delay = 21;
        let appointment = Appointment::new(locator, encrypted_blob, to_self_delay);

        let user_id = [2; 16];
        let user_signature = [5, 6, 7, 8].to_vec();
        let start_block = 42;

        let data = json!({
            "inner": appointment,
            "user_id": user_id,
            "user_signature": user_signature,
            "start_block": start_block
        })
        .to_string();

        let e = ExtendedAppointment::from_json(&data).unwrap();

        assert_eq!(e.inner, appointment);
        assert_eq!(e.user_id, user_id);
        assert_eq!(e.user_signature, user_signature);
        assert_eq!(e.start_block, start_block);
    }

    #[test]
    fn test_to_json() {
        let locator = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        let encrypted_blob = [1, 2, 3, 4].to_vec();
        let to_self_delay = 21;
        let appointment = Appointment::new(locator, encrypted_blob, to_self_delay);

        let user_id = [2; 16];
        let user_signature = [5, 6, 7, 8].to_vec();
        let start_block = 42;

        let extended_appointment = ExtendedAppointment::new(
            appointment.clone(),
            user_id,
            user_signature.clone(),
            start_block,
        );
        let e_json = extended_appointment.to_json();

        println!("{}", e_json);

        assert_eq!(e_json["inner"], json!(appointment));
        assert_eq!(e_json["user_id"], json!(user_id));
        assert_eq!(e_json["user_signature"], json!(user_signature));
        assert_eq!(e_json["start_block"], json!(start_block));
    }
}
