use teos_common::appointment::Locator;
use teos_common::protos as common_msgs;
#[cfg(feature = "accountable")]
use teos_common::receipts::AppointmentReceipt;


// #[cfg(not(feature = "accountable"))]
pub fn get_dummy_add_appointment_response(locator: Locator, #[cfg(feature = "accountable")]receipt: &AppointmentReceipt,) -> common_msgs::AddAppointmentResponse {
    common_msgs::AddAppointmentResponse {
        locator: locator.to_vec(),
        #[cfg(feature = "accountable")]
        start_block: receipt.start_block(),
        #[cfg(not(feature = "accountable"))]
        start_block: 0,
        #[cfg(feature = "accountable")]
        signature: receipt.signature().unwrap(),
        #[cfg(not(feature = "accountable"))]
        signature: "None".to_string(),
        available_slots: 21,
        subscription_expiry: 1000,
    }
}
