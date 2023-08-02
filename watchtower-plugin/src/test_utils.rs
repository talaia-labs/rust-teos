use teos_common::appointment::Locator;
use teos_common::protos as common_msgs;
#[cfg(feature = "accountable")]
use teos_common::receipts::AppointmentReceipt;
#[cfg(feature = "accountable")]
pub fn get_dummy_add_appointment_response(
    locator: Locator,
    #[cfg(feature = "accountable")] 
    receipt: &AppointmentReceipt
) -> common_msgs::AddAppointmentResponse {
    common_msgs::AddAppointmentResponse {
        locator: locator.to_vec(),
        start_block: receipt.start_block(),
        signature: receipt.signature().unwrap(),
        available_slots: 21,
        subscription_expiry: 1000,
    }
}
