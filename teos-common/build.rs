fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute("AppointmentData.appointment_data", "#[serde(untagged)]")
        .field_attribute("AppointmentData.appointment_data", "#[serde(flatten)]")
        .field_attribute("appointment_data", "#[serde(rename = \"appointment\")]")
        .field_attribute("user_id", "#[serde(with = \"hex::serde\")]")
        .field_attribute("locator", "#[serde(with = \"hex::serde\")]")
        .field_attribute(
            "locators",
            "#[serde(with = \"crate::ser::serde_vec_bytes\")]",
        )
        .field_attribute("encrypted_blob", "#[serde(with = \"hex::serde\")]")
        .field_attribute("dispute_txid", "#[serde(with = \"crate::ser::serde_be\")]")
        .field_attribute("penalty_txid", "#[serde(with = \"crate::ser::serde_be\")]")
        .field_attribute("penalty_rawtx", "#[serde(with = \"hex::serde\")]")
        .field_attribute(
            "GetAppointmentResponse.status",
            "#[serde(with = \"crate::ser::serde_status\")]",
        )
        .compile(
            &[
                "proto/common/teos/v2/appointment.proto",
                "proto/common/teos/v2/user.proto",
            ],
            &["proto/common/teos/v2"],
        )?;

    Ok(())
}
