fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute("AppointmentData.appointment_data", "#[serde(untagged)]")
        .field_attribute("AppointmentData.appointment_data", "#[serde(flatten)]")
        .field_attribute("appointment_data", "#[serde(rename = \"appointment\")]")
        .field_attribute("user_id", "#[serde(with = \"hex::serde\")]")
        .field_attribute("locator", "#[serde(with = \"hex::serde\")]")
        .field_attribute("encrypted_blob", "#[serde(with = \"hex::serde\")]")
        .field_attribute("tx", "#[serde(with = \"hex::serde\")]")
        .field_attribute(
            "locators",
            "#[serde(serialize_with = \"crate::api::http::serialize_locators\")]",
        )
        .field_attribute(
            "GetAppointmentResponse.status",
            "#[serde(with = \"crate::api::serde_status\")]",
        )
        .compile(
            &[
                "proto/teos/appointment.proto",
                "proto/teos/tower_services.proto",
                "proto/teos/user.proto",
            ],
            &["proto/teos"],
        )?;

    Ok(())
}
