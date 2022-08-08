fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .extern_path(".common.teos.v2", "::teos-common::protos")
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .field_attribute("user_id", "#[serde(with = \"hex::serde\")]")
        .field_attribute("tower_id", "#[serde(with = \"hex::serde\")]")
        .field_attribute(
            "user_ids",
            "#[serde(serialize_with = \"teos_common::ser::serde_vec_bytes::serialize\")]",
        )
        .field_attribute(
            "GetUserResponse.appointments",
            "#[serde(serialize_with = \"teos_common::ser::serde_vec_bytes::serialize\")]",
        )
        .compile(
            &[
                "proto/teos/v2/appointment.proto",
                "proto/teos/v2/tower_services.proto",
                "proto/teos/v2/user.proto",
            ],
            &["proto/teos/v2", "../teos-common/proto/"],
        )?;

    Ok(())
}
