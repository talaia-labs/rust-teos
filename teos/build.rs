fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().compile(
        &[
            "proto/teos/appointment.proto",
            "proto/teos/tower_services.proto",
            "proto/teos/user.proto",
        ],
        &["proto/teos"],
    )?;

    Ok(())
}
