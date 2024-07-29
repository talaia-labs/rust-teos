/* The following code for generating mTLS certificates is adapted from:
 * https://github.com/ElementsProject/lightning/blob/master/plugins/grpc-plugin/src/tls.rs
 *
 * This file is licensed under the BSD-MIT license, as described here:
 * https://github.com/ElementsProject/lightning/blob/master/LICENSE
*/

use rcgen::{Certificate, Error as RcgenError, KeyPair};
use std::convert::TryFrom;
use std::path::Path;

/// Packs the reasons why generating mtls certificates may fail.
#[derive(Debug)]
pub enum GenCertificateFailure {
    RcgenError(RcgenError),
    IoError(std::io::Error),
}

impl From<RcgenError> for GenCertificateFailure {
    fn from(e: RcgenError) -> Self {
        GenCertificateFailure::RcgenError(e)
    }
}

impl From<std::io::Error> for GenCertificateFailure {
    fn from(e: std::io::Error) -> Self {
        GenCertificateFailure::IoError(e)
    }
}

/// Just a wrapper around a certificate and an associated keypair.
#[derive(Clone, Debug)]
struct Identity {
    pub key: Vec<u8>,
    pub certificate: Vec<u8>,
}

impl TryFrom<&Identity> for (Certificate, KeyPair) {
    type Error = RcgenError;

    fn try_from(id: &Identity) -> Result<(Certificate, KeyPair), RcgenError> {
        let key = KeyPair::from_pem(&String::from_utf8_lossy(&id.key))?;
        let params =
            rcgen::CertificateParams::from_ca_cert_pem(&String::from_utf8_lossy(&id.certificate))?;
        let cert = params.self_signed(&key)?;
        Ok((cert, key))
    }
}

pub fn tls_init(
    directory: &Path,
) -> Result<(tonic::transport::Identity, Vec<u8>), GenCertificateFailure> {
    let ca = generate_or_load_identity("teos Root CA", directory, "ca", None)?;
    let server = generate_or_load_identity("teos grpc Server", directory, "server", Some(&ca))?;
    let _client = generate_or_load_identity("teos grpc Client", directory, "client", Some(&ca))?;
    let server_id = tonic::transport::Identity::from_pem(&server.certificate, &server.key);

    Ok((server_id, ca.certificate))
}

/// Generate a given identity
fn generate_or_load_identity(
    name: &str,
    directory: &Path,
    filename: &str,
    parent: Option<&Identity>,
) -> Result<Identity, GenCertificateFailure> {
    // Just our naming convention here.
    let cert_path = directory.join(format!("{filename}.pem"));
    let key_path = directory.join(format!("{filename}-key.pem"));
    // Did we have to generate a new key? In that case we also need to regenerate the certificate.
    if !key_path.exists() || !cert_path.exists() {
        log::debug!("Generating a new keypair in {key_path:?}, it didn't exist",);
        let keypair = KeyPair::generate()?;
        std::fs::write(&key_path, keypair.serialize_pem())?;
        log::debug!("Generating a new certificate for key {key_path:?} at {cert_path:?}",);

        // Configure the certificate we want.
        let subject_alt_names = vec!["teos".to_string(), "localhost".to_string()];
        let mut params = rcgen::CertificateParams::new(subject_alt_names)?;
        if parent.is_none() {
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        } else {
            params.is_ca = rcgen::IsCa::NoCa;
        }
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);

        std::fs::write(
            &cert_path,
            match parent {
                None => params.self_signed(&keypair)?.pem(),
                Some(ca) => {
                    let (ca_cert, ca_key) = <(Certificate, KeyPair)>::try_from(ca)?;
                    params.signed_by(&keypair, &ca_cert, &ca_key)?.pem()
                }
            },
        )?;
    }

    let key = std::fs::read(&key_path)?;
    let certificate = std::fs::read(cert_path)?;
    Ok(Identity { certificate, key })
}
