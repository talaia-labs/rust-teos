use std::convert::TryInto;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::path::PathBuf;

use tokio::fs;
use tokio::net::TcpStream;
use torut::control::UnauthenticatedConn;
use torut::onion::TorSecretKeyV3;
use triggered::{Listener, Trigger};

pub struct TorAPI {
    sk: TorSecretKeyV3,
    api_endpoint: SocketAddr,
    onion_port: u16,
    tor_control_port: u16,
}

impl TorAPI {
    pub async fn new(
        api_endpoint: SocketAddr,
        onion_port: u16,
        tor_control_port: u16,
        path: PathBuf,
    ) -> Self {
        let key = if let Some(key) = TorAPI::load_sk(path.clone()).await {
            key
        } else {
            log::info!("Generating fresh Tor secret key");
            let key = TorSecretKeyV3::generate();
            TorAPI::store_sk(&key, path).await;
            key
        };

        Self {
            sk: key,
            api_endpoint,
            onion_port,
            tor_control_port,
        }
    }

    pub fn get_onion_address(&self) -> String {
        self.sk.public().get_onion_address().to_string()
    }

    /// Loads a Tor key from disk (if found).
    async fn load_sk(path: PathBuf) -> Option<TorSecretKeyV3> {
        log::info!("Loading Tor secret key from disk");
        let key = fs::read(path.join("onion_v3_sk"))
            .await
            .map_err(|e| log::warn!("Tor secret key cannot be loaded. {e}"))
            .ok()?;
        let key: [u8; 64] = key
            .try_into()
            .map_err(|_| log::error!("Cannot convert loaded data into Tor secret key"))
            .ok()?;

        Some(TorSecretKeyV3::from(key))
    }

    /// Stores a Tor key to disk.
    async fn store_sk(key: &TorSecretKeyV3, path: PathBuf) {
        if let Err(e) = fs::write(path.join("onion_v3_sk"), key.as_bytes()).await {
            log::error!("Cannot store Tor secret key. {e}");
        }
    }

    /// Tries to connect to the Tor control port
    async fn connect_tor_cp(&self) -> Result<TcpStream, Error> {
        let sock = TcpStream::connect(format!("127.0.0.1:{}", self.tor_control_port))
            .await
            .map_err(|_| {
                Error::new(
                    ErrorKind::ConnectionRefused,
                    "failed to connect to Tor control port",
                )
            })?;
        Ok(sock)
    }

    /// Expose an onion service that re-directs to the public api.
    pub async fn expose_onion_service(
        &self,
        service_ready: Trigger,
        shutdown_signal_tor: Listener,
    ) -> Result<(), Error> {
        let stream = self
            .connect_tor_cp()
            .await
            .map_err(|e| Error::new(ErrorKind::ConnectionRefused, e))?;

        let mut unauth_conn = UnauthenticatedConn::new(stream);

        let pre_auth = unauth_conn
            .load_protocol_info()
            .await
            .map_err(|e| Error::new(ErrorKind::ConnectionRefused, e))?;

        let auth_data = pre_auth
            .make_auth_data()?
            .expect("failed to make auth data");

        unauth_conn.authenticate(&auth_data).await.map_err(|_| {
            Error::new(
                ErrorKind::PermissionDenied,
                "failed to authenticate with Tor",
            )
        })?;

        let mut auth_conn = unauth_conn.into_authenticated().await;

        auth_conn.set_async_event_handler(Some(|_| async move { Ok(()) }));

        auth_conn
            .add_onion_v3(
                &self.sk,
                false,
                false,
                false,
                None,
                &mut [(self.onion_port, self.api_endpoint)].iter(),
            )
            .await
            .map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!("failed to create onion hidden service: {e}"),
                )
            })?;

        log::info!(
            "Onion service: {}:{}",
            self.get_onion_address(),
            self.onion_port
        );
        service_ready.trigger();
        shutdown_signal_tor.await;

        auth_conn
            .del_onion(
                &self
                    .sk
                    .public()
                    .get_onion_address()
                    .get_address_without_dot_onion(),
            )
            .await
            .unwrap();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;

    use teos_common::test_utils::get_random_user_id;

    #[tokio::test]
    async fn test_store_load_sk() {
        let key = TorSecretKeyV3::generate();
        let tmp_path = TempDir::new(&format!("data_dir_{}", get_random_user_id())).unwrap();

        TorAPI::store_sk(&key, tmp_path.path().into()).await;
        let loaded_key = TorAPI::load_sk(tmp_path.path().into()).await;

        assert_eq!(key, loaded_key.unwrap())
    }

    #[tokio::test]
    async fn test_load_sk_inexistent() {
        let tmp_path = TempDir::new(&format!("data_dir_{}", get_random_user_id())).unwrap();
        let loaded_key = TorAPI::load_sk(tmp_path.path().into()).await;

        assert_eq!(loaded_key, None);
    }

    #[tokio::test]
    async fn test_load_sk_wrong_format() {
        let tmp_path = TempDir::new(&format!("data_dir_{}", get_random_user_id())).unwrap();
        fs::write(tmp_path.path().join("onion_v3_sk"), "random stuff")
            .await
            .unwrap();
        let loaded_key = TorAPI::load_sk(tmp_path.path().into()).await;

        assert_eq!(loaded_key, None);
    }

    #[tokio::test]
    async fn test_connect_tor_cp_fail() {
        let wrong_cp = 9000;
        let tmp_path = TempDir::new(&format!("data_dir_{}", get_random_user_id())).unwrap();
        let tor_api = TorAPI::new(
            "127.0.1.1:9814".parse().unwrap(),
            9814,
            wrong_cp,
            tmp_path.path().into(),
        )
        .await;

        match tor_api.connect_tor_cp().await {
            Ok(_) => {}
            Err(e) => {
                assert_eq!("failed to connect to Tor control port", e.to_string())
            }
        }
    }
}
