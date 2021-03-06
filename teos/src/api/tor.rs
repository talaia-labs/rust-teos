use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use torut::control::UnauthenticatedConn;
use torut::onion::TorSecretKeyV3;
use triggered::Listener;

/// Expose an onion service that re-directs to the public api.
pub async fn expose_onion_service(
    tor_control_port: u16,
    api_port: u16,
    onion_port: u16,
    shutdown_signal_tor: Listener,
) -> Result<(), Error> {
    let stream = connect_tor_cp(format!("127.0.0.1:{}", tor_control_port).parse().unwrap())
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

    let key = TorSecretKeyV3::generate();

    auth_conn
        .add_onion_v3(
            &key,
            false,
            false,
            false,
            None,
            &mut [(
                onion_port,
                format!("127.0.0.1:{}", api_port).parse().unwrap(),
            )]
            .iter(),
        )
        .await
        .map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to create onion hidden service: {}", e),
            )
        })?;

    print_onion_service(key.clone(), onion_port);

    // NOTE: Needed to keep connection with control port & hidden service running, as soon as we leave
    // this function the control port stream is dropped and the hidden service is killed
    loop {
        sleep(Duration::from_secs(1)).await;
        if shutdown_signal_tor.is_triggered() {
            break;
        }
    }

    auth_conn
        .del_onion(
            &key.public()
                .get_onion_address()
                .get_address_without_dot_onion(),
        )
        .await
        .unwrap();
    Ok(())
}

async fn connect_tor_cp(addr: SocketAddr) -> Result<TcpStream, Error> {
    let sock = TcpStream::connect(addr).await.map_err(|_| {
        Error::new(
            ErrorKind::ConnectionRefused,
            "failed to connect to tor control port",
        )
    })?;
    Ok(sock)
}

fn print_onion_service(key: TorSecretKeyV3, onion_port: u16) {
    let onion_addr = key.public().get_onion_address();
    let onion = format!("{}:{}", onion_addr, onion_port);
    log::info!("onion service: {}", onion);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connect_tor_cp_fail() {
        let tor_control_port = 9000;
        let addr = format!("127.0.0.1:{}", tor_control_port).parse().unwrap();
        match connect_tor_cp(addr).await {
            Ok(_) => {}
            Err(e) => {
                assert_eq!("failed to connect to tor control port", e.to_string())
            }
        }
    }
}
