use hex::FromHex;
use serde_json::to_string_pretty as pretty_json;
use std::str::FromStr;
use structopt::StructOpt;
use tokio::fs;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tonic::Request;

use teos::cli_config::{Command, Config, Opt};
use teos::config;
use teos::protos as msgs;
use teos::protos::private_tower_services_client::PrivateTowerServicesClient;
use teos_common::appointment::Locator;
use teos_common::UserId;

#[tokio::main]
async fn main() {
    let opt = Opt::from_args();
    let path = config::data_dir_absolute_path(opt.data_dir.clone());

    // Create data dir if it does not exist
    fs::create_dir_all(&path).await.unwrap_or_else(|e| {
        eprintln!("Cannot create data dir: {e:?}");
        std::process::exit(1);
    });

    let command = opt.command.clone();

    // Load conf (from file or defaults) and patch it with the command line parameters received (if any)
    let mut conf = config::from_file::<Config>(&path.join("teos.toml"));
    conf.patch_with_options(opt);

    let key = fs::read(&path.join("client-key.pem"))
        .await
        .expect("unable to read client key from disk");
    let certificate = fs::read(path.join("client.pem"))
        .await
        .expect("unable to read client cert from disk");
    let ca_cert = Certificate::from_pem(
        fs::read(path.join("ca.pem"))
            .await
            .expect("unable to read ca cert from disk"),
    );

    let tls = ClientTlsConfig::new()
        .domain_name("localhost")
        .ca_certificate(ca_cert)
        .identity(Identity::from_pem(certificate, key));

    let channel = Channel::from_shared(format!("http://{}:{}", conf.rpc_bind, conf.rpc_port))
        .expect("Cannot create channel from endpoint")
        .tls_config(tls)
        .unwrap_or_else(|e| {
            eprintln!("Could not configure tls: {e:?}");
            std::process::exit(1);
        })
        .connect()
        .await
        .unwrap_or_else(|_| {
            eprintln!("Could not connect to tower. Is teosd running?");
            std::process::exit(1);
        });

    let mut client = PrivateTowerServicesClient::new(channel);

    match command {
        Command::GetAllAppointments => {
            let appointments = client.get_all_appointments(Request::new(())).await.unwrap();
            println!("{}", pretty_json(&appointments.into_inner()).unwrap());
        }
        Command::GetAppointments(appointments_data) => {
            match Locator::from_hex(&appointments_data.locator) {
                Ok(locator) => {
                    match client
                        .get_appointments(Request::new(msgs::GetAppointmentsRequest {
                            locator: locator.to_vec(),
                        }))
                        .await
                    {
                        Ok(appointments) => {
                            println!("{}", pretty_json(&appointments.into_inner()).unwrap())
                        }
                        Err(status) => println!("{}", status.message()),
                    }
                }
                Err(e) => println!("{e}"),
            };
        }
        Command::GetTowerInfo => {
            let info = client.get_tower_info(Request::new(())).await.unwrap();
            println!("{}", pretty_json(&info.into_inner()).unwrap())
        }
        Command::GetUsers => {
            let users = client.get_users(Request::new(())).await.unwrap();
            println!("{}", pretty_json(&users.into_inner()).unwrap());
        }
        Command::GetUser(user) => {
            match UserId::from_str(&user.user_id) {
                Ok(user_id) => {
                    match client
                        .get_user(Request::new(msgs::GetUserRequest {
                            user_id: user_id.to_vec(),
                        }))
                        .await
                    {
                        Ok(response) => {
                            println!("{}", pretty_json(&response.into_inner()).unwrap())
                        }
                        Err(status) => println!("{}", status.message()),
                    }
                }
                Err(e) => println!("{e}"),
            };
        }
        Command::Stop => {
            println!("Shutting down tower");
            client.stop(Request::new(())).await.unwrap();
        }
    };
}
