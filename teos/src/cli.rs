use std::fs;
use std::str::FromStr;
use structopt::StructOpt;
use tonic::Request;

use rusty_teos::cli_config::{Command, Config, Opt};
use rusty_teos::config;
use rusty_teos::protos as msgs;
use rusty_teos::protos::private_tower_services_client::PrivateTowerServicesClient;
use teos_common::UserId;

#[tokio::main]
async fn main() {
    let opt = Opt::from_args();
    let path = config::data_dir_absolute_path(opt.data_dir.clone());

    // Create data dir if it does not exist
    fs::create_dir_all(&path).unwrap_or_else(|e| {
        eprint!("Cannot create data dir: {:?}\n", e);
        std::process::exit(1);
    });

    let command = opt.command.clone();

    // Load conf (from file or defaults) and patch it with the command line parameters received (if any)
    let mut conf = config::from_file::<Config>(path.join("teos.toml"));
    conf.patch_with_options(opt);

    // Create gRPC client and send request
    let mut client =
        PrivateTowerServicesClient::connect(format!("http://{}:{}", conf.rpc_bind, conf.rpc_port))
            .await
            .unwrap_or_else(|e| {
                eprint!("Cannot connect to the tower. Connection refused\n");
                if conf.debug {
                    eprint!("{:?}\n", e);
                }
                std::process::exit(1);
            });

    match command {
        Command::GetAllAppointments => {
            let appointments = client.get_all_appointments(Request::new(())).await.unwrap();
            println!("{}", appointments.into_inner());
        }
        Command::GetTowerInfo => {
            let info = client.get_tower_info(Request::new(())).await.unwrap();
            println!("{}", info.into_inner())
        }
        Command::GetUsers => {
            let users = client.get_users(Request::new(())).await.unwrap();
            println!("{}", users.into_inner());
        }
        Command::GetUser(data) => {
            match UserId::from_str(&data.user_id) {
                Ok(user_id) => {
                    match client
                        .get_user(Request::new(msgs::GetUserRequest {
                            user_id: user_id.serialize(),
                        }))
                        .await
                    {
                        Ok(response) => println!("{}", response.into_inner()),
                        Err(status) => println!("{}", status.message()),
                    }
                }
                Err(e) => println!("{}", e),
            };
        }
        Command::Stop => {
            println!("Shutting down tower");
            client.stop(Request::new(())).await.unwrap();
        }
    };
}
