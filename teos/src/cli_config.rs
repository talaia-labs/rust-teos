//! Logic related to the tower CLI configuration and command line parameter parsing.

use serde::Deserialize;
use structopt::StructOpt;

#[derive(Debug, StructOpt, Clone)]
#[structopt(rename_all = "snake_case")]
pub enum Command {
    /// Gets information about all appointments stored in the tower
    GetAllAppointments,
    /// Gets information about specific appointments stored in the tower using a locator
    GetAppointments(GetAppointmentsData),
    /// Gets generic information about the tower, like tower id and aggregate data on users and appointments
    GetTowerInfo,
    /// Gets an array with the user ids of all the users registered to the tower
    GetUsers,
    /// Gets information about a specific user
    GetUser(GetUserData),
    /// Requests a graceful shutdown of the tower
    Stop,
}

#[derive(Debug, StructOpt, Clone)]
#[structopt(rename_all = "lowercase")]
pub struct GetUserData {
    /// The user identifier (33-byte compressed public key).
    pub user_id: String,
}

#[derive(Debug, StructOpt, Clone)]
pub struct GetAppointmentsData {
    /// The locator of the appointments (16-byte hexadecimal string).
    pub locator: String,
}

/// Holds all the command line options and commands.
#[derive(StructOpt, Debug)]
#[structopt(rename_all = "lowercase")]
#[structopt(
    version = "0.0.1",
    about = "The Eye of Satoshi - CLI",
    name = "teos-cli"
)]
pub struct Opt {
    /// Address teos RPC server is bind to [default: localhost]
    #[structopt(long)]
    pub rpc_bind: Option<String>,

    /// Port teos RPC server is bind to [default: 8814]
    #[structopt(long)]
    pub rpc_port: Option<u16>,

    /// Specify data directory
    #[structopt(long, default_value = "~/.teos")]
    pub data_dir: String,

    /// Runs teos-cli in debug mode [default: false]
    #[structopt(long)]
    pub debug: bool,

    /// Command
    #[structopt(subcommand)]
    pub command: Command,
}

/// Holds all configuration options.
///
/// The overwrite policy goes, from less to more:
/// - Defaults
/// - Configuration file
/// - Command line options
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    pub rpc_bind: String,
    pub rpc_port: u16,
    pub debug: bool,
}

impl Config {
    /// Patches the configuration options with the command line options.
    pub fn patch_with_options(&mut self, options: Opt) {
        if options.rpc_bind.is_some() {
            self.rpc_bind = options.rpc_bind.unwrap();
        }
        if options.rpc_port.is_some() {
            self.rpc_port = options.rpc_port.unwrap();
        }

        self.debug |= options.debug;
    }
}

impl Default for Config {
    /// Sets the tower [Config] defaults.
    ///
    /// Notice the defaults are not enough, and the tower will refuse to run on them.
    /// For instance, the defaults do set the `bitcoind` `rpu_user` and `rpc_password`
    /// to empty strings so the user is forced the set them (and most importantly so the
    /// user does not use any values provided here).
    fn default() -> Self {
        Self {
            rpc_bind: "localhost".into(),
            rpc_port: 8814,
            debug: false,
        }
    }
}
