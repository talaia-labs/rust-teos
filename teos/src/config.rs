//! Logic related to the tower configuration and command line parameter parsing.

use bitcoin::network::constants::Network;
use serde::Deserialize;
use std;
use std::path::PathBuf;
use std::str::FromStr;
use structopt::StructOpt;

/// Holds all the command line options.
#[derive(StructOpt, Debug)]
#[structopt(rename_all = "lowercase")]
#[structopt(version = "0.0.1", about = "The Eye of Satoshi - Lightning Watchtower")]
pub struct Opt {
    // FIXME: Not currently used
    /// Address teos HTTP(s) API will bind to [default: localhost]
    #[structopt(long)]
    pub api_bind: Option<String>,

    // FIXME: Not currently used
    /// Port teos HTTP(s) API will bind to [default: 9814]
    #[structopt(long)]
    pub api_port: Option<u16>,

    // FIXME: Not currently used
    /// Address teos RPC server will bind to [default: localhost]
    #[structopt(long)]
    pub rpc_bind: Option<String>,

    // FIXME: Not currently used
    /// Port teos RPC server will bind to [default: 8814]
    #[structopt(long)]
    pub rpc_port: Option<u16>,

    /// Network bitcoind is connected to. Either bitcoin, testnet, signet or regtest [default: bitcoin]
    #[structopt(long)]
    pub btc_network: Option<String>,

    /// bitcoind rpcuser [default: user]
    #[structopt(long)]
    pub btc_rpc_user: Option<String>,

    /// bitcoind rpcpassword [default: passwd]
    #[structopt(long)]
    pub btc_rpc_password: Option<String>,

    /// bitcoind rpcconnect [default: localhost]
    #[structopt(long)]
    pub btc_rpc_connect: Option<String>,

    /// bitcoind rpcport [default: 8332]
    #[structopt(long)]
    pub btc_rpc_port: Option<u16>,

    /// Specify data directory
    #[structopt(long, default_value = "~/.teos")]
    pub data_dir: String,

    // FIXME: Not currently used
    /// Run teos in background as a daemon [default: false]
    #[structopt(short, long)]
    pub daemon: Option<bool>,

    /// Run teos in debug mode [default: false]
    #[structopt(long)]
    pub debug: Option<bool>,

    /// Overwrites the tower secret key. THIS IS IRREVERSIBLE AND WILL CHANGE YOUR TOWER ID
    #[structopt(long)]
    pub overwrite_key: bool,
}

impl Opt {
    /// Patches the data directory from relative to absolute if necessary.
    pub fn data_dir_absolute_path(&self) -> PathBuf {
        if self.data_dir.starts_with("~") {
            if self.data_dir.starts_with("~/") {
                home::home_dir().unwrap().join(&self.data_dir[2..])
            } else {
                home::home_dir().unwrap().join(&self.data_dir[1..])
            }
        } else {
            PathBuf::from(&self.data_dir)
        }
    }
}

/// Error raised if something is wrong with the configuration.
#[derive(PartialEq, Eq, Debug)]
struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Configuration error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Holds all configuration options.
///
/// The overwrite policy goes, from less to more:
/// - Defaults
/// - Configuration file
/// - Command line options
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    // API
    pub api_bind: String,
    pub api_port: u16,

    // RPC
    pub rpc_bind: String,
    pub rpc_port: u16,

    // Bitcoind
    pub btc_network: String,
    pub btc_rpc_user: String,
    pub btc_rpc_password: String,
    pub btc_rpc_connect: String,
    pub btc_rpc_port: u16,

    // Flags
    pub daemon: bool,
    pub debug: bool,
    pub overwrite_key: bool,

    // General
    pub subscription_slots: u32,
    pub subscription_duration: u32,
    pub expiry_delta: u32,
    pub min_to_self_delay: u16,
}

impl Config {
    /// Loads the configuration options from a given TOML file.
    pub fn from_file(path: PathBuf) -> Config {
        match std::fs::read(&path) {
            Ok(file_content) => toml::from_slice::<Config>(&file_content).map_or_else(
                |e| {
                    println!("Couldn't parse config file: {}", e);
                    println!("Loading default configuration");
                    Self::default()
                },
                |config| {
                    println!("Loading configuration from file");
                    config
                },
            ),
            Err(e) => {
                println!("Couldn't read config file: {}", e);
                println!("Loading default configuration");
                Self::default()
            }
        }
    }

    /// Patches the configuration options with the command line options.
    pub fn patch_with_options(&mut self, options: Opt) {
        if options.api_bind.is_some() {
            self.api_bind = options.api_bind.unwrap();
        }
        if options.api_port.is_some() {
            self.api_port = options.api_port.unwrap();
        }
        if options.rpc_bind.is_some() {
            self.rpc_bind = options.rpc_bind.unwrap();
        }
        if options.rpc_port.is_some() {
            self.rpc_port = options.rpc_port.unwrap();
        }
        if options.btc_network.is_some() {
            self.btc_network = options.btc_network.unwrap();
        }
        if options.btc_rpc_user.is_some() {
            self.btc_rpc_user = options.btc_rpc_user.unwrap();
        }
        if options.btc_rpc_password.is_some() {
            self.btc_rpc_password = options.btc_rpc_password.unwrap();
        }
        if options.btc_rpc_connect.is_some() {
            self.btc_rpc_connect = options.btc_rpc_connect.unwrap();
        }
        if options.btc_rpc_port.is_some() {
            self.btc_rpc_port = options.btc_rpc_port.unwrap();
        }
        if options.daemon.is_some() {
            self.daemon = options.daemon.unwrap();
        }
        if options.debug.is_some() {
            self.debug = options.debug.unwrap();
        }
        self.overwrite_key = options.overwrite_key;
    }

    /// Verifies that [Config] is properly built.
    ///
    /// This includes:
    /// - `bitcoind` credentials have been set
    /// - The Bitcoin network has been properly set (to either bitcoin, testnet, signet or regtest)
    ///
    /// This will also assign the default `btc_rpc_port` depending on the network if it has not
    /// been overwritten at this point.
    ///
    /// # Exits
    ///
    /// If any of the checks does not pass.
    pub fn verify(&mut self) {
        if self.btc_rpc_user == String::new() {
            eprint!("btc_rpc_user must be set");
            std::process::exit(1);
        }
        if self.btc_rpc_password == String::new() {
            eprint!("btc_rpc_password must be set");
            std::process::exit(1);
        }

        match Network::from_str(&self.btc_network) {
            Ok(network) => {
                // Set the port to it's default (depending on the network) if it has not been
                // overwritten at this point.
                if self.btc_rpc_port == 0 {
                    self.btc_rpc_port = match network {
                        Network::Testnet => 18333,
                        Network::Signet => 38333,
                        Network::Regtest => 18443,
                        _ => 8442,
                    }
                }
            }
            Err(_) => {
                eprint!(
                    "btc_network not recognized. Expected {{bitcoin, testnet, signet, regtest}}, received {}",
                    self.btc_network
                );
                std::process::exit(1);
            }
        }
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
            api_bind: "localhost".to_owned(),
            api_port: 9814,
            rpc_bind: "localhost".to_owned(),
            rpc_port: 8814,
            btc_network: "bitcoin".to_owned(),
            btc_rpc_user: String::new(),
            btc_rpc_password: String::new(),
            btc_rpc_connect: "localhost".to_owned(),
            btc_rpc_port: 0,
            daemon: false,
            debug: false,
            overwrite_key: false,
            subscription_slots: 10000,
            subscription_duration: 4320,
            expiry_delta: 6,
            min_to_self_delay: 20,
        }
    }
}
