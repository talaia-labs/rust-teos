//! Logic related to the tower configuration and command line parameter parsing.

use bitcoin::network::constants::Network;
use serde::Deserialize;
use std;
use std::path::PathBuf;
use std::str::FromStr;
use structopt::StructOpt;

pub fn data_dir_absolute_path(data_dir: String) -> PathBuf {
    if let Some(a) = data_dir.strip_prefix('~') {
        if let Some(b) = data_dir.strip_prefix("~/") {
            home::home_dir().unwrap().join(b)
        } else {
            home::home_dir().unwrap().join(a)
        }
    } else {
        PathBuf::from(&data_dir)
    }
}

pub fn from_file<T: Default + serde::de::DeserializeOwned>(path: PathBuf) -> T {
    match std::fs::read(&path) {
        Ok(file_content) => toml::from_slice::<T>(&file_content).map_or_else(
            |e| {
                println!("Couldn't parse config file: {}", e);
                println!("Loading default configuration");
                T::default()
            },
            |config| {
                println!("Loading configuration from file");
                config
            },
        ),
        Err(e) => {
            println!("Couldn't read config file: {}", e);
            println!("Loading default configuration");
            T::default()
        }
    }
}

/// Error raised if something is wrong with the configuration.
#[derive(PartialEq, Eq, Debug)]
pub struct ConfigError(String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Configuration error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Holds all the command line options.
#[derive(StructOpt, Debug, Clone)]
#[structopt(rename_all = "lowercase")]
#[structopt(version = "0.0.1", about = "The Eye of Satoshi - Lightning watchtower")]
pub struct Opt {
    /// Address teos HTTP(s) API will bind to [default: localhost]
    #[structopt(long)]
    pub api_bind: Option<String>,

    /// Port teos HTTP(s) API will bind to [default: 9814]
    #[structopt(long)]
    pub api_port: Option<u16>,

    /// Address teos RPC server will bind to [default: localhost]
    #[structopt(long)]
    pub rpc_bind: Option<String>,

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

    /// Runs teos in debug mode
    #[structopt(long)]
    pub debug: bool,

    /// Overwrites the tower secret key. THIS IS IRREVERSIBLE AND WILL CHANGE YOUR TOWER ID
    #[structopt(long)]
    pub overwrite_key: bool,
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
    pub debug: bool,
    pub overwrite_key: bool,

    // General
    pub subscription_slots: u32,
    pub subscription_duration: u32,
    pub expiry_delta: u32,
    pub min_to_self_delay: u16,
    pub polling_delta: u16,

    // Internal API
    pub internal_api_bind: String,
    pub internal_api_port: u32,
}

impl Config {
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

        self.debug |= options.debug;
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
    pub fn verify(&mut self) -> Result<(), ConfigError> {
        if self.btc_rpc_user == String::new() {
            return Err(ConfigError("btc_rpc_user must be set".to_owned()));
        }
        if self.btc_rpc_password == String::new() {
            return Err(ConfigError("btc_rpc_password must be set".to_owned()));
        }

        match Network::from_str(&self.btc_network) {
            Ok(network) => {
                // Set the port to it's default (depending on the network) if it has not been
                // overwritten at this point.
                if self.btc_rpc_port == 0 {
                    self.btc_rpc_port = match network {
                        Network::Testnet => 18332,
                        Network::Signet => 38332,
                        Network::Regtest => 18443,
                        _ => 8332,
                    }
                }
                Ok(())
            }
            Err(_) => {
                Err(ConfigError(format!("btc_network not recognized. Expected {{bitcoin, testnet, signet, regtest}}, received {}",
                self.btc_network)))
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
            api_bind: "127.0.0.1".into(),
            api_port: 9814,
            rpc_bind: "127.0.0.1".into(),
            rpc_port: 8814,
            btc_network: "bitcoin".into(),
            btc_rpc_user: String::new(),
            btc_rpc_password: String::new(),
            btc_rpc_connect: "localhost".into(),
            btc_rpc_port: 0,

            debug: false,
            overwrite_key: false,
            subscription_slots: 10000,
            subscription_duration: 4320,
            expiry_delta: 6,
            min_to_self_delay: 20,
            polling_delta: 60,
            internal_api_bind: "127.0.0.1".into(),
            internal_api_port: 50051,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Default for Opt {
        fn default() -> Self {
            Self {
                api_bind: None,
                api_port: None,
                rpc_bind: None,
                rpc_port: None,
                btc_network: None,
                btc_rpc_user: None,
                btc_rpc_password: None,
                btc_rpc_connect: None,
                btc_rpc_port: None,
                data_dir: String::from("~/.teos"),

                debug: false,
                overwrite_key: false,
            }
        }
    }

    #[test]
    fn test_config_patch_with_options() {
        // Tests that a given Config is overwritten with Opts if the options are present
        let mut config = Config::default();
        let config_clone = config.clone();
        let mut opt = Opt::default();

        let expected_value = String::from("test");
        opt.api_bind = Some(expected_value.clone());
        config.patch_with_options(opt);

        // Check the field has been updated
        assert_eq!(config.api_bind, expected_value);

        // Check the rest of fields are equal. The easiest is to just the field back and compare with a clone
        config.api_bind = config_clone.api_bind.clone();
        assert_eq!(config, config_clone);
    }

    #[test]
    fn test_config_default_not_verify() {
        // Tests that the default configuration does not pass verification checks. This is on purpose so some fields are
        // required to be updated by the user.
        let mut config = Config::default();
        assert!(matches!(config.verify(), Err(ConfigError { .. })));
    }

    #[test]
    fn test_config_default_verify_overwrite_required() {
        // Tests that setting a some btc_rpc_user and btc_rpc_password results in a Config object that verifies
        let mut config = Config {
            btc_rpc_user: "user".to_owned(),
            btc_rpc_password: "password".to_owned(),
            ..Default::default()
        };
        config.verify().unwrap();
    }

    #[test]
    fn test_config_verify_wrong_network() {
        // Tests that setting a wrong network will make verify fail
        let mut config = Config {
            btc_rpc_user: "user".to_owned(),
            btc_rpc_password: "password".to_owned(),
            btc_network: "wrong_network".to_owned(),
            ..Default::default()
        };
        assert!(matches!(config.verify(), Err(ConfigError { .. })));
    }
}
