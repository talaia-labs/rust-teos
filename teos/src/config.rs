use serde::Deserialize;
use std;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "lowercase")]
#[structopt(version = "version goes here", about = "Program help goes here")]
pub struct Opt {
    /// Address teos HTTP(s) API will bind to [default: localhost]
    #[structopt(long)]
    pub api_bind: Option<String>,

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

    /// Network bitcoind is connected to. Either mainnet, testnet or regtest [default: main]
    // FIXME: Not currently used
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

    // FIXME: Not currently used
    /// Overwrites the tower secret key. THIS IS IRREVERSIBLE AND WILL CHANGE YOUR TOWER ID
    #[structopt(long)]
    pub overwrite_key: bool,
}

impl Opt {
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

#[derive(PartialEq, Eq, Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Configuration error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

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

    // General
    pub subscription_slots: u32,
    pub subscription_duration: u32,
    pub expiry_delta: u32,
    pub min_to_self_delay: u16,
}

impl Config {
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
                    config.verify();
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

    pub fn patch_with_options(&mut self, options: Opt) {
        if options.api_bind.is_some() {
            self.api_bind = options.api_bind.unwrap()
        }
        if options.api_port.is_some() {
            self.api_port = options.api_port.unwrap()
        }
        if options.rpc_bind.is_some() {
            self.rpc_bind = options.rpc_bind.unwrap()
        }
        if options.rpc_port.is_some() {
            self.rpc_port = options.rpc_port.unwrap()
        }
        if options.btc_network.is_some() {
            self.btc_network = options.btc_network.unwrap()
        }
        if options.btc_rpc_user.is_some() {
            self.btc_rpc_user = options.btc_rpc_user.unwrap()
        }
        if options.btc_rpc_password.is_some() {
            self.btc_rpc_password = options.btc_rpc_password.unwrap()
        }
        if options.btc_rpc_connect.is_some() {
            self.btc_rpc_connect = options.btc_rpc_connect.unwrap()
        }
        if options.btc_rpc_port.is_some() {
            self.btc_rpc_port = options.btc_rpc_port.unwrap()
        }
        if options.daemon.is_some() {
            self.daemon = options.daemon.unwrap()
        }
        if options.debug.is_some() {
            self.debug = options.debug.unwrap()
        }
    }

    pub fn verify(&self) {
        if self.btc_rpc_user == String::new() {
            eprint!("btc_rpc_user must be set");
            std::process::exit(-1);
        }
        if self.btc_rpc_password == String::new() {
            eprint!("btc_rpc_password must be set");
            std::process::exit(-1);
        }

        // TODO: check if we can simplify this
        if ![
            "main".to_owned(),
            "mainnet".to_owned(),
            "test".to_owned(),
            "testnet".to_owned(),
            "regtest".to_owned(),
        ]
        .contains(&self.btc_network)
        {
            eprint!(
                "btc_network not recognized. Expected [mainnet, testnet, regtest], received {}",
                self.btc_network
            );
            std::process::exit(-1);
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_bind: "localhost".to_owned(),
            api_port: 9814,
            rpc_bind: "localhost".to_owned(),
            rpc_port: 8814,
            btc_network: "main".to_owned(),
            btc_rpc_user: String::new(),
            btc_rpc_password: String::new(),
            btc_rpc_connect: "localhost".to_owned(),
            btc_rpc_port: 8832,
            daemon: false,
            debug: false,
            subscription_slots: 10000,
            subscription_duration: 4320,
            expiry_delta: 6,
            min_to_self_delay: 20,
        }
    }
}
