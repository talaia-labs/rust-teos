//! Command line and configuration file handling, mirroring `teos/src/config.rs`.

use serde::Deserialize;
use std::path::PathBuf;
use structopt::StructOpt;

/// Resolves `~`-prefixed data directories to absolute paths.
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

/// Loads a TOML config file, falling back to defaults on failure.
pub fn from_file<T: Default + serde::de::DeserializeOwned>(path: &PathBuf) -> T {
    match std::fs::read(path) {
        Ok(file_content) => toml::from_slice::<T>(&file_content).unwrap_or_else(|e| {
            eprintln!("Couldn't parse config file: {e}");
            T::default()
        }),
        Err(_) => T::default(),
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
#[structopt(
    version = env!("CARGO_PKG_VERSION"),
    about = "Watchtower client for ldk-server nodes (ships teos appointments to an Eye of Satoshi tower)"
)]
pub struct Opt {
    /// Base URL of the ldk-server node API (e.g. http://localhost:3002)
    #[structopt(long)]
    pub ldk_server_url: Option<String>,

    /// API key used to authenticate against the ldk-server API (HMAC-SHA256)
    #[structopt(long)]
    pub api_key: Option<String>,

    /// Hex-encoded public key (33 bytes) identifying the tower
    #[structopt(long)]
    pub tower_id: Option<String>,

    /// Tower network address, host:port or onion (e.g. teos.talaia.watch:9814)
    #[structopt(long)]
    pub tower_net_addr: Option<String>,

    /// Tor SOCKS5 proxy address used to reach onion towers [default: 127.0.0.1:9050]
    #[structopt(long, default_value = "127.0.0.1:9050")]
    pub tor_proxy: String,

    /// Specify data directory [default: ~/.ldk-watchtower]
    #[structopt(long, default_value = "~/.ldk-watchtower")]
    pub data_dir: String,

    /// How often the ldk-server watchtower state is polled, in seconds [default: 60]
    #[structopt(long)]
    pub poll_interval_secs: Option<u64>,

    /// Watch only this `user_channel_id` (hex). Repeatable. If unset, all channels
    /// returned by the export endpoint are watched
    #[structopt(long)]
    pub watch_channel: Vec<String>,

    /// Path to a TOML configuration file. Command line options take precedence
    #[structopt(long, parse(from_os_str))]
    pub config: Option<PathBuf>,
}

/// Optional TOML configuration file content. All fields default to `None`/empty and
/// are overridden by their command line counterparts.
#[derive(Deserialize, Default, Debug)]
#[serde(deny_unknown_fields, default)]
pub struct ConfigFile {
    pub ldk_server_url: Option<String>,
    pub api_key: Option<String>,
    pub tower_id: Option<String>,
    pub tower_net_addr: Option<String>,
    pub tor_proxy: Option<String>,
    pub data_dir: Option<String>,
    pub poll_interval_secs: Option<u64>,
    pub watch_channel: Vec<String>,
}

/// The fully-resolved configuration the client runs with.
#[derive(Debug, Clone)]
pub struct Config {
    pub ldk_server_url: String,
    pub api_key: String,
    pub tower_id: String,
    pub tower_net_addr: String,
    pub tor_proxy: String,
    pub data_dir: PathBuf,
    pub poll_interval_secs: u64,
    pub watch_channels: Vec<String>,
}

impl Config {
    pub fn from_opt(opt: Opt) -> Result<Config, ConfigError> {
        let file = opt
            .config
            .as_ref()
            .map(from_file::<ConfigFile>)
            .unwrap_or_default();

        let required = |name: &str,
                        cli: Option<String>,
                        file: Option<String>|
         -> Result<String, ConfigError> {
            cli.or(file)
                .ok_or_else(|| ConfigError(format!("--{name} is required")))
        };

        Ok(Config {
            ldk_server_url: required("ldk-server-url", opt.ldk_server_url, file.ldk_server_url)?,
            api_key: required("api-key", opt.api_key, file.api_key)?,
            tower_id: required("tower-id", opt.tower_id, file.tower_id)?,
            tower_net_addr: required("tower-net-addr", opt.tower_net_addr, file.tower_net_addr)?,
            // `tor_proxy` and `data_dir` have CLI defaults, so they always come
            // from the command line (which mirrors teos' behavior).
            tor_proxy: opt.tor_proxy,
            data_dir: data_dir_absolute_path(opt.data_dir),
            poll_interval_secs: opt
                .poll_interval_secs
                .or(file.poll_interval_secs)
                .unwrap_or(60),
            watch_channels: if opt.watch_channel.is_empty() {
                file.watch_channel
            } else {
                opt.watch_channel
            },
        })
    }
}
