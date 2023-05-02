// Collection of ENV variable names and values
pub const TOWERS_DATA_DIR: &str = "TOWERS_DATA_DIR";
pub const DEFAULT_TOWERS_DATA_DIR: &str = ".watchtower";

/// Collections of plugin option names, default values and descriptions

pub const WT_PORT: &str = "watchtower-port";
pub const DEFAULT_WT_PORT: i64 = 9814;
pub const WT_PORT_DESC: &str = "tower API port";
pub const WT_MAX_RETRY_TIME: &str = "watchtower-max-retry-time";
pub const DEFAULT_WT_MAX_RETRY_TIME: i64 = 3600;
pub const WT_MAX_RETRY_TIME_DESC: &str = "for how long (in seconds) a retry strategy will try to reach a temporary unreachable tower before giving up. Defaults to 1 hour";
pub const WT_AUTO_RETRY_DELAY: &str = "watchtower-auto-retry-delay";
pub const DEFAULT_WT_AUTO_RETRY_DELAY: i64 = 28800;
pub const WT_AUTO_RETRY_DELAY_DESC: &str = "how long (in seconds) a retrier will wait before auto-retrying a failed tower. Defaults to once every 8 hours";
pub const DEV_WT_MAX_RETRY_INTERVAL: &str = "dev-watchtower-max-retry-interval";
pub const DEFAULT_DEV_WT_MAX_RETRY_INTERVAL: i64 = 900;
pub const DEV_WT_MAX_RETRY_INTERVAL_DESC: &str =
    "maximum length (in seconds) for a retry interval. Defaults to 15 min";

/// Collections of rpc method names and descriptions

pub const RPC_REGISTER_TOWER: &str = "registertower";
pub const RPC_REGISTER_TOWER_DESC: &str =
    "Registers the client public key (user id) with the tower";
pub const RPC_GET_REGISTRATION_RECEIPT: &str = "getregistrationreceipt";
pub const RPC_GET_REGISTRATION_RECEIPT_DESC: &str =
    "Gets the latest registration receipt given a tower id";
pub const RPC_GET_APPOINTMENT: &str = "getappointment";
pub const RPC_GET_APPOINTMENT_DESC: &str =
    "Gets appointment data from the tower given a tower id and a locator";
pub const RPC_GET_APPOINTMENT_RECEIPT: &str = "getappointmentreceipt";
pub const RPC_GET_APPOINTMENT_RECEIPT_DESC: &str =
    "Gets a (local) appointment receipt given a tower id and a locator";
pub const RPC_GET_SUBSCRIPTION_INFO: &str = "getsubscriptioninfo";
pub const RPC_GET_SUBSCRIPTION_INFO_DESC: &str =
    "Gets the subscription information directly from the tower";
pub const RPC_LIST_TOWERS: &str = "listtowers";
pub const RPC_LIST_TOWERS_DESC: &str = "Lists all registered towers";
pub const RPC_GET_TOWER_INFO: &str = "gettowerinfo";
pub const RPC_GET_TOWER_INFO_DESC: &str = "Shows the info about a tower given a tower id";
pub const RPC_RETRY_TOWER: &str = "retrytower";
pub const RPC_RETRY_TOWER_DESC: &str =
    "Retries to send pending appointment to an unreachable tower";
pub const RPC_ABANDON_TOWER: &str = "abandontower";
pub const RPC_ABANDON_TOWER_DESC: &str = "Forgets about a tower and wipes all local data";
pub const RPC_PING: &str = "pingtower";
pub const RPC_PING_DESC: &str = "Polls the tower to check if it is online";

/// Collections of hook names

pub const HOOK_COMMITMENT_REVOCATION: &str = "commitment_revocation";
