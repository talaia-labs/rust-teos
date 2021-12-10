#![allow(dead_code)]
// Ported from https://github.com/bitcoin/bitcoin/blob/0.18/src/rpc/protocol.h
// TODO: Check if e can get rid of this whole module once `bitcoincore-rpc` is fully integrated.

// General application defined errors
pub const RPC_MISC_ERROR: i32 = -1; // std::exception thrown in command handling
pub const RPC_TYPE_ERROR: i32 = -3; // Unexpected type was passed as parameter
pub const RPC_INVALID_ADDRESS_OR_KEY: i32 = -5; // Invalid address or key
pub const RPC_OUT_OF_MEMORY: i32 = -7; // Ran out of memory during operation
pub const RPC_INVALID_PARAMETER: i32 = -8; // Invalid  missing or duplicate parameter
pub const RPC_DATABASE_ERROR: i32 = -20; // Database error
pub const RPC_DESERIALIZATION_ERROR: i32 = -22; // Error parsing or validating structure in raw format
pub const RPC_VERIFY_ERROR: i32 = -25; // General error during transaction or block submission
pub const RPC_VERIFY_REJECTED: i32 = -26; // Transaction or block was rejected by network rules
pub const RPC_VERIFY_ALREADY_IN_CHAIN: i32 = -27; // Transaction already in chain
pub const RPC_IN_WARMUP: i32 = -28; // Client still warming up
pub const RPC_METHOD_DEPRECATED: i32 = -32; // RPC method is deprecated

// Aliases for backward compatibility
pub const RPC_TRANSACTION_ERROR: i32 = RPC_VERIFY_ERROR;
pub const RPC_TRANSACTION_REJECTED: i32 = RPC_VERIFY_REJECTED;
pub const RPC_TRANSACTION_ALREADY_IN_CHAIN: i32 = RPC_VERIFY_ALREADY_IN_CHAIN;

// P2P client errors
pub const RPC_CLIENT_NOT_CONNECTED: i32 = -9; // Bitcoin is not connected
pub const RPC_CLIENT_IN_INITIAL_DOWNLOAD: i32 = -10; // Still downloading initial blocks
pub const RPC_CLIENT_NODE_ALREADY_ADDED: i32 = -23; // Node is already added
pub const RPC_CLIENT_NODE_NOT_ADDED: i32 = -24; // Node has not been added before
pub const RPC_CLIENT_NODE_NOT_CONNECTED: i32 = -29; // Node to disconnect not found in connected nodes
pub const RPC_CLIENT_INVALID_IP_OR_SUBNET: i32 = -30; // Invalid IP/Subnet
pub const RPC_CLIENT_P2P_DISABLED: i32 = -31; // No valid connection manager instance found

// Wallet errors
pub const RPC_WALLET_ERROR: i32 = -4; // Unspecified problem with wallet (key not found etc.)
pub const RPC_WALLET_INSUFFICIENT_FUNDS: i32 = -6; // Not enough funds in wallet or account
pub const RPC_WALLET_INVALID_LABEL_NAME: i32 = -11; // Invalid label name
pub const RPC_WALLET_KEYPOOL_RAN_OUT: i32 = -12; // Keypool ran out  call keypoolrefill first
pub const RPC_WALLET_UNLOCK_NEEDED: i32 = -13; // Enter the wallet passphrase with walletpassphrase first
pub const RPC_WALLET_PASSPHRASE_INCORRECT: i32 = -14; // The wallet passphrase entered was incorrect
pub const RPC_WALLET_WRONG_ENC_STATE: i32 = -15; // Command given in wrong wallet encryption state (encrypting an encrypted wallet etc.)
pub const RPC_WALLET_ENCRYPTION_FAILED: i32 = -16; // Failed to encrypt the wallet
pub const RPC_WALLET_ALREADY_UNLOCKED: i32 = -17; // Wallet is already unlocked
pub const RPC_WALLET_NOT_FOUND: i32 = -18; // Invalid wallet specified
pub const RPC_WALLET_NOT_SPECIFIED: i32 = -19; // No wallet specified (error when there are multiple wallets loaded)
