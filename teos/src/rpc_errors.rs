#![allow(dead_code)]
// Ported from https://github.com/bitcoin/bitcoin/blob/0.18/src/rpc/protocol.h
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

// Rejection reasons, from Bitcoin Core's `src/validation.cpp`, `src/policy/policy.cpp`, `src/consensus/tx_check.cpp`
// and `src/consensus/tx_verify.cpp`. Unlike the codes above these are not an enum upstream, they are
// string literals handed back inside the error message of a rejected `sendrawtransaction`.

/// Rejection reasons that depend on the penalty alone, so no amount of retrying will fix them.
///
/// This is inherently not comprehensive; the reasons are not enumerated upstream and new ones can be added at any time.
/// Our default is to retry everything we don't know about, this can make us waste time, but never lose a penalty that could have been avoided.
///
/// New reasons can be added on demand, as long as it helps refining the logic.
///
/// Reasons are stable across bitcoind 27.0 onwards unless noted otherwise.
pub const PERMANENT_REJECT_REASONS: [&str; 20] = [
    // Malformed, from `CheckTransaction`
    "bad-txns-vin-empty",
    "bad-txns-vout-empty",
    "bad-txns-oversize",
    "bad-txns-vout-negative",
    "bad-txns-vout-toolarge",
    "bad-txns-txouttotal-toolarge",
    "bad-txns-inputs-duplicate",
    "bad-cb-length",
    "bad-txns-prevout-null",
    "coinbase",
    // Amounts that cannot add up, from `CheckTxInputs`
    "bad-txns-inputvalues-outofrange",
    "bad-txns-in-belowout",
    "bad-txns-fee-outofrange",
    // Scripts that will never verify. Renamed in 30.0, both spellings kept so that the reason is
    // picked up on either side of that release.
    "mandatory-script-verify-flag-failed", // <= 29.x
    "non-mandatory-script-verify-flag",    // <= 29.x
    "block-script-verify-flag-failed",     // >= 30.0
    "mempool-script-verify-flag-failed",   // >= 30.0
    // Shape of the transaction or of the outputs it spends, from `IsStandardTx` / `AreInputsStandard`
    "bad-txns-nonstandard-inputs",
    "bad-witness-nonstandard",
    "bad-txns-too-many-sigops",
];

/// Pulls the rejection reason out of a `sendrawtransaction` error message.
///
/// The message is `TxValidationState::ToString()`, that is, the reason on its own or
/// `reason, debug message`. Some reasons carry a detail of their own between parentheses, as the script
/// verification ones do, so everything past the reason itself is dropped.
pub fn reject_reason(message: &str) -> &str {
    message.split([' ', ',']).next().unwrap_or(message)
}

/// Whether the backend will never take this transaction, no matter how many times it is offered.
pub fn is_permanent_rejection(code: i32, message: &str) -> bool {
    code == RPC_DESERIALIZATION_ERROR || PERMANENT_REJECT_REASONS.contains(&reject_reason(message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_reason() {
        // The reason on its own
        assert_eq!(reject_reason("bad-txns-vin-empty"), "bad-txns-vin-empty");
        // Followed by a debug message
        assert_eq!(
            reject_reason("bad-txns-inputs-duplicate, some detail"),
            "bad-txns-inputs-duplicate"
        );
        // Carrying a detail of its own, as the script verification ones do
        assert_eq!(
            reject_reason(
                "block-script-verify-flag-failed (Operation not valid with the current stack size)"
            ),
            "block-script-verify-flag-failed"
        );
        // Reasons made of several words are not mistaken for one we know
        assert!(!PERMANENT_REJECT_REASONS.contains(&reject_reason("mempool min fee not met")));
    }

    #[test]
    fn test_is_permanent_rejection() {
        // A penalty the backend can never take
        assert!(is_permanent_rejection(
            RPC_VERIFY_REJECTED,
            "block-script-verify-flag-failed (Signature must be zero for failed CHECK(MULTI)SIG operation)"
        ));
        // The pre-30.0 spelling of the same thing
        assert!(is_permanent_rejection(
            RPC_VERIFY_REJECTED,
            "mandatory-script-verify-flag-failed (Operation not valid with the current stack size)"
        ));
        // Reasons that read as final but are not. Wrongly calling one final drops a
        // penalty that could still have been published.
        for reason in [
            // A consensus failure, yet it depends on what else is in the mempool
            "bad-txns-spends-conflicting-tx",
            // Not to be swept in alongside the bare `coinbase` reason, which is final
            "bad-txns-premature-spend-of-coinbase",
            // Policy the node operator can turn off, so not ours to call final
            "dust",
            "bare-multisig",
            // The input is gone, but a reorg may bring it back, and it is also what we get when our own
            // penalty won the race and its output was spent
            "bad-txns-inputs-missingorspent",
            // A timelock that has not matured yet will
            "non-BIP68-final",
        ] {
            assert!(!is_permanent_rejection(RPC_VERIFY_REJECTED, reason));
        }
        // Anything we don't know about is retried rather than dropped
        assert!(!is_permanent_rejection(
            RPC_VERIFY_REJECTED,
            "some-reason-a-later-bitcoind-made-up"
        ));
        // A transaction the backend cannot even parse is final whatever the message says
        assert!(is_permanent_rejection(RPC_DESERIALIZATION_ERROR, ""));
    }
}
