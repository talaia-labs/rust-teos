//! Local protobuf definitions for the ldk-server `WatchtowerStateExport` API.
//!
//! These messages mirror the canonical definitions found in
//! `ldk-server-grpc/src/proto/{api,types}.proto` (branch `feat/watchtower-export`
//! of `github.com/vincenzopalazzo/ldk-server`). They are defined locally with
//! `prost` so this crate does not need a git dependency on any ldk-server repo.
//!
//! The wire format is what matters: as long as the field numbers and types match,
//! messages are interoperable with the ones encoded by ldk-server.

/// Path (relative to the server base URL) of the `WatchtowerStateExport` endpoint.
///
/// Mirrors `WATCHTOWER_STATE_EXPORT_PATH` in `ldk-server-grpc/src/endpoints.rs`.
pub const WATCHTOWER_STATE_EXPORT_PATH: &str = "WatchtowerStateExport";

/// Represents a transaction outpoint.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct OutPoint {
    /// The referenced transaction's txid (hex-encoded).
    #[prost(string, tag = "1")]
    pub txid: String,
    /// The index of the referenced output in the transaction's vout.
    #[prost(uint32, tag = "2")]
    pub vout: u32,
}

/// A justice (penalty) transaction claiming the `to_local` output of a counterparty
/// commitment transaction via the revocation path.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct JusticeTransaction {
    /// The txid (hex-encoded) of the counterparty commitment transaction this justice
    /// transaction spends from. This is also the source of the watchtower locator
    /// (the first 16 bytes of the txid).
    #[prost(string, tag = "1")]
    pub commitment_txid: String,
    /// The commitment number of the counterparty commitment transaction.
    #[prost(uint64, tag = "2")]
    pub commitment_number: u64,
    /// The value, in satoshis, of the `to_local` output being claimed.
    #[prost(uint64, tag = "3")]
    pub to_local_value_sats: u64,
    /// The fully-built justice transaction, consensus-serialized.
    ///
    /// The transaction is signed iff `signed` is true. In v1 ldk-server exports
    /// entries with `signed = false` and empty `justice_tx` bytes.
    #[prost(bytes = "vec", tag = "4")]
    pub justice_tx: Vec<u8>,
    /// Whether `justice_tx` is fully signed and ready to be handed to a watchtower.
    #[prost(bool, tag = "5")]
    pub signed: bool,
}

/// The watchtower-relevant state of a single channel, as exported by the
/// `WatchtowerStateExport` RPC.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct WatchtowerChannelState {
    /// The channel's funding outpoint.
    #[prost(message, optional, tag = "1")]
    pub funding_txo: Option<OutPoint>,
    /// The hex-encoded local `user_channel_id` of this channel.
    #[prost(string, tag = "2")]
    pub user_channel_id: String,
    /// The channel ID (hex-encoded).
    #[prost(string, tag = "3")]
    pub channel_id: String,
    /// The node ID of the channel's remote counterparty.
    #[prost(string, tag = "4")]
    pub counterparty_node_id: String,
    /// The `to_self_delay` (in blocks) encumbering the counterparty's `to_local` output.
    #[prost(uint32, tag = "5")]
    pub to_self_delay: u32,
    /// The justice transactions for the latest known counterparty commitment state(s).
    #[prost(message, repeated, tag = "6")]
    pub justice_transactions: Vec<JusticeTransaction>,
}

/// Requests an export of the per-channel watchtower state.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct WatchtowerStateExportRequest {
    /// If set, only the state of the channel with this hex-encoded `user_channel_id`
    /// is exported. Otherwise the state of all channels is exported.
    #[prost(string, optional, tag = "1")]
    pub user_channel_id: Option<String>,
}

/// The response for the `WatchtowerStateExport` RPC.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct WatchtowerStateExportResponse {
    /// The exported watchtower state, one entry per channel.
    #[prost(message, repeated, tag = "1")]
    pub channel_states: Vec<WatchtowerChannelState>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn test_state_export_response_protobuf_roundtrip() {
        let response = WatchtowerStateExportResponse {
            channel_states: vec![WatchtowerChannelState {
                funding_txo: Some(OutPoint {
                    txid: "d6ac4a5e61657c4c604dcde855a1db74ec6b3e54f32695d72c5e11c7761ea1b4"
                        .to_owned(),
                    vout: 0,
                }),
                user_channel_id: "aabbccdd".to_owned(),
                channel_id: "11223344".to_owned(),
                counterparty_node_id:
                    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_owned(),
                to_self_delay: 144,
                justice_transactions: vec![
                    // A signed entry, ready to be turned into an appointment.
                    JusticeTransaction {
                        commitment_txid:
                            "d6ac4a5e61657c4c604dcde855a1db74ec6b3e54f32695d72c5e11c7761ea1b4"
                                .to_owned(),
                        commitment_number: 42,
                        to_local_value_sats: 100_000,
                        justice_tx: vec![0xde, 0xad, 0xbe, 0xef],
                        signed: true,
                    },
                    // A v1-style unsigned entry with empty justice tx bytes.
                    JusticeTransaction {
                        commitment_txid:
                            "0000000000000000000000000000000000000000000000000000000000000001"
                                .to_owned(),
                        commitment_number: 41,
                        to_local_value_sats: 99_000,
                        justice_tx: Vec::new(),
                        signed: false,
                    },
                ],
            }],
        };

        let encoded = response.encode_to_vec();
        let decoded = WatchtowerStateExportResponse::decode(encoded.as_slice()).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_state_export_request_protobuf_roundtrip() {
        for req in [
            WatchtowerStateExportRequest {
                user_channel_id: None,
            },
            WatchtowerStateExportRequest {
                user_channel_id: Some("aabbccdd".to_owned()),
            },
        ] {
            let encoded = req.encode_to_vec();
            assert_eq!(
                WatchtowerStateExportRequest::decode(encoded.as_slice()).unwrap(),
                req
            );
        }
    }
}
