//! Bounded retry with exponential backoff for tower interactions.
//!
//! A simplified, blocking take on `watchtower-plugin/src/retrier.rs`: transient
//! (connection) errors are retried with exponential backoff within a bounded
//! elapsed time, while permanent errors (tower API rejections, misbehavior) are
//! surfaced immediately. Cross-restart durability is not handled here: the
//! SQLite database is the persistent retry queue (see `dbm.rs`).

use std::time::Duration;

use backoff::{Error as BackoffError, ExponentialBackoff};

use crate::tower::{AddAppointmentError, RequestError};

/// Errors surfaced by the retry logic once it gives up (or immediately, for
/// permanent failures).
#[derive(Debug)]
pub enum RetryError {
    /// The tower could not be reached within the retry budget.
    Unreachable,
    /// The tower rejected the request (permanent API error).
    Api(String, u8),
    /// The tower signed a receipt with a key not matching its tower id.
    Misbehaving(crate::tower::MisbehaviorProof),
}

impl std::fmt::Display for RetryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RetryError::Unreachable => write!(f, "tower cannot be reached"),
            RetryError::Api(e, code) => write!(f, "tower API error ({code}): {e}"),
            RetryError::Misbehaving(_) => write!(f, "tower misbehaved"),
        }
    }
}

fn classify(e: AddAppointmentError) -> BackoffError<RetryError> {
    match e {
        AddAppointmentError::RequestError(RequestError::ConnectionError(_)) => {
            BackoffError::transient(RetryError::Unreachable)
        }
        AddAppointmentError::RequestError(e) => {
            log::warn!("Unexpected error interacting with the tower: {e}. Retrying");
            BackoffError::transient(RetryError::Unreachable)
        }
        AddAppointmentError::ApiError(e) => {
            BackoffError::permanent(RetryError::Api(e.error, e.error_code))
        }
        AddAppointmentError::SignatureError(proof) => {
            BackoffError::permanent(RetryError::Misbehaving(proof))
        }
    }
}

/// Retries `op` with exponential backoff until it succeeds, fails permanently, or
/// `max_elapsed` has passed.
pub fn retry_with_backoff<T>(
    max_elapsed: Duration,
    mut op: impl FnMut() -> Result<T, AddAppointmentError>,
) -> Result<T, RetryError> {
    let backoff = ExponentialBackoff {
        initial_interval: Duration::from_secs(1),
        max_interval: Duration::from_secs(30),
        max_elapsed_time: Some(max_elapsed),
        ..Default::default()
    };

    backoff::retry_notify(
        backoff,
        || op().map_err(classify),
        |e, next: Duration| log::info!("{e}. Retrying in {}s", next.as_secs()),
    )
    .map_err(|e| match e {
        BackoffError::Permanent(e) | BackoffError::Transient { err: e, .. } => e,
    })
}
