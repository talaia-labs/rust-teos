# Contributing to the Eye of Satoshi

The following is a set of guidelines for contributing to `rust-teos`.

## Code Style Guidelines
We use `rustfmt` as our base code formatter. Before submitting a PR make sure you have properly formatted your code by running:

```bash
cargo fmt
```

In addition, we use [clippy](https://github.com/rust-lang/rust-clippy/) to catch common mistakes and improve the code:

```bash
cargo clippy
```

On top of that, there are a few rules to also have in mind.

### Code Spacing
Blocks of code should be created to separate logical sections:

```rust
let mut tx_tracker_map = self.tx_tracker_map.lock().unwrap();
if let Some(map) = tx_tracker_map.get_mut(&tracker.penalty_tx.txid()) {
    map.insert(uuid);
} else {
    tx_tracker_map.insert(tracker.penalty_tx.txid(), HashSet::from_iter(vec![uuid]));
}

let mut unconfirmed_txs = self.unconfirmed_txs.lock().unwrap();
if confirmations == 0 {
    unconfirmed_txs.insert(tracker.penalty_tx.txid());
}
```

## Code Documentation
Code should be documented, specially if its visibility is public.

Here's an example of struct docs:

```rust
/// Component in charge of keeping track of triggered appointments.
///
/// The [Responder] receives data from the [Watcher](crate::watcher::Watcher) in form of a [Breach].
/// From there, a [TransactionTracker] is created and the penalty transaction is sent to the network via the [Carrier].
/// The [Transaction] is then monitored to make sure it makes it to a block and it gets [irrevocably resolved](https://github.com/lightning/bolts/blob/master/05-onchain.md#general-nomenclature).
#[derive(Debug)]
pub struct Responder {
    /// A map holding a summary of every tracker ([TransactionTracker]) hold by the [Responder], identified by [UUID].
    /// The identifiers match those used by the [Watcher](crate::watcher::Watcher).
    trackers: Mutex<HashMap<UUID, TrackerSummary>>,
    /// A map between [Txid]s and [UUID]s.
    tx_tracker_map: Mutex<HashMap<Txid, HashSet<UUID>>>,
    /// A collection of transactions yet to get a single confirmation.
    /// Only keeps track of penalty transactions being monitored by the [Responder].
    unconfirmed_txs: Mutex<HashSet<Txid>>,
    /// A collection of [Transaction]s that have missed some confirmation, along with the missed count.
    /// Only keeps track of penalty transactions being monitored by the [Responder].
    missed_confirmations: Mutex<HashMap<Txid, u8>>,
    /// A [Carrier] instance. Data is sent to the `bitcoind` through it.
    carrier: Mutex<Carrier>,
    /// A [Gatekeeper] instance. Data regarding users is requested to it.
    gatekeeper: Arc<Gatekeeper>,
    /// A [DBM] (database manager) instance. Used to persist tracker data into disk.
    dbm: Arc<Mutex<DBM>>,
    /// The last known block header.
    last_known_block_header: Mutex<BlockHeaderData>,
}
```

## Test Coverage
Tests should be provided to cover both positive and negative conditions. The test should cover both the proper execution as well as all the covered error paths. PR with no proper test coverage will be rejected. 

## Signing Commits

We require that all commits to be merged into master are signed. You can enable commit signing on GitHub by following [Signing commits](https://help.github.com/en/github/authenticating-to-github/signing-commits).
