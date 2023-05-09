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
Tests should be provided to cover both positive and negative conditions. Tests should cover both the proper execution as well as all the covered error paths. PR with no proper test coverage will not be merged.

## Git conventions 

### Commits, titles, and descriptions

- Changes must be split logically in commits, such that a commit is self-contained
- In general terms, all commits need to pass the test suite. There may be some exceptions to this rule if the change you are working on touches several components of the codebase and it makes more sense to split the change by component (or group of components)
- Commit titles need to be short and explanatory. If we are, for instance, adding an RPC command to the backend, "Adds command X to the backend" will be a good short description, "Add command" or "Fix #123" where #123 is an issue referencing this feature **IS NOT**
- Descriptions can be provided to give more context about what has been fixed and how

### Pull requests

- Pull request titles need to be explanatory, in the same way, commits titles were. If a PR includes a single commit, they can share the title, otherwise, a general title of what we are trying to achieve is required. **DO NOT REFERENCE ISSUES IN PULL REQUEST TITLES**, save that for the PR description
- PR descriptions need to guide the reviewer into what has been changed. You can reference issues here. If the PR is a fix of a simple issue, "Fix #123" may suffice, however, if it involves several changes, a proper explanation of both what has been fixed and how is due. These are two good examples of PR descriptions, both long and short: [188](https://github.com/talaia-labs/rust-teos/pull/188), [194](https://github.com/talaia-labs/rust-teos/pull/194)
- **WE DO NOT PILE "fix" COMMITS IN A PULL REQUEST**, that is, if some fixes are requested by reviewers, or something was missing from our original approach, it needs to be squashed. Do **NOT** do this:

	```
	886b0ff Adds X functionality to component Y
	801ff5d Fixes the previous commit because Z
	67ac345 Addresses review comments
	7dc7fcd Updates X because G was missing
	b60999c Adds missing test
	...
	```
	
- Create a new branch to work on your pull request. **DO NOT** work from the master branch of your fork*
- **DO NOT** merge master into your branch, rebase master instead*

	\* If you're not sure how to handle this, check external documentation on how to manage multiple remotes for the same repository.

###  Signing Commits

We require that all commits to be merged into master are signed. You can enable commit signing on GitHub by following [Signing commits](https://help.github.com/en/github/authenticating-to-github/signing-commits).
