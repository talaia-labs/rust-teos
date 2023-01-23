# Install

The tower can be installed and tested using cargo:

```
git clone https://github.com/talaia-labs/rust-teos.git
cd rust-teos
cargo install --locked --path teos
```

You can run tests with:

```
cargo test
```

Please refer to the cargo documentation for more detailed instructions.

# Systemd setup for backend

Refer to [contrib](contrib/init/README.md) for a detailed explanation of how to set up your systemd service for `teosd`.