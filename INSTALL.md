# Install

The tower can be installed and tested using cargo:

```
git clone https://github.com/talaia-labs/rust-teos.git
cd rust-teos
cargo install --path teos
```

You can run tests with:

```
cargo test
```

Please refer to the cargo documentation for more detailed instructions.


### If you want to create a system service to run your application follow the instructions below:


# Systemd setup for backend


#### Create a simple file copying the contents below to the file, and use the command:
`sudo nano /etc/systemd/system/teosd.service`
#### This will create a file named teos.service in the /etc/systemd/system/ path

#### One you create it and copy and paste, change the information with your proper installation path, user, and comments:

#### ------------- don't copy this line, copy under it --------------------------
```
[Unit]
Description=The Eye of Satoshi daemon
Requires=bitcoind.service
After=bitcoind.service
Wants=network.target
After=network.target

[Service]
ExecStart=/home/<USER>/.cargo/bin/teosd

# Process management
####################
Type=simple
Restart=on-failure
TimeoutSec=300
RestartSec=60

# Directory creation and permissions
####################################
User=<USER>
Group=<GROUP>

# Hardening measures
####################
# Provide a private /tmp and /var/tmp.
PrivateTmp=true

# Mount /usr, /boot/ and /etc read-only for the process.
ProtectSystem=full

# Disallow the process and all of its children to gain
# new privileges through execve().
NoNewPrivileges=true

# Use a new /dev namespace only populated with API pseudo devices
# such as /dev/null, /dev/zero and /dev/random.
PrivateDevices=true

# Deny the creation of writable and executable memory mappings.
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target

```
#### ------------- don't copy this line, copy above it --------------------------

#### The next step is to enable the service with the following command:
`sudo systemctl enable teosd.service`

#### And start the service with the command:
`sudo systemctl start teosd.service`

#### If you need to stop the service, use the command:
`sudo systemctl stop teosd.service`
