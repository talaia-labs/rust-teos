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

If you would like to create a system service to run your application follow the instructions below.

Since the teos service requires bitcoin to run, it's strongly recommended that you also create a system service for bitcoin. Follow this link for instructions to do so: [bitcoind service](https://twofaktor.github.io/minibolt/guide/bitcoin/bitcoin-client.html#autostart-on-boot).


Once the bitcoin system services have completed, proceed using your preferred text editor, and create a file in the systemd folder. For instance:

`sudo nano /etc/systemd/system/teosd.service`

This will create a file named teos.service in the /etc/systemd/system/ path

Copy the following information replacing the relevant information with yours (`<USER>` and `<GROUP>`):


```
[Unit]
Description=The Eye of Satoshi daemon
Requires=bitcoind.service
After=bitcoind.service
Wants=network.target
After=network.target

[Service]
ExecStart=/home/<USER>/.cargo/bin/teosd
StandardOutput=journal
StandardError=journal
SyslogIdentifier=<USER>

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

The next step  is enabling the service. You can do so by running:
`sudo systemctl enable teosd.service`

Finally, you can start the service by running:
`sudo systemctl start teosd.service`

