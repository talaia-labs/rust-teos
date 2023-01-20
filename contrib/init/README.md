**This document guides you into how to set-up a systemd service to run `teosd`.**

Since the teos service requires bitcoin to run, it is strongly recommended to also create a [system service for bitcoin](https://github.com/bitcoin/bitcoin/blob/master/contrib/init/bitcoind.service).

Once you have set the bitcoin service, proceed to copy [teosd.service](teosd.service) to the systemd folder, that is, if running from this folder:

```
cp teosd.service /etc/systemd/system
```

You can also create a file called `teosd.service` in the systemd folder and copy the content of [teosd.service](teosd.service) to it:

```
sudo vim /etc/systemd/system/teosd.service
```

Notice the provided service file is using `teos` both as user and group for the service, so you may want to update that if that is not the configuration you are intending to use. Here are the lines to be updated:

```
[Service]
ExecStart=/home/<user>/.cargo/bin/teosd
SyslogIdentifier=<user>

# Directory creation and permissions
####################################
User=<user>
Group=<group>
```

The next step is enabling the service. You can do so by running:

```
sudo systemctl enable teosd.service
```

Finally, you can start the service by running:

```
sudo systemctl start teosd.service
```

From that point on, the tower will be run every time your system is turned on, and restarted if needed.
