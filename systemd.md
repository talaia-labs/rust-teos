Systemd setup for backend


Create a simple file copying the contents below to the file, and use the command:
sudo nano /usr/lib/systemd/system/teos.service 
#this will create a file named teos.service in the /usr/lib/systemd/system/ path

And change it with your proper installation path, user, and comments:

------------- don't copy this line, copy under it --------------------------

[Unit]
Description=The Eye of Satoshi daemon
Requires=teos.service
After=bitcond.service

[Service]
WorkingDirectory=/home/<USER>/.teos
ExecStart=/home/<USER>/.cargo/bin/teosd --datadir=/home/<USER>/.teos/ 
StandardOutput=journal
StandardError=journal
SyslogIdentifier=<USER>
User=<USER>
Group=<USER>
Type=simple
PIDFile=/run/teos/teos.pid
Restart=on-failure

[Install]
WantedBy=multi-user.target
------------- don't copy this line, copy above it --------------------------

The next step is to enable the service with the following command:
sudo systemctl enable teos.service

And start the service with the command:
sudo systemctl start teos.service

If you need to stop the service, use the command:
sudo systemctl stop teos.service
