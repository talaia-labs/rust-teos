## Running `teosd` in a docker container
A `teos` image can be built from the Dockerfile located in `docker`. You can create the image by running:

	cd rust-teos
	docker build -f docker/Dockerfile -t teos .
	
Then we can create a container by running:

	docker run -it teos

One way to feed `teos` custom config options is to set environment variables:

	docker run -it -e <ENV_VARIABLES> teos
	
Notice that the ENV variables are optional, if unset the corresponding default setting is used. The following ENVs are available:

```
- API_BIND=<teos_api_hostname>
- API_PORT=<teos_api_port>
- RPC_BIND=<teos_rpc_hostname>
- RPC_PORT=<teos_rpc_port>
- BTC_NETWORK=<btc_network>
- BTC_RPC_CONNECT=<btc_node_hostname>
- BTC_RPC_PORT=<btc_node_port>
- BTC_RPC_USER=<btc_rpc_username>
- BTC_RPC_PASSWORD=<btc_rpc_password>
# The following options can be set turned on by setting them to "true"
- DEBUG=<debug_bool>
- DEPS_DEBUG=<deps_debug_bool>
- OVERWRITE_KEY=<overwrite_key_bool>
- FORCE_UPDATE=<force_update_bool>
```

### Volume persistence

You may also want to run docker with a volume, so you can have data persistence in `teosd` databases and keys.
If so, run:

    docker volume create teos-data
    
And add the the mount parameter to `docker run`:

    -v teos-data:/home/teos/.teos

If you are running `teosd` and `bitcoind` in the same machine, continue reading for how to create the container based on your OS.

### `bitcoind` running on the same machine (UNIX)
The easiest way to run both together in the same machine using UNIX is to set the container to use the host network.
	
For example, if both `teosd` and `bitcoind` are running on default settings, run:
    
```
docker run \
  --network=host \
  --name teos \
  -v teos-data:/home/teos/.teos \
  -e BTC_RPC_USER=<btc_rpc_username> \
  -e BTC_RPC_PASSWORD=<btc_rpc_password> \
  -it teos
```

Notice that you may still need to set your RPC authentication details, since, hopefully, your credentials won't match the `teosd` defaults.

### `bitcoind` running on the same machine (OSX or Windows)

Docker for OSX and Windows does not allow to use the host network (nor to use the `docker0` bridge interface). To work around this
you can use the special `host.docker.internal` domain:

```
docker run \
  -p 9814:9814 \
  -p 8814:8814 \
  --name teos \
  -v teos-data:/home/teos/.teos \
  -e BTC_RPC_CONNECT=host.docker.internal \
  -e BTC_RPC_USER=<btc_rpc_username> \
  -e BTC_RPC_PASSWORD=<btc_rpc_password> \
  -e API_BIND=0.0.0.0 \
  -e RPC_BIND=0.0.0.0 \
  -it teos
```

Notice that we also needed to add `API_BIND=0.0.0.0` and `RPC_BIND=0.0.0.0` to bind the API to all interfaces of the container.
Otherwise it will bind to `localhost` and we won't be able to send requests to the tower from the host.

### Interacting with a TEOS instance

Once our `teos` instance is running in the container, we can interact with it using `teos-cli`. We have two main ways of doing so:

1) You can open a shell to the Docker instance by calling:

`docker exec -it <CONTAINER_NAME> sh`

Then you can use the `teos-cli` binary from inside the container as you would use it from your host machine.

2) Using `teos-cli` remotely (assuming you have it installed in the source machine) and pointing to the container. To do so, you will need to copy over the necessary credentials to the host machine. To do so, you can follow the instructions in [the main README](https://github.com/talaia-labs/rust-teos/blob/master/README.md#running-teos-cli-remotely).

### Plugging in Tor

You may have noticed, in the above section where the environment variables are covered, that the Tor options are nowhere to be found. That's because these instructions assume that users will likely be setting up Tor in another container.

On the machine where you have Tor running, you can follow [these instructions](https://community.torproject.org/onion-services/setup/) for setting up a hidden service manually.

For instance, if you're running `teosd` in a Docker container on the same machine as where Tor is running, you can create a hidden service from the host machine to hide the IP of the `teosd` API (listening on port 9814 for example). If you're using Linux, you can do so by editing your `torrc` file on the host machine with the below option:

```
HiddenServiceDir /var/lib/tor/teosd # Path for Linux. This may differ depending on your OS.
HiddenServicePort 9814 127.0.0.1:9814
```

Then restart Tor.

If all works correctly, the hidden service public key will be located in the `HiddenServiceDir` you set above, in the file called `hostname`.
