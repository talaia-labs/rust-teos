#!/bin/sh

# Define the start command
START_COMMAND="teosd"

# Set the API bind address
if [[ ! -z ${API_BIND} ]]; then
    START_COMMAND="$START_COMMAND --apibind $API_BIND"
fi

# Set the API port
if [[ ! -z ${API_PORT} ]]; then
    START_COMMAND="$START_COMMAND --apiport $API_PORT"
fi

# Set the RPC bind address
if [[ ! -z ${RPC_BIND} ]]; then
    START_COMMAND="$START_COMMAND --rpcbind $RPC_BIND"
fi

# Set the RPC port
if [[ ! -z ${RPC_PORT} ]]; then
    START_COMMAND="$START_COMMAND --rpcport $RPC_PORT"
fi

# Set the Bitcoin network
if [[ ! -z ${BTC_NETWORK} ]]; then
    START_COMMAND="$START_COMMAND --btcnetwork $BTC_NETWORK"
fi

# Set the Bitcoin RPC credentials
if [[ ! -z ${BTC_RPC_USER} ]]; then
    START_COMMAND="$START_COMMAND --btcrpcuser $BTC_RPC_USER"
fi

if [[ ! -z ${BTC_RPC_PASSWORD} ]]; then
    START_COMMAND="$START_COMMAND --btcrpcpassword $BTC_RPC_PASSWORD"
fi

# Set the Bitcoin RPC connection details
if [[ ! -z ${BTC_RPC_CONNECT} ]]; then
    START_COMMAND="$START_COMMAND --btcrpcconnect $BTC_RPC_CONNECT"
fi

if [[ ! -z ${BTC_RPC_PORT} ]]; then
    START_COMMAND="$START_COMMAND --btcrpcport $BTC_RPC_PORT"
fi

if [ "${DEBUG}" == "true" ]; then
    START_COMMAND="$START_COMMAND --debug"
fi

if [ "${DEPS_DEBUG}" == "true" ]; then
    START_COMMAND="$START_COMMAND --depsdebug"
fi

if [ "${OVERWRITE_KEY}" == "true" ]; then
    START_COMMAND="$START_COMMAND --overwritekey"
fi

if [ "${FORCE_UPDATE}" == "true" ]; then
    START_COMMAND="$START_COMMAND --forceupdate"
fi

# Start the TEOS daemon
$START_COMMAND
