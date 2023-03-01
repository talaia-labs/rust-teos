#!/bin/bash

# Define the start command
START_COMMAND="teosd"

# Set the API bind address
if [[ ! -z ${API_BIND} ]]; then
    START_COMMAND="$START_COMMAND --api-bind $API_BIND"
fi

# Set the API port
if [[ ! -z ${API_PORT} ]]; then
    START_COMMAND="$START_COMMAND --api-port $API_PORT"
fi

# Set the RPC bind address
if [[ ! -z ${RPC_BIND} ]]; then
    START_COMMAND="$START_COMMAND --rpc-bind $RPC_BIND"
fi

# Set the RPC port
if [[ ! -z ${RPC_PORT} ]]; then
    START_COMMAND="$START_COMMAND --rpc-port $RPC_PORT"
fi

# Set the Bitcoin network
if [[ ! -z ${BTC_NETWORK} ]]; then
    START_COMMAND="$START_COMMAND --btc-network $BTC_NETWORK"
fi

# Set the Bitcoin RPC credentials
if [[ ! -z ${BTC_RPC_USER} ]]; then
    START_COMMAND="$START_COMMAND --btc-rpc-user $BTC_RPC_USER"
fi

if [[ ! -z ${BTC_RPC_PASSWORD} ]]; then
    START_COMMAND="$START_COMMAND --btc-rpc-password $BTC_RPC_PASSWORD"
fi

# Set the Bitcoin RPC connection details
if [[ ! -z ${BTC_RPC_CONNECT} ]]; then
    START_COMMAND="$START_COMMAND --btc-rpc-connect $BTC_RPC_CONNECT"
fi

if [[ ! -z ${BTC_RPC_PORT} ]]; then
    START_COMMAND="$START_COMMAND --btc-rpc-port $BTC_RPC_PORT"
fi

# Set the Bitcoin feed connection details
if [[ ! -z ${BTC_FEED_CONNECT} ]]; then
    START_COMMAND="$START_COMMAND --btc-feed-connect $BTC_FEED_CONNECT"
fi

if [[ ! -z ${BTC_FEED_PORT} ]]; then
    START_COMMAND="$START_COMMAND --btc-feed-port $BTC_FEED_PORT"
fi

# Start the TEOS daemon
$START_COMMAND
