import time
import pytest


def change_endianness(x):
    """Changes the endianness (from BE to LE and vice versa) of a given value.

    :param x: Given value which endianness will be changed.
    :type x: hex str
    :return: The opposite endianness representation of the given value.
    :rtype: hex str
    """

    b = bytes.fromhex(x)
    return b[::-1].hex()


@pytest.mark.developer("Requires dev_sign_last_tx")
def test_watchtower(node_factory, bitcoind, teosd):
    """
    Test watchtower hook.

    l1 and l2 open a channel, make a couple of updates and then l1 cheats on
    l2 while that one is offline. The watchtower plugin meanwhile stashes all
    the penalty transactions and we release the one matching the offending
    commitment transaction.
    """

    l1, l2 = node_factory.line_graph(2, opts=[{"allow_broken_log": True}, {"plugin": "watchtower-client"}])

    # We need to register l2 with the tower
    tower_id = teosd.cli.get_tower_info()["tower_id"]
    l2.rpc.registertower(tower_id)

    # Force a new commitment
    l1.rpc.pay(l2.rpc.invoice(25000000, "lbl1", "desc1")["bolt11"])
    tx = l1.rpc.dev_sign_last_tx(l2.info["id"])["tx"]

    # Now make sure it is out of date
    l1.rpc.pay(l2.rpc.invoice(25000000, "lbl2", "desc2")["bolt11"])

    # l2 stops watching the chain, allowing the watchtower to react
    l2.stop()

    # Now l1 cheats
    dispute_txid = bitcoind.rpc.sendrawtransaction(tx)
    locator = change_endianness(dispute_txid[32:])

    # Make sure l2's normal penalty_tx doesn't reach the network
    l2.daemon.rpcproxy.mock_rpc("sendrawtransaction", lambda: None)
    l2.start()

    # The tower will react once the dispute gets confirmed. For now it is still watching for it
    assert l2.rpc.getappointment(tower_id, locator)["status"] == "being_watched"

    # Confirm the dispute so the tower can react with the penalty
    bitcoind.generate_block(1)
    time.sleep(1)
    penalty_txid = bitcoind.rpc.getrawmempool()[0]

    # The channel still exists between the two peers, but it's on chain
    assert l1.rpc.listpeers()["peers"][0]["channels"][0]["state"] == "ONCHAIN"
    assert l2.rpc.getappointment(tower_id, locator)["status"] == "dispute_responded"

    # Generate blocks until the penalty gets irrevocably resolved
    for i in range(101):
        bitcoind.generate_block(1)
        time.sleep(0.1)
        if i < 100:
            assert l2.rpc.getappointment(tower_id, locator)["status"] == "dispute_responded"
        else:
            # Once the channel gets irrevocably resolved the tower will forget about it
            assert l2.rpc.getappointment(tower_id, locator) == {"error": "Appointment not found", "error_code": 36}

    # Make sure the penalty outputs are in l2's wallet
    fund_txids = [o["txid"] for o in l2.rpc.listfunds()["outputs"]]
    assert penalty_txid in fund_txids


@pytest.mark.timeout(60)
def test_unreachable_watchtower(node_factory, bitcoind, teosd):
    # Set the max retry interval to 1 sec so we know how much to wait for the next retry attempt
    max_interval_time = 1
    l1, l2 = node_factory.line_graph(
        2,
        opts=[
            {},
            {
                "plugin": "watchtower-client",
                "allow_broken_log": True,
                "dev-watchtower-max-retry-interval": max_interval_time,
            },
        ],
    )

    # We need to register l2 with the tower
    tower_id = teosd.cli.get_tower_info()["tower_id"]
    l2.rpc.registertower(tower_id)

    # Stop the tower
    teosd.stop()

    # Make a new payment with an unreachable tower
    l1.rpc.pay(l2.rpc.invoice(25000000, "lbl1", "desc1")["bolt11"])
    assert l2.rpc.gettowerinfo(tower_id)["status"] == "temporary_unreachable"
    assert l2.rpc.gettowerinfo(tower_id)["pending_appointments"]

    # Start the tower and check the automatic backoff works (wait while are pending appointments)
    teosd.start()
    while l2.rpc.gettowerinfo(tower_id)["pending_appointments"]:
        time.sleep(1)

    assert l2.rpc.gettowerinfo(tower_id)["status"] == "reachable"


def test_retry_watchtower(node_factory, bitcoind, teosd):
    # The plugin is set to give up on retrying straight-away so we can test this fast.
    l1, l2 = node_factory.line_graph(
        2, opts=[{}, {"plugin": "watchtower-client", "allow_broken_log": True, "watchtower-max-retry-time": 0}]
    )

    # We need to register l2 with the tower
    tower_id = teosd.cli.get_tower_info()["tower_id"]
    l2.rpc.registertower(tower_id)

    # Stop the tower
    teosd.stop()

    # Make a new payment with an unreachable tower
    l1.rpc.pay(l2.rpc.invoice(25000000, "lbl1", "desc1")["bolt11"])
    assert l2.rpc.gettowerinfo(tower_id)["status"] == "unreachable"
    assert l2.rpc.gettowerinfo(tower_id)["pending_appointments"]

    # Start the tower and retry it
    teosd.start()
    l2.rpc.retrytower(tower_id)
    while l2.rpc.gettowerinfo(tower_id)["pending_appointments"]:
        time.sleep(1)

    assert l2.rpc.gettowerinfo(tower_id)["status"] == "reachable"


def test_misbehaving_watchtower(node_factory, bitcoind, teosd, directory):
    l1, l2 = node_factory.line_graph(2, opts=[{}, {"plugin": "watchtower-client", "allow_broken_log": True}])

    # We need to register l2 with the tower
    tower_id = teosd.cli.get_tower_info()["tower_id"]
    l2.rpc.registertower(tower_id)

    # Restart overwriting the tower private key
    teosd.stop()
    teosd.start(overwrite_key=True)

    # Make a new payment and check the state
    l1.rpc.pay(l2.rpc.invoice(25000000, "lbl1", "desc1")["bolt11"])
    assert l2.rpc.gettowerinfo(tower_id)["status"] == "misbehaving"
    assert l2.rpc.gettowerinfo(tower_id)["misbehaving_proof"]


def test_get_appointment(node_factory, bitcoind, teosd, directory):
    l1, l2 = node_factory.line_graph(2, opts=[{"allow_broken_log": True}, {"plugin": "watchtower-client"}])

    # We need to register l2 with the tower
    tower_id = teosd.cli.get_tower_info()["tower_id"]
    l2.rpc.registertower(tower_id)

    # Force a new commitment
    l1.rpc.pay(l2.rpc.invoice(25000000, "lbl1", "desc1")["bolt11"])
    tx = l1.rpc.dev_sign_last_tx(l2.info["id"])["tx"]

    # Now make sure it is out of date
    l1.rpc.pay(l2.rpc.invoice(25000000, "lbl2", "desc2")["bolt11"])

    # Now l1 cheats
    dispute_txid = bitcoind.rpc.sendrawtransaction(tx)
    locator = change_endianness(dispute_txid[32:])

    # Check the appointment before mining a block
    appointment = l2.rpc.getappointment(tower_id, locator)["appointment"]
    assert "locator" in appointment and "encrypted_blob" in appointment and "to_self_delay" in appointment

    bitcoind.generate_block(1)
    time.sleep(1)

    # And after. Now this should be a tracker
    tracker = l2.rpc.getappointment(tower_id, locator)["appointment"]
    assert "dispute_txid" in tracker and "penalty_txid" in tracker and "penalty_rawtx" in tracker

    # Manually stop l2, otherwise the tower may be stopped before the tower client and we may get some BROKEN logs.
    l2.stop()
