from pathlib import Path
import subprocess

from pyln.testing.fixtures import *  # noqa: F401,F403
from pyln.testing.utils import DEVELOPER, BITCOIND_CONFIG, TailableProc

WT_PLUGIN = Path("~/.cargo/bin/watchtower-client").expanduser()
TEOSD_CONFIG = {
    "btc_network": "regtest",
    "polling_delta": 0,
}


def write_toml_config(filename, opts):
    with open(filename, "w") as f:
        for k, v in opts.items():
            if isinstance(v, str):
                f.write('{} = "{}"\n'.format(k, v))
            else:
                f.write("{} = {}\n".format(k, v))


class TeosCLI:
    def __init__(self, directory="/tmp/watchtower-test"):
        self.datadir = directory

    def _call(self, method_name, *args):
        try:
            r = subprocess.run(
                ["teos-cli", f"--datadir={self.datadir}/teos", method_name, *args],
                capture_output=True,
                text=True,
            )
            if r.returncode != 0:
                result = ValueError(f"Unknown method {method_name}")
            else:
                result = json.loads(r.stdout)
        except json.JSONDecodeError:
            result = None
        return result

    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            # Prevent RPC calls for non-existing python internal attribute
            # access. If someone tries to get an internal attribute
            # of RawProxy instance, and the instance does not have this
            # attribute, we do not want the bogus RPC call to happen.
            raise AttributeError

        # Create a callable to do the actual call
        f = lambda *args: self._call(name, *args)  # noqa: E731

        # Make debuggers show <function teos.cli.name> rather than <function
        # teos.cli.<lambda>>
        f.__name__ = name
        return f


class TeosD(TailableProc):
    def __init__(self, bitcoind_rpcport, directory="/tmp/watchtower-test"):
        self.teos_dir = os.path.join(directory, "teos")
        self.prefix = "teosd"
        TailableProc.__init__(self, self.teos_dir)
        self.cli = TeosCLI(directory)

        if not os.path.exists(self.teos_dir):
            os.makedirs(self.teos_dir)

        self.cmd_line = [
            "teosd",
            f"--datadir={self.teos_dir}",
            f'--btcrpcuser={BITCOIND_CONFIG["rpcuser"]}',
            f'--btcrpcpassword={BITCOIND_CONFIG["rpcpassword"]}',
            f"--btcrpcport={bitcoind_rpcport}",
        ]

        self.conf_file = os.path.join(self.teos_dir, "teos.toml")
        write_toml_config(self.conf_file, TEOSD_CONFIG)

    def start(self, overwrite_key=False):
        if overwrite_key:
            self.cmd_line.append("--overwritekey")
        TailableProc.start(self)
        self.wait_for_log("Tower ready")

        logging.info("TeosD started")

    def stop(self):
        self.cli.stop()
        self.wait_for_log("Shutting down tower")

        return TailableProc.stop(self)


@pytest.fixture
def teosd(bitcoind, directory):
    # Set the user data dir for the watchtower-plugin so it uses a unique one per test.
    os.environ["TOWERS_DATA_DIR"] = os.path.join(directory, "watchtower")

    teosd = TeosD(directory=directory, bitcoind_rpcport=bitcoind.rpcport)
    teosd.start()
    yield teosd

    teosd.stop()


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call, which can
    # be "setup", "call", "teardown"

    setattr(item, "rep_" + rep.when, rep)


def pytest_configure(config):
    config.addinivalue_line("markers", "developer: only run when developer is flagged on")


def pytest_runtest_setup(item):
    for mark in item.iter_markers(name="developer"):
        if not DEVELOPER:
            if len(mark.args):
                pytest.skip("!DEVELOPER: {}".format(mark.args[0]))
            else:
                pytest.skip("!DEVELOPER: Requires DEVELOPER=1")


@pytest.fixture(scope="function", autouse=True)
def log_name(request):
    # Here logging is used, you can use whatever you want to use for logs
    logging.info("Starting '{}'".format(request.node.name))
