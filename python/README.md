# ferotrx: Python client for FeroTRX

A typed Python client for the [FeroTRX](https://github.com/jkobierczynski/FeroTRX)
control server (`ferotrx serve`): load profiles, start and stop stateless
runs, stateful TCP and UDP runs and receivers, and read live counters, from
scripts, notebooks and test suites. Blocking (`ferotrx.Client`) and asyncio
(`ferotrx.AsyncClient`) clients; TLS, mutual TLS and tokens; no dependencies
beyond the standard library; Python 3.10 or newer.

```sh
pip install "git+https://github.com/jkobierczynski/FeroTRX#subdirectory=python"
# or from a checkout:
pip install ./python
```

```python
import ferotrx

with ferotrx.Client("192.168.56.10", token="s3cret") as c:
    c.load_profile("lab-two-vlans.toml", upload=True)  # this machine's file
    run = c.start("lab-two-vlans", iface="enp0s3", duration="30s")
    for update in c.watch(run.id):
        print(f"{update.run.total.pps:.0f} pps")

    tcp = c.tcp_start("/srv/profiles/lab-tcp.toml", connections=500, cps=100)
    done = c.tcp_wait(tcp.id)
    assert done.client.completed == 500, done
```

The full guide, with every method, TLS, errors and the asyncio client, is
[docs/python-client.md](https://github.com/jkobierczynski/FeroTRX/blob/main/docs/python-client.md).
Examples are in [`examples/`](examples/).

The package version follows FeroTRX's: `ferotrx` 0.24.0 is made for
`ferotrx serve` 0.24.0 (control protocol 2) and reads older and newer servers
of the same protocol.

## Development

```sh
cd python
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
cargo build -p ferotrx-cli          # the tests start target/debug/ferotrx serve
pytest                               # FEROTRX_BIN=... for another binary
mypy && ruff check . && ruff format --check .
```

The tests in `tests/test_lab.py` send real traffic across a veth pair and need
a root server; see the file for how to run them (CI does).

License: GPL-3.0-or-later.
