from nixkeeper_vulnerabilities import fetch

# The real ones, for tests of fetch.py itself (which replace urlopen).
REAL = {"get_json": fetch.get_json, "get_file": fetch.get_file}


def _no_network(url, *args, **kwargs):
    raise AssertionError(f"a test asked the network: {url}")


# Tests never ask the real sources: each gives its own answers. Every way
# fetch.py has of asking is replaced.
fetch.get_json = _no_network
fetch.get_file = _no_network
