from nixkeeper_vulnerabilities import fetch


def _no_network(url):
    raise AssertionError(f"a test asked the network: {url}")


# Tests never ask the real sources: each gives its own answers.
fetch.get_json = _no_network
