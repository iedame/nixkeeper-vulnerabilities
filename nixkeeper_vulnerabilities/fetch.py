"""Asking the sources: JSON over HTTPS, one request at a time, at most one
a PAUSE, with a User-Agent that says who's asking."""

import json
import time
import urllib.error
import urllib.request

USER_AGENT = (
    "nixkeeper-vulnerabilities (+https://github.com/iedame/nixkeeper-vulnerabilities)"
)
# Seconds from one request to the next. Nothing here is in a hurry: a late
# digest only leaves nixkeeper with what it had. The NixOS security tracker
# allows 30 requests a minute without an account (its API_THROTTLE_ANONYMOUS,
# "30/min"): one every 2 seconds reached the 31st within a minute, and was
# refused; 2.5 is 24 a minute.
PAUSE = 2.5
# Refused for asking too often (429): wait as long as the answer says
# (Retry-After, in seconds; else a minute), at most MAX_WAIT, and ask again,
# at most RETRIES times.
RETRIES = 2
MAX_WAIT = 120
# urlopen's timeout bounds each wait for the next bytes; DEADLINE bounds the
# whole answer, so a server sending a little at a time can't hold the run.
TIMEOUT = 60
DEADLINE = 180
_last = 0.0


def _pace():
    """Wait until PAUSE has passed since the last request."""
    global _last
    wait = _last + PAUSE - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    _last = time.monotonic()


def _read(resp, deadline):
    """resp's body, raising TimeoutError once time.monotonic() is past
    deadline, however steadily it trickles in."""
    read = getattr(resp, "read1", resp.read)  # what has arrived, at most n
    chunks = []
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("the answer took too long to arrive")
        chunk = read(65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def retry_after(error):
    """Seconds a 429 answer asks to wait (its Retry-After), at most
    MAX_WAIT; a minute when it doesn't say."""
    try:
        wait = float(error.headers.get("Retry-After"))
    except (TypeError, ValueError, AttributeError):
        wait = 60
    return min(max(wait, 1), MAX_WAIT)


def get_json(url):
    """url's JSON answer, at most one request a PAUSE; refused for asking too
    often (429), asked again after the wait it says (RETRIES times). Raises
    on any other failure (urllib.error.URLError, TimeoutError, ValueError):
    what wasn't read is read next run."""
    for attempt in range(RETRIES + 1):
        _pace()
        req = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        deadline = time.monotonic() + DEADLINE
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return json.loads(_read(resp, deadline))
        except urllib.error.HTTPError as e:
            if e.code != 429 or attempt == RETRIES:
                raise
            wait = retry_after(e)
            print(f"  asked too often: waiting {wait:.0f} s ({url})")
            time.sleep(wait)
    raise AssertionError("unreachable")


# A whole file (an OSV archive: PyPI's is ~35 MB) may take longer.
FILE_DEADLINE = 900


def get_file(url, etag=None):
    """(url's bytes, its ETag), or (None, etag) when it hasn't changed since
    etag (the server says 304: nothing downloaded). At most one request a
    PAUSE. Raises on any other failure."""
    _pace()
    headers = {"User-Agent": USER_AGENT}
    if etag:
        headers["If-None-Match"] = etag
    req = urllib.request.Request(url, headers=headers)
    deadline = time.monotonic() + FILE_DEADLINE
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return _read(resp, deadline), resp.headers.get("ETag")
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return None, etag
        raise
