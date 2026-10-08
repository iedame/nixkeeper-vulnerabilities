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
# digest only leaves nixkeeper with what it had.
PAUSE = 2.0
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


def get_json(url):
    """url's JSON answer, at most one request a PAUSE. Raises on any failure
    (urllib.error.URLError, TimeoutError, ValueError): what wasn't read is
    read next run."""
    _pace()
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    deadline = time.monotonic() + DEADLINE
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(_read(resp, deadline))


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
