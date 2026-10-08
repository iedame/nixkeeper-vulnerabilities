"""The digest nixkeeper reads (data/), and the state kept between runs.

data/vulnerabilities.json.gz:

    {"format": 1,
     "tracker": {
       "suggestions": {
         "48625": {"cve": "CVE-2026-75818", "issue": "NIXPKGS-2026-2925",
                   "title": "Heap Buffer Overflow in ...",
                   "score": 1.8, "severity": "low", "cvss": "cvssV4_0",
                   "affected": [{"product": "Aspell",
                                 "versions": [["affected", "<0.60.8.3"]]}],
                   "packages": {"aspell": {"version": "0.60.8.2",
                                           "status": "affected"}}}},
       "issues": {
         "NIXPKGS-2026-2925": {
           "title": "...", "status": "affected",
           "github": "https://github.com/NixOS/nixpkgs/issues/571389"}},
       "packages": {"aspell": [{"suggestion": "48625", "version": "0.60.8.2",
                                "status": "affected"}]}},
     "osv": {
       "advisories": {
         "PYSEC-2023-74": {"aliases": ["CVE-2023-32681", "GHSA-j8r2-6x86-q33q"],
                           "cves": ["CVE-2023-32681"],
                           "summary": "...", "severity": "moderate",
                           "cvss": "CVSS:3.1/...",
                           "ecosystem": "PyPI", "package": "requests"}},
       "packages": {"python313Packages.requests": ["PYSEC-2023-74"]}}}

The NixOS security tracker's published suggestions (tracker.py): by id,
each one's CVE, its issue (in "issues" once read: their pass is slower),
severity (the newest CVSS version's score, when the CVE has one), the
version ranges the CVE record gives, and its packages on nixos-unstable
with the tracker's verdict there (version: null when the channel's
branches differ; both null for an older suggestion's packages, which the
tracker no longer evaluates on a channel); and by package, the
suggestions naming it. OSV's advisories for language packages (osv.py)
that some nixpkgs package's version matches: their aliases and CVEs
(CRAN's from "upstream" too), a summary, severity and CVSS vector when
given, and the ecosystem and name; and by attribute, which.

data/meta.json: {"format": 1, "tracker": {"readAt", "suggestions",
"issues", "packages", "complete", "pass", "stopped"?, "token"?, "tokenExpiry"?,
"tokenRenewal"?}, "osv": {"readAt",
"nixpkgsIndexedAt", "inSets", "ecosystems", "packages", "advisories"}}:
when the tracker was last read from, how many of each the digest has,
whether every list has been read through at least once (until then, the
digest has only part of it), where the reading is, and what stopped the
last run's reading of a list, if anything did, and with a tracker token,
whether it was "used" or "refused", when it expires, and whether it was
"renewed" (or that renewal "failed"); when OSV was last
read, the nixpkgs index it matched, how many nixpkgs packages are in the
sets it covers, each ecosystem's advisories for nixpkgs' names, and how
many packages and advisories match.

data/state.json.gz: what the reading keeps between runs (tracker.py's
state). The digest files are the same, byte for byte, when their content
is: unchanged data isn't published again."""

import gzip
import json
import os

FORMAT = 1
DIGEST = "vulnerabilities.json.gz"
META = "meta.json"
STATE = "state.json.gz"


def _write_gz(path, data):
    text = json.dumps(data, sort_keys=True, separators=(",", ":"))
    # mtime=0: the same content gives the same bytes.
    with open(path, "wb") as f:
        f.write(gzip.compress(text.encode(), compresslevel=9, mtime=0))


def _read_gz(path):
    with gzip.open(path, "rt") as f:
        return json.load(f)


def read_state(directory):
    """The state the last run kept, or {} if there's none yet."""
    try:
        return _read_gz(os.path.join(directory, STATE))
    except FileNotFoundError:
        return {}


def read_meta(directory):
    try:
        with open(os.path.join(directory, META)) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def write(directory, state, digest, meta):
    """Write the state, the digest and meta.json to directory."""
    os.makedirs(directory, exist_ok=True)
    _write_gz(os.path.join(directory, STATE), {"format": FORMAT, **state})
    _write_gz(os.path.join(directory, DIGEST), {"format": FORMAT, **digest})
    with open(os.path.join(directory, META), "w") as f:
        json.dump({"format": FORMAT, **meta}, f, indent=2, sort_keys=True)
        f.write("\n")
