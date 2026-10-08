"""OSV (https://osv.dev): advisories for language packages, matched to
nixpkgs' packages by registry name and version.

nixpkgs' side comes from nixkeeper-versions (data/nixpkgs.json.gz: every
attribute's pname and version, from the channel's package index): an
attribute of a package set (SETS: python313Packages.requests) is that
ecosystem's package (PyPI's requests), its pname normalized as the
ecosystem compares names.

OSV's side: each ecosystem's archive of advisories
(https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip),
downloaded when it changed (its ETag: otherwise the server answers 304 and
nothing is downloaded), and again when nixpkgs' file changed (a package
new to nixpkgs may have advisories already). Of each archive, only the
advisories for names nixpkgs has are kept.

A package matches an advisory when its version is one of those the
advisory lists as affected (OSV lists them for every advisory these
ecosystems have, worked out from its ranges): exact, so no ecosystem's
version order is needed. An advisory with no fixed version lists every
release as affected, so it matches a newer one too, even when its text
says it was fixed (older PyPI advisories: beaker 1.13.0, "through
1.11.0"): weaker than the tracker's verdict."""

import gzip
import io
import json
import re
import sys
import urllib.error
import zipfile

from . import fetch

NIXPKGS_URL = "https://raw.githubusercontent.com/iedame/nixkeeper-versions/data/data/nixpkgs.json.gz"
OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com"
# Package sets and their OSV ecosystem: an attribute directly in the set
# (python313Packages.requests, not python313Packages.requests.dist).
SETS = (
    (re.compile(r"^python3\d*Packages\.[^.]+$"), "PyPI"),
    (re.compile(r"^haskellPackages\.[^.]+$"), "Hackage"),
    (re.compile(r"^rPackages\.[^.]+$"), "CRAN"),
    (re.compile(r"^rubyPackages(_\d+_\d+)?\.[^.]+$"), "RubyGems"),
    (re.compile(r"^ocamlPackages\.[^.]+$"), "opam"),
    # Not Hex (Elixir and Erlang): nixpkgs' beam27Packages, beam28Packages,
    # ... (and beamMinimal*) hold the toolchain (elixir, erlang, rebar3,
    # elixir-ls, ...; about 30 attributes each, 2026-10-08), not Hex's
    # libraries, which projects build themselves (mix2nix): nothing for its
    # advisories to match. Should nixpkgs package Hex libraries, add
    # (re.compile(r"^beam(Minimal)?\d+Packages\.[^.]+$"), "Hex").
    # Likewise others OSV has but nixpkgs doesn't package as a set by
    # registry name: npm (nodePackages is being removed), crates.io and Go
    # (libraries are vendored per package, not attributes).
)
ECOSYSTEMS = tuple(dict.fromkeys(eco for _, eco in SETS))
CVE = re.compile(r"^CVE-\d{4}-\d+$")


def name_key(ecosystem, name):
    """name as ecosystem compares names: PyPI's normalized (PEP 503:
    requests_oauthlib and Requests-OAuthlib are one), the others' in any
    case."""
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def ecosystem_of(attr):
    for pattern, ecosystem in SETS:
        if pattern.match(attr):
            return ecosystem
    return None


def wanted(packages):
    """{attr: [ecosystem, name key, version]} of nixpkgs' packages
    (nixpkgs.json.gz's "packages") in a set OSV covers, with a version."""
    found = {}
    for attr, p in packages.items():
        ecosystem = ecosystem_of(attr)
        if ecosystem and p.get("pname") and p.get("version"):
            found[attr] = [ecosystem, name_key(ecosystem, p["pname"]), p["version"]]
    return found


def advisory(record):
    """What the digest keeps of an OSV record."""
    cves = [a for a in record.get("aliases") or [] if CVE.match(a)]
    cves += [u for u in record.get("upstream") or [] if CVE.match(u) and u not in cves]
    severity = (record.get("database_specific") or {}).get("severity")
    vector = next(
        (s.get("score") for s in record.get("severity") or [] if s.get("score")), None
    )
    return {
        "aliases": record.get("aliases") or [],
        "cves": cves,
        "summary": record.get("summary")
        or (record.get("details") or "").split("\n", 1)[0][:200],
        **({"severity": severity.lower()} if isinstance(severity, str) else {}),
        **({"cvss": vector} if vector else {}),
    }


def index(archive, ecosystem, names):
    """({name key: [[id, [affected versions]], ...]}, {id: advisory}) of an
    ecosystem's archive (all.zip's bytes), for the names nixpkgs has only;
    withdrawn advisories left out."""
    found, advisories = {}, {}
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        for entry in z.namelist():
            if not entry.endswith(".json"):
                continue
            record = json.loads(z.read(entry))
            if record.get("withdrawn"):
                continue
            for affected in record.get("affected") or []:
                package = affected.get("package") or {}
                if package.get("ecosystem") != ecosystem:
                    continue
                key = name_key(ecosystem, package.get("name") or "")
                if key not in names or not affected.get("versions"):
                    continue
                found.setdefault(key, []).append([record["id"], affected["versions"]])
                advisories[record["id"]] = {
                    **advisory(record),
                    "ecosystem": ecosystem,
                    "package": package.get("name"),
                }
    return found, advisories


def update(state, get=None):
    """Bring the OSV part of state up to date: nixpkgs' packages in the sets
    ("packages": {attr: [ecosystem, name key, version]}), and each
    ecosystem's advisories for them ("ecosystems": {ecosystem: {"etag",
    "index", "advisories"}}). Returns how many files were downloaded (304s
    aren't), or None when nixpkgs' file isn't published yet (the state
    stays). An ecosystem that can't be read keeps what it had, and the
    others go on; nixpkgs' file failing raises (what was read stays)."""
    get = get or fetch.get_file
    downloaded = 0
    try:
        body, etag = get(NIXPKGS_URL, state.get("nixpkgsEtag"))
    except urllib.error.HTTPError as e:
        if e.code == 404:  # nixkeeper-versions hasn't published it yet
            return None
        raise
    fresh = body is not None
    if fresh:
        downloaded += 1
        facts = json.loads(gzip.decompress(body))
        state["packages"] = wanted(facts.get("packages") or {})
        state["nixpkgsEtag"] = etag
        state["nixpkgsIndexedAt"] = facts.get("indexedAt")
    packages = state.get("packages") or {}
    ecosystems = state.setdefault("ecosystems", {})
    for ecosystem in ECOSYSTEMS:
        names = {key for eco, key, _ in packages.values() if eco == ecosystem}
        last = ecosystems.get(ecosystem) or {}
        # nixpkgs changed: download again whatever the ETag, for new names.
        etag = None if fresh else last.get("etag")
        try:
            archive, etag = get(f"{OSV_URL}/{ecosystem}/all.zip", etag)
            if archive is None:
                continue
            downloaded += 1
            found, advisories = index(archive, ecosystem, names)
        except (urllib.error.URLError, OSError, ValueError, zipfile.BadZipFile) as e:
            print(f"::warning::OSV {ecosystem}: not read ({e})", file=sys.stderr)
            continue
        ecosystems[ecosystem] = {"etag": etag, "index": found, "advisories": advisories}
    return downloaded


def matches(state):
    """{attr: [advisory ids]} of nixpkgs' packages whose version an
    advisory lists as affected."""
    ecosystems = state.get("ecosystems") or {}
    found = {}
    for attr, (ecosystem, key, version) in sorted(
        (state.get("packages") or {}).items()
    ):
        entries = ((ecosystems.get(ecosystem) or {}).get("index") or {}).get(key) or []
        ids = sorted({i for i, versions in entries if version in versions})
        if ids:
            found[attr] = ids
    return found


def digest(state):
    """The OSV part of the published digest: the advisories some package
    matches, and by package which."""
    packages = matches(state)
    used = {i for ids in packages.values() for i in ids}
    advisories = {}
    for e in (state.get("ecosystems") or {}).values():
        for i, a in (e.get("advisories") or {}).items():
            if i in used:
                advisories[i] = a
    return {"advisories": dict(sorted(advisories.items())), "packages": packages}
