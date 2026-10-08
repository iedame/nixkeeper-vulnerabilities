"""`python3 -m nixkeeper_vulnerabilities [DATA_DIR]`: bring the digest in
DATA_DIR (default data/) up to date, as far as one run reads (tracker.py
says how much), and OSV's advisories for language packages (osv.py): a
source that can't be read keeps what the digest had."""

import sys
import urllib.error
from datetime import UTC, datetime

from . import digest, osv, tracker


def check_token(directory):
    """`--check-token`: fail (1) when the published meta.json says the
    tracker token was refused or couldn't be renewed, so the workflow's run
    fails and GitHub tells its owner; the digest is published either way."""
    trouble = tracker.token_trouble(digest.read_meta(directory))
    if trouble:
        print(f"::error::{trouble}", file=sys.stderr)
        return 1
    print("The tracker token is fine (or none is set).")
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--check-token":
        return check_token(argv[1] if len(argv) > 1 else "data")
    directory = argv[0] if argv else "data"
    started = datetime.now(UTC)
    now = started.isoformat(timespec="seconds")
    state = digest.read_state(directory)
    state.pop("format", None)
    meta = digest.read_meta(directory)
    meta.pop("format", None)

    part = state.setdefault("tracker", {})
    # What was read before a failure stays; the rest, next run.
    asker = tracker.Asker()
    asker.renew(started)
    pages, errors = tracker.update(part, asker)
    read_at = now if pages else meta.get("tracker", {}).get("readAt")
    print(f"Security tracker: read {pages} pages.")
    for error in errors:
        print(f"::warning::Security tracker: stopped reading {error}", file=sys.stderr)
    found = tracker.digest(part)
    meta["tracker"] = {
        "readAt": read_at,
        "suggestions": len(found["suggestions"]),
        "issues": len(found["issues"]),
        "packages": len(found["packages"]),
        "complete": tracker.complete(part),
        **({"stopped": errors} if errors else {}),
        **asker.meta(),
        "pass": {
            "suggestions": part.get("suggestionsPass"),
            "issues": part.get("issuesPass"),
        },
    }

    osv_state = state.setdefault("osv", {})
    try:
        files = osv.update(osv_state)
        if files is None:
            print("OSV: nixkeeper-versions' nixpkgs.json.gz isn't published yet.")
        else:
            meta["osv"] = {**meta.get("osv", {}), "readAt": now}
            print(f"OSV: {files} files downloaded (the rest unchanged).")
    except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
        print(f"::warning::OSV: stopped reading ({e})", file=sys.stderr)
    advisories = osv.digest(osv_state)
    if osv_state.get("packages"):
        meta["osv"] = {
            **meta.get("osv", {}),
            "nixpkgsIndexedAt": osv_state.get("nixpkgsIndexedAt"),
            "inSets": len(osv_state["packages"]),
            "ecosystems": {
                eco: sum(len(v) for v in (e.get("index") or {}).values())
                for eco, e in sorted((osv_state.get("ecosystems") or {}).items())
            },
            "packages": len(advisories["packages"]),
            "advisories": len(advisories["advisories"]),
        }
    digest.write(directory, state, {"tracker": found, "osv": advisories}, meta)
    m = meta["tracker"]
    print(
        f"  {m['suggestions']:,} suggestions, {m['issues']:,} issues, "
        f"{m['packages']:,} packages"
        + ("" if m["complete"] else " (first pass still going)")
    )
    if o := meta.get("osv"):
        print(
            f"  OSV: {o.get('packages', 0):,} packages match "
            f"{o.get('advisories', 0):,} advisories"
        )
    return 0
