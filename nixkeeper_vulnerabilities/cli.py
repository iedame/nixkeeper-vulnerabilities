"""`python3 -m nixkeeper_vulnerabilities [DATA_DIR]`: bring the digest in
DATA_DIR (default data/) up to date, as far as one run reads (tracker.py
says how much): a source that can't be read keeps what the digest had."""

import sys
import urllib.error
from datetime import UTC, datetime

from . import digest, tracker


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    directory = argv[0] if argv else "data"
    now = datetime.now(UTC).isoformat(timespec="seconds")
    state = digest.read_state(directory)
    state.pop("format", None)
    meta = digest.read_meta(directory)
    meta.pop("format", None)

    part = state.setdefault("tracker", {})
    try:
        pages = tracker.update(part)
        read_at = now
        print(f"Security tracker: read {pages} pages.")
    except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
        # What was read before the failure stays; the rest, next run.
        read_at = meta.get("tracker", {}).get("readAt")
        print(f"::warning::Security tracker: stopped reading ({e})", file=sys.stderr)
    found = tracker.digest(part)
    meta["tracker"] = {
        "readAt": read_at,
        "suggestions": len(found["suggestions"]),
        "issues": len(found["issues"]),
        "packages": len(found["packages"]),
        "complete": tracker.complete(part),
        "pass": {
            "suggestions": part.get("suggestionsPass"),
            "issues": part.get("issuesPass"),
        },
    }
    digest.write(directory, state, {"tracker": found}, meta)
    m = meta["tracker"]
    print(
        f"  {m['suggestions']:,} suggestions, {m['issues']:,} issues, "
        f"{m['packages']:,} packages"
        + ("" if m["complete"] else " (first pass still going)")
    )
    return 0
