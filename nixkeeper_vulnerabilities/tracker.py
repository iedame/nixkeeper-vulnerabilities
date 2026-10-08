"""The NixOS security tracker (https://tracker.security.nixos.org): the NixOS
security team's triage of CVEs for nixpkgs. CVE records are matched to
nixpkgs packages automatically, then people accept or reject each match
("suggestion"); accepted ones are published, grouped into issues
(NIXPKGS-2026-2925, each with a GitHub issue on nixpkgs).

Read through its public API, without an account:

- /api/v1/suggestions?status=published: each published suggestion's CVE,
  title, severity, the products and versions the CVE record says are
  affected, and its packages with their version and status (affected,
  unaffected or unknown) on nixos-unstable. Ten a page, newest modified
  first, and a page is large (~700 KB: every package's every channel).
- /api/v1/issues: each issue's status (affected, not affected, not for us,
  won't fix, unknown) and GitHub issue. Ten a page, small.

So the suggestions are read sparingly: the first time, in BACKFILL_PAGES a
run until all are read; after that, the newest pages each run until one
brings nothing new (HEAD_PAGES at most), and a slow rotation through the
rest (ROTATE_PAGES a run: about a week a pass), which notices changes that
didn't move a suggestion to the front. Issues, small, rotate ISSUE_PAGES a
run (about a day a pass). Something not seen for two whole passes is gone
(the list moves while it's read, so one pass can miss an item)."""

from . import fetch

TRACKER_URL = "https://tracker.security.nixos.org"
SUGGESTIONS = f"{TRACKER_URL}/api/v1/suggestions?status=published"
ISSUES = f"{TRACKER_URL}/api/v1/issues"
# The channel nixkeeper follows.
CHANNEL = "nixos-unstable"

BACKFILL_PAGES = 40
HEAD_PAGES = 5
ROTATE_PAGES = 3
ISSUE_PAGES = 15

# A package's status on a channel, when its sub-branches differ: the worst.
RANK = {"unaffected": 0, "unknown": 1, "affected": 2}
# Issue statuses, as the API gives them.
ISSUE_STATUS = {
    "U": "unknown",
    "A": "affected",
    "NA": "notAffected",
    "O": "notForUs",
    "W": "wontFix",
}
# Of a CVE's scores, the newest CVSS version's.
CVSS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")


def on_channel(package, channel=CHANNEL):
    """{"version", "status"} of a suggestion's package on channel, or None
    when the tracker doesn't have it there."""
    found = (package.get("channels") or {}).get(channel)
    if not found:
        return None
    branches = [b for b in (found.get("sub_branches") or {}).values() if b]
    statuses = [b["status"] for b in branches if b.get("status") in RANK]
    status = found.get("status") or max(statuses, key=RANK.get, default="unknown")
    versions = sorted({b["version"] for b in branches if b.get("version")})
    return {"version": versions[0] if len(versions) == 1 else None, "status": status}


def severity(metrics):
    """{"score", "severity", "cvss"} of the newest CVSS version among a CVE's
    metrics, or {} when it has none."""
    scored = [m for m in metrics or [] if m.get("format") in CVSS]
    if not scored:
        return {}
    best = min(scored, key=lambda m: CVSS.index(m["format"]))
    return {
        "score": best.get("base_score"),
        "severity": (best.get("base_severity") or "").lower() or None,
        "cvss": best["format"],
    }


def suggestion(s):
    """What the digest keeps of a published suggestion: its CVE, issue,
    title, severity, the affected products' version constraints as the CVE
    record gives them (so a reader can check a newer nixpkgs version
    itself), and its packages on CHANNEL."""
    packages = {}
    for attr, package in sorted((s.get("packages") or {}).items()):
        if found := on_channel(package):
            packages[attr] = found
    return {
        "cve": s.get("cve_id"),
        "issue": s.get("issue_code"),
        "title": s.get("title"),
        **severity(s.get("metrics")),
        "affected": [
            {"product": p.get("name"), "versions": p.get("version_constraints") or []}
            for p in s.get("affected_products") or []
        ],
        "packages": packages,
    }


def issue(i):
    """What the digest keeps of an issue."""
    return {
        "title": i.get("title"),
        "status": ISSUE_STATUS.get(i.get("status"), "unknown"),
        "github": i.get("github_issue_url"),
    }


def page_url(url, page):
    return f"{url}{'&' if '?' in url else '?'}page={page}"


def walk(get, url, cycle, pages, take):
    """Read up to pages pages of url's list from cycle["page"] on, giving
    each item to take; at the list's end, start over and count a pass
    (cycle["n"]). Returns how many pages were read."""
    read = 0
    while read < pages:
        answer = get(page_url(url, cycle["page"]))
        read += 1
        for item in answer.get("results") or []:
            take(item)
        if answer.get("next"):
            cycle["page"] += 1
        else:
            cycle["page"] = 1
            cycle["n"] += 1
            break
    return read


def forget_unseen(found, cycle):
    """Drop what wasn't seen during the last two passes."""
    for key in [k for k, v in found.items() if v["seen"] < cycle["n"] - 2]:
        del found[key]


def update(state, get=None):
    """Bring the tracker's part of state up to date (as far as this run
    goes): {"suggestions": {id: ...}, "issues": {code: ...}, and where each
    list's passes are}, asking with get (fetch.get_json, looked up when
    called). Returns how many pages were read, or raises (what was read so
    far stays in state)."""
    get = get or fetch.get_json
    found = state.setdefault("suggestions", {})
    issues = state.setdefault("issues", {})
    s_cycle = state.setdefault("suggestionsPass", {"n": 0, "page": 1})
    i_cycle = state.setdefault("issuesPass", {"n": 0, "page": 1})
    read = 0
    changed = False

    def take_suggestion(s):
        nonlocal changed
        key = str(s["id"])
        kept = suggestion(s)
        if {k: v for k, v in found.get(key, {}).items() if k != "seen"} != kept:
            changed = True
        found[key] = {**kept, "seen": s_cycle["n"]}

    if s_cycle["n"] == 0:  # the first pass: read what it takes, a run at a time
        read += walk(get, SUGGESTIONS, s_cycle, BACKFILL_PAGES, take_suggestion)
    else:
        # The newest first, until a page brings nothing new.
        head = {"n": s_cycle["n"], "page": 1}
        for _ in range(HEAD_PAGES):
            changed = False
            read += walk(get, SUGGESTIONS, head, 1, take_suggestion)
            if not changed or head["page"] == 1:  # nothing new, or the end
                break
        read += walk(get, SUGGESTIONS, s_cycle, ROTATE_PAGES, take_suggestion)
        forget_unseen(found, s_cycle)

    def take_issue(i):
        issues[i["code"]] = {**issue(i), "seen": i_cycle["n"]}

    read += walk(get, ISSUES, i_cycle, ISSUE_PAGES, take_issue)
    forget_unseen(issues, i_cycle)
    return read


def digest(state):
    """The tracker's part of the published digest: the suggestions and
    issues without the reading's bookkeeping, and by package the
    suggestions that name it."""
    suggestions = {
        k: {f: v for f, v in s.items() if f != "seen"}
        for k, s in sorted(
            state.get("suggestions", {}).items(), key=lambda kv: int(kv[0])
        )
    }
    packages = {}
    for key, s in suggestions.items():
        for attr, on in s["packages"].items():
            packages.setdefault(attr, []).append({"suggestion": key, **on})
    return {
        "suggestions": suggestions,
        "issues": {
            code: {f: v for f, v in i.items() if f != "seen"}
            for code, i in sorted(state.get("issues", {}).items())
        },
        "packages": dict(sorted(packages.items())),
    }


def complete(state):
    """Whether both lists have been read through at least once."""
    return all(
        state.get(name, {}).get("n", 0) > 0
        for name in ("suggestionsPass", "issuesPass")
    )
