# nixkeeper-vulnerabilities

A digest of what vulnerability sources say about nixpkgs packages, for
[nixkeeper](https://github.com/iedame/nixkeeper): one file nixkeeper
downloads instead of asking each source about each package, kept up to
date hourly by a workflow, read slowly and politely.

Today nixkeeper's "vulnerable" comes from Repology, which matches CVEs by
version only and can't know which ones nixpkgs has patched. This digest
gathers the sources that know more, starting with the people who triage
CVEs for nixpkgs.

## Sources

- **The [NixOS security tracker](https://tracker.security.nixos.org)**
  ([source](https://github.com/NixOS/nix-security-tracker)): the NixOS
  security team's triage. CVE records (from the official CVE List) are
  matched to nixpkgs packages automatically, then people accept or reject
  each match; accepted ones are published as issues (`NIXPKGS-2026-2925`,
  each with a GitHub issue on nixpkgs). Read through its public API, no
  account: published suggestions (CVE, severity, affected version ranges,
  packages and their status on nixos-unstable) and issues (status, GitHub
  issue).

  A page of suggestions is large (~700 KB for ten), so they're read
  sparingly: the first time, 40 pages a run until all are read (about
  half a day); after that, the newest pages each run until one brings
  nothing new, and a slow rotation through the rest (3 pages a run, about
  a week a pass). Issues are small and rotate 15 pages a run (about a day
  a pass). One request every 2 seconds, with a User-Agent linking here.

Planned, one at a time: [OSV](https://osv.dev) for language packages
(PyPI, crates.io, npm, Go, Hackage...) and by source repository and tag
(its `GIT` ecosystem); NVD for packages whose nixpkgs metadata declares a
CPE. nixpkgs' own `meta.knownVulnerabilities` stays in nixkeeper, which
already downloads it.

## The digest

On the `data` branch:

- [`data/vulnerabilities.json.gz`](https://raw.githubusercontent.com/iedame/nixkeeper-vulnerabilities/data/data/vulnerabilities.json.gz):

  ```json
  {"format": 1,
   "tracker": {
     "suggestions": {"48625": {"cve": "CVE-2026-75818", "issue": "NIXPKGS-2026-2925",
                               "title": "Heap Buffer Overflow in GNU Aspell's prezip utility",
                               "score": 1.8, "severity": "low", "cvss": "cvssV4_0",
                               "affected": [{"product": "Aspell", "versions": [["affected", "<0.60.8.3"]]}],
                               "packages": {"aspell": {"version": "0.60.8.2", "status": "affected"}}}},
     "issues": {"NIXPKGS-2026-2925": {"title": "...", "status": "affected",
                                      "github": "https://github.com/NixOS/nixpkgs/issues/571389"}},
     "packages": {"aspell": [{"suggestion": "48625", "version": "0.60.8.2", "status": "affected"}]}}}
  ```

  The tracker's published suggestions by id: the CVE, its issue (in
  `issues` once read: their pass is slower), the severity (the newest CVSS
  version's score, when the CVE has one), the version ranges the CVE
  record gives (so a newer nixpkgs version can be checked against them
  without asking again), and each package's version and status
  (`affected`, `unaffected`, `unknown`) on nixos-unstable, as the tracker
  last evaluated it (`version` null when the channel's branches differ).
  `packages` lists the suggestions naming each package. Issue status:
  `affected`, `notAffected`, `notForUs`, `wontFix` or `unknown`.
- [`data/meta.json`](https://raw.githubusercontent.com/iedame/nixkeeper-vulnerabilities/data/data/meta.json):
  when each source was last read (`readAt`), how many suggestions, issues
  and packages the digest has, whether every list has been read through
  at least once (`complete`; until then the digest has only part of it),
  and where the reading is (`pass`).
- `data/state.json.gz`: what the reading keeps between runs.

The data branch is main plus one commit holding `data/`
(`scripts/data-branch.sh`), replaced each run, so no history piles up. A
source that can't be read keeps what the digest had; nixkeeper falls back to
Repology's flag for anything the digest doesn't cover.

## Running it

```sh
nix run github:iedame/nixkeeper-vulnerabilities -- data
```

or, in a checkout, `python3 -m nixkeeper_vulnerabilities data` (Python 3.11
or later, standard library only). `nix flake check` runs the tests (which
never ask the real sources), formatting and lint; `nix fmt` formats.

## License

MIT, for the code. The data comes from the sources named above.
