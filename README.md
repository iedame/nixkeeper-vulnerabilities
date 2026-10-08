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
  a pass). One request every 2.5 seconds, 24 a minute: the tracker allows
  30 a minute without an account, and answers more with 429 (then the
  digest waits as long as it says and asks again). If one list can't be
  read further, the other still is. User-Agent linking here.

- **[OSV](https://osv.dev)**, for language packages: the advisories of
  PyPI, Hackage, CRAN, RubyGems and opam (OSV's per-ecosystem archives),
  matched to nixpkgs' package sets (python3*Packages, haskellPackages,
  rPackages, rubyPackages*, ocamlPackages) by name, as each ecosystem
  compares names, and by exact version: a package matches an advisory that
  lists its version as affected. nixpkgs' names and versions come from
  [nixkeeper-versions](https://github.com/iedame/nixkeeper-versions)'
  `nixpkgs.json.gz` (from the channel's package index). Each archive is
  downloaded only when it changed (its ETag), or when nixpkgs' file did;
  of it, only the advisories for names nixpkgs has are kept. An advisory
  with no fixed version lists every release as affected, so it matches
  newer ones too, even when its text says it was fixed (older PyPI ones):
  weaker than the tracker's verdict. On 2026-10-08: 79,063 packages in
  those sets, 262 matching 406 advisories. Not covered: OSV's ecosystems
  nixpkgs doesn't package as a set of registry packages: Hex (nixpkgs'
  `beam*Packages` hold the Elixir/Erlang toolchain, not Hex's libraries),
  npm (`nodePackages` is being removed), crates.io and Go (libraries are
  vendored per package); `osv.py`'s `SETS` says how to add one should
  that change.

Planned: OSV by source repository and tag or commit (its `GIT` ecosystem,
for packages outside the language sets, from nixkeeper-versions' `src`);
NVD for packages whose nixpkgs metadata declares a CPE. nixpkgs' own
`meta.knownVulnerabilities` stays in nixkeeper, which already downloads
it.

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
     "packages": {"aspell": [{"suggestion": "48625", "version": "0.60.8.2", "status": "affected"}]}},
   "osv": {
     "advisories": {"PYSEC-2023-74": {"aliases": ["CVE-2023-32681", "GHSA-j8r2-6x86-q33q"],
                                      "cves": ["CVE-2023-32681"], "summary": "...",
                                      "severity": "moderate", "cvss": "CVSS:3.1/...",
                                      "ecosystem": "PyPI", "package": "requests"}},
     "packages": {"python313Packages.requests": ["PYSEC-2023-74"]}}}
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

  OSV's advisories that some nixpkgs package's version matches: their
  aliases and CVEs (CRAN's from `upstream` too), a summary, the severity
  and CVSS vector when the advisory gives them, and the ecosystem and
  package name; `packages` lists, by attribute, the advisories it matches.
- [`data/meta.json`](https://raw.githubusercontent.com/iedame/nixkeeper-vulnerabilities/data/data/meta.json):
  when each source was last read (`readAt`), how many suggestions, issues
  and packages the digest has, whether every list has been read through
  at least once (`complete`; until then the digest has only part of it),
  where the reading is (`pass`), what stopped the last run's reading, if
  anything did (`stopped`), and with a token, whether it was `used` or
  `refused`, when it expires and whether it was renewed (`token`,
  `tokenExpiry`, `tokenRenewal`; see "A tracker token"); for OSV, the nixpkgs index it
  matched (`nixpkgsIndexedAt`), how many nixpkgs packages are in the sets
  it covers (`inSets`), each ecosystem's advisories for nixpkgs' names
  (`ecosystems`), and how many packages and advisories match.
- `data/state.json.gz`: what the reading keeps between runs.

The data branch is main plus one commit holding `data/`
(`scripts/data-branch.sh`), replaced each run, so no history piles up. A
source that can't be read keeps what the digest had; nixkeeper falls back to
Repology's flag for anything the digest doesn't cover.

## A tracker token

Without an account, the NixOS security tracker answers 30 requests a
minute, and the digest reads at 24. With an account's API token it allows
120, and the digest reads at about 100 (and more of the first pass a run:
150 pages instead of 40). Optional, for a first pass or a fork that wants
it sooner:

1. Sign in to the [tracker](https://tracker.security.nixos.org) (with
   GitHub) and create a token at
   [/user/tokens](https://tracker.security.nixos.org/user/tokens). The
   tracker shows it once, and allows one per account: creating another
   replaces it.
2. Add it to the repository as the Actions secret
   `NIXKEEPER_TRACKER_TOKEN` (Settings → Secrets and variables →
   Actions). The workflow passes it to the digest, which sends it to the
   tracker only.

A token lasts 30 days, and the digest keeps it alive: each run asks when
it expires, and within a week of that extends it by 30 days from now (the
tracker allows that with the token itself). So it only stops working if
it's revoked or replaced (creating another at `/user/tokens` replaces
it), or the digest doesn't run for a month. Then the run goes on without
it at 24 a minute, the digest is published, and the workflow's last step
("Check the tracker token") fails the run, so GitHub tells you; it fails
too when the token couldn't be extended, saying when it expires.
`meta.json`'s `tracker` says `token` (`used` or `refused`), `tokenExpiry`,
and `tokenRenewal` when it was extended (`renewed`) or couldn't be
(`failed`). Run locally with it: `NIXKEEPER_TRACKER_TOKEN=... python3 -m
nixkeeper_vulnerabilities data`.

## Running it

```sh
nix run github:iedame/nixkeeper-vulnerabilities -- data
```

or, in a checkout, `python3 -m nixkeeper_vulnerabilities data` (Python 3.11
or later, standard library only). `nix flake check` runs the tests (which
never ask the real sources), formatting and lint; `nix fmt` formats.

## License

MIT, for the code. The data comes from the sources named above.
