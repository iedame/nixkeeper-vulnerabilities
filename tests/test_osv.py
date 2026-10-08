import contextlib
import gzip
import io
import json
import unittest
import urllib.error
import zipfile

from nixkeeper_vulnerabilities import osv

NIXPKGS = {
    "indexedAt": "2026-10-08T04:07:00+00:00",
    "packages": {
        "python313Packages.requests": {"pname": "requests", "version": "2.31.0"},
        "python313Packages.requests-oauthlib": {
            "pname": "Requests_OAuthlib",
            "version": "2.0.0",
        },
        "haskellPackages.aeson": {"pname": "aeson", "version": "2.2.3.0"},
        "haskellPackages.old": {"pname": "aeson", "version": "1.0.0.0"},
        "python313Packages.requests.dist": {"pname": "requests", "version": "2.31.0"},
        "ripgrep": {"pname": "ripgrep", "version": "15.1.0"},
    },
}
PYPI = [
    {
        "id": "PYSEC-2023-74",
        "aliases": ["CVE-2023-32681", "GHSA-j8r2-6x86-q33q"],
        "summary": "Leaking Proxy-Authorization headers",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H"}],
        "database_specific": {"severity": "MODERATE"},
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "versions": ["2.30.0", "2.31.0"],
            }
        ],
    },
    {
        "id": "GHSA-oauth",
        "details": "A first line.\nMore.",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests-oauthlib"},
                "versions": ["2.0.0"],
            }
        ],
    },
    {
        "id": "PYSEC-gone",
        "withdrawn": "2026-01-01T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "versions": ["2.31.0"],
            }
        ],
    },
    {
        "id": "PYSEC-not-ours",
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "django"}, "versions": ["1.0"]}
        ],
    },
]
HACKAGE = [
    {
        "id": "HSEC-2023-0001",
        "aliases": ["CVE-2022-3433"],
        "summary": "Hash flooding vulnerability in aeson",
        "affected": [
            {
                "package": {"ecosystem": "Hackage", "name": "aeson"},
                "versions": ["1.0.0.0", "2.0.0.0"],
            }
        ],
    }
]
CRAN = [
    {
        "id": "RSEC-2023-0",
        "upstream": ["CVE-2017-12108"],
        "summary": "readxl",
        "affected": [
            {"package": {"ecosystem": "CRAN", "name": "readxl"}, "versions": []}
        ],
    }
]


def archive(records):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for r in records:
            z.writestr(f"{r['id']}.json", json.dumps(r))
    return out.getvalue()


class Server:
    """nixkeeper-versions' file and OSV's archives, with ETags."""

    def __init__(self):
        self.files = {
            osv.NIXPKGS_URL: gzip.compress(json.dumps(NIXPKGS).encode()),
            f"{osv.OSV_URL}/PyPI/all.zip": archive(PYPI),
            f"{osv.OSV_URL}/Hackage/all.zip": archive(HACKAGE),
            f"{osv.OSV_URL}/CRAN/all.zip": archive(CRAN),
            **{f"{osv.OSV_URL}/{e}/all.zip": archive([]) for e in ("RubyGems", "opam")},
        }
        self.etags = {url: "v1" for url in self.files}
        self.sent = []

    def __call__(self, url, etag=None):
        if url not in self.files:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        if etag == self.etags[url]:
            return None, etag
        self.sent.append(url)
        return self.files[url], self.etags[url]


class Osv(unittest.TestCase):
    def test_names_as_each_ecosystem_compares_them(self):
        self.assertEqual(osv.name_key("PyPI", "Requests_OAuthlib"), "requests-oauthlib")
        self.assertEqual(osv.name_key("Hackage", "Aeson"), "aeson")
        self.assertEqual(osv.ecosystem_of("python314Packages.numpy"), "PyPI")
        self.assertEqual(osv.ecosystem_of("rubyPackages_3_4.rails"), "RubyGems")
        self.assertIsNone(osv.ecosystem_of("python313Packages.requests.dist"))
        self.assertIsNone(osv.ecosystem_of("ripgrep"))

    def test_matched_by_exact_version(self):
        state = {}
        osv.update(state, Server())
        found = osv.digest(state)
        self.assertEqual(
            found["packages"],
            {
                "haskellPackages.old": ["HSEC-2023-0001"],  # 1.0.0.0 affected
                "python313Packages.requests": ["PYSEC-2023-74"],  # not the withdrawn
                "python313Packages.requests-oauthlib": ["GHSA-oauth"],
            },
        )
        a = found["advisories"]["PYSEC-2023-74"]
        self.assertEqual(a["cves"], ["CVE-2023-32681"])
        self.assertEqual((a["severity"], a["cvss"]), ("moderate", "CVSS:3.1/AV:N/AC:H"))
        self.assertEqual((a["ecosystem"], a["package"]), ("PyPI", "requests"))
        self.assertEqual(found["advisories"]["GHSA-oauth"]["summary"], "A first line.")
        # Only nixpkgs' names are kept of an archive.
        self.assertNotIn("django", state["ecosystems"]["PyPI"]["index"])

    def test_unchanged_files_arent_downloaded_again(self):
        server, state = Server(), {}
        osv.update(state, server)
        server.sent.clear()
        self.assertEqual(osv.update(state, server), 0)
        self.assertEqual(server.sent, [])
        # PyPI's archive changed: only it.
        server.etags[f"{osv.OSV_URL}/PyPI/all.zip"] = "v2"
        osv.update(state, server)
        self.assertEqual(server.sent, [f"{osv.OSV_URL}/PyPI/all.zip"])
        # nixpkgs changed: every archive again, for packages new to it.
        server.sent.clear()
        server.etags[osv.NIXPKGS_URL] = "v2"
        osv.update(state, server)
        self.assertEqual(len(server.sent), 1 + len(osv.ECOSYSTEMS))

    def test_an_ecosystem_failing_keeps_its_last(self):
        server, state = Server(), {}
        osv.update(state, server)
        server.etags[osv.NIXPKGS_URL] = "v2"  # every archive asked again
        del server.files[f"{osv.OSV_URL}/Hackage/all.zip"]
        with contextlib.redirect_stderr(io.StringIO()):
            osv.update(state, server)
        self.assertIn("haskellPackages.old", osv.digest(state)["packages"])

    def test_waits_for_nixpkgs_file(self):
        server = Server()
        del server.files[osv.NIXPKGS_URL]
        state = {}
        self.assertIsNone(osv.update(state, server))
        self.assertEqual(osv.digest(state), {"advisories": {}, "packages": {}})

    def test_cves_from_upstream_too(self):
        a = osv.advisory(CRAN[0])
        self.assertEqual(a["cves"], ["CVE-2017-12108"])


if __name__ == "__main__":
    unittest.main()
