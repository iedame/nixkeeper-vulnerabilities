import copy
import io
import json
import os
import tempfile
import unittest
import urllib.error
from datetime import UTC, datetime
from unittest import mock
from urllib.parse import parse_qs, urlparse

from nixkeeper_vulnerabilities import cli, digest, fetch, tracker

HERE = os.path.dirname(__file__)
with open(os.path.join(HERE, "suggestions-page.json")) as f:
    SAMPLE = json.load(f)["results"]  # three real ones, trimmed


class Fake:
    """The tracker's two lists, ten a page, as its API pages them."""

    def __init__(self, suggestions, issues=()):
        self.lists = {"suggestions": list(suggestions), "issues": list(issues)}
        self.asked = []

    def __call__(self, url):
        self.asked.append(url)
        parsed = urlparse(url)
        name = parsed.path.rsplit("/", 1)[1]
        page = int(parse_qs(parsed.query).get("page", ["1"])[0])
        items = self.lists[name]
        chunk = items[(page - 1) * 10 : page * 10]
        more = page * 10 < len(items)
        return {"count": len(items), "next": "more" if more else None, "results": chunk}


def made(n, start=1):
    """n suggestions like the sample's first, with their own ids and CVEs."""
    out = []
    for i in range(start, start + n):
        s = copy.deepcopy(SAMPLE[0])
        s["id"], s["cve_id"] = i, f"CVE-2026-{i}"
        out.append(s)
    return out


class Reading(unittest.TestCase):
    def test_a_suggestion(self):
        got = tracker.suggestion(SAMPLE[0])
        self.assertEqual(got["cve"], "CVE-2026-75818")
        self.assertEqual(got["issue"], "NIXPKGS-2026-2925")
        self.assertEqual(
            (got["score"], got["severity"], got["cvss"]), (1.8, "low", "cvssV4_0")
        )
        self.assertEqual(
            got["affected"],
            [{"product": "Aspell", "versions": [["affected", "<0.60.8.3"]]}],
        )
        self.assertEqual(
            got["packages"], {"aspell": {"version": "0.60.8.2", "status": "affected"}}
        )
        many = tracker.suggestion(SAMPLE[2])  # vllm, in several package sets
        self.assertIn("python313Packages.vllm", many["packages"])

    def test_on_the_channel(self):
        def package(*branches, status=None):
            subs = {f"b{i}": b for i, b in enumerate(branches)}
            return {
                "channels": {"nixos-unstable": {"status": status, "sub_branches": subs}}
            }

        self.assertIsNone(tracker.on_channel({"channels": {"nixos-26.05": {}}}))
        same = package(
            {"version": "1", "status": "unaffected"},
            {"version": "1", "status": "affected"},
        )
        self.assertEqual(
            tracker.on_channel(same), {"version": "1", "status": "affected"}
        )
        differ = package(
            {"version": "1", "status": "unknown"},
            {"version": "2", "status": "unaffected"},
        )
        self.assertEqual(
            tracker.on_channel(differ), {"version": None, "status": "unknown"}
        )
        said = package({"version": "1", "status": "affected"}, status="unaffected")
        self.assertEqual(tracker.on_channel(said)["status"], "unaffected")

    def test_branches_since_2026_10_08(self):
        # The tracker's shape since it evaluates git branches: master's.
        with open(os.path.join(HERE, "suggestions-branches.json")) as f:
            branches = json.load(f)["results"]
        got = tracker.suggestion(branches[0])
        for found in got["packages"].values():
            self.assertEqual(found["branch"], "master")
            self.assertIn(found["status"], tracker.RANK)
            self.assertTrue(found["version"])
        both = {
            "branches": {
                "master": {"version": "2", "status": "affected"},
                "nixos-unstable": {"version": "1", "status": "unaffected"},
            }
        }
        found = tracker.on_channel(both)
        self.assertEqual(  # the channel nixkeeper follows, when listed
            {k: found[k] for k in ("version", "status", "branch")},
            {"version": "1", "status": "unaffected", "branch": "nixos-unstable"},
        )
        self.assertEqual(set(found["branches"]), {"master", "nixos-unstable"})
        # Every branch, whatever the release is called: the stable one says
        # whether a fix still has to be backported.
        miniupnpd = got["packages"]["miniupnpd"]
        self.assertEqual(set(miniupnpd["branches"]), {"master", "release-26.05"})
        self.assertEqual(miniupnpd["branches"]["release-26.05"]["status"], "affected")
        # Only on a release branch: no verdict for unstable, the branch kept.
        only = tracker.on_channel(
            {"branches": {"release-26.11": {"version": "3", "status": "affected"}}}
        )
        self.assertEqual((only["status"], only["branch"]), (None, None))
        self.assertEqual(only["branches"]["release-26.11"]["status"], "affected")
        self.assertIsNone(tracker.on_channel({"branches": {}}))

    def test_packages_without_channel_data_kept(self):
        old = copy.deepcopy(SAMPLE[0])
        old["packages"]["aspell"]["channels"] = {}  # no longer evaluated
        self.assertEqual(
            tracker.suggestion(old)["packages"],
            {"aspell": {"version": None, "status": None}},
        )

    def test_no_score(self):
        self.assertEqual(tracker.severity([]), {})
        self.assertEqual(
            tracker.severity(
                [
                    {"format": "cvssV3_1", "base_score": 7.5, "base_severity": "HIGH"},
                    {
                        "format": "cvssV4_0",
                        "base_score": 6.0,
                        "base_severity": "MEDIUM",
                    },
                ]
            )["cvss"],
            "cvssV4_0",
        )


class Passes(unittest.TestCase):
    def test_first_pass_a_run_at_a_time(self):
        fake = Fake(made(45), [{"code": "NIXPKGS-1", "status": "A", "title": "t"}])
        state = {}
        with mock.patch.object(tracker, "BACKFILL_PAGES", 2):
            tracker.update(state, fake)
            self.assertEqual(len(state["suggestions"]), 20)
            self.assertFalse(tracker.complete(state))
            tracker.update(state, fake)
            tracker.update(state, fake)  # pages 5 and the end
        self.assertEqual(len(state["suggestions"]), 45)
        self.assertTrue(tracker.complete(state))
        self.assertEqual(state["issues"]["NIXPKGS-1"]["status"], "affected")

    def test_then_the_newest_until_nothing_new(self):
        fake = Fake(made(45))
        state = {}
        tracker.update(state, fake)  # all of it, the first pass
        fake.asked.clear()
        changed = made(1, start=100) + fake.lists["suggestions"]  # a new one in front
        fake.lists["suggestions"] = changed
        tracker.update(state, fake)
        self.assertIn("100", state["suggestions"])
        heads = [u for u in fake.asked if "page=1" in u and "suggestions" in u]
        # page 1 brought something new, page 2 nothing: two head pages, then
        # the rotation's three.
        sugg = [u for u in fake.asked if "suggestions" in u]
        self.assertEqual(len(sugg), 2 + tracker.ROTATE_PAGES)
        self.assertTrue(heads)

    def test_an_older_state_is_read_again(self):
        fake = Fake(made(45))  # 5 pages
        state = {"suggestionsPass": {"n": 3, "page": 2}}  # version 1's
        with mock.patch.object(tracker, "BACKFILL_PAGES", 1):
            tracker.update(state, fake)
            self.assertEqual(state["version"], tracker.VERSION)
            # Back to a first pass, from page 1, a backfill's pages a run.
            self.assertEqual(state["suggestionsPass"], {"n": 0, "page": 2})
            self.assertIn(tracker.page_url(tracker.SUGGESTIONS, 1), fake.asked)
            tracker.update(state, fake)  # now version 2: not again
            self.assertEqual(state["suggestionsPass"]["page"], 3)

    def test_gone_after_two_passes_unseen(self):
        fake = Fake(made(5))
        state = {}
        tracker.update(state, fake)
        fake.lists["suggestions"] = made(4)  # 5 unpublished
        # One page: each run is a whole pass. One pass without it isn't
        # enough (a pass can miss an item while the list moves); two are.
        tracker.update(state, fake)
        self.assertIn("5", state["suggestions"])
        tracker.update(state, fake)
        self.assertNotIn("5", state["suggestions"])

    def test_issues_read_when_suggestions_stop(self):
        fake = Fake(made(5), [{"code": "NIXPKGS-1", "status": "A", "title": "t"}])

        def get(url):
            if "suggestions" in url:
                raise urllib.error.HTTPError(url, 429, "Too Many Requests", None, None)
            return fake(url)

        state = {}
        pages, errors = tracker.update(state, get)
        self.assertEqual(pages, 1)  # the issues' page
        self.assertIn("NIXPKGS-1", state["issues"])
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("suggestions:"))

    def test_a_refused_token_goes_on_without_it(self):
        fake = Fake(SAMPLE)

        def get_json(url, token=None):
            if token:
                raise fetch.TokenRefused("401 Unauthorized")
            return fake(url)

        asker = tracker.Asker("old")
        with (
            mock.patch.object(tracker.fetch, "get_json", get_json),
            mock.patch("sys.stderr", io.StringIO()),
        ):
            self.assertEqual(asker("https://x/api/v1/suggestions?page=1")["count"], 3)
            self.assertEqual(asker.said(), "refused")
            self.assertIsNone(asker.token)  # not tried again this run
        self.assertIsNone(tracker.Asker("").said())  # none set
        self.assertEqual(tracker.Asker("t").said(), "used")

    def renew(self, expiry, refuse=False):
        """An Asker's renew() against a tracker whose token expires then;
        what was asked, and the Asker."""
        asked = []

        def get_json(url, token=None, method="GET"):
            asked.append(method)
            if refuse:
                raise fetch.TokenRefused("401 Unauthorized")
            if method == "PATCH":
                return {"expiry": "2026-11-07T12:00:00+00:00"}
            return {"expiry": expiry}

        asker = tracker.Asker("t")
        with (
            mock.patch.object(tracker.fetch, "get_json", get_json),
            mock.patch("sys.stderr", io.StringIO()),
            mock.patch("builtins.print"),
        ):
            asker.renew(datetime(2026, 10, 8, 12, tzinfo=UTC))
        return asked, asker

    def test_renewed_a_week_before_it_expires(self):
        asked, asker = self.renew("2026-10-12T00:00:00+00:00")
        self.assertEqual(asked, ["GET", "PATCH"])
        self.assertEqual(
            asker.meta(),
            {"token": "used", "tokenExpiry": "2026-11-07", "tokenRenewal": "renewed"},
        )
        asked, asker = self.renew("2026-11-01T00:00:00+00:00")  # far off
        self.assertEqual(asked, ["GET"])
        self.assertEqual(asker.meta(), {"token": "used", "tokenExpiry": "2026-11-01"})

    def test_refused_on_renewal_is_dropped(self):
        _, asker = self.renew("x", refuse=True)
        self.assertIsNone(asker.token)
        self.assertEqual(asker.meta(), {"token": "refused"})

    def test_a_failed_renewal_keeps_the_token(self):
        _, asker = self.renew("not a date")
        self.assertEqual(asker.token, "t")
        self.assertEqual(asker.meta()["tokenRenewal"], "failed")

    def test_trouble_fails_the_run(self):
        self.assertIsNone(tracker.token_trouble({}))  # no token: fine
        self.assertIsNone(tracker.token_trouble({"tracker": {"token": "used"}}))
        self.assertIn(
            "refused", tracker.token_trouble({"tracker": {"token": "refused"}})
        )
        failed = {
            "tracker": {
                "token": "used",
                "tokenRenewal": "failed",
                "tokenExpiry": "2026-10-12",
            }
        }
        self.assertIn("2026-10-12", tracker.token_trouble(failed))
        with tempfile.TemporaryDirectory() as d:
            digest.write(d, {}, {}, {"tracker": {"token": "refused"}})
            with mock.patch("sys.stderr", io.StringIO()):
                self.assertEqual(cli.main(["--check-token", d]), 1)
            digest.write(d, {}, {}, {"tracker": {"token": "used"}})
            with mock.patch("builtins.print"):
                self.assertEqual(cli.main(["--check-token", d]), 0)

    def test_a_token_reads_more_of_the_first_pass(self):
        fake = Fake(made(45))
        fake.token = "t"  # as an Asker with a token
        state = {}
        fake.lists["issues"] = [
            {"code": f"NIXPKGS-{i}", "status": "A", "title": "t"} for i in range(45)
        ]
        with (
            mock.patch.object(tracker, "TOKEN_BACKFILL_PAGES", 5),
            mock.patch.object(tracker, "TOKEN_ISSUE_PAGES", 5),
        ):
            tracker.update(state, fake)
        self.assertEqual(len(state["suggestions"]), 45)  # all 5 pages in one run
        self.assertEqual(len(state["issues"]), 45)  # issues likewise

    def test_by_package(self):
        state = {}
        tracker.update(state, Fake(SAMPLE))
        found = tracker.digest(state)
        self.assertEqual(
            [s["suggestion"] for s in found["packages"]["aspell"]], ["48625", "48729"]
        )
        self.assertNotIn("seen", found["suggestions"]["48625"])
        # Each branch's status in the suggestion, not repeated by package.
        state = {}
        with open(os.path.join(HERE, "suggestions-branches.json")) as f:
            tracker.update(state, Fake(json.load(f)["results"]))
        found = tracker.digest(state)
        self.assertNotIn("branches", found["packages"]["miniupnpd"][0])
        self.assertIn(
            "branches", found["suggestions"]["49914"]["packages"]["miniupnpd"]
        )


def not_published(url, etag=None):
    """nixkeeper-versions' nixpkgs.json.gz not there yet: OSV waits."""
    raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)


class Run(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(fetch, "get_file", not_published)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_published_and_the_same_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(tracker.fetch, "get_json", Fake(SAMPLE)):
                cli.main([d])
            with open(os.path.join(d, digest.DIGEST), "rb") as f:
                first = f.read()
            meta = digest.read_meta(d)
            self.assertEqual(meta["tracker"]["suggestions"], 3)
            self.assertTrue(meta["tracker"]["complete"])
            # Read again, nothing changed: the digest is byte for byte the same.
            with mock.patch.object(tracker.fetch, "get_json", Fake(SAMPLE)):
                cli.main([d])
            with open(os.path.join(d, digest.DIGEST), "rb") as f:
                self.assertEqual(f.read(), first)

    def test_a_failure_keeps_what_was_read(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(tracker.fetch, "get_json", Fake(SAMPLE)):
                cli.main([d])
            read_at = digest.read_meta(d)["tracker"]["readAt"]

            def down(url):
                raise OSError("no answer")

            with mock.patch.object(tracker.fetch, "get_json", down):
                self.assertEqual(cli.main([d]), 0)
            meta = digest.read_meta(d)
            self.assertEqual(meta["tracker"]["suggestions"], 3)
            self.assertEqual(meta["tracker"]["readAt"], read_at)


if __name__ == "__main__":
    unittest.main()
