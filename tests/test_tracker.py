import copy
import json
import os
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlparse

from nixkeeper_vulnerabilities import cli, digest, tracker

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

    def test_by_package(self):
        state = {}
        tracker.update(state, Fake(SAMPLE))
        found = tracker.digest(state)
        self.assertEqual(
            [s["suggestion"] for s in found["packages"]["aspell"]], ["48625", "48729"]
        )
        self.assertNotIn("seen", found["suggestions"]["48625"])


class Run(unittest.TestCase):
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
