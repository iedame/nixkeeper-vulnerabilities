import email.message
import io
import unittest
import urllib.error
from unittest import mock

from nixkeeper_vulnerabilities import fetch

from . import REAL


def refused(wait="7"):
    headers = email.message.Message()
    if wait is not None:
        headers["Retry-After"] = wait
    return urllib.error.HTTPError("https://x", 429, "Too Many Requests", headers, None)


class Answer(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TooOften(unittest.TestCase):
    """The tracker allows 30 requests a minute: refused (429), wait as it
    says and ask again."""

    def get(self, answers):
        slept = []
        with (
            mock.patch.object(fetch.urllib.request, "urlopen", side_effect=answers),
            mock.patch.object(fetch.time, "sleep", side_effect=slept.append),
            mock.patch.object(fetch, "_last", 0.0),
            mock.patch("builtins.print"),
        ):
            return REAL["get_json"]("https://x"), slept

    def test_waits_as_asked_then_asks_again(self):
        got, slept = self.get([refused("7"), Answer(b'{"ok": 1}')])
        self.assertEqual(got, {"ok": 1})
        self.assertIn(7.0, slept)

    def test_a_minute_when_it_doesnt_say_and_never_long(self):
        self.assertEqual(fetch.retry_after(refused(None)), 60)
        self.assertEqual(fetch.retry_after(refused("3600")), fetch.MAX_WAIT)

    def test_gives_up_after_retries(self):
        with self.assertRaises(urllib.error.HTTPError):
            self.get([refused("1")] * (fetch.RETRIES + 1))

    def test_other_errors_at_once(self):
        gone = urllib.error.HTTPError("https://x", 404, "Not Found", None, None)
        with self.assertRaises(urllib.error.HTTPError):
            self.get([gone, Answer(b"{}")])


class Token(unittest.TestCase):
    def test_sent_as_bearer_at_the_faster_pace(self):
        sent, paused = [], []
        with (
            mock.patch.object(
                fetch.urllib.request,
                "urlopen",
                side_effect=lambda req, timeout: sent.append(req) or Answer(b"{}"),
            ),
            mock.patch.object(fetch, "_pace", side_effect=paused.append),
        ):
            REAL["get_json"]("https://x", "secret")
        self.assertEqual(sent[0].get_header("Authorization"), "Bearer secret")
        self.assertEqual(paused, [fetch.TOKEN_PAUSE])

    def test_refused(self):
        expired = urllib.error.HTTPError("https://x", 401, "Unauthorized", None, None)
        with (
            mock.patch.object(fetch.urllib.request, "urlopen", side_effect=[expired]),
            mock.patch.object(fetch, "_pace"),
            self.assertRaises(fetch.TokenRefused),
        ):
            REAL["get_json"]("https://x", "old")


class Pace(unittest.TestCase):
    def test_under_the_trackers_limit(self):
        self.assertLessEqual(60 / fetch.PAUSE, 25)  # it allows 30 a minute


if __name__ == "__main__":
    unittest.main()
