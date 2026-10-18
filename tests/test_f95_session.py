"""
Offline tests for the browser-backed F95Session (scraper/auth.py).

The outward contract is frozen: agents call ensure_authenticated/get/
get_json/resolve_masked and must keep doing so unchanged while the
transport underneath became a BrowserSession.

    python -m pytest tests/test_f95_session.py -v
"""
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scraper.auth import F95Session, AuthError
from scraper.browser import BrowserResponse, CfBlocked


class FakeResp:
    """Minimal playwright APIResponse shape for building BrowserResponse."""

    def __init__(self, status, text, headers=None, url=""):
        self.status = status
        self._text = text
        self.headers = headers or {}
        self.url = url

    def text(self):
        return self._text


class StubBrowserSession:
    """BrowserSession stand-in: scripted request answers, recorded logins."""

    def __init__(self, logged_in=False, responses=None):
        self.logged_in = logged_in
        self.logins = []
        self.requests = []
        self.checks = 0
        self._responses = list(responses or [])

    def is_logged_in(self):
        self.checks += 1
        return self.logged_in

    def login(self, user, password):
        self.logins.append((user, password))
        self.logged_in = True

    def request(self, url, timeout=None):
        self.requests.append(url)
        if not self._responses:
            raise AssertionError(f"unexpected request call: {url}")
        item = self._responses.pop(0) if len(self._responses) > 1 \
            else self._responses[0]
        return item


def test_get_returns_browser_response_fields():
    resp = BrowserResponse(FakeResp(
        200, "<html data-logged-in=\"true\">detail</html>",
        headers={"Content-Type": "text/html"}, url="https://f95zone.to/threads/271262/"))
    sess = F95Session(session=StubBrowserSession(logged_in=True, responses=[resp]))
    got = sess.get("https://f95zone.to/threads/271262/")
    assert got.status_code == 200
    assert "detail" in got.text
    assert got.headers.get("Content-Type") == "text/html"


@pytest.fixture(autouse=True)
def _no_real_handoff(monkeypatch):
    """A live run on this machine leaves f95-handoff.json on disk; without
    this stub the fast tier builds from it and unit tests fetch f95zone
    for real. Hermetic tests mean no .env and no handoff, only fakes."""
    from scraper import auth as authmod
    monkeypatch.setattr(authmod, "f95_cookie_session", lambda: None)


def _stub_creds(monkeypatch):
    """Tests must not need a real .env; login credentials are stubbed."""
    from scraper import auth as authmod
    monkeypatch.setattr(authmod.config, "f95_user",
                        staticmethod(lambda: "u"))
    monkeypatch.setattr(authmod.config, "f95_password",
                        staticmethod(lambda: "p"))


def test_ensure_authenticated_skips_when_logged(monkeypatch):
    _stub_creds(monkeypatch)
    stub = StubBrowserSession(logged_in=True, responses=[FakeResp(200, "x")])
    sess = F95Session(session=stub)
    sess.ensure_authenticated()
    assert stub.logins == []


def test_ensure_authenticated_invokes_login_when_not_logged(monkeypatch):
    _stub_creds(monkeypatch)
    stub = StubBrowserSession(logged_in=False, responses=[FakeResp(200, "x")])
    sess = F95Session(session=stub)
    sess.ensure_authenticated()
    assert stub.logins == [("u", "p")]


def test_ensure_authenticated_reuses_recent_liveness(monkeypatch):
    _stub_creds(monkeypatch)
    stub = StubBrowserSession(logged_in=True, responses=[FakeResp(200, "x")])
    sess = F95Session(session=stub)
    sess.ensure_authenticated()
    sess.ensure_authenticated()
    assert stub.checks == 1   # second call inside the TTL window rechecks nothing
    # after the TTL passes, liveness gets proven again
    from scraper import auth as authmod
    real_monotonic = authmod.time.monotonic
    monkeypatch.setattr(authmod.time, "monotonic",
                        lambda: real_monotonic() + 10_000_000.0)
    sess.ensure_authenticated()
    assert stub.checks == 2
    assert stub.logins == []  # still logged in: verify, never relogin


def test_get_json_parses_or_none():
    good = StubBrowserSession(
        logged_in=True,
        responses=[BrowserResponse(
            FakeResp(200, '{"status": "ok", "msg": {}}'))])
    ok = F95Session(session=good).get_json("https://f95zone.to/feeds/latest?x=1")
    assert ok == {"status": "ok", "msg": {}}

    bad = StubBrowserSession(
        logged_in=True,
        responses=[BrowserResponse(
            FakeResp(200, "<html>challenge page</html>"))])
    nothing = F95Session(session=bad).get_json("https://f95zone.to/feeds/latest?x=1")
    assert nothing is None


def test_refresh_one_does_not_store_guest_data(monkeypatch):
    """A detail fetch that resolves to the guest view (logged_in False)
    must fail the refresh without touching the row: storing it would mark
    the record refreshed while every gated field parsed as None. The row
    stays untouched and refresh_one reports a retryable failure."""
    from scraper.agents.f95 import f95 as f95_agent

    fixture = os.path.join(os.path.dirname(__file__), "..", "scraper",
                           "fixtures", "eternum_loggedout.html")
    with open(fixture, encoding="utf-8") as fh:
        guest_html = fh.read()

    class GuestSession:
        def ensure_authenticated(self):
            pass

        def get(self, url):
            return SimpleNamespace(status_code=200, text=guest_html, url=url)

    agent = f95_agent(session=GuestSession())
    stored = []
    monkeypatch.setattr(f95_agent, "_update_record",
                        lambda *a, **k: stored.append(1))
    out = agent.refresh_one("93340", "local")
    assert stored == []
    assert out.ok is False
    assert out.code == "detail_fetch_failed"


def test_refresh_one_maps_cf_blocked_to_outcome():
    from scraper.agents.f95 import f95 as f95_agent

    class BlockedSession:
        def ensure_authenticated(self):
            pass

        def get(self, url):
            raise CfBlocked("challenge unsolved after clicks")

    agent = f95_agent(session=BlockedSession())
    out = agent.refresh_one("271262", "local")
    assert out.ok is False
    assert out.code == "cf_blocked"
    assert "271262" in out.message


def test_refresh_one_maps_cf_blocked_from_auth_check():
    from scraper.agents.f95 import f95 as f95_agent

    class AuthBlockedSession:
        """The challenge more often blocks the very first liveness probe
        (homepage load) than the detail fetch itself."""

        def ensure_authenticated(self):
            raise CfBlocked("homepage challenge unsolved after clicks")

        def get(self, url):  # pragma: no cover - must never be reached
            raise AssertionError("detail fetch reached past a blocked probe")

    agent = f95_agent(session=AuthBlockedSession())
    out = agent.refresh_one("271262", "local")
    assert out.ok is False
    assert out.code == "cf_blocked"


def test_failed_login_is_not_retried_within_cooldown(monkeypatch):
    """A wrong password must not become one login POST per queued row. The
    requests-era session had XF_REAUTH_COOLDOWN for this; the browser path
    needs it more, since each attempt drives a real form submit."""
    _stub_creds(monkeypatch)

    class BadCreds(StubBrowserSession):
        def login(self, user, password):
            self.logins.append((user, password))
            raise AuthError("bad credentials")

    stub = BadCreds(logged_in=False, responses=[FakeResp(200, "x")])
    sess = F95Session(session=stub)
    for _ in range(3):
        try:
            sess.ensure_authenticated()
        except AuthError:
            pass
    assert len(stub.logins) == 1    # the cooldown absorbed the repeats
