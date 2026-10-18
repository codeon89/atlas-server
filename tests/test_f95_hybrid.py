import json
import pytest
import scraper.auth as auth
import scraper.browser as browser
from requests.cookies import RequestsCookieJar
from types import SimpleNamespace
from scraper.auth import F95CookieSession, F95Session
from scraper.browser import save_handoff, load_handoff, challenged_response

def test_save_and_load_roundtrip(tmp_path):
    handoff = {"user_agent": "UA-1", "cookies": [{"name": "cf_clearance", "value": "v"}],
               "saved_at": 123.0}
    path = str(tmp_path / "h.json")
    save_handoff(path, handoff)
    assert load_handoff(path) == handoff

def test_missing_file_loads_as_none(tmp_path):
    assert load_handoff(str(tmp_path / "nope.json")) is None

def test_bad_handoff_file_behaves_as_missing(tmp_path):
    path = tmp_path / "h.json"; path.write_text("{not json")
    assert load_handoff(str(path)) is None

def test_handoff_without_ua_is_unusable():
    handoff = {"user_agent": "", "cookies": [{"name": "cf_clearance", "value": "v"}]}
    assert not browser.handoff_is_usable(handoff)

def test_handoff_without_clearance_is_unusable():
    handoff = {"user_agent": "UA-1", "cookies": [{"name": "xf_user", "value": "v"}]}
    assert not browser.handoff_is_usable(handoff)

def test_malformed_handoff_shapes_load_as_none(tmp_path):
    for content in ("null", '"just a string"', '{"cookies": null}'):
        path = tmp_path / "h.json"; path.write_text(content)
        assert load_handoff(str(path)) is None, content


class _FakeSession:
    """Stands in for requests.Session: same headers dict, a real cookie
    jar, and a get() that records each call instead of touching the
    network."""
    def __init__(self):
        self.headers = {}
        self.cookies = RequestsCookieJar()
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return ("response", url, kwargs)


def test_fast_session_applies_ua_and_cookies():
    handoff = {"user_agent": "UA-1", "cookies": [
        {"name": "cf_clearance", "value": "cfv", "domain": ".f95zone.to", "path": "/"},
        {"name": "xf_user", "value": "u", "domain": "f95zone.to", "path": "/"},
        {"name": "unrelated", "value": "x", "domain": "example.com", "path": "/"}]}
    fs = F95CookieSession(handoff, session_cls=_FakeSession)
    assert fs._session.headers["User-Agent"] == "UA-1"
    names = {c.name for c in fs._session.cookies}
    assert names == {"cf_clearance", "xf_user"}


def test_fast_session_sends_xhr_headers():
    fs = F95CookieSession({"user_agent": "UA-1", "cookies": []},
                        session_cls=_FakeSession)
    session = fs._session
    assert session.headers["X-Requested-With"] == "XMLHttpRequest"
    assert session.headers["Referer"] == "https://f95zone.to/latest-updates/"
    resp = fs.get("https://f95zone.to/latest-updates/")
    assert session.calls[0] == ("https://f95zone.to/latest-updates/",
                                {"timeout": 30, "allow_redirects": True})
    assert resp == ("response", "https://f95zone.to/latest-updates/",
                    {"timeout": 30, "allow_redirects": True})


def test_f95_cookie_session_gates_on_usability(monkeypatch):
    usable = {"user_agent": "UA-1",
              "cookies": [{"name": "cf_clearance", "value": "v"}]}
    monkeypatch.setattr(browser, "load_handoff", lambda: usable)
    fast = auth.f95_cookie_session()
    assert isinstance(fast, auth.F95CookieSession)
    monkeypatch.setattr(browser, "load_handoff", lambda: None)
    assert auth.f95_cookie_session() is None


# ----- the ladder: challenge detection, plain retry, escalation, pin -----

class FakeFast:                     # canned fast-tier responses
    def __init__(self, responses): self.responses = list(responses); self.calls = 0
    def get(self, url, **kw): self.calls += 1; return self.responses.pop(0)

class BareBrowser:
    """Escalation partner mirroring the REAL BrowserSession surface:
    is_logged_in/login/request/export_handoff and no auth wrapper."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.logins = 0

    def is_logged_in(self):
        return True

    def login(self, *a):
        self.logins += 1

    def request(self, url, timeout=30000):
        return self.responses.pop(0)

    def export_handoff(self):
        return {"user_agent": "UA-2", "cookies": [
            {"name": "cf_clearance", "value": "v", "domain": "f95zone.to",
             "path": "/"}]}

CHALLENGED = SimpleNamespace(status_code=503, text="<title>Just a moment</title>", url="")
CLEAN = SimpleNamespace(status_code=200, text='{"status":"ok"}', url="")

def fast_session_pair(first, second):     # builds an F95Session already carrying a fake fast tier
    sess = F95Session(session=BareBrowser([]))
    sess._fast = FakeFast([first, second]); return sess

def test_single_plain_retry_recovers_without_browser():
    sess = fast_session_pair(CHALLENGED, CLEAN)
    r = sess._fetch("https://f95zone.to/")
    assert r.status_code == 200 and sess._escalations == 0

def test_challenge_triggers_single_escalation_and_recovery(monkeypatch):
    monkeypatch.setattr("scraper.auth.save_handoff", lambda *a, **k: None)
    monkeypatch.setattr("scraper.auth.f95_cookie_session", lambda: FakeFast([CLEAN]))
    sess = F95Session(session=BareBrowser([]))
    sess._fast = FakeFast([CHALLENGED, CHALLENGED])       # first + immediate retry both fail
    r = sess._fetch("https://f95zone.to/")               # after solve, rebuilt fast serves CLEAN
    assert r.status_code == 200
    assert sess._fast.calls == 1    # the rebuilt tier served the recovery
    assert sess._escalations == 0   # clean rebuilt retry reset the budget

def test_two_escalations_pin_browser_for_the_process():
    sess = F95Session(session=BareBrowser([CLEAN, CLEAN]))
    sess._fast = FakeFast([CHALLENGED, CHALLENGED, CHALLENGED, CHALLENGED])
    sess._escalations = 2                                # already at cap
    assert sess._fetch("x").status_code == 200
    assert sess._pinned and sess._fast is None

def test_marker_words_on_200_are_not_challenges():
    sess = fast_session_pair(SimpleNamespace(status_code=200,
        text='[turnstile] this game is fun and just a moment of joy', url=""), None)
    assert sess._fetch("x").status_code == 200 and sess._escalations == 0

def test_cf_mitigated_200_escapes_as_a_challenge(monkeypatch):
    # Cloudflare can sign the interstitial HTTP 200 (observed live on the
    # client); the edge's cf-mitigated header is what names the wall.
    wall = SimpleNamespace(status_code=200,
        text="<title>Just a moment</title>", url="",
        headers={"cf-mitigated": "challenge"})
    monkeypatch.setattr("scraper.auth.save_handoff", lambda *a, **k: None)
    monkeypatch.setattr("scraper.auth.f95_cookie_session", lambda: FakeFast([CLEAN]))
    sess = F95Session(session=BareBrowser([]))
    sess._fast = FakeFast([wall, wall])
    r = sess._fetch("x")                 # retries once, then browser solve
    assert '"status":"ok"' in r.text     # the caller gets content, not the interstitial
    assert sess._fast.calls == 1    # the rebuilt tier served the recovery
    assert sess._escalations == 0   # clean rebuilt retry reset the budget

def test_headerless_old_style_still_gated_by_status():
    # No headers attribute (the common stub shape): the 403/503 gate and
    # no-header 200 rule must be untouched.
    bare = SimpleNamespace(status_code=200, text="<title>Just a moment</title>", url="")
    assert not challenged_response(bare)
    bare.status_code = 503
    assert challenged_response(bare)

def test_clean_rebuilt_retry_resets_the_budget(monkeypatch):
    # Healthy harvests self-heal in the rebuilt retry, so the budget
    # starts over; only a storm that survives the rebuilt tier ever
    # reaches the pin.
    monkeypatch.setattr("scraper.auth.save_handoff", lambda *a, **k: None)
    monkeypatch.setattr("scraper.auth.f95_cookie_session", lambda: FakeFast([CLEAN]))
    sess = F95Session(session=BareBrowser([]))
    for _ in range(3):
        sess._fast = FakeFast([CHALLENGED, CHALLENGED])
        assert sess._fetch("x").status_code == 200
        assert sess._escalations == 0
    assert not sess._pinned

def test_still_challenged_rebuilt_retry_does_not_reset(monkeypatch):
    monkeypatch.setattr("scraper.auth.save_handoff", lambda *a, **k: None)
    monkeypatch.setattr("scraper.auth.f95_cookie_session", lambda: FakeFast([CHALLENGED]))
    sess = F95Session(session=BareBrowser([CLEAN]))
    sess._fast = FakeFast([CHALLENGED, CHALLENGED])
    sess._escalations = 1                       # one strike already on the books
    assert sess._fetch("x").status_code == 200  # the browser serves this response
    assert sess._escalations == 2 and not sess._pinned

def test_nameless_f95_cookie_is_dropped_not_fatal():
    handoff = {"user_agent": "UA-1", "cookies": [
        {"domain": ".f95zone.to", "path": "/"},   # nameless: must be dropped
        {"name": "cf_clearance", "value": "v", "domain": ".f95zone.to", "path": "/"}]}
    fs = F95CookieSession(handoff, session_cls=_FakeSession)
    names = {c.name for c in fs._session.cookies}
    assert names == {"cf_clearance"}


class BareBrowser:
    """Escalation partner mirroring the REAL BrowserSession surface:
    is_logged_in/login/request/export_handoff and no auth wrapper."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.logins = 0

    def is_logged_in(self):
        return True

    def login(self, *a):
        self.logins += 1

    def request(self, url, timeout=30000):
        return self.responses.pop(0)

    def export_handoff(self):
        return {"user_agent": "UA-2", "cookies": [
            {"name": "cf_clearance", "value": "v", "domain": "f95zone.to",
             "path": "/"}]}


def test_escalation_drives_browser_partner_through_builtins_only(monkeypatch):
    # The real delegate has no ensure_authenticated; escalation must work
    # through is_logged_in/login alone.
    monkeypatch.setattr("scraper.auth.save_handoff", lambda *a, **k: None)
    monkeypatch.setattr("scraper.auth.f95_cookie_session", lambda: FakeFast([CLEAN]))
    sess = F95Session(session=BareBrowser([CLEAN]))
    sess._fast = FakeFast([CHALLENGED, CHALLENGED])
    r = sess._fetch("https://f95zone.to/")
    assert r.status_code == 200 and sess._fast.calls == 1
    assert sess._escalations == 0   # clean rebuilt retry reset the budget
    assert sess.session.logins == 0  # profile already logged in: no login.POST


# ----- liveness: ensure_authenticated proves itself on the fast tier -----

def test_fast_liveness_passes_through_probe(monkeypatch):
    class UntouchedBrowser(BareBrowser):
        def is_logged_in(self):
            raise AssertionError("liveness must not touch the browser partner")

    sess = F95Session(session=UntouchedBrowser([]))
    sess._fast = FakeFast([SimpleNamespace(status_code=200, text='data-logged-in="true"', url="")])
    sess.ensure_authenticated()          # must not touch the browser partner
    assert sess._authenticated

def test_fast_expired_login_falls_back_to_browser_login(monkeypatch):
    monkeypatch.setattr("scraper.auth.save_handoff", lambda *a, **k: None)
    monkeypatch.setattr("scraper.auth.f95_cookie_session",
                        lambda: FakeFast([SimpleNamespace(status_code=200, text="guest page", url="")]))
    monkeypatch.setattr(auth.config, "f95_user", staticmethod(lambda: "u"))
    monkeypatch.setattr(auth.config, "f95_password", staticmethod(lambda: "p"))
    fb = BareBrowser([SimpleNamespace(status_code=200, text="ok", url="")])
    sess = F95Session(session=fb)
    sess.ensure_authenticated()
    assert sess.session.logins == 1 and sess._fast is not None

def test_fast_fallback_login_honors_cooldown(monkeypatch):
    monkeypatch.setattr("scraper.auth.save_handoff", lambda *a, **k: None)
    monkeypatch.setattr("scraper.auth.f95_cookie_session",
                        lambda: FakeFast([SimpleNamespace(status_code=200, text="guest page", url="")]))
    monkeypatch.setattr(auth.config, "f95_user", staticmethod(lambda: "u"))
    monkeypatch.setattr(auth.config, "f95_password", staticmethod(lambda: "p"))

    class DyingBrowser(BareBrowser):
        def login(self, *a, **k):
            self.logins += 1
            raise auth.AuthError("bad credentials")

    sess = F95Session(session=DyingBrowser([]))
    for _ in range(3):
        with pytest.raises(auth.AuthError):
            sess.ensure_authenticated()
    assert sess.session.logins == 1  # cooldown absorbed the repeats

def test_cold_start_harvests_handoff_from_browser(monkeypatch, tmp_path):
    # No handoff on disk: the first ensure call must persist the handoff
    # from the browser partner so the fast tier engages, not for the whole
    # process life.
    saved = []
    monkeypatch.setattr("scraper.auth.save_handoff",
                        lambda path, handoff: saved.append((path, handoff)))
    fast = FakeFast([SimpleNamespace(status_code=200, text="ok", url="")])
    monkeypatch.setattr("scraper.auth.f95_cookie_session",
                        lambda: builds.pop(0) if builds else None)
    builds = [None, fast]                # disk build: none; post-harvest build: usable
    monkeypatch.setattr(auth.config, "f95_handoff_file",
                        staticmethod(lambda: str(tmp_path / "h.json")))
    sess = F95Session(session=BareBrowser([]))
    sess.ensure_authenticated()
    assert len(saved) == 1
    path, handoff = saved[0]
    assert path == str(tmp_path / "h.json")
    assert handoff["user_agent"] == "UA-2"
    assert any(c["name"] == "cf_clearance" for c in handoff["cookies"])
    assert sess._fast is fast and sess._authenticated

def test_forced_browser_never_harvests_a_fast_tier(monkeypatch):
    monkeypatch.setenv("F95_TRANSPORT", "browser")
    saved = []
    called = []
    monkeypatch.setattr("scraper.auth.save_handoff",
                        lambda *a, **k: saved.append(1))
    monkeypatch.setattr("scraper.auth.f95_cookie_session",
                        lambda: called.append(1) or None)
    sess = F95Session(session=BareBrowser([]))
    sess.ensure_authenticated()
    assert sess._fast is None and saved == [] and called == []
