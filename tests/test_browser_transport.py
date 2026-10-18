"""
Offline tests for the f95 browser transport (scraper/browser.py).

Every test is network-free: Cloudflare behaviour is simulated by fake pages
that obey only the small surface browser.py touches.

    python -m pytest tests/test_browser_transport.py -v
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scraper.browser as browser
from scraper.auth import AuthError

BASE_URL = "https://f95zone.to/threads/271262/"


class FakeAPI:
    """context.request stand-in. `responses` scripts answers in order; the
    last one repeats so stray extra calls don't IndexError. Extra surface:
    with responses=None an unexpected call is recorded and fails loudly."""

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []

    def get(self, url, timeout=None):
        self.calls.append((url, timeout))
        if not self.responses:
            raise AssertionError(f"unexpected request call: {url}")
        item = self.responses.pop(0) if len(self.responses) > 1 \
            else self.responses[0]
        return item


class FakeResp:
    """Duck-typed playwright APIResponse: .status, .text(), .headers, .url."""

    def __init__(self, status, text, headers=None, url=""):
        self.status = status
        self._text = text
        self.headers = headers or {}
        self.url = url

    def text(self):
        return self._text


class FakeContext:
    """Duck-typed context: `pages`, `new_page()`, `request`.

    The full fake contract browser.py relies on lives here as the single
    documented surface: pages list, new_page(), request.get(url, timeout).
    """

    def __init__(self, page, api=None):
        self.pages = []
        self._page = page
        self.request = api or FakeAPI()

    def new_page(self):
        return self._page


class FakePage:
    """Duck-typed stand-in: title(), content(), goto(), wait_for_timeout()."""

    def __init__(self, title, content="<html><body>ok</body></html>"):
        self._title = title
        self._content = content
        self.gotos = []
        self.fills = []
        self.submit_clicks = 0
        self.content_after_submit = None

    def title(self):
        return self._title

    def set_title(self, title):
        self._title = title

    def content(self):
        return self._content

    def goto(self, url, wait_until=None):
        self.gotos.append(url)

    def wait_for_timeout(self, ms):
        pass

    # -- form interaction (task 4) ----------------------------------------
    def locator(self, sel):
        return SimpleLocator(self, sel)

    def _submit(self, sel):
        self.submit_clicks += 1
        if self.content_after_submit:
            self._content = self.content_after_submit


class SimpleLocator:
    """locator(sel) chain for FakePage: fill()/first.click() only."""

    def __init__(self, page, sel):
        self._page = page
        self._sel = sel

    def fill(self, val):
        self._page.fills.append((self._sel, val))

    def click(self):
        self._page._submit(self._sel)

    @property
    def first(self):
        return self


def make_session(monkeypatch, page, profile="/fake/profile-dir", api=None):
    """Session wired to a fake launch; returns (session, launch-count list)."""
    ctx = FakeContext(page, api)
    calls = []
    monkeypatch.setattr(
        browser, "_launch_context",
        lambda profile_dir, headless: calls.append(1) or ctx)
    return browser.BrowserSession(profile_dir=profile), calls



def test_challenge_detected_by_title():
    assert browser.challenge_detected(FakePage("Just a moment..."))
    assert browser.challenge_detected(FakePage("Checking Your Browser..."))
    assert browser.challenge_detected(
        FakePage("Verify you are human | f95zone"))
    assert not browser.challenge_detected(
        FakePage("Unreal Engine - Dream Team 69 [v0.9.0] [Shodo Games]"))


def test_solve_converts_after_clicks(monkeypatch):
    page = FakePage("Just a moment...")
    clicks = []

    def spy(p):
        clicks.append(1)
        if len(clicks) >= 2:
            page.set_title("F95zone | Adult Games")
        return True

    monkeypatch.setattr(browser, "click_turnstile", spy)
    monkeypatch.setattr(browser.time, "sleep", lambda s: None)

    assert browser.solve_challenge(page, attempts=10, every=10) is True
    assert len(clicks) == 2


def test_solve_exhausts_attempts(monkeypatch):
    page = FakePage("Just a moment...")
    clicks = []
    monkeypatch.setattr(
        browser, "click_turnstile",
        lambda p: clicks.append(1) or True)
    monkeypatch.setattr(browser.time, "sleep", lambda s: None)

    assert browser.solve_challenge(page, attempts=10, every=10) is False
    assert len(clicks) == 10


def _drowse_sleep(monkeypatch):
    monkeypatch.setattr(browser.time, "sleep", lambda s: None)


def test_fetch_page_clean_pass(monkeypatch):
    _drowse_sleep(monkeypatch)
    page = FakePage("Unreal Engine - Dream Team 69 [v0.9.0] [Shodo Games]")
    session, _ = make_session(monkeypatch, page)
    assert session._load(BASE_URL) is page
    assert page.gotos == [BASE_URL]


def test_fetch_page_challenged_then_passes(monkeypatch):
    _drowse_sleep(monkeypatch)
    page = FakePage("Just a moment...")
    solves = []

    def spy(p):
        solves.append(1)
        page.set_title("F95zone | Adult Games")
        return True

    monkeypatch.setattr(browser, "click_turnstile", spy)
    session, _ = make_session(monkeypatch, page)
    assert session._load(BASE_URL) is page
    assert len(solves) >= 1
    # cleared means the page was re-gotoed after the challenge
    assert page.gotos == [BASE_URL, BASE_URL]


def test_fetch_page_never_clears_raises_cf_blocked(monkeypatch):
    _drowse_sleep(monkeypatch)
    page = FakePage("Just a moment...")
    monkeypatch.setattr(browser, "click_turnstile", lambda p: True)
    session, _ = make_session(
        monkeypatch, page, profile="/fake/profile-dir")
    try:
        session._load(BASE_URL)
    except browser.CfBlocked as ex:
        assert "/fake/profile-dir" in str(ex)
    else:
        raise AssertionError("expected CfBlocked")


def test_context_lazily_launched_once(monkeypatch):
    _drowse_sleep(monkeypatch)
    page = FakePage("F95zone")
    session, calls = make_session(monkeypatch, page)
    session._load(BASE_URL)
    session._load("https://f95zone.to/account/")
    assert calls == [1]


def test_profile_dir_resolved_against_app_root(monkeypatch):
    import scraper.config as scraper_config
    monkeypatch.delenv("F95_PROFILE_DIR", raising=False)
    assert scraper_config.config.f95_profile_dir().endswith("f95-profile")
    monkeypatch.setenv("F95_PROFILE_DIR", "/tmp/other-profile")
    assert scraper_config.config.f95_profile_dir() == "/tmp/other-profile"


def _session_with_api(monkeypatch, api, page_title="F95zone"):
    _drowse_sleep(monkeypatch)
    page = FakePage(page_title)
    session, calls = make_session(monkeypatch, page, api=api)
    return session, page


def test_request_returns_response_fields(monkeypatch):
    api = FakeAPI([FakeResp(
        200, '{"status":"ok"}',
        headers={"Content-Type": "application/json"},
        url="https://f95zone.to/latest")])
    session, _ = _session_with_api(monkeypatch, api)
    r = session.request("https://f95zone.to/latest")
    assert r.status_code == 200
    assert r.text == '{"status":"ok"}'
    assert r.headers.get("Content-Type") == "application/json"
    assert r.url == "https://f95zone.to/latest"


def test_request_rewires_once_on_cleared_challenge_then_retry(monkeypatch):
    api = FakeAPI([
        FakeResp(403, "<html>Just a moment...</html>"),
        FakeResp(200, '{"status":"ok"}'),
    ])
    session, page = _session_with_api(
        monkeypatch, api, page_title="Just a moment...")
    clicks = []

    def spy(p):
        clicks.append(1)
        page.set_title("F95zone")
        return True

    monkeypatch.setattr(browser, "click_turnstile", spy)
    r = session.request("https://f95zone.to/latest")
    assert r.status_code == 200
    assert r.text == '{"status":"ok"}'
    assert len(api.calls) == 2          # challenged request, then retry
    assert len(clicks) >= 1             # warm-up cleared a real challenge


def test_request_still_blocked_raises_cf_blocked(monkeypatch):
    api = FakeAPI([FakeResp(403, "<html>Verify you are human</html>")])
    session, _ = _session_with_api(monkeypatch, api)   # warm-up page is clean
    try:
        session.request("https://f95zone.to/latest")
    except browser.CfBlocked as ex:
        assert "/latest" in str(ex)
    else:
        raise AssertionError("expected CfBlocked")


def _form_page(logged_in_after=True):
    page = FakePage(
        "Login",
        content='<html data-logged-in="false"><body>login form</body></html>')
    if logged_in_after:
        page.content_after_submit = (
            '<html data-logged-in="true"><body>home</body></html>')
    return page


def test_is_logged_in_true_false(monkeypatch):
    _drowse_sleep(monkeypatch)
    for content, expected in (
        ('<html data-logged-in="true">', True),
        ('<html data-logged-in="false">', False),
        ("<html><body>bummer</body></html>", False),
    ):
        api = FakeAPI([FakeResp(200, content)])
        page = FakePage("F95zone")
        session, _ = make_session(monkeypatch, page, api=api)
        assert session.is_logged_in() == expected


def test_login_fills_form_and_verifies(monkeypatch):
    _drowse_sleep(monkeypatch)
    page = _form_page()
    session, _ = make_session(monkeypatch, page)
    session.login("doug", "s3crets!")
    assert page.fills == [
        ('input[name="login"]', "doug"),
        ('input[name="password"]', "s3crets!"),
    ]
    assert page.submit_clicks == 1
    assert page.gotos[0].endswith("/login/login")


def test_login_failure_raises_auth_error(monkeypatch):
    _drowse_sleep(monkeypatch)
    page = _form_page(logged_in_after=False)
    session, _ = make_session(monkeypatch, page)
    try:
        session.login("doug", "badpass")
    except AuthError as ex:
        assert "doug" in str(ex) and session.base in str(ex)
    else:
        raise AssertionError("expected AuthError")


def test_login_form_goes_through_challenge_cycle(monkeypatch):
    _drowse_sleep(monkeypatch)
    page = _form_page()
    page.set_title("Just a moment...")
    clicks = []

    def spy(p):
        clicks.append(1)
        page.set_title("Login")
        return True

    monkeypatch.setattr(browser, "click_turnstile", spy)
    session, _ = make_session(monkeypatch, page)
    session.login("doug", "pw")
    assert len(clicks) >= 1          # challenge was handled by _load
    assert page.submit_clicks == 1   # form still got submitted


class RelapsePage(FakePage):
    """The challenge returns after the reload — the still-challenged case."""

    def goto(self, url, wait_until=None):
        super().goto(url, wait_until)
        if len(self.gotos) >= 2:
            self.set_title("Just a moment...")


def test_load_still_challenged_after_reload_raises(monkeypatch):
    _drowse_sleep(monkeypatch)
    page = RelapsePage("Just a moment...")

    def spy(p):
        page.set_title("F95zone")
        return True

    monkeypatch.setattr(browser, "click_turnstile", spy)
    session, _ = make_session(monkeypatch, page)
    try:
        session._load(BASE_URL)
    except browser.CfBlocked:
        pass    # reload brought the challenge back: give up loudly
    else:
        raise AssertionError("expected CfBlocked after relapse")


def test_request_json_body_with_marker_passes_through(monkeypatch):
    """User content may legitimately contain 'Just a moment' etc.; without
    a status gate a clean 200 response would trigger a pointless warm-up
    and could wedge the fetch in a CfBlocked loop."""
    api = FakeAPI([FakeResp(
        200, '{"title": "Just a moment - let the game speak"}')])
    session, _ = _session_with_api(monkeypatch, api)
    r = session.request("https://f95zone.to/latest")
    assert r.status_code == 200
    assert len(api.calls) == 1    # no warm-up fired


def test_solve_honors_click_every_env(monkeypatch):
    """F95_CF_CLICK_EVERY is documented as the click-gap knob; it must be
    read, not silently ignored in favour of the 10s default."""
    page = FakePage("Just a moment...")
    monkeypatch.setattr(browser, "click_turnstile", lambda p: True)
    slept = []
    monkeypatch.setattr(browser.time, "sleep", lambda s: slept.append(s))

    monkeypatch.setenv("F95_CF_CLICK_EVERY", "3")
    browser.solve_challenge(page, attempts=2)
    assert slept == [3, 3]

    monkeypatch.delenv("F95_CF_CLICK_EVERY")
    slept.clear()
    browser.solve_challenge(page, attempts=2)
    assert slept == [10, 10]      # unset falls back to the measured gap


def test_request_retry_clean_status_marker_body_passes(monkeypatch):
    """Clearance expired mid-run: the retry answers 200 with marker words in
    its user content. The retry check needs the same 403/503 gate as the
    first one, or a good fetch gets misreported as still blocked."""
    api = FakeAPI([
        FakeResp(403, "<html>Just a moment...</html>"),
        FakeResp(200, '{"title": "Just a moment - let the game speak"}'),
    ])
    session, page = _session_with_api(
        monkeypatch, api, page_title="Just a moment...")

    def spy(p):
        page.set_title("F95zone")
        return True

    monkeypatch.setattr(browser, "click_turnstile", spy)
    r = session.request("https://f95zone.to/latest")
    assert r.status_code == 200
    assert "Just a moment" in r.text
