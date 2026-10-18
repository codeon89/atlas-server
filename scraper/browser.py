"""
F95 browser transport: patchright persistent context.

Cloudflare challenges every scripted client on f95zone.to (requests, curl_cffi
and vanilla Playwright all get 403), so page access goes through a real,
fingerprint-clean Chromium process driven by patchright. A page load that
lands on a challenge is cleared by clicking the Turnstile widget — the same
happy-path programmatic click the client-side transport ships, measured
converting on the first click on 2026-10.

This layer owns the challenge and the browser profile; login lives
separately (BrowserSession.login) and persistence comes for free from the
profile directory.
"""
import json
import os
import re
import time

# Page titles that mean "Cloudflare is in the way". Blacklist-style because
# the challenge page is served by Cloudflare and its DOM is unstable, while
# the title has been stable across every measured load; checked lowercased.
CF_TITLE_MARKERS = (
    "just a moment",
    "verify you are human",
    "attention required",
    "cf-chl",
    "turnstile",
    "checking your browser",
)

# Spike-measured click cadence and settle time.
FETCH_SETTLE_MS = 5000

_CHALLENGE_RE = re.compile("|".join(re.escape(m) for m in CF_TITLE_MARKERS))


class CfBlocked(RuntimeError):
    """Every click attempt failed to clear the Cloudflare challenge."""
    pass


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _headless():
    return os.environ.get("F95_BROWSER_HEADLESS", "").strip().lower() in (
        "1", "true", "yes")


def challenge_detected(page):
    """True while the page shows any Cloudflare challenge state."""
    title = page.title()
    return bool(title and _CHALLENGE_RE.search(title.lower()))


def click_turnstile(page):
    """One scripted click on the Turnstile checkbox; False if no widget is
    reachable. Happy path mirrors the client's forumWindowFetch: click the
    checkbox inside the challenge iframe, fall back to a raw mouse click on
    its right edge."""
    try:
        fl = page.frame_locator("iframe[src*='challenges.cloudflare.com']").first
        fl.locator("input[type='checkbox']").first.click(timeout=3000)
        return True
    except Exception:
        pass
    try:
        el = page.locator("iframe[src*='challenges.cloudflare.com']").first
        box = el.bounding_box()
        if box:
            page.mouse.click(
                box["x"] + box["width"] - 30, box["y"] + box["height"] / 2)
            return True
    except Exception:
        pass
    return False


def solve_challenge(page, attempts=None, every=None):
    """Click the widget and recheck until it clears or attempts run out.
    Returns True when the challenge is gone. `attempts` defaults to
    F95_CF_CLICK_ATTEMPTS (10) and the gap between clicks to
    F95_CF_CLICK_EVERY (10s)."""
    if attempts is None:
        attempts = _env_int("F95_CF_CLICK_ATTEMPTS", 10)
    if every is None:
        every = _env_int("F95_CF_CLICK_EVERY", 10)
    for _ in range(attempts):
        if not challenge_detected(page):
            return True
        click_turnstile(page)
        time.sleep(every)
    return not challenge_detected(page)


def _launch_context(profile_dir, headless=False):
    """Real launch; module-level so tests can fake the browser wholesale."""
    from patchright.sync_api import sync_playwright

    pw = sync_playwright().start()
    try:
        ctx = pw.chromium.launch_persistent_context(
            user_data_dir=profile_dir,
            headless=headless,
            ignore_default_args=["--enable-automation"],
            args=["--disable-blink-features=AutomationControlled"],
        )
    except Exception:
        pw.stop()
        raise
    ctx._pw_runtime = pw  # kept alive with the context, stopped in close()
    return ctx


class BrowserSession:
    """Persistent-context Chromium session for one f95 scraper process.

    Owns only the transport: launching, navigation through Cloudflare
    challenges, plain HTTP via the context's shared cookie jar, and the
    browser login. The profile directory is the state: clearance, cookies
    and login all survive restarts inside it.
    """

    def __init__(self, profile_dir=None, base="https://f95zone.to"):
        from scraper.config import config
        self.profile_dir = profile_dir or config.f95_profile_dir()
        self.base = base
        self._ctx = None

    def start(self):
        if self._ctx is not None:
            return
        try:
            self._ctx = _launch_context(self.profile_dir, _headless())
        except Exception as ex:
            raise RuntimeError(
                "browser launch failed; get the patchright chromium with "
                f".venv/bin/patchright install chromium ({ex})") from ex

    def close(self):
        ctx, self._ctx = self._ctx, None
        if ctx is None:
            return
        runtime = getattr(ctx, "_pw_runtime", None)
        ctx.close()
        if runtime is not None:
            runtime.stop()

    def export_handoff(self):
        """Snapshot for the requests transport: user agent plus the whole
        context cookie jar, per scraper.browser.load_handoff's contract."""
        self.start()
        page = self._ctx.pages[0] if self._ctx.pages else self._ctx.new_page()
        return {"user_agent": page.evaluate("navigator.userAgent"),
                "cookies": self._ctx.cookies(),
                "saved_at": time.time()}

    def _load(self, url):
        """Navigate to a page, clearing any Cloudflare challenge met on the
        way: solve, reload once, then give up with CfBlocked (the profile
        keeps whatever state the clicks earned for the next run)."""
        self.start()
        page = self._ctx.pages[0] if self._ctx.pages else self._ctx.new_page()
        page.goto(url, wait_until="domcontentloaded")
        page.wait_for_timeout(FETCH_SETTLE_MS)
        if challenge_detected(page):
            if not solve_challenge(page):
                raise CfBlocked(
                    f"cloudflare challenge unsolved after clicks; "
                    f"profile: {self.profile_dir}")
            page.goto(url, wait_until="domcontentloaded")
            page.wait_for_timeout(FETCH_SETTLE_MS)
            if challenge_detected(page):   # reload did not clear it either
                raise CfBlocked(
                    f"cloudflare challenge returned after reload; "
                    f"profile: {self.profile_dir}")
        return page

    def request(self, url, timeout=30000):
        """HTTP GET through the browser context, so the browser's cookies
        (including anything Cloudflare granted the last page load) travel
        with the request. A challenge-marked body gets one warm-up page
        load and a single retry; a second challenge-marked body is
        CfBlocked."""
        self.start()
        resp = BrowserResponse(self._ctx.request.get(url, timeout=timeout))
        if challenged_response(resp):
            self._load(self.base)
            resp = BrowserResponse(self._ctx.request.get(url, timeout=timeout))
            if challenged_response(resp):
                raise CfBlocked(
                    f"challenge still blocking {url} after warm-up; "
                    f"profile: {self.profile_dir}")
        return resp

    def is_logged_in(self):
        self.start()
        resp = self.request(self.base + "/")
        head = resp.text[:2000]
        if 'data-logged-in="true"' in head:
            return True
        if 'data-logged-in="false"' in head:
            return False
        return False

    def login(self, user, password):
        """XenForo login in the browser: fill the form, submit, and prove
        the session landed (data-logged-in flips on the root element).
        State persists in the profile, so this runs once per profile
        lifetime, not per run. Credentials arrive as arguments; callers own
        the config lookup."""
        from scraper.auth import AuthError  # late import: auth delegates here

        page = self._load(self.base + "/login/login")
        page.locator('input[name="login"]').fill(user)
        page.locator('input[name="password"]').fill(password)
        page.locator('button[type="submit"]').first.click()
        page.wait_for_timeout(FETCH_SETTLE_MS)
        if 'data-logged-in="true"' not in page.content()[:2000]:
            raise AuthError(
                f"browser login failed for {self.base} with account {user}: "
                "session did not come up (check credentials / captcha)")


class BrowserResponse:
    """requests.Response stand-in carrying only what scraper callers check.

    Wrapping the raw playwright APIResponse (not aliasing) because callers
    expect `.text` as a plain attribute and `.status_code` naming.
    """

    def __init__(self, resp):
        self.status_code = resp.status
        self.text = resp.text()
        self.headers = resp.headers
        self.url = getattr(resp, "url", "")


def challenged_html(text):
    """True when an HTTP body (any status) is carrying the challenge page.
    Marker-based on purpose: a legit 403 -- a deleted thread, a permission
    wall -- has a different body and must pass through untouched."""
    return bool(_CHALLENGE_RE.search(text.lower()))


def challenged_response(resp):
    """The challenge wall as a response: a challenge status (403/503)
    carrying the challenge body, or Cloudflare's own cf-mitigated header
    on any status -- the edge names the wall, which is how an interstitial
    signed HTTP 200 gets caught. Marker words alone on a 200 are page
    copy, not a wall (a legit 403 -- deleted thread, permission wall --
    has a different body and passes through). One gate shared by the
    browser tier and the ladder."""
    mitigated = getattr(resp, "headers", None).get("cf-mitigated") \
        if getattr(resp, "headers", None) else None
    if str(mitigated or "").strip():
        return True
    return resp.status_code in (403, 503) and challenged_html(resp.text)


def handoff_is_usable(handoff):
    """True when the handoff dict carries what a requests-based session
    needs against Cloudflare: a user agent and the clearance cookie.
    Wrongly shaped payloads (non-dict, or cookies that is not a list)
    count as not usable rather than raising."""
    if not isinstance(handoff, dict) or not handoff.get("user_agent"):
        return False
    cookies = handoff.get("cookies")
    if not isinstance(cookies, list):
        return False
    names = {c.get("name") for c in cookies if isinstance(c, dict)}
    return "cf_clearance" in names


def save_handoff(path, handoff):
    """Atomic write: temp file + os.replace, so a crash between write and
    replace leaves the previous handoff intact for process crashes (an
    fsync'd journal it is not)."""
    tmp = path + ".tmp"  # shortcut: single fixed tmp filename assumes single-writer, upgrade when multi-process saving appears
    with open(tmp, "w") as fh:
        json.dump(handoff, fh)
    os.replace(tmp, path)


def load_handoff(path=None):
    """The saved handoff, or None when missing, corrupt, or not usable
    (None callers treat identically: go the browser route)."""
    if path is None:
        from scraper.config import config
        path = config.f95_handoff_file()
    try:
        with open(path) as fh:
            handoff = json.load(fh)
    except (OSError, ValueError):
        return None
    return handoff if handoff_is_usable(handoff) else None
