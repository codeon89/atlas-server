"""
XenForo authenticated sessions over requests (LewdCorner).

F95zone no longer fetches through requests: Cloudflare rejects scripted HTTP
clients, so F95 pages come from the browser transport in
`scraper/browser.py` (a persistent patchright profile carrying the clearance
and the login), and `F95Session` below is a thin delegator onto it.

Strategy for the requests-based sessions (per requirements):
  - Log in once with the dummy account credentials from .env.
  - Persist the resulting cookies to disk.
  - On every run, reuse the cached cookie and only log in again when it
    has expired. This avoids logging in on every scrape.

XenForo 2 login is a POST to /login/login with the page's CSRF token
(_xfToken). A live session is verified by the `data-logged-in` attribute on
the root <html> element of any page.
"""
import json
import os
import re
import time
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from scraper.config import config
# No cycle: scraper.browser defers its scraper.auth import to call time.
from scraper.browser import challenged_response, save_handoff

# Use the OS trust store (Windows/corporate/AV roots) for TLS verification.
# Fixes "CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate"
# on machines where antivirus or a proxy does HTTPS inspection.
try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

BASE = "https://f95zone.to"

# A normal desktop UA. F95 serves the "you must be registered" gating to
# anything it treats as a guest, so the cookie — not the UA — is what matters,
# but a real UA avoids tripping bot heuristics.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}


class AuthError(RuntimeError):
    pass


def _auth_ttl():
    """How long a session is trusted without re-verification, in seconds.
    0 disables the periodic check. Guards against `_authenticated` being set
    once at startup and never questioned again for the life of a daemon."""
    try:
        return float(os.environ.get("XF_AUTH_TTL", "1800"))
    except ValueError:
        return 1800.0


def _reauth_cooldown():
    """Minimum gap between forced re-logins triggered by an HTTP 401/403.
    Without this, a thread that is legitimately 403 (deleted, or behind a
    permission wall) would trigger a full login on every retry attempt."""
    try:
        return float(os.environ.get("XF_REAUTH_COOLDOWN", "300"))
    except ValueError:
        return 300.0


class XenForoSession:
    """Generic XenForo 2.x authenticated session: cookie persistence + lazy
    login + liveness via the `data-logged-in` flag. Subclasses set the site
    BASE and supply credentials/cookie-file accessors.

    Both F95zone and LewdCorner run XenForo, so the login flow (POST to
    /login/login with the page's _xfToken) and the liveness signal are
    identical; only the base URL and which .env credentials to use differ.
    """

    BASE = ""  # subclass sets this, e.g. "https://f95zone.to"

    def __init__(self, cookie_file):
        self.cookie_file = cookie_file
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self._authenticated = False
        self._auth_checked_at = 0.0   # monotonic stamp of last liveness proof
        self._last_reauth = 0.0       # monotonic stamp of last forced login
        self._load_cookies()

    # ---- credentials (subclass overrides) ----------------------------------
    def _credentials(self):
        """Return (user, password) for login. Overridden per site."""
        raise NotImplementedError

    # ---- cookie persistence -------------------------------------------------
    def _load_cookies(self):
        if not os.path.exists(self.cookie_file):
            return
        try:
            with open(self.cookie_file, "r", encoding="utf-8") as fh:
                for c in json.load(fh):
                    self.session.cookies.set(
                        c["name"], c["value"],
                        domain=c.get("domain"), path=c.get("path", "/"),
                    )
        except (ValueError, KeyError, OSError):
            # Corrupt cookie cache -> ignore and re-login later.
            pass

    def _save_cookies(self):
        data = [
            {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path}
            for c in self.session.cookies
        ]
        tmp = self.cookie_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, self.cookie_file)

    # ---- session state ------------------------------------------------------
    @staticmethod
    def _is_logged_in_html(html):
        # The root <html> tag carries data-logged-in="true"/"false".
        # Cheap string check avoids a full parse just for the flag.
        head = html[:2000]
        if 'data-logged-in="true"' in head:
            return True
        if 'data-logged-in="false"' in head:
            return False
        # Fall back to a full parse if the attribute moved.
        tag = BeautifulSoup(html, "lxml").find("html")
        return bool(tag and tag.get("data-logged-in") == "true")

    def is_logged_in(self):
        """Hit a lightweight page and read the login flag."""
        try:
            r = self.session.get(self.BASE + "/account/", timeout=30,
                                  allow_redirects=True)
        except requests.RequestException:
            return False
        return r.status_code == 200 and self._is_logged_in_html(r.text)

    def login(self):
        """Full XenForo login using credentials from .env."""
        user, password = self._credentials()

        # 1. GET the login form to obtain the CSRF token.
        r = self.session.get(self.BASE + "/login/login", timeout=30)
        if r.status_code != 200:
            raise AuthError(f"Could not load login page (HTTP {r.status_code})")
        soup = BeautifulSoup(r.text, "lxml")
        token_input = soup.find("input", attrs={"name": "_xfToken"})
        token = token_input["value"] if token_input and token_input.has_attr("value") else ""

        # 2. POST credentials.
        payload = {
            "login": user,
            "password": password,
            "remember": "1",
            "_xfRedirect": self.BASE + "/",
            "_xfToken": token,
        }
        headers = {"Referer": self.BASE + "/login/login",
                   "Origin": self.BASE}
        r = self.session.post(self.BASE + "/login/login", data=payload,
                              headers=headers, timeout=30, allow_redirects=True)

        if not self._is_logged_in_html(r.text) and not self.is_logged_in():
            raise AuthError(
                f"Login failed for {self.BASE}. Check the account credentials "
                "in .env, and whether the account triggered a captcha."
            )
        self._authenticated = True
        self._auth_checked_at = time.monotonic()
        self._save_cookies()

    def ensure_authenticated(self):
        """Reuse the cached cookie; only log in when it has expired.

        `_authenticated` is re-verified once every XF_AUTH_TTL seconds rather
        than being trusted for the whole life of the process. A daemon that
        set the flag at startup and never rechecked it would keep believing
        it was logged in for days after the cookie died.
        """
        ttl = _auth_ttl()
        if self._authenticated:
            if ttl <= 0:
                return
            if (time.monotonic() - self._auth_checked_at) < ttl:
                return
            # Stale: prove it, cheaply, rather than assuming.
            if self.is_logged_in():
                self._auth_checked_at = time.monotonic()
                self._save_cookies()
                return
            self._authenticated = False
        if self.is_logged_in():
            self._authenticated = True
            self._auth_checked_at = time.monotonic()
            # Refresh the on-disk copy in case cookies rotated.
            self._save_cookies()
            return
        self.login()

    def _reauth_if_allowed(self, status_code):
        """Force a fresh login, unless we just did one. Returns True if a
        login actually happened (so the caller should retry the request)."""
        now = time.monotonic()
        cooldown = _reauth_cooldown()
        if cooldown > 0 and (now - self._last_reauth) < cooldown:
            return False
        self._last_reauth = now
        self._authenticated = False
        try:
            self.login()
        except AuthError as ex:
            print(f"  re-auth after HTTP {status_code} failed: {ex}")
            return False
        return True

    # ---- request helpers ----------------------------------------------------
    def get(self, url, **kwargs):
        """Authenticated GET. Verifies the session is live, retrying login
        once if the cookie expired mid-run.

        Two ways a dead session shows up, and BOTH have to be handled:
          * HTTP 200 with data-logged-in="false" -- the soft logout.
          * HTTP 401/403 -- the hard one. A challenge or a lapsed cookie can
            come back as 403 rather than a logged-out page. The old code only
            checked the 200 case, so once the site started answering 403 the
            session could never recover: ensure_authenticated() short-circuits
            on `_authenticated`, which nothing ever cleared. Every subsequent
            request failed identically until the process was restarted.
        The cooldown in _reauth_if_allowed stops a genuinely-403 thread
        (deleted / permission-walled) from triggering a login storm.
        """
        self.ensure_authenticated()
        kwargs.setdefault("timeout", 30)
        r = self.session.get(url, **kwargs)
        if r.status_code in (401, 403):
            if self._reauth_if_allowed(r.status_code):
                r = self.session.get(url, **kwargs)
        elif r.status_code == 200 and not self._is_logged_in_html(r.text):
            self._authenticated = False
            self.login()
            self._auth_checked_at = time.monotonic()
            r = self.session.get(url, **kwargs)
        return r

    def get_json(self, url, **kwargs):
        """Authenticated GET that returns parsed JSON (or None).

        Used for the LewdCorner latest-updates.php?api=1 feed: it returns JSON
        rather than HTML, so the data-logged-in HTML check in get() doesn't
        apply. We ensure auth up front; if the feed comes back as a login/HTML
        page (cookie died), we re-auth once and retry.
        """
        self.ensure_authenticated()
        kwargs.setdefault("timeout", 30)
        r = self.session.get(url, **kwargs)
        if r.status_code in (401, 403):
            # Same hard-logout case as get(); the feed can be gated too.
            if self._reauth_if_allowed(r.status_code):
                r = self.session.get(url, **kwargs)
        ct = r.headers.get("Content-Type", "")
        if r.status_code == 200 and "json" not in ct.lower():
            # Probably got served an HTML page because the session lapsed.
            if not self._is_logged_in_html(r.text):
                self._authenticated = False
                self.login()
                self._auth_checked_at = time.monotonic()
                r = self.session.get(url, **kwargs)
        try:
            return r.json()
        except ValueError:
            if r.status_code != 200:
                print(f"  unhandled HTTP {r.status_code} on {url}; body unparsed, skipping")
            return None


class F95CookieSession:
    """requests-based fast tier, fed by the browser handoff.

    The handoff harvested from BrowserSession (UA + cf_clearance cookie)
    is what a plain requests.Session needs to pass Cloudflare on the
    listing API and ordinary pages. Headers are set once here: the XHR
    pair (X-Requested-With + Referer) is required by the SAM listing API
    and accepted harmlessly by the other pages. Deliberately no login
    machinery: liveness of the login cookie is checked higher up, in the
    ladder. Responses are returned raw; requests.Response already
    exposes everything consumers (f95.py, the feed path) read.
    """

    def __init__(self, handoff, base="https://f95zone.to",
                 session_cls=requests.Session):
        self.base = base.rstrip("/")
        self._session = session_cls()
        self._session.headers["User-Agent"] = handoff.get("user_agent", "")
        self._session.headers["X-Requested-With"] = "XMLHttpRequest"
        self._session.headers["Referer"] = self.base + "/latest-updates/"
        for cookie in (handoff.get("cookies") or []):
            if not isinstance(cookie, dict):
                continue  # usable handoffs still allow junk entries alongside dicts
            if "f95zone" not in (cookie.get("domain") or ""):
                continue
            if not isinstance(cookie.get("name"), str):
                continue  # a nameless f95zone entry cannot be set on a jar
            self._session.cookies.set(
                cookie["name"], cookie.get("value", ""),
                domain=cookie.get("domain"), path=cookie.get("path", "/"))

    def get(self, url, timeout=30, allow_redirects=True, **kwargs):
        return self._session.get(
            url, timeout=timeout, allow_redirects=allow_redirects, **kwargs)


def f95_cookie_session():
    """The fast tier when a usable handoff is on disk, else None so the
    caller knows to go the browser route."""
    # late import both ways: scraper.browser late-imports scraper.auth
    from scraper.browser import load_handoff
    handoff = load_handoff()
    if handoff is None:
        return None
    return F95CookieSession(handoff)


class F95Session:
    """f95zone session on the patchright browser transport.

    All requests-based machinery here was dropped: f95zone.to answers
    every scripted non-browser client (requests, curl_cffi) with the
    Cloudflare challenge wall, so the transport must be a real Chromium
    process (scraper.browser.BrowserSession). The outward contract stays
    the old one -- ensure_authenticated/get/get_json/resolve_masked -- so
    agents and scripts keep calling exactly what they always did. The
    browser profile holds the state (Cloudflare clearance, session
    cookies, login) that the cookie JSON file used to hold; the
    cookie_file argument is accepted for call-site compatibility only.
    """

    BASE = "https://f95zone.to"

    def __init__(self, cookie_file=None, session=None):
        from scraper.browser import BrowserSession  # late import both ways
        self.cookie_file = cookie_file  # unused; kept so callers keep working
        self.session = session or BrowserSession()
        self._authenticated = False
        self._auth_checked_at = 0.0   # monotonic stamp of last liveness proof
        self._login_failed_at = None  # set on failure, cleared on success
        self._fast = None
        self._escalations = 0
        self._pinned = False
        self._force_browser = os.environ.get("F95_TRANSPORT", "hybrid") != "hybrid"

    _MAX_ESCALATIONS = 2

    def _fetch(self, url):
        """Response for url via the hybrid ladder: fast tier, one plain
        retry when challenged, then escalation to the browser tier."""
        if self._pinned or self._force_browser:
            # Browser tier only. It raises CfBlocked itself when stuck;
            # that propagates unchanged.
            return self.session.request(url)
        if self._fast is None:
            self._fast = f95_cookie_session()
        if self._fast is None:
            return self.session.request(url)
        resp = self._fast.get(url)
        if not challenged_response(resp):
            return resp
        # Ladder retry, not scraping pace: hand-tuned sleeps belong to
        # the agent above, this one just lets a flapping wall flap back.
        time.sleep(1.0)
        resp = self._fast.get(url)
        if not challenged_response(resp):
            # Plain-retry successes never count against the escalation budget.
            return resp
        return self._escalate(url)

    def _escalate(self, url):
        self._escalations += 1
        if self._escalations > self._MAX_ESCALATIONS:
            # Two strikes: the harvested clearance is not holding up; the
            # rest of this process rides the browser tier. Nothing here
            # persists the pin -- a fresh process tries fast again.
            self._pinned = True
            self._fast = None
            return self.session.request(url)
        # The partner is the real BrowserSession: ready it through the
        # primitives it actually has (verify-liveness-login), not the
        # session-level wrapper it does not have.
        self._browser_partner_ready()
        handoff = self._export_handoff()
        if handoff is not None:
            save_handoff(config.f95_handoff_file(), handoff)
        self._fast = f95_cookie_session()
        if self._fast is None:
            return self.session.request(url)
        retry = self._fast.get(url)
        if not challenged_response(retry):
            # A clean rebuilt retry resets the budget: a challenge storm
            # (still challenged) never resets, self-healing expiries do.
            self._escalations = 0
            return retry
        # Still challenged: serve this one through the browser so the run
        # keeps its data; the next run starts fast from the handoff above.
        return self.session.request(url)

    def ensure_authenticated(self):
        """Profile verify, throttled to once per XF_AUTH_TTL seconds (the
        same knob the requests-based session used). While the fast tier
        holds, the proof is one cheap fast-tier probe of /whats-new/
        instead of a browser page render; the browser only launches when
        that probe shows the harvested login died."""
        if not self._pinned and not self._force_browser:
            if self._fast is None:
                self._fast = f95_cookie_session()
            if self._fast is not None:
                if self._authenticated and self._ttl_current():
                    return
                resp = self._fetch(self.BASE + "/whats-new/")
                if resp.status_code == 200 and \
                        XenForoSession._is_logged_in_html(resp.text):
                    self._authenticated = True
                    self._auth_checked_at = time.monotonic()
                    return
                # The page fetched but the login flag is off: the harvested
                # login is dead. The browser profile carries the same
                # session, so its is_logged_in() would only spend a page
                # load repeating what the probe just proved. Re-login
                # directly, under the same cooldown the shipped browser
                # path uses, then re-harvest the handoff so the fast tier
                # resumes.
                self._fast = None
                self._authenticated = False
                self._browser_partner_login()
                handoff = self._export_handoff()
                if handoff is not None:
                    save_handoff(config.f95_handoff_file(), handoff)
                self._fast = f95_cookie_session()
                return
            # Cold start with no handoff: harvest from the just-verified browser
            # instead of riding it for the whole process. A partner that
            # cannot export (bare delegate) just rides the browser tier.
            self._browser_partner_ready()
            handoff = self._export_handoff()
            if handoff is None:
                return
            save_handoff(config.f95_handoff_file(), handoff)
            self._fast = f95_cookie_session()
            return
        self._browser_partner_ready()

    def _export_handoff(self):
        """The browser partner's handoff (session cookie export), or None
        when the delegate has no export_handoff -- the save/serve calls
        above then skip persistence and stay on the browser tier."""
        export = getattr(self.session, "export_handoff", None)
        return export() if export is not None else None

    def _ttl_current(self):
        """True while the liveness stamp is still trusted: either the
        periodic check is disabled or the last proof is younger than
        XF_AUTH_TTL. One copy for both ensure_authenticated and the
        browser partner verification."""
        ttl = _auth_ttl()
        if ttl <= 0:
            return True
        return (time.monotonic() - self._auth_checked_at) < ttl

    def _browser_partner_ready(self):
        """The browser partner challenged-and-logged-in: throttled profile
        verify (the same XF_AUTH_TTL knob), a cheap liveness proof, then
        a cooldown-gated login if the profile is spent. Touches only the
        BrowserSession primitives that exist for real (is_logged_in,
        login), so escalation and the auth check share it verbatim."""
        if self._authenticated:
            if self._ttl_current():
                return
            # Stale stamp: prove it cheaply rather than re-login.
            if self.session.is_logged_in():
                self._auth_checked_at = time.monotonic()
                return
            self._authenticated = False
        if self.session.is_logged_in():
            self._authenticated = True
            self._auth_checked_at = time.monotonic()
            return
        self._browser_partner_login()

    def _browser_partner_login(self):
        """One login POST under the XF_REAUTH_COOLDOWN gap the requests
        session used: a wrong password must not become one attempt per
        queued row, since each attempt drives a real form submit."""
        if self._login_failed_at is not None and \
                (time.monotonic() - self._login_failed_at) < _reauth_cooldown():
            raise AuthError(
                "browser login still in cooldown after an earlier failure; "
                "check F95_USER/F95_PASSWORD")
        try:
            self.session.login(config.f95_user(), config.f95_password())
        except AuthError:
            self._login_failed_at = time.monotonic()
            raise
        self._login_failed_at = None
        self._authenticated = True
        self._auth_checked_at = time.monotonic()

    def get(self, url, **kwargs):
        # kwargs (timeout, allow_redirects, headers...) are deliberately
        # dropped for the browser tier: BrowserSession.request takes a
        # milliseconds-based timeout, so forwarding seconds-based kwargs
        # would be unsafe. Known caller that passes some anyway:
        # tools/diagnostics/test_masked_resolve.py:181 sends timeout=30
        # and gets the transport's own value instead.
        self.ensure_authenticated()
        return self._fetch(url)

    def get_json(self, url, **kwargs):
        """Authenticated GET that returns parsed JSON (or None). Used for
        the listing feed; a body that is not JSON still reads as None to
        the caller. The ladder absorbs challenges before this point, so
        what reaches here is a real page or a CfBlocked from the browser
        tier when the wall cannot be cleared."""
        resp = self.get(url, **kwargs)
        try:
            return json.loads(resp.text)
        except ValueError:
            if resp.status_code != 200:
                print(f"  unhandled HTTP {resp.status_code} on {url}; body unparsed, skipping")
            return None

    def resolve_masked(self, url):
        """Resolve an F95 /masked/ link to its real destination URL.

        Masked tokens are encrypted server-side and cannot be decoded
        offline, so this makes ONE network request (authenticated) and
        reads the redirect target or the external-link anchor. Resolve
        lazily/on demand -- not for every mirror on every scrape -- to
        avoid rate limiting.

        Never exercised against the live site: nothing on the refresh
        path resolves masked links today, so this has no production
        caller yet.

        Returns the destination URL, or None if it couldn't be resolved.
        """
        if "/masked/" not in (url or ""):
            return url
        self.ensure_authenticated()
        try:
            r = self._fetch(url)
        except Exception:
            return None
        if r.url and "f95zone.to" not in urlparse(r.url).netloc:
            return r.url
        m = re.search(r'href="(https?://[^"]+)"[^>]*link--external', r.text)
        return m.group(1) if m else None


class LCSession(XenForoSession):
    """LewdCorner session. Same XenForo login as F95; only the base URL and
    credentials differ. The latest-updates.php?api=1 feed is fetched with
    get_json() through this authenticated session."""

    BASE = "https://lewdcorner.com"

    def __init__(self, cookie_file=None):
        super().__init__(cookie_file or config.lc_cookie_file())

    def _credentials(self):
        return config.lc_user(), config.lc_password()
