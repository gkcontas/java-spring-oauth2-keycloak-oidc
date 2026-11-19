#!/usr/bin/env python3
"""Talks to Keycloak the way a browser and an OAuth client would.

Only the standard library. Tokens for users come from the real authorization
code flow with PKCE: the script opens the login page, fills the form and
exchanges the code - there is no password grant in this realm.

    scripts/kc.py token alice                      # access token, docs-cli, documents:read
    scripts/kc.py token alice "documents:write"    # also asks for documents:write
    scripts/kc.py token bob "" other-app           # token issued to another client
    scripts/kc.py tokens alice                     # full token response as JSON
    scripts/kc.py service                          # client credentials of report-job
"""
import base64
import hashlib
import html
import http.cookiejar
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

REALM_URL = os.environ.get("REALM_URL", "http://localhost:8180/realms/docs")
REDIRECTS = {
    "docs-cli": "http://localhost:8765/callback",
    "other-app": "http://localhost:8766/callback",
}


class LocalhostPolicy(http.cookiejar.DefaultCookiePolicy):
    """Keycloak marks its cookies Secure even over plain HTTP. Browsers still
    send Secure cookies to http://localhost; urllib does not, so do it here."""

    def return_ok_secure(self, cookie, request):
        return True


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def browser():
    jar = http.cookiejar.CookieJar(policy=LocalhostPolicy())
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect())
    return opener, jar


def request(opener, url, data=None, headers=None, method=None):
    body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with opener.open(req, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def fill_login_form(opener, page, username, password):
    match = re.search(r'<form id="kc-form-login"[^>]*action="([^"]+)"', page)
    if not match:
        raise RuntimeError("login form not found")
    return request(opener, html.unescape(match.group(1)),
                   {"username": username, "password": password, "credentialId": ""})


def pkce_pair():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def authorization_code(username, password, client_id="docs-cli", extra_scope=""):
    opener, _ = browser()
    verifier, challenge = pkce_pair()
    redirect_uri = REDIRECTS[client_id]
    query = urllib.parse.urlencode({
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
        "scope": ("openid " + extra_scope).strip(), "state": secrets.token_urlsafe(16),
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    status, _, page = request(opener, f"{REALM_URL}/protocol/openid-connect/auth?{query}")
    if status != 200:
        raise RuntimeError(f"authorization endpoint answered {status}: {page[:200]}")
    status, headers, _ = fill_login_form(opener, page, username, password)
    location = headers.get("Location", "")
    code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get("code", [None])[0]
    if status != 302 or not code:
        raise RuntimeError(f"login failed: {status} {location}")
    status, _, body = request(opener, f"{REALM_URL}/protocol/openid-connect/token", {
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
        "client_id": client_id, "code_verifier": verifier,
    })
    if status != 200:
        raise RuntimeError(f"code exchange failed: {status} {body}")
    return json.loads(body)


def client_credentials(client_id="report-job", secret="report-job-secret"):
    opener, _ = browser()
    status, _, body = request(opener, f"{REALM_URL}/protocol/openid-connect/token", {
        "grant_type": "client_credentials", "client_id": client_id, "client_secret": secret,
    })
    if status != 200:
        raise RuntimeError(f"client credentials failed: {status} {body}")
    return json.loads(body)


def logout(refresh_token, client_id="docs-cli"):
    opener, _ = browser()
    status, _, body = request(opener, f"{REALM_URL}/protocol/openid-connect/logout",
                              {"client_id": client_id, "refresh_token": refresh_token})
    return status


def web_login(app_url, username, password=None):
    """Logs into the BFF like a browser: app -> Keycloak login form -> app.
    Returns the opener (holding the session cookie), the jar and the
    authorization request URL the application built."""
    opener, jar = browser()
    url, authorize_url, page = f"{app_url}/web/me", None, None
    for _ in range(10):
        status, headers, page = request(opener, url)
        if status == 200 and "kc-form-login" in page:
            authorize_url = url
            status, headers, page = fill_login_form(opener, page, username, password or username)
        if status not in (301, 302, 303):
            break
        url = urllib.parse.urljoin(url, headers["Location"])
    if status != 200:
        raise RuntimeError(f"web login ended with {status} at {url}")
    return opener, jar, authorize_url


def csrf_header(opener, app_url):
    status, _, body = request(opener, f"{app_url}/web/csrf")
    token = json.loads(body)
    return {token["headerName"]: token["token"]}


def main(argv):
    command = argv[1] if len(argv) > 1 else "token"
    if command in ("token", "tokens"):
        user = argv[2] if len(argv) > 2 else "alice"
        scope = argv[3] if len(argv) > 3 else ""
        client = argv[4] if len(argv) > 4 else "docs-cli"
        tokens = authorization_code(user, user, client, scope)
        print(tokens["access_token"] if command == "token" else json.dumps(tokens))
    elif command == "service":
        print(client_credentials()["access_token"])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
