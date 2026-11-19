#!/usr/bin/env python3
"""Measurements for the README. Needs the application (jar) on 8080/8081 and
Keycloak from docker-compose on 8180.

    scripts/measure.py latency      # JWT local x introspection
    scripts/measure.py throughput   # same, 16 concurrent clients
    scripts/measure.py revocation   # how long a token outlives the logout
    scripts/measure.py jwks-flood   # forged kids at the production rate limit
    scripts/measure.py rotation     # new key right after a flood
    scripts/measure.py refresh      # refresh grants per BFF call
    scripts/measure.py backchannel  # Keycloak session end -> local session end
"""
import base64
import http.client
import json
import os
import secrets
import statistics
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(__file__))
import kc  # noqa: E402

APP = "http://localhost:8080"
ADMIN_BASE = "http://localhost:8180"


def percentile(values, p):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(p / 100 * (len(ordered) - 1))))]


def metric(name):
    conn = http.client.HTTPConnection("127.0.0.1", 8081, timeout=5)
    conn.request("GET", f"/actuator/metrics/{name}")
    body = json.loads(conn.getresponse().read())
    return int(body["measurements"][0]["value"])


class Client:
    """One persistent connection to the application."""

    def __init__(self):
        self.conn = http.client.HTTPConnection("localhost", 8080, timeout=10)

    def get(self, path, token):
        start = time.perf_counter()
        self.conn.request("GET", path, headers={"Authorization": f"Bearer {token}"})
        response = self.conn.getresponse()
        response.read()
        return response.status, (time.perf_counter() - start) * 1000


def admin_token():
    opener, _ = kc.browser()
    _, _, body = kc.request(opener, f"{ADMIN_BASE}/realms/master/protocol/openid-connect/token",
                            {"grant_type": "password", "client_id": "admin-cli",
                             "username": "admin", "password": "admin"})
    return json.loads(body)["access_token"]


def admin(method, path, body=None):
    opener, _ = kc.browser()
    data = json.dumps(body).encode() if body is not None else (b"" if method in ("POST", "PUT", "DELETE") else None)
    status, _, text = kc.request(opener, f"{ADMIN_BASE}/admin/realms/docs{path}", data=data, method=method,
                                 headers={"Authorization": f"Bearer {admin_token()}",
                                          "Content-Type": "application/json"})
    if status >= 400:
        raise RuntimeError(f"{method} {path}: {status} {text}")
    return json.loads(text) if text.strip() else None


def set_client_attribute(client_id, name, value):
    client = admin("GET", f"/clients?clientId={client_id}")[0]
    client["attributes"][name] = value
    admin("PUT", f"/clients/{client['id']}", client)


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forged(kid):
    """Well formed, unknown kid, garbage signature: the key lookup happens before the signature check."""
    now = int(time.time())
    header = b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": kid}).encode())
    payload = b64(json.dumps({"iss": kc.REALM_URL, "aud": "docs-api", "sub": "mallory", "typ": "Bearer",
                              "scope": "documents:read", "iat": now, "exp": now + 300}).encode())
    return f"{header}.{payload}.{b64(secrets.token_bytes(256))}"


# ------------------------------------------------------------------ scenarios

def latency(n=2000, warmup=500):
    token = kc.client_credentials()["access_token"]
    for path in ("/api/documents", "/api/introspected/documents"):
        client = Client()
        for _ in range(warmup):
            client.get(path, token)
        jwks, introspections = metric("auth.jwks.fetches"), metric("auth.introspection.requests")
        times = []
        for _ in range(n):
            status, ms = client.get(path, token)
            assert status == 200, status
            times.append(ms)
        print(json.dumps({"path": path, "n": n, "p50_ms": round(percentile(times, 50), 2),
                          "p99_ms": round(percentile(times, 99), 2), "mean_ms": round(statistics.mean(times), 2),
                          "jwks_fetches": metric("auth.jwks.fetches") - jwks,
                          "introspections": metric("auth.introspection.requests") - introspections}))


def throughput(clients=16, seconds=10):
    token = kc.client_credentials()["access_token"]
    for path in ("/api/documents", "/api/introspected/documents"):
        Client().get(path, token)
        results, stop = [], time.time() + seconds

        def worker():
            client, local = Client(), []
            while time.time() < stop:
                status, ms = client.get(path, token)
                local.append((status, ms))
            results.extend(local)

        threads = [threading.Thread(target=worker) for _ in range(clients)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        times = [ms for _, ms in results]
        print(json.dumps({"path": path, "clients": clients, "requests": len(results),
                          "req_per_s": round(len(results) / seconds),
                          "non_200": sum(1 for s, _ in results if s != 200),
                          "p50_ms": round(percentile(times, 50), 2), "p99_ms": round(percentile(times, 99), 2)}))


def revocation(lifespan=60):
    set_client_attribute("docs-cli", "access.token.lifespan", str(lifespan))
    try:
        tokens = kc.authorization_code("bob", "bob")
        exp = json.loads(base64.urlsafe_b64decode(tokens["access_token"].split(".")[1] + "=="))["exp"]
        status = kc.logout(tokens["refresh_token"])
        logged_out = time.time()
        client = Client()
        first_401 = {}
        while len(first_401) < 2 and time.time() - logged_out < lifespan + 120:
            for path in ("/api/documents", "/api/introspected/documents"):
                if path not in first_401 and client.get(path, tokens["access_token"])[0] == 401:
                    first_401[path] = round(time.time() - logged_out, 1)
            time.sleep(0.5)
        print(json.dumps({"logout_status": status, "token_lifespan_s": lifespan,
                          "exp_after_logout_s": round(exp - logged_out, 1),
                          "accepted_after_logout_s": first_401}))
    finally:
        set_client_attribute("docs-cli", "access.token.lifespan", "")


def jwks_flood(seconds=65):
    client, before = Client(), metric("auth.jwks.fetches")
    statuses, start = {}, time.time()
    while time.time() - start < seconds:
        status, _ = client.get("/api/documents", forged(secrets.token_urlsafe(16)))
        statuses[status] = statuses.get(status, 0) + 1
    print(json.dumps({"seconds": seconds, "requests": sum(statuses.values()), "statuses": statuses,
                      "jwks_fetches": metric("auth.jwks.fetches") - before}))


def rotation(flood_seconds=3):
    client = Client()
    start = time.time()
    while time.time() - start < flood_seconds:
        client.get("/api/documents", forged(secrets.token_urlsafe(16)))
    realm_id = admin("GET", "")["id"]
    admin("POST", "/components", {"name": f"rotated-{int(time.time())}", "providerId": "rsa-generated",
                                   "providerType": "org.keycloak.keys.KeyProvider", "parentId": realm_id,
                                   "config": {"priority": [str(2000 + int(time.time()) % 1000)],
                                              "keySize": ["2048"], "active": ["true"], "enabled": ["true"],
                                              "algorithm": ["RS256"]}})
    token = kc.client_credentials()["access_token"]
    issued = time.time()
    statuses = {}
    while True:
        status, _ = client.get("/api/documents", token)
        statuses[status] = statuses.get(status, 0) + 1
        if status == 200 or time.time() - issued > 60:
            break
        time.sleep(0.25)
    print(json.dumps({"flood_seconds": flood_seconds, "new_key_accepted_after_s": round(time.time() - issued, 1),
                      "statuses_until_then": statuses}))


def refresh(lifespan=60, calls=20):
    set_client_attribute("docs-web", "access.token.lifespan", str(lifespan))
    try:
        opener, _, _ = kc.web_login(APP, "alice")
        before, times = metric("auth.token.refreshes"), []
        for _ in range(calls):
            start = time.perf_counter()
            status, _, _ = kc.request(opener, f"{APP}/web/documents")
            assert status == 200, status
            times.append((time.perf_counter() - start) * 1000)
        print(json.dumps({"token_lifespan_s": lifespan, "calls": calls,
                          "refreshes": metric("auth.token.refreshes") - before,
                          "p50_ms": round(percentile(times, 50), 1)}))
    finally:
        set_client_attribute("docs-web", "access.token.lifespan", "")


def backchannel(rounds=20):
    timings = []
    for _ in range(rounds):
        opener, _, _ = kc.web_login(APP, "bob")
        user = admin("GET", "/users?exact=true&username=bob")[0]["id"]
        sessions = admin("GET", f"/users/{user}/sessions")
        start = time.perf_counter()
        for session in sessions:
            admin("DELETE", f"/sessions/{session['id']}")
        while kc.request(opener, f"{APP}/web/me")[0] != 302:
            time.sleep(0.01)
        timings.append((time.perf_counter() - start) * 1000)
    print(json.dumps({"rounds": rounds, "p50_ms": round(percentile(timings, 50), 1),
                      "max_ms": round(max(timings), 1)}))


if __name__ == "__main__":
    scenarios = {"latency": latency, "throughput": throughput, "revocation": revocation,
                 "jwks-flood": jwks_flood, "rotation": rotation, "refresh": refresh, "backchannel": backchannel}
    if len(sys.argv) < 2 or sys.argv[1] not in scenarios:
        raise SystemExit(__doc__)
    scenarios[sys.argv[1]]()
