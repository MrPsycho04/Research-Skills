#!/usr/bin/env python3
"""Scoped, rate-limited downloader for js-collect.

Every request to the target must go through this script. It:
  * refuses any URL outside scope.txt (allow list + !exclusions)
  * enforces the rate ceiling in rate.txt (requests/second)
  * re-checks scope on every redirect hop (no silent hops out of scope)
  * stores bytes content-addressed (cas/sha256/<hash>) and logs to manifest.json

Usage:
  scoped_fetch.py --dir js-collect-output/target --via "katana -jc" URL [URL ...]
  scoped_fetch.py --dir ... --urls-file urls.txt
  scoped_fetch.py --dir ... --header "Cookie: session=..." URL

TLS impersonation is OFF by default. Enable it only if the program explicitly
allows working around bot protection:
  --impersonate chrome124 --confirm-program-allows-bypass
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from urllib.parse import urljoin, urlparse

MAX_REDIRECTS = 5
MAX_BYTES = 25 * 1024 * 1024
REDIRECT_CODES = {301, 302, 303, 307, 308}


def load_rules(path):
    allow, deny = [], []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!"):
                deny.append(line[1:])
            else:
                allow.append(line)
    if not allow:
        sys.exit("scope.txt has no allow entries; refusing to run")
    return allow, deny


def in_scope(url, allow, deny):
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    host = p.hostname.lower()
    if any(fnmatchcase(host, d) for d in deny):
        return False
    return any(fnmatchcase(host, a) for a in allow)


def load_rate(path):
    try:
        with open(path, encoding="utf-8") as fh:
            rate = float(fh.read().strip())
    except (OSError, ValueError):
        rate = 2.0
    return max(rate, 0.01)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def raw_get(url, headers, impersonate):
    """One request, never following redirects. Returns (status, headers, body)."""
    if impersonate:
        from curl_cffi import requests as cr  # pip install curl_cffi
        r = cr.get(url, headers=headers, impersonate=impersonate,
                   allow_redirects=False, timeout=30)
        return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.content[:MAX_BYTES]
    req = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(MAX_BYTES)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(MAX_BYTES)


class Fetcher:
    def __init__(self, base, via, headers, impersonate):
        self.base = base
        self.via = via
        self.headers = headers
        self.impersonate = impersonate
        self.allow, self.deny = load_rules(os.path.join(base, "scope.txt"))
        self.interval = 1.0 / load_rate(os.path.join(base, "rate.txt"))
        self.last = 0.0
        self.manifest_path = os.path.join(base, "manifest.json")
        if os.path.exists(self.manifest_path):
            with open(self.manifest_path, encoding="utf-8") as fh:
                self.manifest = json.load(fh)
        else:
            self.manifest = {"run_contract": {"scope": self.allow, "exclude": self.deny,
                                              "rate_rps": 1.0 / self.interval,
                                              "started": now()}, "files": []}
        for d in ("cas/sha256", "raw"):
            os.makedirs(os.path.join(base, d), exist_ok=True)

    def wait(self):
        delay = self.interval - (time.monotonic() - self.last)
        if delay > 0:
            time.sleep(delay)
        self.last = time.monotonic()

    def fetch(self, url):
        for _ in range(MAX_REDIRECTS + 1):
            if not in_scope(url, self.allow, self.deny):
                print(f"[SKIP out of scope] {url}", file=sys.stderr)
                return None
            self.wait()
            status, hdrs, body = raw_get(url, self.headers, self.impersonate)
            if status in REDIRECT_CODES and "location" in hdrs:
                url = urljoin(url, hdrs["location"])
                continue
            break
        else:
            print(f"[SKIP too many redirects] {url}", file=sys.stderr)
            return None
        if status != 200:
            print(f"[{status}] {url}", file=sys.stderr)
            self.log(url, None, None, status)
            return None
        return self.store(url, body, status)

    def store(self, url, body, status):
        digest = hashlib.sha256(body).hexdigest()
        cas = os.path.join(self.base, "cas", "sha256", digest)
        if not os.path.exists(cas):
            with open(cas, "wb") as fh:
                fh.write(body)
        name = os.path.basename(urlparse(url).path) or "index"
        logical = os.path.join(self.base, "raw", name)
        if os.path.exists(logical) or os.path.islink(logical):
            logical = os.path.join(self.base, "raw", f"{digest[:8]}_{name}")
        try:
            os.symlink(os.path.abspath(cas), logical)
        except OSError:
            shutil.copyfile(cas, logical)
        self.log(url, digest, os.path.relpath(logical, self.base), status, len(body))
        print(f"[ok] {url} -> {os.path.relpath(logical, self.base)}")
        return digest

    def log(self, url, digest, logical, status, size=0):
        self.manifest["files"].append({
            "url": url, "sha256": digest, "logical_path": logical,
            "http_status": status, "size_bytes": size,
            "discovered_via": self.via,
            "method_used": f"curl_cffi impersonate={self.impersonate}" if self.impersonate else "urllib",
            "date_collected": now(),
        })

    def save(self):
        with open(self.manifest_path, "w", encoding="utf-8") as fh:
            json.dump(self.manifest, fh, indent=2)


def now():
    return datetime.now(timezone.utc).isoformat()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", required=True, help="js-collect-output/<target> (must contain scope.txt)")
    ap.add_argument("--via", default="manual", help="how the URL was discovered (recorded in manifest)")
    ap.add_argument("--urls-file")
    ap.add_argument("--header", action="append", default=[], help='e.g. "Cookie: a=b" (repeatable)')
    ap.add_argument("--impersonate", help="curl_cffi browser fingerprint, e.g. chrome124")
    ap.add_argument("--confirm-program-allows-bypass", action="store_true")
    ap.add_argument("urls", nargs="*")
    a = ap.parse_args()

    if a.impersonate and not a.confirm_program_allows_bypass:
        sys.exit("--impersonate needs --confirm-program-allows-bypass "
                 "(only use it if the program permits working around bot protection)")
    if not os.path.exists(os.path.join(a.dir, "scope.txt")):
        sys.exit("missing scope.txt in --dir; create it before any request (Stage 0)")

    urls = list(a.urls)
    if a.urls_file:
        with open(a.urls_file, encoding="utf-8") as fh:
            urls += [u.strip() for u in fh if u.strip()]
    headers = {"User-Agent": "Mozilla/5.0"}
    for h in a.header:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    f = Fetcher(a.dir, a.via, headers, a.impersonate)
    try:
        for u in dict.fromkeys(urls):
            f.fetch(u)
    finally:
        f.save()


if __name__ == "__main__":
    main()
