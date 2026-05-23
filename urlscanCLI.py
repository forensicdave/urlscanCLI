#!/usr/bin/env python3
"""urlscanCLI — urlscan.io command-line tool

Searches urlscan.io for previous scans of a domain or IP address / CIDR range.
Accepts defanged formats (e.g. example[.]com, 1[.]2[.]3[.]4, 2001[:]db8[::]/32).

More information: https://thrunter.org/urlscanCLI
"""

import argparse
import csv
import io
import json
import os
import re
import subprocess
import sys
import time
from contextlib import redirect_stdout
from datetime import datetime, timezone
from typing import Optional
import urllib.request
import urllib.parse
import urllib.error


VERSION = "2026-03-15"

URLSCAN_BASE = "https://urlscan.io/api/v1"
KEYCHAIN_SERVICE = "urlscanCLI"
KEYCHAIN_ACCOUNT = "api-key"

_debug     = False
_useragent = "Urlscan (+https://thrunter.org/urlscan)"
_outfile   = None


def dbg(msg: str) -> None:
    if _debug:
        print(f"[DEBUG] {msg}", file=sys.stderr)


def _mask(key: Optional[str]) -> str:
    """Partially redact an API key for safe debug display."""
    if not key:
        return "(none)"
    return key[:4] + "..." + key[-4:] if len(key) > 8 else "****"


def _safe_filename_part(value: str) -> str:
    """Escape a query string for safe use in a filename."""
    safe = re.sub(r'[^A-Za-z0-9\-]', '_', value)
    safe = re.sub(r'_+', '_', safe)
    return safe.strip('_')


def _emit(content: str, logdir: Optional[str], operation: str, query: str, fmt: str = "txt") -> None:
    """Write content to stdout and, if logdir is set, also save it to a timestamped log file.

    fmt should be "txt", "json", or "csv".

    If a global output filename (-o/--output) is set, the content is *redirected*
    to that file instead of stdout (used verbatim; placed inside --logdir if that
    is also given, otherwise written relative to the current directory or as an
    absolute path). When no output filename is set, the content goes to stdout,
    and a copy is also saved if --logdir is given, using an auto-generated
    timestamped name. Notifications, debug, and progress always go to stderr.
    """
    if not _outfile:
        sys.stdout.write(content)
    if _outfile:
        path = os.path.join(logdir, _outfile) if logdir else _outfile
    elif logdir:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        ext = fmt
        query_part = _safe_filename_part(query)
        filename = f"URLSCAN_{ts}_{operation}_{query_part}.{ext}" if query_part else f"URLSCAN_{ts}_{operation}.{ext}"
        path = os.path.join(logdir, filename)
    else:
        return
    dbg(f"Writing log: {path}")
    try:
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(content)
        print(f"[Logged to {path}]", file=sys.stderr)
    except OSError as exc:
        print(f"Warning: could not write log file {path!r}: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Keychain helpers (macOS)
# ---------------------------------------------------------------------------

def keychain_save(key: str) -> None:
    """Save the API key to the macOS keychain."""
    dbg(f"Saving API key to keychain  service={KEYCHAIN_SERVICE!r}  account={KEYCHAIN_ACCOUNT!r}  key={_mask(key)}")
    result = subprocess.run(
        ["security", "add-generic-password",
         "-s", KEYCHAIN_SERVICE,
         "-a", KEYCHAIN_ACCOUNT,
         "-w", key,
         "-U"],
        capture_output=True,
    )
    dbg(f"keychain save  returncode={result.returncode}")
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode().strip())


def keychain_load() -> Optional[str]:
    """Load the API key from the macOS keychain. Returns None if not found."""
    dbg(f"Loading API key from keychain  service={KEYCHAIN_SERVICE!r}  account={KEYCHAIN_ACCOUNT!r}")
    result = subprocess.run(
        ["security", "find-generic-password",
         "-s", KEYCHAIN_SERVICE,
         "-a", KEYCHAIN_ACCOUNT,
         "-w"],
        capture_output=True,
    )
    if result.returncode == 0:
        key = result.stdout.decode().strip() or None
        dbg(f"Keychain hit  key={_mask(key)}")
        return key
    dbg("Keychain miss — no stored API key found")
    return None


def keychain_delete() -> bool:
    """Delete the API key from the macOS keychain. Returns True if deleted."""
    dbg(f"Deleting API key from keychain  service={KEYCHAIN_SERVICE!r}  account={KEYCHAIN_ACCOUNT!r}")
    result = subprocess.run(
        ["security", "delete-generic-password",
         "-s", KEYCHAIN_SERVICE,
         "-a", KEYCHAIN_ACCOUNT],
        capture_output=True,
    )
    dbg(f"keychain delete  returncode={result.returncode}")
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Domain normalisation
# ---------------------------------------------------------------------------

def defang(value: str) -> str:
    """Convert a defanged domain/URL to a plain domain name."""
    original = value
    value = value.strip()
    # Strip scheme including defanged variants: hxxp://, hxxps://, http://, https://
    value = re.sub(r'^hxx?ps?[:\[:\]]+/{0,2}', '', value, flags=re.IGNORECASE)
    value = re.sub(r'^https?://', '', value, flags=re.IGNORECASE)
    # Replace [.], [dot], (dot), {.} etc. with a real dot
    value = re.sub(r'\[\.\]|\[dot\]|\(dot\)|\{\.\}|\[:\]', '.', value, flags=re.IGNORECASE)
    # Remove surrounding brackets that sometimes wrap characters
    value = value.replace('[', '').replace(']', '')
    # Strip path, query, port
    value = value.split('/')[0]
    value = value.split('?')[0]
    value = value.split(':')[0]
    result = value.strip().lower()
    if result != original.strip().lower():
        dbg(f"Defang  {original!r}  →  {result!r}")
    else:
        dbg(f"Defang  {result!r}  (no changes)")
    return result


def defang_ip(value: str) -> str:
    """Normalise a defanged IP address or CIDR range.

    Handles IPv4 (1[.]2[.]3[.]4), IPv6 (2001[:]db8[:]::1),
    and CIDR suffixes (1[.]2[.]3[.]0/24, 2001[:]db8[::]/32).
    """
    original = value.strip()
    v = original
    # Replace defanged dots: [.] [dot] (dot) {.}
    v = re.sub(r'\[\.\]|\[dot\]|\(dot\)|\{\.\}', '.', v, flags=re.IGNORECASE)
    # Replace defanged colons: [:] [colon] (colon) — used in IPv6
    v = re.sub(r'\[:\]|\[colon\]|\(colon\)', ':', v, flags=re.IGNORECASE)
    # Drop any remaining brackets/parens (e.g. (1.2.3.4))
    v = re.sub(r'[\[\]()]', '', v)
    result = v.strip()
    if result != original:
        dbg(f"Defang IP  {original!r}  →  {result!r}")
    else:
        dbg(f"Defang IP  {result!r}  (no changes)")
    return result


def defang_url(value: str) -> str:
    """Normalise a defanged URL, preserving the full path and query string.

    Unlike defang(), this function keeps everything after the host so the
    complete URL can be submitted for scanning.
    """
    original = value.strip()
    v = original
    # Fix defanged scheme: hxxps:// -> https://, hxxp:// -> http://
    v = re.sub(r'^hxxps://', 'https://', v, flags=re.IGNORECASE)
    v = re.sub(r'^hxxp://',  'http://',  v, flags=re.IGNORECASE)
    # Add a scheme if none is present so urlparse can split host from path
    if not re.match(r'^https?://', v, re.IGNORECASE):
        v = 'https://' + v
    # Split into scheme+host and everything after, defang only the host part
    m = re.match(r'^(https?://)([^/?#]*)(.*)', v, re.IGNORECASE | re.DOTALL)
    if m:
        scheme, host, rest = m.groups()
        host = re.sub(r'\[\.\]|\[dot\]|\(dot\)|\{\.\}', '.', host, flags=re.IGNORECASE)
        host = re.sub(r'\[:\]|\[colon\]|\(colon\)', ':', host, flags=re.IGNORECASE)
        host = re.sub(r'[\[\]()]', '', host)
        v = scheme + host + rest
    result = v.strip()
    if result != original:
        dbg(f"Defang URL  {original!r}  →  {result!r}")
    else:
        dbg(f"Defang URL  {result!r}  (no changes)")
    return result


def validate_ip_or_cidr(value: str) -> bool:
    """Return True if value looks like an IPv4, IPv6, or CIDR address."""
    import ipaddress
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def _get(url: str, api_key: Optional[str]) -> dict:
    headers = {"User-Agent": _useragent}
    if api_key:
        headers["API-Key"] = api_key
    dbg(f"GET {url}")
    dbg(f"    API key: {_mask(api_key)}")
    req = urllib.request.Request(url, headers=headers)
    t0 = time.monotonic()
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
        elapsed = time.monotonic() - t0
        dbg(f"    HTTP {resp.status}  {len(body)} bytes  {elapsed:.2f}s")
        return json.loads(body)


def search(query: str, api_key: Optional[str], size: int = 10) -> dict:
    params = urllib.parse.urlencode({"q": query, "size": size})
    url = f"{URLSCAN_BASE}/search/?{params}"
    dbg(f"Search query: {query!r}  size={size}")
    data = _get(url, api_key)
    dbg(f"Search returned {len(data.get('results', []))} hits  total={data.get('total', 0)}  has_more={data.get('has_more', False)}")
    return data


def search_domain(domain: str, api_key: Optional[str], size: int = 10) -> dict:
    return search(f"page.domain:{domain}", api_key, size)


def search_hash(sha256: str, api_key: Optional[str], size: int = 10) -> dict:
    return search(f"files.sha256:{sha256}", api_key, size)


def submit_scan(url: str, visibility: str, api_key: Optional[str]) -> dict:
    """Submit a URL to urlscan.io for scanning and return the API response."""
    endpoint = f"{URLSCAN_BASE}/scan/"
    headers = {
        "User-Agent":   _useragent,
        "Content-Type": "application/json",
    }
    if api_key:
        headers["API-Key"] = api_key
    payload = json.dumps({"url": url, "visibility": visibility}).encode()
    dbg(f"POST {endpoint}")
    dbg(f"    visibility={visibility!r}  url={url!r}  API key={_mask(api_key)}")
    req = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")
    t0 = time.monotonic()
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
        elapsed = time.monotonic() - t0
        dbg(f"    HTTP {resp.status}  {len(body)} bytes  {elapsed:.2f}s")
        return json.loads(body)


def poll_result(uuid: str, api_key: Optional[str]) -> Optional[dict]:
    """Try to fetch a scan result once.

    Returns the result dict if available, None if the scan is not yet ready
    (HTTP 404), or raises urllib.error.HTTPError for any other HTTP error.
    """
    url = f"{URLSCAN_BASE}/result/{uuid}/"
    dbg(f"Polling result for UUID: {uuid}")
    try:
        data = _get(url, api_key)
        dbg(f"Poll hit  page={data.get('page', {}).get('url', '?')}")
        return data
    except urllib.error.HTTPError as e:
        if e.code == 404:
            dbg("Poll miss — scan not yet ready (404)")
            return None
        raise


def extract_scan_uuid(value: str) -> str:
    """Return the bare UUID from a scan ID or a full urlscan result URL."""
    value = value.strip()
    # Accept full result URLs: https://urlscan.io/result/<uuid>/
    m = re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', value, re.IGNORECASE)
    return m.group(1).lower() if m else value


def get_hostname(hostname: str, api_key: Optional[str]) -> dict:
    """Call the urlscan hostname API and return the raw response."""
    url = f"{URLSCAN_BASE}/hostname/{urllib.parse.quote(hostname, safe='')}/"
    dbg(f"Hostname API: {url}")
    return _get(url, api_key)


def get_quota(api_key: str) -> dict:
    """Call the urlscan user quotas API and return the raw response."""
    url = "https://urlscan.io/user/quotas/"
    dbg(f"Quota API: {url}")
    return _get(url, api_key)


def get_available_brands(api_key: str) -> dict:
    """Call the urlscan available brands API and return the raw response."""
    url = f"{URLSCAN_BASE}/pro/availableBrands"
    dbg(f"Available Brands API: {url}")
    return _get(url, api_key)


def get_brands_summary(api_key: str) -> dict:
    """Call the urlscan brands summary API and return the raw response.

    This endpoint is slower — it returns total detections and the most recent
    phishing hit for every tracked brand.
    """
    url = f"{URLSCAN_BASE}/pro/brands"
    dbg(f"Brands Summary API: {url}")
    return _get(url, api_key)


def search_ip(ip_or_cidr: str, api_key: Optional[str], size: int = 10) -> dict:
    import ipaddress
    net = ipaddress.ip_network(ip_or_cidr, strict=False)
    is_single_ipv4 = (net.prefixlen == net.max_prefixlen
                      and net.version == 4)
    if is_single_ipv4:
        # Simple field query works for plain IPv4 addresses
        query = f"page.ip:{net.network_address}"
    else:
        # IPv6 addresses contain ':' which ES query-string syntax reserves,
        # and '/' in CIDR also breaks the parser — use ES range syntax for both.
        query = f"page.ip:[{net.network_address} TO {net.broadcast_address}]"
    dbg(f"IP search query: {query!r}")
    return search(query, api_key, size)


def get_result(uuid: str, api_key: Optional[str]) -> dict:
    dbg(f"Fetching detail for UUID: {uuid}")
    try:
        data = _get(f"{URLSCAN_BASE}/result/{uuid}/", api_key)
        dbg(f"Detail fetch OK  page={data.get('page', {}).get('url', '?')}")
        return data
    except urllib.error.HTTPError as e:
        dbg(f"Detail fetch failed  HTTP {e.code} — skipping")
        return {}


# ---------------------------------------------------------------------------
# Quota display
# ---------------------------------------------------------------------------

def print_quota_text(data: dict) -> None:
    """Print the quota/status response in human-readable form."""
    SEP  = "=" * 64
    DASH = "-" * 64

    print(SEP)
    print("  urlscan.io — API Quota Status")
    print(SEP)

    scope = data.get("scope")
    if scope:
        print(f"  Scope:        {scope}")

    limits = data.get("limits", {})
    if not limits:
        print("  (no quota data returned)")
        print(SEP)
        return

    # Known action types shown in a fixed order; remainder printed after
    ACTION_TYPES = ("search", "retrieve", "public", "unlisted", "private", "livescan", "malicious")
    WINDOWS      = ("minute", "hour", "day")

    print()
    for action in ACTION_TYPES:
        block = limits.get(action)
        if not isinstance(block, dict):
            continue
        print(DASH)
        print(f"  {action.capitalize()}")
        print(DASH)
        for window in WINDOWS:
            wb = block.get(window)
            if not isinstance(wb, dict):
                continue
            used      = wb.get("used", 0)
            limit     = wb.get("limit", 0)
            remaining = wb.get("remaining", limit - used)
            pct       = wb.get("percent", 0)
            reset     = wb.get("reset", "")
            reset_str = f"  resets {reset}" if reset else ""
            print(f"  {window:<8}  {used:>7,} / {limit:<9,}  {remaining:>8,} left  ({pct}%){reset_str}")
        last_activity = block.get("lastActivity", "")
        last_ip       = block.get("lastIP", "")
        if last_activity:
            print(f"  Last activity: {last_activity}  from {last_ip}" if last_ip else
                  f"  Last activity: {last_activity}")
        print()

    # Account-level metadata
    features = limits.get("features", [])
    products  = limits.get("products", [])
    max_results    = limits.get("maxSearchResults")
    max_retention  = limits.get("maxRetentionPeriodDays")
    if features or products or max_results or max_retention:
        print(DASH)
        print("  Account")
        print(DASH)
        if products:
            print(f"  Plans:        {', '.join(products)}")
        if features:
            print(f"  Features:     {', '.join(features)}")
        if max_results is not None:
            print(f"  Max results:  {max_results:,}")
        if max_retention is not None:
            print(f"  Retention:    {max_retention} days")
        print()

    print(SEP)


# ---------------------------------------------------------------------------
# Brand display
# ---------------------------------------------------------------------------

def print_brands_text(kits: list) -> None:
    """Print the available brands list in human-readable form."""
    SEP  = "=" * 64
    DASH = "-" * 64

    print(SEP)
    print("  urlscan.io — Tracked Brands")
    print(SEP)
    print(f"  Total brands: {len(kits)}")
    print()
    print(DASH)
    print(f"  {'Brand':<30} {'Vertical':<20} {'Country'}")
    print(DASH)
    for kit in kits:
        name     = kit.get("name", "")
        vertical = ", ".join(kit.get("vertical", []))
        country  = ", ".join(c.upper() for c in kit.get("country", []))
        print(f"  {name:<30} {vertical:<20} {country}")
    print()
    print(SEP)


def _format_brands_csv(kits: list) -> str:
    """Format available brands as CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["key", "name", "vertical", "country", "region", "keywords", "domains", "asns"])
    for kit in kits:
        writer.writerow([
            kit.get("key", ""),
            kit.get("name", ""),
            "; ".join(kit.get("vertical", [])),
            "; ".join(kit.get("country", [])),
            "; ".join(kit.get("region", [])),
            "; ".join(kit.get("keywords", [])),
            "; ".join(kit.get("terms", {}).get("domains", [])),
            "; ".join(kit.get("terms", {}).get("asns", [])),
        ])
    return buf.getvalue()


def print_brand_detail_text(brand_info: dict, hits: list, total: int) -> None:
    """Print brand phishing tracking detail in human-readable form."""
    SEP  = "=" * 64
    DASH = "-" * 64

    name     = brand_info.get("name", "")
    key      = brand_info.get("key", "")
    vertical = ", ".join(brand_info.get("vertical", []))
    country  = ", ".join(c.upper() for c in brand_info.get("country", []))
    domains  = brand_info.get("terms", {}).get("domains", [])
    asns     = brand_info.get("terms", {}).get("asns", [])
    keywords = brand_info.get("keywords", [])

    print(SEP)
    print(f"  urlscan.io — Brand: {name}")
    print(SEP)
    print(f"  Key:        {key}")
    print(f"  Vertical:   {vertical}")
    print(f"  Country:    {country}")
    if keywords:
        print(f"  Keywords:   {', '.join(keywords)}")
    if domains:
        print(f"  Domains:    {', '.join(domains[:10])}")
        if len(domains) > 10:
            print(f"              (+{len(domains) - 10} more)")
    if asns:
        print(f"  ASNs:       {', '.join(asns)}")
    print()

    print(DASH)
    print(f"  Phishing Detections")
    print(DASH)
    print(f"  Total detected: {total:,}")
    print()

    if hits:
        print(DASH)
        print("  Most Recent Detection")
        print(DASH)
        for hit in hits:
            task = hit.get("task", {})
            uuid = hit.get("_id", task.get("uuid", ""))
            scan_time = _fmt_date(task.get("time", ""))
            # Brand summary hits have minimal fields; show what's available
            url   = task.get("url", hit.get("page", {}).get("url", ""))
            title = hit.get("page", {}).get("title", "")

            print(f"  Time:       {scan_time}")
            if url:
                print(f"  URL:        {url}")
            if title:
                print(f"  Title:      {title[:80]}")
            if uuid:
                print(f"  Report:     https://urlscan.io/result/{uuid}/")
            print()

    print(SEP)


# ---------------------------------------------------------------------------
# Data extraction
# ---------------------------------------------------------------------------

def extract_whois(result: dict) -> dict:
    """Pull registration data from the detailed scan result."""
    raw = (result.get("meta", {})
                 .get("processors", {})
                 .get("whois", {})
                 .get("data", {}))
    if not raw:
        dbg("WHOIS: no data found in result")
        return {}
    dbg(f"WHOIS: raw keys present: {sorted(raw.keys())}")

    def first(val):
        """Return first item if list, else value itself."""
        if isinstance(val, list):
            return val[0] if val else ""
        return val or ""

    def as_list(val):
        if isinstance(val, list):
            return val
        if isinstance(val, str):
            return [v.strip() for v in val.split(",") if v.strip()]
        return []

    return {
        "registrar":    first(raw.get("registrar", "")),
        "registrant":   first(raw.get("registrant_org", raw.get("org", ""))),
        "created":      first(raw.get("creation_date",  raw.get("created", ""))),
        "updated":      first(raw.get("updated_date",   raw.get("updated", ""))),
        "expires":      first(raw.get("expiration_date", raw.get("expires", ""))),
        "name_servers": as_list(raw.get("name_servers", raw.get("nameservers", []))),
        "status":       as_list(raw.get("status", [])),
        "dnssec":       raw.get("dnssec", ""),
    }


def extract_certs(result: dict) -> list:
    """Extract unique TLS certificates from the detailed scan result."""
    raw_certs = result.get("lists", {}).get("certificates", [])
    dbg(f"Certs: {len(raw_certs)} raw certificate entries in result")
    certs = []
    seen = set()
    for cert in raw_certs:
        subject = cert.get("subjectName", "")
        if subject in seen:
            continue
        seen.add(subject)

        def ts(val):
            if isinstance(val, (int, float)) and val > 0:
                return datetime.fromtimestamp(val, tz=timezone.utc).strftime("%Y-%m-%d")
            return str(val) if val else ""

        certs.append({
            "subject":    subject,
            "issuer":     cert.get("issuer", ""),
            "valid_from": ts(cert.get("validFrom")),
            "valid_to":   ts(cert.get("validTo")),
            "san":        cert.get("sanList", []),
        })
    dbg(f"Certs: {len(certs)} unique subjects after dedup")
    return certs


def _fmt_date(s: str) -> str:
    if not s:
        return ""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            pass
    return s


def _verdict_label(verdicts: dict) -> str:
    overall = verdicts.get("overall", {})
    if overall.get("malicious"):
        return " [MALICIOUS]"
    score = overall.get("score", 0)
    if score and score > 0:
        return f" [score:{score}]"
    return ""


def print_submission_text(resp: dict) -> None:
    """Print the result of a scan submission in human-readable form."""
    SEP  = "=" * 64
    DASH = "-" * 64
    print(SEP)
    print("  urlscan.io — Scan Submitted")
    print(SEP)
    print(f"  Message:    {resp.get('message', '')}")
    print(f"  URL:        {resp.get('url', '')}")
    print(f"  Visibility: {resp.get('visibility', '')}")
    print()
    print(DASH)
    print("  Scan Result")
    print(DASH)
    print(f"  UUID:       {resp.get('uuid', '')}")
    print(f"  Result URL: {resp.get('result', '')}")
    print(f"  API URL:    {resp.get('api', '')}")
    print(SEP)


def print_scan_text(r: dict) -> None:
    """Print a human-readable report for a single scan result."""
    SEP  = "=" * 64
    DASH = "-" * 64

    task     = r.get("task", {})
    page     = r.get("page", {})
    verdicts = r.get("verdicts", {})
    stats    = r.get("stats", {})
    lists    = r.get("lists", {})
    data     = r.get("data", {})
    meta     = r.get("meta", {})

    overall  = verdicts.get("overall", {})
    engines  = verdicts.get("engines", {})
    urlscan_v = verdicts.get("urlscan", {})
    community = verdicts.get("community", {})

    def brand_names(brands: list) -> list:
        """Normalise brands — may be plain strings or dicts with a 'name' key."""
        return [b["name"] if isinstance(b, dict) else b for b in brands]

    uuid = task.get("uuid", "")

    # --- Header --------------------------------------------------------------
    print(SEP)
    print(f"  urlscan.io Scan Report")
    print(SEP)
    print(f"  Scan ID:    {uuid}")
    print(f"  Scanned:    {_fmt_date(task.get('time', ''))}")
    print(f"  URL:        {task.get('url', '')}")
    print(f"  Method:     {task.get('method', '')}  ({task.get('source', '')})")
    print(f"  Visibility: {task.get('visibility', '')}")
    if task.get("tags"):
        print(f"  Tags:       {', '.join(task['tags'])}")
    print()

    # --- Verdict -------------------------------------------------------------
    print(DASH)
    print("  Verdict")
    print(DASH)
    malicious = overall.get("malicious", False)
    score     = overall.get("score", 0)
    verdict_str = "MALICIOUS" if malicious else ("Suspicious" if score > 0 else "Clean")
    print(f"  Overall:    {verdict_str}  (score: {score})")

    # urlscan engine
    if urlscan_v.get("hasVerdicts"):
        uscore = urlscan_v.get("score", 0)
        umali  = urlscan_v.get("malicious", False)
        print(f"  urlscan:    {'MALICIOUS' if umali else 'Clean'}  (score: {uscore})")
        if urlscan_v.get("categories"):
            print(f"    Categories: {', '.join(urlscan_v['categories'])}")
        if urlscan_v.get("brands"):
            print(f"    Brands:     {', '.join(brand_names(urlscan_v['brands']))}")

    # AV / threat-intel engines
    if engines.get("hasVerdicts") or engines.get("enginesTotal", 0) > 0:
        etotal = engines.get("enginesTotal", 0)
        emali  = engines.get("maliciousTotal", 0)
        ebenign = engines.get("benignTotal", 0)
        print(f"  Engines:    {emali} malicious / {ebenign} benign / {etotal} total")
        if engines.get("maliciousVerdicts"):
            print(f"    Flagged by: {', '.join(engines['maliciousVerdicts'][:8])}")

    # Community votes
    if community.get("votesTotal", 0) > 0:
        print(f"  Community:  {community['votesMalicious']} malicious / "
              f"{community['votesBenign']} benign  ({community['votesTotal']} votes)")

    if overall.get("tags"):
        print(f"  Tags:       {', '.join(overall['tags'])}")
    print()

    # --- Page info -----------------------------------------------------------
    print(DASH)
    print("  Page")
    print(DASH)
    fields = [
        ("URL",        page.get("url")),
        ("Domain",     page.get("domain")),
        ("IP",         page.get("ip")),
        ("PTR",        page.get("ptr")),
        ("Country",    (f"{page.get('city', '')} {page.get('country', '')}".strip()) or None),
        ("ASN",        (f"{page.get('asn', '')} {page.get('asnname', '')}".strip()) or None),
        ("Server",     page.get("server")),
        ("Status",     str(page["status"]) if page.get("status") else None),
        ("MIME type",  page.get("mimeType")),
        ("Title",      page.get("title")),
        ("Language",   page.get("language")),
    ]
    for label_str, val in fields:
        if val:
            print(f"  {label_str:<12}{val}")

    # TLS info from page fields
    tls_issuer = page.get("tlsIssuer")
    tls_from   = page.get("tlsValidFrom")
    tls_days   = page.get("tlsValidDays")
    if tls_issuer or tls_from:
        tls_line = f"  {'TLS':<12}{tls_issuer or ''}"
        if tls_from:
            tls_line += f"  (valid from {tls_from[:10]}"
            if tls_days:
                tls_line += f", {tls_days} days remaining"
            tls_line += ")"
        print(tls_line)

    if page.get("umbrellaRank"):
        print(f"  {'Umbrella':<12}rank #{page['umbrellaRank']:,}")
    print()

    # --- Technologies --------------------------------------------------------
    wappa = meta.get("processors", {}).get("wappa", {}).get("data", [])
    if wappa:
        print(DASH)
        print("  Detected Technologies")
        print(DASH)
        for tech in wappa:
            cats = ", ".join(c["name"] for c in tech.get("categories", []))
            conf = tech.get("confidenceTotal", 0)
            line = f"  {tech['app']:<28}  {cats}"
            if conf < 100:
                line += f"  (confidence: {conf}%)"
            print(line)
        print()

    # --- Certificates --------------------------------------------------------
    certs = extract_certs(r)
    if certs:
        print(DASH)
        print("  TLS Certificates")
        print(DASH)
        for cert in certs:
            print(f"  Subject:    {cert['subject']}")
            if cert["issuer"]:
                print(f"  Issuer:     {cert['issuer']}")
            if cert["valid_from"] or cert["valid_to"]:
                print(f"  Validity:   {cert['valid_from']}  →  {cert['valid_to']}")
            san = cert.get("san", [])
            if san:
                preview = san[:6]
                extra   = len(san) - len(preview)
                line    = ", ".join(preview)
                if extra:
                    line += f"  (+{extra} more)"
                print(f"  SANs:       {line}")
            print()

    # --- Observed IPs --------------------------------------------------------
    ips = lists.get("ips", [])
    if ips:
        print(DASH)
        print("  Observed IPs")
        print(DASH)
        for ds in stats.get("ipStats", []):
            ip_addr  = ds.get("ip", "")
            asn_info = ds.get("asn", {})
            country  = asn_info.get("country", "")
            asn_name = asn_info.get("name", "")
            reqs     = ds.get("requests", "")
            domains  = ", ".join(ds.get("domains", [])[:4])
            loc      = f" ({country})" if country else ""
            asn_str  = f"  {asn_name}" if asn_name else ""
            print(f"  {ip_addr}{loc}{asn_str}  [{reqs} requests]  {domains}")
        print()

    # --- Observed domains ----------------------------------------------------
    domains = lists.get("domains", [])
    if domains:
        print(DASH)
        print("  Observed Domains")
        print(DASH)
        for ds in stats.get("domainStats", []):
            dom   = ds.get("domain", "")
            count = ds.get("count", "")
            size  = ds.get("encodedSize", 0)
            size_str = f"{size/1024:.1f} KB" if size else ""
            print(f"  {dom:<40}  {count:>3} requests  {size_str}")
        print()

    # --- Resource stats ------------------------------------------------------
    print(DASH)
    print("  Resource Summary")
    print(DASH)
    total_reqs   = sum(s.get("count", 0) for s in stats.get("protocolStats", []))
    secure_pct   = stats.get("securePercentage", 0)
    uniq_countries = stats.get("uniqCountries", 0)
    total_links  = stats.get("totalLinks", 0)
    malicious_res = stats.get("malicious", 0)
    print(f"  Requests:   {total_reqs}  ({secure_pct}% HTTPS)")
    print(f"  Countries:  {uniq_countries} unique")
    print(f"  Links:      {total_links} outbound")
    if malicious_res:
        print(f"  Malicious:  {malicious_res} flagged resources")
    print()

    # --- Links ---------------------------------------------------------------
    links = data.get("links", [])
    if links:
        print(DASH)
        print("  Outbound Links")
        print(DASH)
        for lnk in links[:20]:
            href = lnk.get("href", "")
            text = lnk.get("text", "").strip()
            label_part = f"  [{text[:30]}]  " if text else "  "
            print(f"{label_part}{href}")
        if len(links) > 20:
            print(f"  ... and {len(links) - 20} more")
        print()

    # --- URLs / screenshots --------------------------------------------------
    print(DASH)
    print("  Report Links")
    print(DASH)
    print(f"  Report:     {task.get('reportURL', f'https://urlscan.io/result/{uuid}/')}")
    print(f"  Screenshot: {task.get('screenshotURL', '')}")
    print(f"  DOM:        {task.get('domURL', '')}")
    print(SEP)


# Human-readable labels for hostname API source types
_HOSTNAME_SOURCE_LABELS = {
    "ct":               "Certificate Transparency",
    "pdns":             "Passive DNS",
    "scan":             "Direct scan",
    "scan-cert-subject": "Certificate subject (in scan)",
    "scan-link":        "Hyperlink (in scan)",
    "seenDates":        "Overall activity window",
}
# Sources that are internal bookkeeping — skip in output
_HOSTNAME_SOURCE_SKIP = {"shardDate"}


def extract_hostname_summary(results: list) -> dict:
    """Distil the hostname API results list into a per-source summary dict."""
    summary = {}
    for r in results:
        src = r.get("source", "")
        if src in _HOSTNAME_SOURCE_SKIP:
            continue
        entry = summary.setdefault(src, {"first_seen": None, "last_seen": None})
        for field in ("first_seen", "last_seen"):
            val = r.get(field)
            if not val:
                continue
            if entry[field] is None or val < entry[field]:
                entry[field] = val if field == "first_seen" else entry[field]
            if entry[field] is None or val > entry[field]:
                entry[field] = val if field == "last_seen" else entry[field]
        # Simpler: just keep whichever is earliest/latest across all records per source
        fs = r.get("first_seen")
        ls = r.get("last_seen")
        if fs and (entry["first_seen"] is None or fs < entry["first_seen"]):
            entry["first_seen"] = fs
        if ls and (entry["last_seen"] is None or ls > entry["last_seen"]):
            entry["last_seen"] = ls
    dbg(f"Hostname summary: {len(summary)} source types: {sorted(summary)}")
    return summary


def print_hostname_text(hostname: str, summary: dict, total: int):
    SEP  = "=" * 64
    DASH = "-" * 64

    print(SEP)
    print(f"  urlscan.io Hostname — {hostname}")
    print(SEP)
    print(f"  Total records: {total}")
    print()

    if not summary:
        print("  No hostname data found.")
        print(SEP)
        return

    # Overall activity window first (if present)
    overall = summary.get("seenDates")
    if overall:
        print(DASH)
        print("  Activity Window")
        print(DASH)
        print(f"  First seen:  {_fmt_date(overall['first_seen'])}")
        print(f"  Last seen:   {_fmt_date(overall['last_seen'])}")
        print()

    # Per-source breakdown
    print(DASH)
    print("  Observed In")
    print(DASH)
    order = ["scan", "pdns", "ct", "scan-cert-subject", "scan-link"]
    shown = set()
    for src in order + sorted(set(summary) - set(order)):
        if src == "seenDates" or src not in summary:
            continue
        if src in shown:
            continue
        shown.add(src)
        entry = summary[src]
        label = _HOSTNAME_SOURCE_LABELS.get(src, src)
        fs = _fmt_date(entry["first_seen"]) or "unknown"
        ls = _fmt_date(entry["last_seen"])  or "unknown"
        print(f"  {label}")
        print(f"    First seen:  {fs}")
        print(f"    Last seen:   {ls}")
        print()

    print(SEP)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_text(label: str, hits: list, total: int, whois: dict, certs: list):
    SEP  = "=" * 64
    DASH = "-" * 64

    print(SEP)
    print(f"  urlscan.io — {label}")
    print(SEP)
    print(f"  Total scans indexed: {total}   Showing: {len(hits)}")
    print()

    # --- Registration info --------------------------------------------------
    if whois:
        print(DASH)
        print("  Domain Registration (WHOIS)")
        print(DASH)
        fields = [
            ("Registrar",    whois.get("registrar")),
            ("Registrant",   whois.get("registrant")),
            ("Created",      whois.get("created")),
            ("Updated",      whois.get("updated")),
            ("Expires",      whois.get("expires")),
            ("DNSSEC",       whois.get("dnssec")),
        ]
        for label, val in fields:
            if val:
                print(f"  {label:<14}{val}")
        ns = whois.get("name_servers", [])
        if ns:
            print(f"  {'Name Servers':<14}{', '.join(ns[:6])}")
        status = whois.get("status", [])
        if status:
            # These can be long; show up to 2
            print(f"  {'Status':<14}{'; '.join(status[:2])}")
        print()

    # --- Certificates -------------------------------------------------------
    if certs:
        print(DASH)
        print("  TLS Certificates (most recent scan)")
        print(DASH)
        for cert in certs[:8]:
            print(f"  Subject:    {cert['subject']}")
            if cert["issuer"]:
                print(f"  Issuer:     {cert['issuer']}")
            if cert["valid_from"] or cert["valid_to"]:
                print(f"  Validity:   {cert['valid_from']}  →  {cert['valid_to']}")
            san = cert.get("san", [])
            if san:
                preview = san[:6]
                extra = len(san) - len(preview)
                line = ", ".join(preview)
                if extra > 0:
                    line += f"  (+{extra} more)"
                print(f"  SANs:       {line}")
            print()

    # --- Scan history -------------------------------------------------------
    print(DASH)
    print("  Scan History")
    print(DASH)

    if not hits:
        print("  No scans found.")
        print()
    else:
        for i, hit in enumerate(hits, 1):
            task     = hit.get("task", {})
            page     = hit.get("page", {})
            verdicts = hit.get("verdicts", {})
            uuid     = hit.get("_id", task.get("uuid", ""))

            scan_time = _fmt_date(task.get("time", ""))
            url       = task.get("url", page.get("url", ""))
            ip        = page.get("ip", "")
            country   = page.get("country", "")
            asn       = page.get("asn", "")
            asnname   = page.get("asnname", "")
            server    = page.get("server", "")
            title     = page.get("title", "")
            verdict   = _verdict_label(verdicts)

            print(f"  [{i}] {scan_time}{verdict}")
            if url:
                print(f"      URL:     {url}")
            if ip:
                loc = f" ({country})" if country else ""
                asn_str = f"  {asn} {asnname}".rstrip() if asn else ""
                print(f"      IP:      {ip}{loc}{asn_str}")
            if server:
                print(f"      Server:  {server}")
            if title:
                print(f"      Title:   {title[:80]}")
            if uuid:
                print(f"      Report:  https://urlscan.io/result/{uuid}/")
            print()

    print(SEP)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _build_scan_list(hits: list) -> list:
    return [
        {
            "scan_time":  hit.get("task", {}).get("time", ""),
            "url":        hit.get("task", {}).get("url", hit.get("page", {}).get("url", "")),
            "uuid":       hit.get("_id", hit.get("task", {}).get("uuid", "")),
            "ip":         hit.get("page", {}).get("ip", ""),
            "country":    hit.get("page", {}).get("country", ""),
            "asn":        hit.get("page", {}).get("asn", ""),
            "asnname":    hit.get("page", {}).get("asnname", ""),
            "server":     hit.get("page", {}).get("server", ""),
            "title":      hit.get("page", {}).get("title", ""),
            "malicious":  hit.get("verdicts", {}).get("overall", {}).get("malicious", False),
            "score":      hit.get("verdicts", {}).get("overall", {}).get("score", 0),
            "report_url": f"https://urlscan.io/result/{hit['_id']}/" if hit.get("_id") else "",
        }
        for hit in hits
    ]


def _format_csv(hits: list) -> str:
    """Format scan results as CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["scan_time", "url", "domain", "ip", "country", "asn",
                     "asnname", "server", "title", "malicious", "score", "report_url"])
    for hit in hits:
        task = hit.get("task", {})
        page = hit.get("page", {})
        verdicts = hit.get("verdicts", {})
        uuid = hit.get("_id", task.get("uuid", ""))
        writer.writerow([
            task.get("time", ""),
            task.get("url", page.get("url", "")),
            page.get("domain", ""),
            page.get("ip", ""),
            page.get("country", ""),
            page.get("asn", ""),
            page.get("asnname", ""),
            page.get("server", ""),
            page.get("title", ""),
            verdicts.get("overall", {}).get("malicious", False),
            verdicts.get("overall", {}).get("score", 0),
            f"https://urlscan.io/result/{uuid}/" if uuid else "",
        ])
    return buf.getvalue()


def main():
    global _debug, _useragent, _outfile

    parser = argparse.ArgumentParser(
        description=f"urlscanCLI {VERSION} — search and interact with urlscan.io from the command line.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s 'example[.]com'
  %(prog)s 'hxxps://example[.]com/path' --json
  %(prog)s evil.com --size 25 --api-key YOUR_KEY
  %(prog)s --ip 1.2.3.4
  %(prog)s --ip '1[.]2[.]3[.]4'
  %(prog)s --ip 2001:db8::1
  %(prog)s --ip '2001[:]db8[::]/32'
  %(prog)s --ip 192.168.1.0/24 --json
  %(prog)s --hostname www.example.com
  %(prog)s --hostname 'www.example[.]com' --json
  %(prog)s --scan 019cec3d-b942-7124-9337-15b39874e417
  %(prog)s --scan https://urlscan.io/result/019cec3d-b942-7124-9337-15b39874e417/ --json
  %(prog)s --urlscan https://example.com
  %(prog)s --urlscan 'hxxps://evil[.]com/path' --public
  %(prog)s --urlscan https://example.com --unlisted --json
  %(prog)s --urlscan https://example.com --wait
  %(prog)s --urlscan https://example.com --wait --json
  %(prog)s --hash 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
  %(prog)s --hash 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b --json
  %(prog)s --search 'page.domain:example.com AND page.country:US'
  %(prog)s --search 'task.tags:phishing' --csv
  %(prog)s --search 'page.server:nginx AND date:>2024-01-01' --json --size 50
  %(prog)s example.com --csv
  %(prog)s --brands
  %(prog)s --brands --csv
  %(prog)s --brand microsoft
  %(prog)s --brand google --json --size 25

Keychain management (macOS):
  %(prog)s --save-key YOUR_KEY   Save API key to keychain
  %(prog)s --delete-key          Remove API key from keychain
  %(prog)s --status              Show API quota status for the configured key

More information: https://thrunter.org/urlscanCLI
""",
    )
    parser.add_argument("domain",      nargs="?", help="Domain to search (defanged format accepted)")
    parser.add_argument("--ip",        metavar="ADDR",
                        help="IP address or CIDR range to search (defanged format accepted)")
    parser.add_argument("--hostname",  metavar="HOST",
                        help="Hostname to query via the urlscan Hostname API (defanged format accepted)")
    parser.add_argument("--scan",      metavar="SCANID",
                        help="Fetch and display a specific scan result by UUID or full result URL")
    parser.add_argument("--urlscan",   metavar="URL",
                        help="Submit a URL for scanning (default visibility: private)")
    parser.add_argument("--hash",      metavar="SHA256",
                        help="Search for scans containing a file with this SHA256 hash")
    parser.add_argument("--search",    metavar="QUERY",
                        help="Run a raw search query against the urlscan.io search API "
                             "(Elasticsearch query syntax, e.g. 'page.domain:example.com AND page.country:US')")
    parser.add_argument("--brands",    action="store_true",
                        help="List all brands tracked by urlscan.io's phishing detection (requires API key)")
    parser.add_argument("--brand",     metavar="KEY",
                        help="Show phishing tracking details and recent detections for a specific brand key "
                             "(use --brands to discover available keys)")
    vis_group = parser.add_mutually_exclusive_group()
    vis_group.add_argument("--public",   action="store_true",
                           help="Submit scan with public visibility (use with --urlscan)")
    vis_group.add_argument("--unlisted", action="store_true",
                           help="Submit scan with unlisted visibility (use with --urlscan)")
    parser.add_argument("--wait",      action="store_true",
                        help="After submitting with --urlscan, wait for the scan to complete "
                             "and display the full report (initial wait: 30s, retry every 15s)")
    fmt_group = parser.add_mutually_exclusive_group()
    fmt_group.add_argument("--json",  action="store_true", help="Output as JSON")
    fmt_group.add_argument("--csv",   action="store_true",
                           help="Output scan results as CSV (header row + data rows)")
    parser.add_argument("--size",     type=int, default=10, metavar="N",
                        help="Max results to return (default: 10, max: 10000)")
    parser.add_argument("--api-key",  metavar="KEY",
                        help="urlscan.io API key (overrides keychain)")
    parser.add_argument("--save-key", metavar="KEY",
                        help="Save API key to macOS keychain and exit")
    parser.add_argument("--delete-key", action="store_true",
                        help="Delete saved API key from macOS keychain and exit")
    parser.add_argument("--status", action="store_true",
                        help="Show API quota/rate-limit status for the configured API key and exit")
    parser.add_argument("--no-detail", action="store_true",
                        help="Skip fetching the full result (no WHOIS/cert data, faster)")
    parser.add_argument("--logdir",   metavar="DIR",
                        help="Directory to write a copy of the output to (timestamped file)")
    parser.add_argument("-o", "--output", dest="output", metavar="FILE",
                        help="Output file name to write a copy of the output to "
                             "(used verbatim; placed inside --logdir if that is also given)")
    parser.add_argument("--useragent", metavar="UA",
                        help=f"Override the HTTP User-Agent (default: '{_useragent}')")
    parser.add_argument("--debug", "--DEBUG", dest="debug", action="store_true",
                        help="Print debug information to stderr")
    parser.add_argument("--version", action="version", version=f"urlscanCLI {VERSION}")

    args = parser.parse_args()

    _debug = args.debug
    if args.useragent:
        _useragent = args.useragent
    _outfile = args.output
    dbg(f"urlscanCLI starting  debug=True  useragent={_useragent!r}  output={_outfile!r}")

    if args.logdir and not os.path.isdir(args.logdir):
        print(f"Error: --logdir {args.logdir!r} is not an existing directory.", file=sys.stderr)
        sys.exit(1)

    # --- Keychain management (no target required) ----------------------------
    if args.save_key:
        try:
            keychain_save(args.save_key)
            print(f"API key saved to keychain (service: {KEYCHAIN_SERVICE!r}).")
        except RuntimeError as e:
            print(f"Error saving to keychain: {e}", file=sys.stderr)
            sys.exit(1)
        return

    if args.delete_key:
        if keychain_delete():
            print("API key removed from keychain.")
        else:
            print("No API key found in keychain.", file=sys.stderr)
            sys.exit(1)
        return

    # --- Quota status (no target required) -----------------------------------
    if args.status:
        # Resolve key early so we can report it even before the normal key block
        status_key = args.api_key or keychain_load()
        if not status_key:
            print("Error: --status requires an API key (use --api-key or --save-key).",
                  file=sys.stderr)
            sys.exit(1)
        dbg(f"Quota API key: {_mask(status_key)}")
        try:
            data = get_quota(status_key)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            print(f"Error from urlscan.io: HTTP {e.code} — {body}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        if args.json:
            _emit(json.dumps(data, indent=2, default=str) + '\n',
                  args.logdir, 'STATUS', '', fmt="json")
        else:
            buf = io.StringIO()
            with redirect_stdout(buf):
                print_quota_text(data)
            _emit(buf.getvalue(), args.logdir, 'STATUS', '', fmt="txt")
        return

    # --- Validate mode -------------------------------------------------------
    modes = sum([bool(args.domain), bool(args.ip), bool(args.hostname),
                 bool(args.scan), bool(args.urlscan), bool(args.hash),
                 bool(args.search), bool(args.brands), bool(args.brand)])
    if modes > 1:
        parser.error("provide only one of: domain, --ip, --hostname, --scan, --urlscan, --hash, --search, --brands, --brand")
    if modes == 0:
        parser.error("provide a domain, --ip, --hostname, --scan, --urlscan, --hash, --search, --brands, or --brand")
    if (args.public or args.unlisted) and not args.urlscan:
        parser.error("--public and --unlisted can only be used with --urlscan")
    if args.wait and not args.urlscan:
        parser.error("--wait can only be used with --urlscan")

    # --- Resolve API key: CLI flag > keychain --------------------------------
    api_key = args.api_key
    if api_key:
        dbg(f"API key source: --api-key flag  key={_mask(api_key)}")
    else:
        api_key = keychain_load()
        if api_key:
            dbg(f"API key source: keychain  key={_mask(api_key)}")
        else:
            dbg("API key source: none — unauthenticated requests")

    # =========================================================================
    # URL submission mode
    # =========================================================================
    if args.urlscan:
        if not api_key:
            print("Error: --urlscan requires an API key (use --api-key or --save-key).",
                  file=sys.stderr)
            sys.exit(1)

        target_url = defang_url(args.urlscan)
        visibility = "public" if args.public else ("unlisted" if args.unlisted else "private")
        dbg(f"Submitting URL: {target_url!r}  visibility={visibility!r}")

        try:
            resp = submit_scan(target_url, visibility=visibility, api_key=api_key)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            print(f"Error from urlscan.io: HTTP {e.code} — {body}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        # Use the hostname from the submitted URL as the log filename query part
        parsed_host = urllib.parse.urlparse(target_url).netloc or target_url
        submitted_uuid = resp.get("uuid", "")

        if not args.wait:
            # Just emit the submission receipt and exit
            if args.json:
                _emit(json.dumps(resp, indent=2, default=str) + '\n',
                      args.logdir, 'URLSCAN', parsed_host, fmt="json")
            else:
                buf = io.StringIO()
                with redirect_stdout(buf):
                    print_submission_text(resp)
                _emit(buf.getvalue(), args.logdir, 'URLSCAN', parsed_host, fmt="txt")
            return

        # --wait: print submission info to stderr so stdout stays clean for
        # the final report, then poll until the scan result is available.
        print(f"Submitted: {resp.get('result', submitted_uuid)}", file=sys.stderr)
        print(f"Visibility: {resp.get('visibility', '')}  |  UUID: {submitted_uuid}", file=sys.stderr)

        INITIAL_WAIT  = 30
        RETRY_WAIT    = 15

        print(f"Waiting {INITIAL_WAIT}s for scan to complete...", file=sys.stderr)
        time.sleep(INITIAL_WAIT)

        scan_data = None
        attempt = 0
        while scan_data is None:
            attempt += 1
            dbg(f"Poll attempt {attempt} for UUID {submitted_uuid}")
            try:
                scan_data = poll_result(submitted_uuid, api_key=api_key)
            except urllib.error.HTTPError as e:
                body = e.read().decode(errors="replace")
                print(f"Error from urlscan.io: HTTP {e.code} — {body}", file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

            if scan_data is None:
                print(f"Not ready yet. Checking again in {RETRY_WAIT}s...", file=sys.stderr)
                time.sleep(RETRY_WAIT)

        print("Scan complete.", file=sys.stderr)

        # Emit the full scan result (log under SCAN + UUID for consistency with --scan)
        if args.json:
            _emit(json.dumps(scan_data, indent=2, default=str) + '\n',
                  args.logdir, 'SCAN', submitted_uuid, fmt="json")
        else:
            buf = io.StringIO()
            with redirect_stdout(buf):
                print_scan_text(scan_data)
            _emit(buf.getvalue(), args.logdir, 'SCAN', submitted_uuid, fmt="txt")
        return

    # =========================================================================
    # Scan result mode
    # =========================================================================
    if args.scan:
        uuid = extract_scan_uuid(args.scan)
        dbg(f"Scan UUID: {uuid!r}")
        # Basic UUID format check
        if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', uuid, re.IGNORECASE):
            print(f"Error: '{args.scan}' does not look like a valid scan UUID or result URL.",
                  file=sys.stderr)
            sys.exit(1)

        try:
            data = get_result(uuid, api_key=api_key)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            print(f"Error from urlscan.io: HTTP {e.code} — {body}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        if not data:
            print(f"Error: no result found for scan ID '{uuid}'.", file=sys.stderr)
            sys.exit(1)

        if args.json:
            _emit(json.dumps(data, indent=2, default=str) + '\n',
                  args.logdir, 'SCAN', uuid, fmt="json")
        else:
            buf = io.StringIO()
            with redirect_stdout(buf):
                print_scan_text(data)
            _emit(buf.getvalue(), args.logdir, 'SCAN', uuid, fmt="txt")
        return

    # =========================================================================
    # Hostname mode
    # =========================================================================
    if args.hostname:
        hostname = defang(args.hostname)
        dbg(f"Resolved hostname: {hostname!r}")
        if not hostname or "." not in hostname:
            print(f"Error: '{args.hostname}' does not look like a valid hostname.", file=sys.stderr)
            sys.exit(1)

        try:
            data = get_hostname(hostname, api_key=api_key)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            print(f"Error from urlscan.io: HTTP {e.code} — {body}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        results = data.get("results", [])
        total   = len(results)
        dbg(f"Hostname API returned {total} records  item={data.get('item', '')}")

        summary = extract_hostname_summary(results)

        if args.json:
            out = {
                "query_type": "hostname",
                "query":      hostname,
                "total":      total,
                "sources":    summary,
            }
            _emit(json.dumps(out, indent=2, default=str) + '\n',
                  args.logdir, 'HOST', hostname, fmt="json")
        else:
            buf = io.StringIO()
            with redirect_stdout(buf):
                print_hostname_text(hostname, summary, total)
            _emit(buf.getvalue(), args.logdir, 'HOST', hostname, fmt="txt")
        return

    # =========================================================================
    # IP / CIDR mode
    # =========================================================================
    if args.ip:
        ip_raw = defang_ip(args.ip)
        dbg(f"Resolved IP/CIDR: {ip_raw!r}")
        if not validate_ip_or_cidr(ip_raw):
            print(f"Error: '{args.ip}' does not look like a valid IP address or CIDR range.",
                  file=sys.stderr)
            sys.exit(1)

        import ipaddress
        net = ipaddress.ip_network(ip_raw, strict=False)
        is_cidr = net.prefixlen != net.max_prefixlen
        label = f"IP range {ip_raw}" if is_cidr else f"IP {ip_raw}"
        dbg(f"Mode: IP  is_cidr={is_cidr}  label={label!r}")

        try:
            data = search_ip(ip_raw, api_key=api_key, size=args.size)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            print(f"Error from urlscan.io: HTTP {e.code} — {body}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        hits  = data.get("results", [])
        total = data.get("total", 0)

        # Certs are still useful for IP lookups; skip WHOIS (not relevant)
        detail = {}
        if not args.no_detail and hits:
            uuid = hits[0].get("_id") or hits[0].get("task", {}).get("uuid", "")
            if uuid:
                detail = get_result(uuid, api_key=api_key)

        certs = extract_certs(detail)

        if args.json:
            out = {
                "query_type":   "cidr" if is_cidr else "ip",
                "query":        ip_raw,
                "total":        total,
                "certificates": certs,
                "scans":        _build_scan_list(hits),
            }
            _emit(json.dumps(out, indent=2, default=str) + '\n',
                  args.logdir, 'IP', ip_raw, fmt="json")
        elif args.csv:
            _emit(_format_csv(hits), args.logdir, 'IP', ip_raw, fmt="csv")
        else:
            buf = io.StringIO()
            with redirect_stdout(buf):
                print_text(label, hits, total, whois={}, certs=certs)
            _emit(buf.getvalue(), args.logdir, 'IP', ip_raw, fmt="txt")
        return

    # =========================================================================
    # Hash mode
    # =========================================================================
    if args.hash:
        sha256 = args.hash.strip().lower()
        dbg(f"SHA256 hash: {sha256!r}")
        if not re.fullmatch(r'[0-9a-f]{64}', sha256):
            print(f"Error: '{args.hash}' does not look like a valid SHA256 hash (expected 64 hex characters).",
                  file=sys.stderr)
            sys.exit(1)

        try:
            data = search_hash(sha256, api_key=api_key, size=args.size)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            print(f"Error from urlscan.io: HTTP {e.code} — {body}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        hits  = data.get("results", [])
        total = data.get("total", 0)
        label = f"SHA256 {sha256}"
        dbg(f"Hash search returned {len(hits)} hits  total={total}")

        if args.json:
            out = {
                "query_type": "hash",
                "query":      sha256,
                "total":      total,
                "scans":      _build_scan_list(hits),
            }
            _emit(json.dumps(out, indent=2, default=str) + '\n',
                  args.logdir, 'HASH', sha256, fmt="json")
        elif args.csv:
            _emit(_format_csv(hits), args.logdir, 'HASH', sha256, fmt="csv")
        else:
            buf = io.StringIO()
            with redirect_stdout(buf):
                print_text(label, hits, total, whois={}, certs=[])
            _emit(buf.getvalue(), args.logdir, 'HASH', sha256, fmt="txt")
        return

    # =========================================================================
    # Search mode (freeform query)
    # =========================================================================
    if args.search:
        query_str = args.search.strip()
        dbg(f"Freeform search query: {query_str!r}")

        try:
            data = search(query_str, api_key=api_key, size=args.size)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            print(f"Error from urlscan.io: HTTP {e.code} — {body}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        hits  = data.get("results", [])
        total = data.get("total", 0)
        # Truncate label for display if query is very long
        label = query_str if len(query_str) <= 60 else query_str[:57] + "..."
        dbg(f"Search returned {len(hits)} hits  total={total}")

        if args.json:
            out = {
                "query_type": "search",
                "query":      query_str,
                "total":      total,
                "scans":      _build_scan_list(hits),
            }
            _emit(json.dumps(out, indent=2, default=str) + '\n',
                  args.logdir, 'SEARCH', query_str, fmt="json")
        elif args.csv:
            _emit(_format_csv(hits), args.logdir, 'SEARCH', query_str, fmt="csv")
        else:
            buf = io.StringIO()
            with redirect_stdout(buf):
                print_text(label, hits, total, whois={}, certs=[])
            _emit(buf.getvalue(), args.logdir, 'SEARCH', query_str, fmt="txt")
        return

    # =========================================================================
    # Brands list mode
    # =========================================================================
    if args.brands:
        if not api_key:
            print("Error: --brands requires an API key (use --api-key or --save-key).",
                  file=sys.stderr)
            sys.exit(1)

        try:
            data = get_available_brands(api_key)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            print(f"Error from urlscan.io: HTTP {e.code} — {body}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        kits = data.get("kits", [])
        dbg(f"Available brands: {len(kits)}")

        if args.json:
            out = {
                "query_type": "brands",
                "total":      len(kits),
                "brands":     kits,
            }
            _emit(json.dumps(out, indent=2, default=str) + '\n',
                  args.logdir, 'BRANDS', '', fmt="json")
        elif args.csv:
            _emit(_format_brands_csv(kits), args.logdir, 'BRANDS', '', fmt="csv")
        else:
            buf = io.StringIO()
            with redirect_stdout(buf):
                print_brands_text(kits)
            _emit(buf.getvalue(), args.logdir, 'BRANDS', '', fmt="txt")
        return

    # =========================================================================
    # Brand detail mode
    # =========================================================================
    if args.brand:
        if not api_key:
            print("Error: --brand requires an API key (use --api-key or --save-key).",
                  file=sys.stderr)
            sys.exit(1)

        brand_key = args.brand.strip().lower()
        dbg(f"Brand key: {brand_key!r}")

        # Strategy: try the search API first (returns multiple results, respects
        # --size), fall back to the brands summary endpoint if the search field
        # is not available on the current plan (HTTP 403).
        brand_query = f"verdicts.urlscan.brands.key:{brand_key}"
        search_ok = False
        hits  = []
        total = 0

        dbg(f"Attempting brand search via: {brand_query!r}")
        try:
            search_data = search(brand_query, api_key=api_key, size=args.size)
            hits  = search_data.get("results", [])
            total = search_data.get("total", 0)
            search_ok = True
            dbg(f"Brand search OK  hits={len(hits)}  total={total}")
        except urllib.error.HTTPError as e:
            if e.code == 403:
                dbg("Brand search field not available on current plan (403) — falling back to summary API")
                print("Note: brand search field is not available on your current API plan. "
                      "Falling back to brand summary (most recent detection only). "
                      "Upgrade your plan to search 'verdicts.urlscan.brands.key' for full results.",
                      file=sys.stderr)
            else:
                body = e.read().decode(errors="replace")
                print(f"Error from urlscan.io: HTTP {e.code} — {body}", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        # Fetch brand metadata (always needed for display)
        try:
            brands_data = get_available_brands(api_key)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            print(f"Error from urlscan.io: HTTP {e.code} — {body}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        brand_info = None
        for kit in brands_data.get("kits", []):
            if kit.get("key", "").lower() == brand_key:
                brand_info = kit
                break

        if not brand_info:
            print(f"Error: brand key '{args.brand}' not found. Use --brands to list available brand keys.",
                  file=sys.stderr)
            sys.exit(1)

        # If the search API was blocked, fall back to brands summary
        if not search_ok:
            try:
                summary_data = get_brands_summary(api_key)
            except urllib.error.HTTPError as e:
                body = e.read().decode(errors="replace")
                print(f"Error from urlscan.io: HTTP {e.code} — {body}", file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)

            brand_entry = None
            for entry in summary_data.get("responses", []):
                brand = entry.get("brand", {})
                if brand.get("key", "").lower() == brand_key:
                    brand_entry = entry
                    break

            if brand_entry:
                hits  = brand_entry.get("hits", [])
                total = brand_entry.get("total", 0)
            dbg(f"Brand summary fallback  total={total}  hits={len(hits)}")

        dbg(f"Brand found: {brand_info.get('name')!r}  total={total}  hits={len(hits)}")

        if args.json:
            out = {
                "query_type": "brand",
                "query":      brand_key,
                "brand":      brand_info,
                "total":      total,
                "scans":      _build_scan_list(hits),
            }
            _emit(json.dumps(out, indent=2, default=str) + '\n',
                  args.logdir, 'BRAND', brand_key, fmt="json")
        elif args.csv:
            _emit(_format_csv(hits), args.logdir, 'BRAND', brand_key, fmt="csv")
        else:
            buf = io.StringIO()
            with redirect_stdout(buf):
                print_brand_detail_text(brand_info, hits, total)
            _emit(buf.getvalue(), args.logdir, 'BRAND', brand_key, fmt="txt")
        return

    # =========================================================================
    # Domain mode
    # =========================================================================
    domain = defang(args.domain)
    dbg(f"Resolved domain: {domain!r}")
    if not domain or "." not in domain:
        print(f"Error: '{args.domain}' does not look like a valid domain.", file=sys.stderr)
        sys.exit(1)

    try:
        data = search_domain(domain, api_key=api_key, size=args.size)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"Error from urlscan.io: HTTP {e.code} — {body}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    hits  = data.get("results", [])
    total = data.get("total", 0)

    detail = {}
    if not args.no_detail and hits:
        uuid = hits[0].get("_id") or hits[0].get("task", {}).get("uuid", "")
        if uuid:
            detail = get_result(uuid, api_key=api_key)

    whois = extract_whois(detail)
    certs = extract_certs(detail)

    if args.json:
        out = {
            "query_type":   "domain",
            "query":        domain,
            "total":        total,
            "whois":        whois,
            "certificates": certs,
            "scans":        _build_scan_list(hits),
        }
        _emit(json.dumps(out, indent=2, default=str) + '\n',
              args.logdir, 'RESULTS', domain, fmt="json")
    elif args.csv:
        _emit(_format_csv(hits), args.logdir, 'RESULTS', domain, fmt="csv")
    else:
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_text(domain, hits, total, whois, certs)
        _emit(buf.getvalue(), args.logdir, 'RESULTS', domain, fmt="txt")


if __name__ == "__main__":
    main()
