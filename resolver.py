"""
Mesin resolver: mengikuti redirect dan mencari URL tujuan yang tersembunyi
di halaman perantara (parameter URL, base64, meta refresh, JavaScript).

Keamanan: setiap hop diperiksa agar tidak mengarah ke alamat internal
(localhost, jaringan privat, metadata cloud). Hanya port 80/443.
Untuk produksi, tambahkan juga firewall egress / proxy di level server.
"""
import base64
import html
import ipaddress
import re
import socket
import time
from urllib.parse import urlparse, urljoin, parse_qs, unquote

import requests

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
MAX_HOPS = 10
MAX_BODY = 1_000_000      # byte yang dibaca per halaman
DEADLINE = 25             # detik, batas total per permintaan

# Domain aset/sosmed yang bukan tujuan akhir
IGNORED_SUFFIX = (
    "gstatic.com", "googleapis.com", "googletagmanager.com", "google-analytics.com",
    "youtube.com", "youtu.be", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "tiktok.com", "cloudflare.com", "jsdelivr.net", "jquery.com",
    "w3.org", "schema.org", "bootstrapcdn.com", "fontawesome.com", "disqus.com",
    "histats.com", "wp.com", "gravatar.com",
)

URL_RE_META = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*url=([^"\'>\s]+)', re.I)
URL_RE_JS = re.compile(
    r'(?:window\.|document\.|top\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']|'
    r'location\.(?:replace|assign)\(\s*["\']([^"\']+)["\']', re.I)
URL_RE_ATOB = re.compile(r'atob\(\s*["\']([^"\']+)["\']', re.I)
URL_RE_DATA = re.compile(
    r'(?:data-(?:url|href|link|target)|"(?:url|link|target|href|redirect)")'
    r'\s*[=:]\s*["\'](https?://[^"\']+)', re.I)
B64_RE = re.compile(r"[A-Za-z0-9_\-+/]{16,2000}={0,2}")


class UnsafeURL(ValueError):
    """URL tidak valid atau tidak diizinkan untuk dibuka."""


def is_http(url):
    return urlparse(url).scheme in ("http", "https")


def host_of(url):
    return (urlparse(url).hostname or "").lower()


def check_safe(url):
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise UnsafeURL("Masukkan link yang diawali http:// atau https://")
    try:
        port = p.port
    except ValueError:
        raise UnsafeURL("Link tidak valid.")
    if port not in (None, 80, 443):
        raise UnsafeURL("Link dengan port khusus tidak didukung.")
    try:
        infos = socket.getaddrinfo(p.hostname, port or (443 if p.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise UnsafeURL("Domain tidak ditemukan.")
    for info in infos:
        if not ipaddress.ip_address(info[4][0]).is_global:
            raise UnsafeURL("Alamat ini tidak diizinkan.")


def is_ignored(url, current_host):
    host = host_of(url)
    if not host or host == current_host or "google." in host:
        return True
    return any(host == d or host.endswith("." + d) for d in IGNORED_SUFFIX)


def try_b64(text):
    text = unquote(text).strip()
    padded = text + "=" * (-len(text) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            out = decoder(padded).decode("utf-8", "ignore").strip()
        except Exception:
            continue
        if out.lower().startswith(("http://", "https://")) and out.isprintable():
            return out
    return None


def candidates_from_url(url):
    """Tujuan yang tersembunyi di URL itu sendiri. -> [(url, via)]"""
    found = []
    parsed = urlparse(url)
    for values in parse_qs(parsed.query).values():
        for v in values:
            if v.lower().startswith(("http://", "https://")):
                found.append((v, "param"))
            else:
                dec = try_b64(v)
                if dec:
                    found.append((dec, "base64"))
    for seg in parsed.path.split("/"):
        if len(seg) >= 16:
            dec = try_b64(seg)
            if dec:
                found.append((dec, "base64"))
    return found


def candidates_from_html(body, base_url):
    """Tujuan yang tersembunyi di isi halaman. -> [(url, via)]"""
    found = []
    text = html.unescape(body).replace("\\/", "/")
    for m in URL_RE_META.finditer(text):
        found.append((urljoin(base_url, m.group(1)), "meta"))
    for m in URL_RE_JS.finditer(text):
        found.append((urljoin(base_url, m.group(1) or m.group(2)), "js"))
    for m in URL_RE_ATOB.finditer(text):
        dec = try_b64(m.group(1))
        if dec:
            found.append((dec, "base64"))
    for m in URL_RE_DATA.finditer(text):
        found.append((m.group(1), "html"))
    for m in B64_RE.finditer(text):
        dec = try_b64(m.group(0))
        if dec:
            found.append((dec, "base64"))
    return found


def _first_valid(cands, host, seen):
    for cand, via in cands:
        cand = cand.strip()
        if is_http(cand) and cand not in seen and not is_ignored(cand, host):
            return cand, via
    return None, None


def resolve(start):
    session = requests.Session()
    session.headers.update({"User-Agent": UA, "Accept-Language": "id,en;q=0.8"})
    chain = [{"url": start, "via": None}]
    seen = {start}
    url, note = start, None
    deadline = time.monotonic() + DEADLINE

    for hop in range(MAX_HOPS):
        host = host_of(url)

        # 1) tujuan yang tersembunyi di URL (tanpa akses jaringan)
        nxt, via = _first_valid(candidates_from_url(url), host, seen)

        # 2) redirect HTTP atau isi halaman
        if not nxt:
            if time.monotonic() > deadline:
                note = "Waktu pemeriksaan habis."
                break
            try:
                check_safe(url)
            except UnsafeURL:
                if hop == 0:
                    raise
                note = "Hop berikutnya tidak dapat diperiksa."
                break
            try:
                r = session.get(url, allow_redirects=False, timeout=(5, 10), stream=True)
            except requests.RequestException:
                note = "Halaman tidak bisa dibuka dari server."
                break
            try:
                loc = r.headers.get("Location")
                if r.is_redirect and loc:
                    cand = urljoin(url, loc)
                    if is_http(cand) and cand not in seen:
                        nxt, via = cand, "redirect"
                else:
                    ctype = r.headers.get("Content-Type", "").lower()
                    if any(t in ctype for t in ("text", "html", "json", "javascript")):
                        raw = r.raw.read(MAX_BODY, decode_content=True)
                        body = raw.decode(r.encoding or "utf-8", "ignore")
                        nxt, via = _first_valid(candidates_from_html(body, url), host, seen)
            finally:
                r.close()

        if not nxt:
            break
        seen.add(nxt)
        chain.append({"url": nxt, "via": via})
        url = nxt

    return {"input": start, "final": url, "resolved": url != start,
            "chain": chain, "note": note}
