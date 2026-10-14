// Netlify Function (v2) - endpoint: POST /api/resolve
// Tanpa dependensi: memakai fetch, dns, dan net bawaan Node.
import { lookup } from "node:dns/promises";
import net from "node:net";

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";
const MAX_HOPS = 8;
const MAX_BODY = 1_000_000;   // byte yang dibaca per halaman
const DEADLINE_MS = 8000;     // function Netlify default hanya ~10 detik

const IGNORED_SUFFIX = [
  "gstatic.com", "googleapis.com", "googletagmanager.com", "google-analytics.com",
  "youtube.com", "youtu.be", "facebook.com", "twitter.com", "x.com", "instagram.com",
  "tiktok.com", "cloudflare.com", "jsdelivr.net", "jquery.com", "w3.org", "schema.org",
  "bootstrapcdn.com", "fontawesome.com", "disqus.com", "histats.com", "wp.com", "gravatar.com",
];

const RE_META = /<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^"']*url=([^"'>\s]+)/gi;
const RE_JS = /(?:window\.|document\.|top\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']|location\.(?:replace|assign)\(\s*["']([^"']+)["']/gi;
const RE_ATOB = /atob\(\s*["']([^"']+)["']/gi;
const RE_DATA = /(?:data-(?:url|href|link|target)|"(?:url|link|target|href|redirect)")\s*[=:]\s*["'](https?:\/\/[^"']+)/gi;
const RE_B64 = /[A-Za-z0-9_\-+/]{16,2000}={0,2}/g;

class UnsafeURL extends Error {}

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });

/* ---------- keamanan (anti-SSRF) ---------- */
function isPublicIPv4(ip) {
  const [a, b] = ip.split(".").map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 168 || b === 0)) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  return true;
}
function expandV6(ip) {
  // -> array 8 hextet (angka), atau null bila tidak valid
  let v = ip.toLowerCase().split("%")[0];
  const dotted = v.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    const [a, b, c, d] = dotted[1].split(".").map(Number);
    v = v.replace(dotted[1], ((a << 8) | b).toString(16) + ":" + ((c << 8) | d).toString(16));
  }
  const halves = v.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0) return null;
  const parts = [...head, ...Array(fill).fill("0"), ...tail].map((h) => parseInt(h, 16));
  return parts.length === 8 && parts.every((n) => Number.isInteger(n) && n >= 0 && n <= 0xffff) ? parts : null;
}
function isPublicIP(ip) {
  if (net.isIPv4(ip)) return isPublicIPv4(ip);
  const p = expandV6(ip);
  if (!p) return false;
  const first96Zero = p.slice(0, 6).every((n) => n === 0);
  if (first96Zero) return false;                                   // ::, ::1, ::a.b.c.d
  if (p.slice(0, 5).every((n) => n === 0) && p[5] === 0xffff)      // ::ffff:a.b.c.d
    return isPublicIPv4(`${p[6] >> 8}.${p[6] & 255}.${p[7] >> 8}.${p[7] & 255}`);
  if (p[0] === 0x64 && p[1] === 0xff9b) return false;              // NAT64
  if (p[0] === 0x2002) return false;                               // 6to4
  if ((p[0] & 0xfe00) === 0xfc00) return false;                    // fc00::/7
  if ((p[0] & 0xffc0) === 0xfe80) return false;                    // fe80::/10
  if ((p[0] & 0xff00) === 0xff00) return false;                   // multicast
  if (p[0] === 0x2001 && p[1] === 0x0db8) return false;           // dokumentasi
  return true;
}
async function checkSafe(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new UnsafeURL("Link tidak valid."); }
  if (u.protocol !== "http:" && u.protocol !== "https:")
    throw new UnsafeURL("Masukkan link yang diawali http:// atau https://");
  if (u.port && u.port !== "80" && u.port !== "443")
    throw new UnsafeURL("Link dengan port khusus tidak didukung.");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(host)) {
    if (!isPublicIP(host)) throw new UnsafeURL("Alamat ini tidak diizinkan.");
    return;
  }
  let addrs;
  try { addrs = await lookup(host, { all: true }); }
  catch { throw new UnsafeURL("Domain tidak ditemukan."); }
  if (addrs.some((a) => !isPublicIP(a.address)))
    throw new UnsafeURL("Alamat ini tidak diizinkan.");
}

/* ---------- pencari URL tujuan ---------- */
const isHttp = (u) => /^https?:\/\//i.test(u);
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } };
const absolute = (u, base) => { try { return new URL(u, base).href; } catch { return ""; } };

function isIgnored(url, currentHost) {
  const h = hostOf(url);
  if (!h || h === currentHost || h.includes("google.")) return true;
  return IGNORED_SUFFIX.some((d) => h === d || h.endsWith("." + d));
}

function tryB64(text) {
  let t;
  try { t = decodeURIComponent(text).trim(); } catch { t = String(text).trim(); }
  if (!/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(t)) return null;
  const out = Buffer.from(t, "base64").toString("utf8").trim();
  return /^https?:\/\//i.test(out) && /^[^\x00-\x1f\x7f]+$/.test(out) ? out : null;
}

function candidatesFromUrl(url) {
  const found = [];
  let u;
  try { u = new URL(url); } catch { return found; }
  for (const v of u.searchParams.values()) {
    if (/^https?:\/\//i.test(v)) found.push([v, "param"]);
    else { const d = tryB64(v); if (d) found.push([d, "base64"]); }
  }
  for (const seg of u.pathname.split("/")) {
    if (seg.length >= 16) { const d = tryB64(seg); if (d) found.push([d, "base64"]); }
  }
  return found;
}

function unescapeHtml(s) {
  return s.replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#0?39;/g, "'")
          .replace(/&#x2f;/gi, "/").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
          .replace(/\\\//g, "/");
}

function candidatesFromHtml(body, base) {
  const found = [];
  const text = unescapeHtml(body);
  for (const m of text.matchAll(RE_META)) found.push([absolute(m[1], base), "meta"]);
  for (const m of text.matchAll(RE_JS)) found.push([absolute(m[1] || m[2], base), "js"]);
  for (const m of text.matchAll(RE_ATOB)) { const d = tryB64(m[1]); if (d) found.push([d, "base64"]); }
  for (const m of text.matchAll(RE_DATA)) found.push([m[1], "html"]);
  for (const m of text.matchAll(RE_B64)) { const d = tryB64(m[0]); if (d) found.push([d, "base64"]); }
  return found;
}

function firstValid(cands, host, seen) {
  for (const [c, via] of cands) {
    const cand = (c || "").trim();
    if (isHttp(cand) && !seen.has(cand) && !isIgnored(cand, host)) return [cand, via];
  }
  return [null, null];
}

async function readLimited(res, max) {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const dec = new TextDecoder("utf-8", { fatal: false });
  let out = "", total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      out += dec.decode(value, { stream: true });
      if (total >= max) break;
    }
  } catch {
    // timeout atau koneksi putus: pakai bagian yang sudah terbaca
  } finally {
    try { await reader.cancel(); } catch { /* abaikan */ }
  }
  return out;
}

async function resolveLink(start) {
  const chain = [{ url: start, via: null }];
  const seen = new Set([start]);
  let url = start, note = null;
  const deadline = Date.now() + DEADLINE_MS;

  for (let hop = 0; hop < MAX_HOPS; hop++) {
    const host = hostOf(url);

    // 1) tujuan yang tersembunyi di URL itu sendiri (tanpa akses jaringan)
    let [nxt, via] = firstValid(candidatesFromUrl(url), host, seen);

    // 2) redirect HTTP atau isi halaman
    if (!nxt) {
      const remaining = deadline - Date.now();
      if (remaining < 1000) { note = "Waktu pemeriksaan habis."; break; }
      try { await checkSafe(url); }
      catch (e) {
        if (hop === 0) throw e;
        note = "Hop berikutnya tidak dapat diperiksa.";
        break;
      }
      let res;
      try {
        res = await fetch(url, {
          redirect: "manual",
          headers: { "User-Agent": UA, "Accept-Language": "id,en;q=0.8" },
          signal: AbortSignal.timeout(Math.min(6000, remaining)),
        });
      } catch {
        note = "Halaman tidak bisa dibuka dari server.";
        break;
      }
      try {
        const loc = res.headers.get("location");
        if (res.status >= 300 && res.status < 400 && loc) {
          await res.body?.cancel().catch(() => {});
          const cand = absolute(loc, url);
          if (isHttp(cand) && !seen.has(cand)) { nxt = cand; via = "redirect"; }
        } else {
          const ctype = (res.headers.get("content-type") || "").toLowerCase();
          if (["text", "html", "json", "javascript"].some((t) => ctype.includes(t))) {
            const body = await readLimited(res, MAX_BODY);
            [nxt, via] = firstValid(candidatesFromHtml(body, url), host, seen);
          } else {
            await res.body?.cancel().catch(() => {});
          }
        }
      } catch {
        note = "Halaman tidak bisa dibaca dari server.";
        break;
      }
    }

    if (!nxt) break;
    seen.add(nxt);
    chain.push({ url: nxt, via });
    url = nxt;
  }
  return { input: start, final: url, resolved: url !== start, chain, note };
}

/* ---------- handler ---------- */
export default async (req) => {
  if (req.method !== "POST") return json({ error: "Metode tidak didukung." }, 405);

  let data = {};
  try { data = await req.json(); } catch { /* biarkan kosong */ }
  let url = String(data?.url ?? "").trim();
  if (!url) return json({ error: "Tempel link terlebih dahulu." }, 400);
  if (url.length > 2048) return json({ error: "Link terlalu panjang." }, 400);
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;

  try {
    return json(await resolveLink(url));
  } catch (e) {
    if (e instanceof UnsafeURL) return json({ error: e.message }, 400);
    console.error("resolve error:", e?.stack || e);
    return json({ error: "Terjadi kesalahan di server. Coba lagi." }, 500);
  }
};

export const config = {
  path: "/api/resolve",
  // batas per IP; harus ditulis di sini, tidak bisa lewat netlify.toml
  rateLimit: { windowLimit: 20, windowSize: 60, aggregateBy: ["ip", "domain"] },
};
