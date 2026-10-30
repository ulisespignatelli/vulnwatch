#!/usr/bin/env python3
"""
VulnWatch - recolector diario.

Descarga y combina:
  * CVEs de la NVD (API 2.0) - todas, incremental por fecha de modificación
  * Catálogo KEV de CISA (vulnerabilidades explotadas activamente)
  * Puntajes EPSS de FIRST (probabilidad de explotación)
  * Noticias de seguridad por RSS/Atom

y genera archivos JSON estáticos en site/data/ que lee la web.
Sólo usa la biblioteca estándar de Python (no hace falta pip install).
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape

import config as C

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
NOW = datetime.now(timezone.utc)


def log(*a):
    print(f"[{datetime.now(timezone.utc):%H:%M:%S}]", *a, flush=True)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def http_get(url: str, params: dict | None = None, headers: dict | None = None,
             retries: int = 5, timeout: int = 60) -> bytes:
    if params:
        url = url + "?" + urllib.parse.urlencode(params)
    h = {"User-Agent": C.USER_AGENT, "Accept-Encoding": "gzip"}
    h.update(headers or {})
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                return data
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (403, 429, 500, 502, 503, 504):
                wait = 10 * (attempt + 1)
                log(f"  HTTP {e.code} en {url[:80]}… reintento en {wait}s")
                time.sleep(wait)
                continue
            raise
        except Exception as e:  # timeouts, conexión, etc.
            last = e
            wait = 5 * (attempt + 1)
            log(f"  Error {e!r} en {url[:80]}… reintento en {wait}s")
            time.sleep(wait)
    raise RuntimeError(f"No se pudo descargar {url}: {last}")


def read_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    tmp.replace(path)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def parse_dt(s: str) -> datetime:
    s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Almacén mensual de CVEs  (site/data/cves/YYYY-MM.json)
# ---------------------------------------------------------------------------
SCORE_FIELDS = ("score", "severity", "cvss_version", "vector", "cvss_source")
KEEP_FIELDS = ("kev", "kev_added", "ransomware", "epss", "epss_pct", "exploit", "title")


class MonthStore:
    """Todas las CVEs, repartidas en un archivo JSON por mes de publicación."""

    def __init__(self):
        self.cache: dict[str, dict[str, dict]] = {}
        self.index: dict[str, str] = {}      # id -> "YYYY-MM"
        self.dirty: set[str] = set()
        self.load_all()

    @staticmethod
    def months_on_disk() -> list[str]:
        return sorted(p.stem for p in C.CVE_DIR.glob("*.json"))

    def month(self, key: str) -> dict[str, dict]:
        if key not in self.cache:
            rows = read_json(C.CVE_DIR / f"{key}.json", [])
            self.cache[key] = {r["id"]: r for r in rows}
            for r in rows:
                self.index[r["id"]] = key
        return self.cache[key]

    def get(self, cve_id: str) -> dict | None:
        k = self.index.get(cve_id)
        return self.cache[k].get(cve_id) if k else None

    def upsert(self, rec: dict) -> bool:
        """Inserta o actualiza. Devuelve True si el CVE es nuevo."""
        old = self.get(rec["id"])
        if old:
            # conservar enriquecimientos y datos que la nueva fuente no trae
            for k in KEEP_FIELDS:
                if k in old and k not in rec:
                    rec[k] = old[k]
            if rec.get("score") is None and old.get("score") is not None:
                for k in SCORE_FIELDS:
                    rec[k] = old.get(k)
            for k in ("products", "cwe", "refs", "desc"):
                if not rec.get(k) and old.get(k):
                    rec[k] = old[k]
            self._drop(rec["id"])
        key = rec["published"][:7]
        self.month(key)[rec["id"]] = rec
        self.index[rec["id"]] = key
        self.dirty.add(key)
        return old is None

    def _drop(self, cve_id: str):
        k = self.index.pop(cve_id, None)
        if k and self.cache[k].pop(cve_id, None) is not None:
            self.dirty.add(k)

    def remove(self, cve_id: str, published: str = ""):
        self._drop(cve_id)

    def load_all(self):
        for k in self.months_on_disk():
            self.month(k)

    def save(self):
        for key in sorted(self.dirty):
            rows = sorted(self.cache[key].values(), key=lambda r: r["published"], reverse=True)
            write_json(C.CVE_DIR / f"{key}.json", rows)
        log(f"  {len(self.dirty)} archivo(s) mensual(es) guardado(s)")
        self.dirty.clear()


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------
def pick_cvss(metrics: dict):
    """Elige la mejor métrica CVSS disponible (v4 > v3.1 > v3.0 > v2), preferentemente la Primary."""
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                     ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        lst = metrics.get(key) or []
        if not lst:
            continue
        lst = sorted(lst, key=lambda m: 0 if m.get("type") == "Primary" else 1)
        m = lst[0]
        d = m.get("cvssData", {})
        sev = d.get("baseSeverity") or m.get("baseSeverity") or ""
        return {
            "score": d.get("baseScore"),
            "severity": sev.upper(),
            "cvss_version": ver,
            "vector": d.get("vectorString", ""),
            "cvss_source": m.get("source", ""),
        }
    return {"score": None, "severity": "NONE", "cvss_version": "", "vector": "", "cvss_source": ""}


def extract_products(cve: dict) -> list[str]:
    out = []
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable", True):
                    continue
                parts = m.get("criteria", "").split(":")
                if len(parts) > 5:
                    vp = f"{parts[3]}:{parts[4]}".replace("_", " ")
                    if vp not in out:
                        out.append(vp)
    return out[:12]


def parse_nvd(item: dict) -> dict:
    cve = item["cve"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    desc_es = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "es"), "")
    cwes = []
    for w in cve.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in cwes:
                cwes.append(v)
    refs = []
    for r in cve.get("references", []) or []:
        u = r.get("url")
        if u and u.lower().startswith(("http://", "https://")) and u not in [x["url"] for x in refs]:
            refs.append({"url": u, "tags": r.get("tags", [])[:3]})
    rec = {
        "id": cve["id"],
        "published": cve.get("published", "")[:19],
        "modified": cve.get("lastModified", "")[:19],
        "status": cve.get("vulnStatus", ""),
        "source": cve.get("sourceIdentifier", ""),
        "desc": desc,
        **pick_cvss(cve.get("metrics", {}) or {}),
        "cwe": cwes[:4],
        "products": extract_products(cve),
        "refs": refs[:10],
        "origin": "nvd",
    }
    if desc_es:
        rec["desc_es"] = desc_es
    return rec


def nvd_pages(params: dict):
    headers = {"apiKey": C.NVD_API_KEY} if C.NVD_API_KEY else {}
    pause = 0.8 if C.NVD_API_KEY else 6.5  # límites públicos de la NVD
    start, total = 0, None
    while total is None or start < total:
        p = dict(params, startIndex=start, resultsPerPage=2000)
        data = json.loads(http_get(C.NVD_API, p, headers))
        total = data.get("totalResults", 0)
        vulns = data.get("vulnerabilities", [])
        log(f"  NVD {start + len(vulns)}/{total}")
        yield from vulns
        start += len(vulns) or 2000
        if start < total:
            time.sleep(pause)


def windows(since: datetime, until: datetime, days=110):
    """La NVD acepta rangos de hasta 120 días."""
    cur = since
    while cur < until:
        end = min(cur + timedelta(days=days), until)
        yield cur, end
        cur = end


def sync_nvd(meta: dict, store: MonthStore, force_backfill: bool) -> list[str]:
    new_ids = []

    def handle(item):
        rec = parse_nvd(item)
        if not rec["published"]:
            return
        if rec["status"] == "Rejected":
            store.remove(rec["id"], rec["published"])
            return
        if store.upsert(rec):
            new_ids.append(rec["id"])

    last = meta.get("nvd_last_sync")
    if not last or force_backfill:
        since = parse_dt(C.BACKFILL_FROM + "T00:00:00")
        log(f"NVD: carga inicial por fecha de publicación desde {since:%Y-%m-%d}")
        for a, b in windows(since, NOW):
            log(f" ventana {a:%Y-%m-%d} → {b:%Y-%m-%d}")
            for it in nvd_pages({"pubStartDate": iso(a) + ".000+00:00", "pubEndDate": iso(b) + ".000+00:00"}):
                handle(it)
            store.save()  # guardar progreso por si se corta
        if force_backfill and last:
            since = parse_dt(last) - timedelta(hours=2)
        else:
            since = None
    else:
        since = parse_dt(last) - timedelta(hours=2)  # solapamiento de seguridad

    if since:
        log(f"NVD: cambios desde {since:%Y-%m-%d %H:%M} UTC")
        for a, b in windows(since, NOW):
            for it in nvd_pages({"lastModStartDate": iso(a) + ".000+00:00", "lastModEndDate": iso(b) + ".000+00:00"}):
                handle(it)

    meta["nvd_last_sync"] = iso(NOW)
    log(f"NVD: {len(new_ids)} CVEs nuevas")
    return new_ids


# ---------------------------------------------------------------------------
# CVE.org (cvelistV5): CVEs al instante + indicador de explotación (SSVC)
# ---------------------------------------------------------------------------
def _cvss5(metrics: list, source: str):
    for key, ver in (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV2_0", "2.0")):
        for m in metrics or []:
            d = m.get(key)
            if d and d.get("baseScore") is not None:
                sev = (d.get("baseSeverity") or "").upper()
                if not sev:
                    s = d["baseScore"]
                    sev = "CRITICAL" if s >= 9 else "HIGH" if s >= 7 else "MEDIUM" if s >= 4 else "LOW" if s > 0 else "NONE"
                return {"score": d["baseScore"], "severity": sev, "cvss_version": ver,
                        "vector": d.get("vectorString", ""), "cvss_source": source}
    return None


def parse_cve5(r: dict) -> dict | None:
    meta = r.get("cveMetadata", {})
    if meta.get("state") != "PUBLISHED":
        return None
    cna = r.get("containers", {}).get("cna", {}) or {}
    adps = r.get("containers", {}).get("adp", []) or []
    desc = next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "")
    products = []
    for a in cna.get("affected", []) or []:
        v, p = (a.get("vendor") or "").strip().lower(), (a.get("product") or "").strip().lower()
        if p and v not in ("n/a", "") and f"{v}:{p}" not in products:
            products.append(f"{v}:{p}")
        elif p and p not in ("n/a",) and p not in products:
            products.append(p)
    cwes = []
    for pt in (cna.get("problemTypes") or []) + [x for a in adps for x in (a.get("problemTypes") or [])]:
        for d in pt.get("descriptions", []) or []:
            c = d.get("cweId")
            if c and c not in cwes:
                cwes.append(c)
    cvss = _cvss5(cna.get("metrics"), meta.get("assignerShortName", "CNA"))
    exploit = ""
    for a in adps:
        if not cvss:
            cvss = _cvss5(a.get("metrics"), a.get("providerMetadata", {}).get("shortName", "ADP"))
        for m in a.get("metrics", []) or []:
            o = m.get("other", {})
            if o.get("type") == "ssvc":
                for opt in o.get("content", {}).get("options", []):
                    if "Exploitation" in opt:
                        exploit = str(opt["Exploitation"]).lower()
    refs = [{"url": x["url"], "tags": (x.get("tags") or [])[:3]} for x in (cna.get("references") or [])
            if str(x.get("url", "")).lower().startswith(("http://", "https://"))]
    rec = {
        "id": meta["cveId"],
        "published": (meta.get("datePublished") or meta.get("dateUpdated") or "")[:19],
        "modified": (meta.get("dateUpdated") or "")[:19],
        "status": "Publicada en CVE.org",
        "source": meta.get("assignerShortName", ""),
        "desc": desc,
        **(cvss or {"score": None, "severity": "NONE", "cvss_version": "", "vector": "", "cvss_source": ""}),
        "cwe": cwes[:4],
        "products": products[:12],
        "refs": refs[:10],
        "origin": "cve.org",
    }
    if cna.get("title"):
        rec["title"] = cna["title"][:200]
    if exploit in ("poc", "active"):
        rec["exploit"] = exploit
    return rec


def sync_cvelist(meta: dict, store: MonthStore) -> list[str]:
    from concurrent.futures import ThreadPoolExecutor
    try:
        delta = json.loads(http_get(C.CVELIST_DELTA, retries=3))
    except Exception as e:
        log(f"CVE.org: fallo {e}")
        return []
    since = meta.get("cvelist_last") or iso(NOW - timedelta(days=3))
    min_pub = C.BACKFILL_FROM
    links, last_done = {}, since
    # de la más vieja a la más nueva; si se llega al tope, la próxima ejecución sigue desde ahí
    for entry in sorted(delta, key=lambda e: e.get("fetchTime", "")):
        ft = entry.get("fetchTime", "")[:19]
        if ft <= since:
            continue
        batch = {}
        for kind in ("new", "updated"):
            for it in entry.get(kind, []) or []:
                cid = it["cveId"]
                # nuevas: siempre. actualizadas: si ya las tenemos o son de años del rango cargado
                if kind == "new" or store.get(cid) or cid.split("-")[1] >= min_pub[:4]:
                    batch[cid] = it["githubLink"]
        if links and len(links) + len(batch) > C.CVELIST_MAX_FETCH:
            break
        links.update(batch)
        last_done = ft
    ids = list(links)
    log(f"CVE.org: {len(ids)} registros nuevos/modificados entre {since} y {last_done}")

    def get(cid):
        try:
            return cid, json.loads(http_get(links[cid], retries=2, timeout=30))
        except Exception as e:
            return cid, e

    new_ids, errors = [], 0
    with ThreadPoolExecutor(max_workers=12) as ex:
        for cid, raw in ex.map(get, ids):
            if isinstance(raw, Exception):
                errors += 1
                continue
            state = raw.get("cveMetadata", {}).get("state")
            if state == "REJECTED":
                store.remove(cid)
                continue
            rec = parse_cve5(raw)
            if not rec or rec["published"] < min_pub:
                continue
            old = store.get(cid)
            if old and old.get("origin") == "nvd":
                # la NVD manda; CVE.org sólo completa lo que falta
                changed = False
                if old.get("score") is None and rec.get("score") is not None:
                    for k in SCORE_FIELDS:
                        old[k] = rec[k]
                    changed = True
                for k in ("products", "cwe"):
                    if not old.get(k) and rec.get(k):
                        old[k] = rec[k]
                        changed = True
                for k in ("exploit", "title"):
                    if rec.get(k) and old.get(k) != rec[k]:
                        old[k] = rec[k]
                        changed = True
                if changed:
                    store.dirty.add(store.index[cid])
            elif store.upsert(rec):
                new_ids.append(cid)
    meta["cvelist_last"] = last_done
    log(f"CVE.org: {len(new_ids)} CVEs nuevas (aún no en NVD), {errors} errores de descarga")
    return new_ids


# ---------------------------------------------------------------------------
# KEV
# ---------------------------------------------------------------------------
def sync_kev() -> tuple[dict, list[str]]:
    prev = {k["id"] for k in read_json(C.DATA / "kev.json", {}).get("items", [])}
    raw = None
    for url in C.KEV_URLS:
        try:
            raw = json.loads(http_get(url, retries=3))
            log(f"KEV: {raw.get('count')} entradas desde {url.split('/')[2]}")
            break
        except Exception as e:
            log(f"KEV: fallo {url}: {e}")
    if raw is None:
        old = read_json(C.DATA / "kev.json", {})
        return {k["id"]: k for k in old.get("items", [])}, []
    items = []
    for v in raw.get("vulnerabilities", []):
        items.append({
            "id": v["cveID"],
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "added": v.get("dateAdded", ""),
            "due": v.get("dueDate", ""),
            "desc": v.get("shortDescription", ""),
            "action": v.get("requiredAction", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
            "cwe": v.get("cwes", []),
            "notes": v.get("notes", ""),
        })
    items.sort(key=lambda x: (x["added"], x["id"]), reverse=True)
    write_json(C.DATA / "kev.json", {"version": raw.get("catalogVersion"),
                                     "released": raw.get("dateReleased"), "items": items})
    new = [i["id"] for i in items if i["id"] not in prev] if prev else []
    log(f"KEV: {len(new)} agregadas desde la última ejecución")
    return {i["id"]: i for i in items}, new


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------
def sync_epss() -> dict[str, tuple[float, float]]:
    for url in C.EPSS_URLS:
        try:
            data = http_get(url, retries=3, timeout=120)
            if data[:2] == b"\x1f\x8b":
                data = gzip.decompress(data)
            text = io.StringIO(data.decode("utf-8"))
            first = text.readline()  # "#model_version:...,score_date:..."
            if not first.startswith("#"):
                text.seek(0)
            out = {}
            for row in csv.DictReader(text):
                try:
                    out[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
                except (KeyError, ValueError):
                    pass
            log(f"EPSS: {len(out)} puntajes desde {url.split('/')[2]}")
            return out
        except Exception as e:
            log(f"EPSS: fallo {url}: {e}")
    return {}


def enrich(store: MonthStore, kev: dict, epss: dict):
    store.load_all()
    for key, month in store.cache.items():
        changed = False
        for rec in month.values():
            k = kev.get(rec["id"])
            new = {
                "kev": 1 if k else 0,
                "kev_added": k["added"] if k else "",
                "ransomware": 1 if k and k["ransomware"] == "Known" else 0,
            }
            if epss:
                e = epss.get(rec["id"])
                new["epss"] = round(e[0], 5) if e else None
                new["epss_pct"] = round(e[1], 4) if e else None
            if k and not rec.get("products"):
                new["products"] = [f"{k['vendor'].lower()}:{k['product'].lower()}"]
            for f, v in new.items():
                if rec.get(f) != v:
                    rec[f] = v
                    changed = True
        if changed:
            store.dirty.add(key)


# ---------------------------------------------------------------------------
# Noticias
# ---------------------------------------------------------------------------
TAG_RE = re.compile(r"<[^>]+>")


def clean(s: str, n=400) -> str:
    s = unescape(TAG_RE.sub(" ", s or ""))
    s = re.sub(r"\s+", " ", s).strip()
    return s[:n] + ("…" if len(s) > n else "")


def parse_date(s: str):
    if not s:
        return None
    s = s.strip()
    try:
        return parsedate_to_datetime(s).astimezone(timezone.utc)
    except Exception:
        pass
    try:
        return parse_dt(s)
    except Exception:
        return None


def parse_feed(source: str, xml: bytes) -> list[dict]:
    root = ET.fromstring(xml)
    items = []

    def t(el, *names):
        for n in names:
            x = el.find(n)
            if x is not None and (x.text or "").strip():
                return x.text
        return ""

    atom = "{http://www.w3.org/2005/Atom}"
    nodes = root.findall(".//item") or root.findall(f".//{atom}entry")
    for el in nodes:
        title = t(el, "title", f"{atom}title")
        link = t(el, "link")
        if not link:
            le = el.find(f"{atom}link")
            link = le.get("href", "") if le is not None else ""
        summary = t(el, "description", f"{atom}summary", f"{atom}content",
                    "{http://purl.org/rss/1.0/modules/content/}encoded")
        date = parse_date(t(el, "pubDate", f"{atom}published", f"{atom}updated",
                            "{http://purl.org/dc/elements/1.1/}date"))
        full = f"{title} {summary}"
        cves = sorted({c.upper() for c in CVE_RE.findall(full)})
        link = link.strip()
        if not title or not link.lower().startswith(("http://", "https://")):
            continue
        items.append({
            "title": clean(title, 300),
            "link": link.strip(),
            "source": source,
            "date": iso(date) if date else iso(NOW),
            "summary": clean(summary),
            "cves": cves[:20],
        })
    return items


def sync_news() -> list[dict]:
    old = read_json(C.DATA / "news.json", [])
    by_link = {n["link"]: n for n in old}
    ok = 0
    for source, url in C.NEWS_FEEDS:
        try:
            got = parse_feed(source, http_get(url, retries=2, timeout=30))
            for n in got:
                by_link.setdefault(n["link"], n)
            ok += 1
            log(f"Noticias: {source}: {len(got)}")
        except Exception as e:
            log(f"Noticias: fallo {source}: {e}")
    cutoff = iso(NOW - timedelta(days=C.NEWS_MAX_AGE_DAYS))
    news = [n for n in by_link.values() if n["date"] >= cutoff]
    news.sort(key=lambda n: n["date"], reverse=True)
    news = news[:C.NEWS_MAX]
    write_json(C.DATA / "news.json", news)
    log(f"Noticias: {len(news)} guardadas ({ok}/{len(C.NEWS_FEEDS)} fuentes OK)")
    return news


# ---------------------------------------------------------------------------
# Resúmenes para la web
# ---------------------------------------------------------------------------
def build_summary(store: MonthStore, meta: dict, kev_new: list[str], nvd_new: list[str]):
    store.load_all()
    months, sev_total = [], {}
    recent, cutoff = [], iso(NOW - timedelta(days=14))
    total = 0
    for key in sorted(store.cache, reverse=True):
        rows = store.cache[key].values()
        sev = {}
        for r in rows:
            sev[r["severity"]] = sev.get(r["severity"], 0) + 1
            if r["published"] >= cutoff:
                recent.append(r)
        for s, c in sev.items():
            sev_total[s] = sev_total.get(s, 0) + c
        total += len(rows)
        months.append({"month": key, "count": len(rows), "severity": sev})
    recent.sort(key=lambda r: r["published"], reverse=True)
    write_json(C.DATA / "recent.json", recent)

    history = meta.get("history", [])
    today = NOW.strftime("%Y-%m-%d")
    if history and history[-1]["date"] == today:   # varias ejecuciones por día: acumular
        history[-1]["new_cves"] += len(nvd_new)
        history[-1]["new_kev"] += len(kev_new)
    else:
        history.append({"date": today, "new_cves": len(nvd_new), "new_kev": len(kev_new)})
    meta["history"] = history[-90:]
    meta.update({
        "updated": iso(NOW),
        "total_cves": total,
        "severity": sev_total,
        "months": months,
        "last_run_new_cves": len(nvd_new),
        "last_run_new_kev": kev_new[:50],
    })
    write_json(C.DATA / "meta.json", meta)


# ---------------------------------------------------------------------------
# Alertas Telegram
# ---------------------------------------------------------------------------
def send_telegram(text: str):
    url = f"https://api.telegram.org/bot{C.TELEGRAM_TOKEN}/sendMessage"
    body = urllib.parse.urlencode({"chat_id": C.TELEGRAM_CHAT_ID, "text": text[:4000],
                                   "parse_mode": "HTML", "disable_web_page_preview": "true"}).encode()
    urllib.request.urlopen(urllib.request.Request(url, data=body), timeout=30).read()


def alerts(store: MonthStore, kev: dict, kev_new: list[str], nvd_new: list[str], site_url: str):
    if not (C.TELEGRAM_TOKEN and C.TELEGRAM_CHAT_ID):
        return
    all_recs = {r["id"]: r for m in store.cache.values() for r in m.values()}
    new_recs = [all_recs[i] for i in nvd_new if i in all_recs]
    crit = sorted([r for r in new_recs if (r.get("score") or 0) >= 9],
                  key=lambda r: -(r.get("score") or 0))
    watch = []
    if C.WATCHLIST:
        for r in new_recs:
            hay = (r["desc"] + " " + " ".join(r.get("products", []))).lower()
            if any(w in hay for w in C.WATCHLIST):
                watch.append(r)
    if not (kev_new or crit or watch):
        return
    L = [f"<b>🛡 VulnWatch – {NOW:%d/%m/%Y}</b>", f"CVEs nuevas: {len(new_recs)} · críticas: {len(crit)}"]
    if kev_new:
        L.append(f"\n<b>🔥 Nuevas en KEV (explotadas activamente): {len(kev_new)}</b>")
        for i in kev_new[:10]:
            k = kev[i]
            L.append(f"• {i} – {k['vendor']} {k['product']}")
    if watch:
        L.append(f"\n<b>👁 En tu lista de vigilancia: {len(watch)}</b>")
        for r in watch[:10]:
            L.append(f"• {r['id']} ({r.get('score') or '–'}) {r['desc'][:90]}")
    if crit:
        L.append("\n<b>⚠ Críticas nuevas (CVSS ≥ 9)</b>")
        for r in crit[:10]:
            L.append(f"• {r['id']} ({r['score']}) {r['desc'][:90]}")
    if site_url:
        L.append(f"\n{site_url}")
    try:
        send_telegram("\n".join(L))
        log("Telegram: alerta enviada")
    except Exception as e:
        log(f"Telegram: fallo {e}")


# ---------------------------------------------------------------------------
def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-nvd", action="store_true")
    ap.add_argument("--skip-news", action="store_true")
    ap.add_argument("--skip-cvelist", action="store_true")
    ap.add_argument("--backfill", action="store_true", help="recargar desde BACKFILL_FROM")
    ap.add_argument("--site-url", default="")
    a = ap.parse_args()

    C.CVE_DIR.mkdir(parents=True, exist_ok=True)
    meta = read_json(C.DATA / "meta.json", {})
    store = MonthStore()
    errors = []

    nvd_new = []
    if not a.skip_nvd:
        try:
            nvd_new = sync_nvd(meta, store, a.backfill)
        except Exception as e:
            errors.append(f"NVD: {e}")
            log(f"NVD: ERROR {e}")
        store.save()

    if not a.skip_cvelist:
        try:
            nvd_new += sync_cvelist(meta, store)
        except Exception as e:
            errors.append(f"CVE.org: {e}")
            log(f"CVE.org: ERROR {e}")
        store.save()

    kev, kev_new = sync_kev()
    epss = sync_epss()
    enrich(store, kev, epss)
    store.save()

    if not a.skip_news:
        sync_news()

    meta["errors"] = errors
    build_summary(store, meta, kev_new, nvd_new)
    alerts(store, kev, kev_new, nvd_new, a.site_url)
    log("Listo.")
    return 1 if errors and not meta.get("total_cves") else 0


if __name__ == "__main__":
    sys.exit(main())
