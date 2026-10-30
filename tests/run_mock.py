"""Prueba de punta a punta del recolector con fuentes simuladas (NVD, EPSS, RSS).
KEV se descarga real desde el espejo de GitHub. Uso: python tests/run_mock.py"""
import gzip, json, os, random, sys, urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
os.environ.setdefault("BACKFILL_FROM", (datetime.now(timezone.utc) - timedelta(days=45)).strftime("%Y-%m-%d"))
import config as C, fetch as F  # noqa

random.seed(7)
NOW = datetime.now(timezone.utc)
real_get = F.http_get
F.time.sleep = lambda s: None

kev = json.loads(real_get(C.KEV_URLS[1]))["vulnerabilities"]
VENDORS = [("microsoft", "windows_11"), ("fortinet", "fortios"), ("apache", "http_server"), ("cisco", "ios_xe"),
           ("wordpress", "wordpress"), ("vmware", "esxi"), ("google", "chrome"), ("linux", "linux_kernel"),
           ("ivanti", "connect_secure"), ("oracle", "mysql"), ("paloaltonetworks", "pan-os"), ("atlassian", "confluence")]
KINDS = ["a SQL injection vulnerability", "a cross-site scripting (XSS) vulnerability", "an out-of-bounds write",
         "a remote code execution vulnerability", "a use-after-free", "an authentication bypass",
         "a path traversal vulnerability", "a heap-based buffer overflow", "a server-side request forgery (SSRF)"]
CWES = ["CWE-89", "CWE-79", "CWE-787", "CWE-94", "CWE-416", "CWE-287", "CWE-22", "CWE-122", "CWE-918"]


def sev(s):
    return "CRITICAL" if s >= 9 else "HIGH" if s >= 7 else "MEDIUM" if s >= 4 else "LOW"


def make(i, cid=None, vendor=None):
    pub = NOW - timedelta(days=random.random() * 44, hours=random.random() * 3)
    v, p = vendor or random.choice(VENDORS)
    k = random.randrange(len(KINDS))
    score = round(random.choice([random.uniform(2, 10), random.uniform(5, 8.8)]), 1)
    item = {"cve": {
        "id": cid or f"CVE-{NOW.year}-{50000 + i}",
        "sourceIdentifier": "security@example.com",
        "published": pub.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModified": (pub + timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "vulnStatus": random.choice(["Analyzed", "Awaiting Analysis", "Received"]),
        "descriptions": [{"lang": "en", "value": f"{p.replace('_', ' ').title()} by {v.title()} contains {KINDS[k]} that could allow an attacker to compromise affected systems via crafted requests."}],
        "metrics": {} if random.random() < .12 else {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
            "cvssData": {"version": "3.1", "baseScore": score, "baseSeverity": sev(score),
                         "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": CWES[k]}]}],
        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": f"cpe:2.3:a:{v}:{p}:*:*:*:*:*:*:*:*"}]}]}],
        "references": [{"url": f"https://example.com/advisory/{i}", "tags": ["Vendor Advisory"]}],
    }}
    return item


ITEMS = [make(i) for i in range(2600)]
for j, kv in enumerate(kev[:25]):
    it = make(9000 + j, kv["cveID"], (kv["vendorProject"].lower(), kv["product"].lower().replace(" ", "_")))
    it["cve"]["descriptions"][0]["value"] = kv["shortDescription"]
    ITEMS.append(it)
ITEMS.append(make(99999)); ITEMS[-1]["cve"]["vulnStatus"] = "Rejected"


def fake_nvd(params):
    q = {k: v[0] for k, v in urllib.parse.parse_qs(params).items()}
    a = F.parse_dt((q.get("pubStartDate") or q["lastModStartDate"]).replace(".000", ""))
    b = F.parse_dt((q.get("pubEndDate") or q["lastModEndDate"]).replace(".000", ""))
    fld = "published" if "pubStartDate" in q else "lastModified"
    sel = [x for x in ITEMS if a <= F.parse_dt(x["cve"][fld]) <= b]
    s, n = int(q["startIndex"]), int(q["resultsPerPage"])
    return json.dumps({"totalResults": len(sel), "vulnerabilities": sel[s:s + n]}).encode()


def fake_epss():
    rows = ["#model_version:v2025.03.14,score_date:" + NOW.strftime("%Y-%m-%d"), "cve,epss,percentile"]
    for x in ITEMS:
        e = random.random() ** 6
        rows.append(f"{x['cve']['id']},{e:.5f},{min(.9999, e ** .2):.5f}")
    return gzip.compress("\n".join(rows).encode())


def fake_rss(src):
    ids = [x["cve"]["id"] for x in random.sample(ITEMS, 6)] + [k["cveID"] for k in kev[:3]]
    items = "".join(f"""<item><title>{src}: critical flaw {ids[i]} actively exploited in {random.choice(VENDORS)[0].title()} products</title>
      <link>https://news.example/{src.replace(' ', '')}/{i}</link><pubDate>{(NOW - timedelta(hours=i * 7 + random.random() * 5)).strftime('%a, %d %b %Y %H:%M:%S +0000')}</pubDate>
      <description><![CDATA[<p>Researchers warn about {ids[i]} affecting thousands of exposed devices. Patch now.</p>]]></description></item>""" for i in range(len(ids)))
    return f"<?xml version='1.0'?><rss><channel><title>{src}</title>{items}</channel></rss>".encode()


def mock_get(url, params=None, headers=None, retries=5, timeout=60):
    if url.startswith(C.NVD_API):
        return fake_nvd(urllib.parse.urlencode(params))
    if "epss" in url:
        return fake_epss()
    if "cisa.gov/sites" in url:
        return real_get(C.KEV_URLS[1])
    for name, u in C.NEWS_FEEDS:
        if u == url:
            if name == "Dark Reading":
                raise RuntimeError("feed caído (simulado)")
            return fake_rss(name)
    return real_get(url, params, headers, retries, timeout)


F.http_get = mock_get
sys.argv = ["fetch.py"] + sys.argv[1:]
rc = F.main()
# segunda pasada: incremental
F.NOW = datetime.now(timezone.utc)
print("--- segunda ejecución (incremental) ---")
rc2 = F.main()
sys.exit(rc or rc2)
