"""Pruebas unitarias del recolector (sin conexión a internet).
Ejecutar:  python -m unittest discover -s tests -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
import config as C  # noqa: E402
import fetch as F   # noqa: E402


def nvd_item(**over):
    cve = {
        "id": "CVE-2026-0001",
        "published": "2026-10-01T10:00:00.000",
        "lastModified": "2026-10-02T10:00:00.000",
        "vulnStatus": "Analyzed",
        "sourceIdentifier": "psirt@example.com",
        "descriptions": [{"lang": "en", "value": "Example RCE."}, {"lang": "es", "value": "RCE de ejemplo."}],
        "metrics": {
            "cvssMetricV31": [
                {"source": "vendor", "type": "Secondary", "cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM", "vectorString": "v-sec"}},
                {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "v-pri"}},
            ]
        },
        "weaknesses": [{"description": [{"value": "CWE-78"}, {"value": "NVD-CWE-noinfo"}]}],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:h:fortinet:fortigate:-:*:*:*:*:*:*:*"},
        ]}]}],
        "references": [{"url": "https://example.com/a", "tags": ["Patch"]}, {"url": "https://example.com/a"}],
    }
    cve.update(over)
    return {"cve": cve}


class TestNVD(unittest.TestCase):
    def test_parse_prefers_primary_metric(self):
        r = F.parse_nvd(nvd_item())
        self.assertEqual(r["score"], 9.8)
        self.assertEqual(r["severity"], "CRITICAL")
        self.assertEqual(r["vector"], "v-pri")

    def test_parse_fields(self):
        r = F.parse_nvd(nvd_item())
        self.assertEqual(r["products"], ["fortinet:fortios"])        # ignora CPE no vulnerables
        self.assertEqual(r["cwe"], ["CWE-78"])                       # ignora NVD-CWE-*
        self.assertEqual(len(r["refs"]), 1)                          # deduplica referencias
        self.assertEqual(r["desc_es"], "RCE de ejemplo.")
        self.assertEqual(r["origin"], "nvd")

    def test_cvss_version_priority(self):
        m = {"cvssMetricV2": [{"type": "Primary", "baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}],
             "cvssMetricV40": [{"type": "Secondary", "cvssData": {"baseScore": 8.7, "baseSeverity": "HIGH"}}]}
        self.assertEqual(F.pick_cvss(m)["cvss_version"], "4.0")
        self.assertEqual(F.pick_cvss({})["severity"], "NONE")

    def test_windows_respect_nvd_limit(self):
        a = F.parse_dt("2025-01-01T00:00:00")
        b = F.parse_dt("2025-12-31T00:00:00")
        ws = list(F.windows(a, b))
        self.assertTrue(all((y - x).days <= 120 for x, y in ws))
        self.assertEqual(ws[0][0], a)
        self.assertEqual(ws[-1][1], b)


class TestCVE5(unittest.TestCase):
    def test_real_record_with_cisa_adp(self):
        raw = json.loads((HERE / "fixtures" / "CVE-2024-3400.json").read_text())
        r = F.parse_cve5(raw)
        self.assertEqual(r["id"], "CVE-2024-3400")
        self.assertEqual(r["origin"], "cve.org")
        self.assertEqual(r["exploit"], "active")      # SSVC de CISA
        self.assertIsNotNone(r["score"])
        self.assertTrue(any("pan-os" in p for p in r["products"]))

    def test_rejected_is_ignored(self):
        self.assertIsNone(F.parse_cve5({"cveMetadata": {"state": "REJECTED", "cveId": "CVE-1"}}))


class TestFeeds(unittest.TestCase):
    def test_rss(self):
        xml = b"""<rss><channel><item><title>Fortinet patches CVE-2026-1234 &amp; cve-2026-55555</title>
        <link>https://n.example/1</link><pubDate>Thu, 29 Oct 2026 10:00:00 +0000</pubDate>
        <description><![CDATA[<p>Exploited <b>in the wild</b></p>]]></description></item></channel></rss>"""
        n = F.parse_feed("Test", xml)[0]
        self.assertEqual(n["cves"], ["CVE-2026-1234", "CVE-2026-55555"])
        self.assertEqual(n["summary"], "Exploited in the wild")
        self.assertEqual(n["date"], "2026-10-29T10:00:00")

    def test_rejects_javascript_links(self):
        xml = b"""<rss><channel><item><title>evil</title><link>javascript:alert(1)</link></item>
        <item><title>ok</title><link>https://n.example/ok</link></item></channel></rss>"""
        self.assertEqual([n["title"] for n in F.parse_feed("T", xml)], ["ok"])

    def test_atom(self):
        xml = b"""<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Advisory</title>
        <link href="https://n.example/2"/><updated>2026-10-29T12:00:00Z</updated><summary>CVE-2025-0001</summary></entry></feed>"""
        n = F.parse_feed("Atom", xml)[0]
        self.assertEqual(n["link"], "https://n.example/2")
        self.assertEqual(n["cves"], ["CVE-2025-0001"])


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._old = C.CVE_DIR
        C.CVE_DIR = Path(self.tmp.name)

    def tearDown(self):
        C.CVE_DIR = self._old
        self.tmp.cleanup()

    def test_nvd_update_keeps_enrichment_and_cna_data(self):
        s = F.MonthStore()
        prelim = {"id": "CVE-2026-0001", "published": "2026-10-01T10:00:00", "score": 8.1, "severity": "HIGH",
                  "cvss_version": "3.1", "vector": "x", "cvss_source": "cna", "products": ["acme:app"],
                  "exploit": "poc", "origin": "cve.org", "desc": "d", "cwe": [], "refs": []}
        self.assertTrue(s.upsert(prelim))
        s.get("CVE-2026-0001")["epss"] = 0.5
        nvd = F.parse_nvd(nvd_item(metrics={}, configurations=[]))
        self.assertFalse(s.upsert(nvd))
        r = s.get("CVE-2026-0001")
        self.assertEqual(r["origin"], "nvd")
        self.assertEqual(r["score"], 8.1)          # NVD sin puntaje: se conserva el del CNA
        self.assertEqual(r["products"], ["acme:app"])
        self.assertEqual(r["exploit"], "poc")
        self.assertEqual(r["epss"], 0.5)

    def test_month_move_has_no_duplicates(self):
        s = F.MonthStore()
        s.upsert({"id": "CVE-X", "published": "2026-09-30T23:59:00", "desc": "a"})
        s.upsert({"id": "CVE-X", "published": "2026-10-01T00:01:00", "desc": "b"})
        s.save()
        s2 = F.MonthStore()
        self.assertEqual(sum(len(m) for m in s2.cache.values()), 1)
        self.assertEqual(s2.get("CVE-X")["desc"], "b")


if __name__ == "__main__":
    unittest.main()
