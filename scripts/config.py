"""Configuración del recolector. Todo se puede sobreescribir con variables de entorno."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "site" / "data"
CVE_DIR = DATA / "cves"

# --- NVD ---------------------------------------------------------------
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()   # opcional, acelera 10x
# En la primera ejecución, desde qué fecha (publicación) se cargan CVEs.
BACKFILL_FROM = os.environ.get("BACKFILL_FROM", "").strip() or "2025-01-01"

# --- CVE.org (repositorio oficial CVEProject/cvelistV5) -------------------
# Trae las CVEs apenas se publican (antes que la NVD), con el puntaje del
# fabricante y el indicador de explotación (SSVC) que agrega CISA.
CVELIST_DELTA = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
CVELIST_MAX_FETCH = int(os.environ.get("CVELIST_MAX_FETCH", "4000"))

# --- KEV (CISA) --------------------------------------------------------
KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]

# --- EPSS (FIRST) ------------------------------------------------------
EPSS_URLS = [
    "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "https://epss.cyentia.com/epss_scores-current.csv.gz",
]

# --- Noticias (RSS / Atom) ----------------------------------------------
# Podés agregar o quitar fuentes libremente.
NEWS_FEEDS = [
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("Help Net Security", "https://www.helpnetsecurity.com/feed/"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml"),
    ("Microsoft MSRC", "https://api.msrc.microsoft.com/update-guide/rss"),
    ("Cisco Security", "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"),
    ("Hispasec Una al día", "https://unaaldia.hispasec.com/feed"),
    ("WeLiveSecurity (ES)", "https://www.welivesecurity.com/es/rss/feed/"),
]
NEWS_MAX = 600            # cuántas noticias se guardan
NEWS_MAX_AGE_DAYS = 60

# --- Alertas Telegram (opcionales) --------------------------------------
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
# Palabras clave a vigilar (proveedores/productos), separadas por coma.
WATCHLIST = [w.strip().lower() for w in os.environ.get("WATCHLIST", "").split(",") if w.strip()]

USER_AGENT = "VulnWatch/1.0 (+https://github.com)"
