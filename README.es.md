# VulnWatch 🛡

> 🇬🇧 [Read in English](README.md)

Panel web para ver **todas las vulnerabilidades (CVE)** del día, cuáles se están **explotando activamente** y las **noticias de seguridad**. Se actualiza solo **cada hora** y se aloja **gratis** en GitHub (Actions + Pages). No necesita servidor ni base de datos.

## Qué incluye

| Sección | Contenido |
|---|---|
| **Hoy** | Nuevas en 24 h, críticas, agregadas a KEV, "Atender primero" (ranking por riesgo real), gráfico por día, últimas noticias |
| **Vulnerabilidades** | Todas las CVEs con buscador, filtros (severidad, KEV, ransomware, EPSS, mi lista, revisadas), orden por columnas, navegación por mes, exportación CSV |
| **Explotadas (KEV)** | Catálogo completo de CISA con plazos de remediación y uso en ransomware |
| **Noticias** | 12 fuentes RSS (en inglés y en español); los CVEs que mencionan se abren con un clic |
| **Mi lista** | Tus productos/proveedores: se resaltan en todo el sitio. Marcar CVEs como "revisadas" |
| **Detalle de CVE** | CVSS, EPSS, info KEV, productos, CWE, referencias, noticias relacionadas, búsqueda de PoC |

**Prioridad** = CVSS + probabilidad de explotación (EPSS) + explotación confirmada (KEV) + ransomware. Así lo urgente queda arriba y no solo lo que tiene un CVSS alto.

**Fuentes:** CVE.org (repositorio oficial `CVEProject/cvelistV5`: trae las CVEs minutos después de publicarse, aunque la NVD todavía no las haya analizado, junto con el indicador de exploit/PoC de CISA), NVD API 2.0 (NIST), CISA KEV, FIRST EPSS y feeds RSS (The Hacker News, BleepingComputer, SecurityWeek, Dark Reading, Krebs, CISA, Help Net Security, SANS ISC, Microsoft MSRC, Cisco, Hispasec y WeLiveSecurity).

---

## Puesta en marcha (unos 10 minutos)

1. **Crear el repositorio.** En GitHub → *New repository* (por ejemplo `vulnwatch`). Tiene que ser **público** para que Pages sea gratis; en un plan pago también funciona privado. Subí todos los archivos de esta carpeta:
   ```bash
   cd vulnwatch
   git init -b main && git add . && git commit -m "VulnWatch"
   git remote add origin https://github.com/TU_USUARIO/vulnwatch.git
   git push -u origin main
   ```
2. **Activar Pages.** En el repositorio → *Settings → Pages → Build and deployment → Source:* **GitHub Actions**.
3. **(Recomendado) Clave gratuita de la NVD.** Pedila en https://nvd.nist.gov/developers/request-an-api-key (llega por email). Hace la descarga 10 veces más rápida. Cargala en *Settings → Secrets and variables → Actions → New repository secret* con el nombre `NVD_API_KEY`.
4. **Primera ejecución.** *Actions → "Actualizar datos y publicar" → Run workflow.* La primera vez carga todas las CVEs publicadas desde el 01/01/2025 (tarda de 5 a 15 minutos).
5. **Listo.** El sitio queda en `https://TU_USUARIO.github.io/vulnwatch/` y se actualiza solo cada hora.

### Funciona sin que estés pendiente
- **Todo es gratis**: en repositorios públicos, GitHub Actions y Pages no tienen costo ni límite de minutos.
- **Se reactiva solo**: GitHub desactiva las tareas programadas tras 60 días sin actividad; el workflow se vuelve a habilitar en cada ejecución.
- **Se recupera solo**: si una fuente se cae (NVD, una web de noticias), el resto sigue funcionando y la ejecución siguiente trae lo que faltó.
- **Te avisa si algo se rompe**: GitHub te manda un email cuando una ejecución falla, y la web muestra un aviso arriba.

### Cargar el historial completo (opcional)
Por defecto se cargan las CVEs desde 2025. Para traer más años: *Actions → Run workflow*, tildá **backfill** y poné, por ejemplo, `2015-01-01` en *backfill_from*. Con clave NVD tarda unos 30–60 minutos; sin clave puede tardar varias horas. Desde 1999 son más de 300.000 CVEs (cerca de 1 GB de JSON), así que lo recomendable es desde 2015 o 2020. Para que las ejecuciones automáticas siguientes no lo pierdan, creá también la **variable** `BACKFILL_FROM` con la misma fecha (*Settings → Secrets and variables → Actions → Variables*).

### Alertas por Telegram (opcional)
1. En Telegram hablale a **@BotFather** → `/newbot` → copiá el *token*.
2. Escribile cualquier cosa a tu bot y abrí `https://api.telegram.org/bot<TOKEN>/getUpdates` para ver tu `chat.id`.
3. Cargá los secrets `TELEGRAM_TOKEN` y `TELEGRAM_CHAT_ID`.
4. (Opcional) Creá la **variable** `WATCHLIST` con tus productos separados por coma, por ejemplo `fortinet,windows server,exchange,vmware`.

Vas a recibir un mensaje cuando haya nuevas vulnerabilidades en KEV, CVEs críticas (CVSS ≥ 9) o coincidencias con tu lista. Si no hay novedades, no te llega nada.

---

## Cómo funciona

```
GitHub Actions (cada hora)
  └─ scripts/fetch.py  ── CVE.org · NVD · KEV · EPSS · RSS
        └─ site/data/*.json  ──► rama "data" (se sobrescribe, así el repo no crece)
              └─ GitHub Pages publica site/  ──► navegador (HTML+JS estático)
```

- `scripts/fetch.py`: recolector incremental. Solo usa la biblioteca estándar de Python, sin dependencias.
- `scripts/config.py`: fuentes de noticias, fecha de carga inicial, límites. **Para agregar o quitar fuentes RSS, editá `NEWS_FEEDS`.**
- `site/`: la web (`index.html`, `app.js`, `style.css`).
- `site/data/`: datos generados (`meta.json`, `recent.json` con los últimos 14 días, `kev.json`, `news.json` y `cves/AAAA-MM.json`, un archivo por mes).

### Probar en tu computadora
```bash
python3 scripts/fetch.py            # descarga datos reales (con internet)
cd site && python3 -m http.server   # abrir http://localhost:8000
```
Sin internet: `python3 tests/run_mock.py` genera datos de ejemplo.

## Notas
- La "Mi lista" y las marcas de revisado se guardan en tu navegador (localStorage).
- La NVD tiene demoras en el análisis de muchas CVEs recientes. Por eso algunas aparecen "Sin puntaje" o sin producto hasta que la NVD las analiza; el sistema las actualiza solo cuando eso pasa.
