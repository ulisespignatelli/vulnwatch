#!/usr/bin/env python3
"""
Genera la "placa" diaria de VulnWatch para redes sociales + el texto para el posteo.
  - Lee site/data/meta.json y recent.json (datos reales ya recolectados).
  - Elige las vulnerabilidades más importantes por riesgo (KEV + EPSS + CVSS).
  - Crea una imagen 1080x1350 (formato de posteo de Instagram) con Pillow.
  - Escribe la descripción (caption) con hashtags.
  - Opcional: publica la imagen en Telegram (sendPhoto) si hay token configurado.

Uso:  python scripts/social.py [--handle @UP_Ciberseguridad] [--telegram]
Salida: site/data/social/today.png y site/data/social/today.txt
"""
from __future__ import annotations
import argparse
import json
import mimetypes
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "site" / "data"
OUT = DATA / "social"
FONTS = Path(__file__).resolve().parent / "assets"

# --- colores (identidad VulnWatch) ---
BG = (11, 15, 23)
CARD = (21, 28, 42)
LINE = (35, 44, 61)
TX = (230, 235, 244)
TX2 = (154, 166, 187)
TX3 = (107, 119, 140)
ACC = (0, 212, 164)
SEV_COLOR = {
    "CRITICAL": (255, 77, 109), "HIGH": (255, 140, 66),
    "MEDIUM": (242, 201, 76), "LOW": (76, 201, 240), "NONE": (107, 119, 140),
}
KEV = (255, 56, 100)

MONTHS_ES = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio",
             "agosto", "septiembre", "octubre", "noviembre", "diciembre"]


def font(size, bold=False):
    f = FONTS / ("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf")
    return ImageFont.truetype(str(f), size)


def read_json(p, default):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return default


def priority(r):
    p = (r.get("score") or 0) * 4 + (r.get("epss") or 0) * 45
    if r.get("kev"):
        p += 60
    elif r.get("exploit") == "active":
        p += 45
    elif r.get("exploit") == "poc":
        p += 15
    if r.get("ransomware"):
        p += 15
    return p


def pick_top(recent, n=3):
    scored = sorted(recent, key=priority, reverse=True)
    return scored[:n]


def wrap(draw, text, fnt, max_w):
    words, lines, cur = text.split(), [], ""
    for w in words:
        test = (cur + " " + w).strip()
        if draw.textlength(test, font=fnt) <= max_w:
            cur = test
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def pill(draw, xy, text, fnt, bg, fg=(255, 255, 255), pad=(14, 7)):
    w = draw.textlength(text, font=fnt)
    x, y = xy
    draw.rounded_rectangle([x, y, x + w + pad[0] * 2, y + fnt.size + pad[1] * 2], radius=9, fill=bg)
    draw.text((x + pad[0], y + pad[1] - 1), text, font=fnt, fill=fg)
    return x + w + pad[0] * 2


def tag_for(r):
    if r.get("kev"):
        return "EXPLOTADA", KEV
    if r.get("exploit") == "active":
        return "EXPLOTADA", KEV
    if r.get("exploit") == "poc":
        return "PoC PÚBLICO", SEV_COLOR["HIGH"]
    if r.get("ransomware"):
        return "RANSOMWARE", (123, 44, 191)
    return None


def shield(draw, cx, cy, s, color):
    # escudo simple con tilde
    pts = [(cx, cy - s), (cx + s * 0.8, cy - s * 0.55), (cx + s * 0.8, cy + s * 0.2),
           (cx, cy + s), (cx - s * 0.8, cy + s * 0.2), (cx - s * 0.8, cy - s * 0.55)]
    draw.polygon(pts, fill=color)
    draw.line([(cx - s * 0.35, cy - s * 0.05), (cx - s * 0.08, cy + s * 0.25), (cx + s * 0.42, cy - s * 0.3)],
              fill=BG, width=max(3, int(s * 0.16)), joint="curve")


def build_image(meta, top, handle):
    W, H = 1080, 1350
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # glow superior
    glow = Image.new("RGB", (W, H), BG)
    gd = ImageDraw.Draw(glow)
    gd.ellipse([W * 0.4, -300, W * 1.2, 300], fill=(10, 40, 33))
    img = Image.blend(img, glow, 0.5)
    d = ImageDraw.Draw(img)

    d.rectangle([0, 0, W, 8], fill=ACC)
    M = 70

    # header
    shield(d, M + 22, 92, 26, ACC)
    d.text((M + 60, 70), "Vuln", font=font(42, True), fill=ACC)
    vw = d.textlength("Vuln", font=font(42, True))
    d.text((M + 60 + vw, 70), "Watch", font=font(42, True), fill=TX)
    today = datetime.now(timezone.utc)
    fecha = f"{today.day} de {MONTHS_ES[today.month - 1]}"
    d.text((W - M - d.textlength(fecha, font=font(30)), 82), fecha, font=font(30), fill=TX3)

    # título
    d.text((M, 180), "Para vigilar hoy", font=font(76, True), fill=TX)
    sub = "Las vulnerabilidades más críticas del día,"
    d.text((M, 278), sub, font=font(34), fill=TX2)
    d.text((M, 320), "ordenadas por riesgo real.", font=font(34), fill=TX2)

    # tarjetas
    y = 400
    CARD_H = 258
    for r in top:
        sev = (r.get("severity") or "NONE").upper()
        col = SEV_COLOR.get(sev, SEV_COLOR["NONE"])
        d.rounded_rectangle([M, y, W - M, y + CARD_H], radius=22, fill=CARD, outline=LINE, width=1)
        d.rounded_rectangle([M, y + 18, M + 9, y + CARD_H - 18], radius=5, fill=col)
        ix = M + 38
        # CVE id
        d.text((ix, y + 26), r.get("id", ""), font=font(42, True), fill=TX)
        # pills a la derecha de la fila
        px = ix
        py = y + 92
        score = r.get("score")
        px = pill(d, (px, py), f"CVSS {score}" if score is not None else "Sin puntaje", font(26, True),
                  col, fg=(20, 16, 0) if sev in ("MEDIUM",) else (255, 255, 255))
        t = tag_for(r)
        if t:
            px = pill(d, (px + 10, py), t[0], font(26, True), t[1])
        ep = r.get("epss")
        if ep is not None:
            px = pill(d, (px + 10, py), f"EPSS {round(ep*100,1)}%", font(26, True), (37, 44, 61), fg=TX2)
        # descripción (2 líneas)
        desc = (r.get("desc_es") or r.get("desc") or "").strip()
        lines = wrap(d, desc, font(30), W - 2 * M - 76)[:2]
        dy = y + 150
        for ln in lines:
            d.text((ix, dy), ln, font=font(30), fill=TX2)
            dy += 40
        y += CARD_H + 24

    # footer
    fy = H - 150
    d.line([(M, fy), (W - M, fy)], fill=LINE, width=1)
    total = meta.get("total_cves")
    d.text((M, fy + 24), "Todas las CVEs · gratis · actualizado cada hora", font=font(30), fill=TX3)
    hl = f"🔗 link en bio   {handle}"
    # sin emoji en Pillow: usar texto
    d.text((M, fy + 70), "Panel completo: link en la bio", font=font(32, True), fill=ACC)
    d.text((W - M - d.textlength(handle, font=font(32, True)), fy + 70), handle, font=font(32, True), fill=TX)
    _ = (total, hl)
    return img


def build_caption(top, handle, site_url):
    L = ["🛡️ Vulnerabilidades para vigilar HOY", ""]
    for r in top:
        t = tag_for(r)
        extra = f" — {t[0]}" if t else ""
        sc = r.get("score")
        L.append(f"🔴 {r.get('id')} (CVSS {sc}){extra}" if sc is not None else f"🔴 {r.get('id')}{extra}")
    L += ["",
          "Las traigo de VulnWatch, un panel que armé para ver todas las CVEs al instante, marcar las que se están explotando activamente (CISA KEV) y ordenarlas por riesgo real. Gratis y actualizado cada hora.",
          "",
          f"👉 Panel completo en el link de mi bio.",
          "",
          "#ciberseguridad #pentesting #cybersecurity #infosec #hacking #CVE #vulnerabilidades #opensource #programacion #tecnologia"]
    _ = (handle, site_url)
    return "\n".join(L)


def _graph(url, params):
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(url, data=data)
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
        return json.loads(r.read().decode())


def _graph_get(url, params):
    full = url + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(full)   # GET
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
        return json.loads(r.read().decode())


def _wait_container_ready(base, container_id, token, tries=20, pause=4):
    """Espera a que un contenedor de media de Instagram termine de procesarse (status FINISHED)."""
    for _ in range(tries):
        try:
            st = _graph_get(f"{base}/{container_id}", {"fields": "status_code", "access_token": token})
        except urllib.error.HTTPError:
            time.sleep(pause); continue
        code = st.get("status_code")
        if code == "FINISHED":
            return True
        if code == "ERROR":
            raise RuntimeError(f"contenedor {container_id} en ERROR: {st}")
        time.sleep(pause)
    return False


def publish_instagram(ig_user_id, token, image_url, caption):
    """Publica una foto en el feed de Instagram vía Graph API (cuenta Business/Creator).
       image_url debe ser una URL pública a un JPEG. Devuelve el id del post.
       El servidor se puede cambiar con la variable IG_API_BASE (por defecto el de Instagram Login)."""
    base = os.environ.get("IG_API_BASE", "").strip() or "https://graph.facebook.com/v21.0"
    try:
        container = _graph(f"{base}/{ig_user_id}/media",
                           {"image_url": image_url, "caption": caption[:2200], "access_token": token})
        cid = container.get("id")
        if not cid:
            raise RuntimeError(f"sin creation_id: {container}")
        out = _graph(f"{base}/{ig_user_id}/media_publish",
                     {"creation_id": cid, "access_token": token})
        return out.get("id")
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        raise RuntimeError(f"HTTP {e.code}: {detail}") from None


def send_telegram_message(token, chat_id, text, preview=True):
    """Envía un mensaje de texto a Telegram (con o sin vista previa del link)."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    body = urllib.parse.urlencode({
        "chat_id": chat_id, "text": text[:4000], "parse_mode": "HTML",
        "disable_web_page_preview": "false" if preview else "true",
    }).encode()
    req = urllib.request.Request(url, data=body)
    with urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context()) as r:
        return r.status == 200


def _esc_html(s):
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def sync_news_telegram(max_per_run=6):
    """Publica en Telegram SOLO las noticias nuevas (no publicadas antes).
    En la primera corrida marca todo lo actual como visto, para no mandar el backlog."""
    token = os.environ.get("TELEGRAM_TOKEN", "").strip()
    chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not (token and chat):
        return
    news = read_json(DATA / "news.json", [])
    if not news:
        return
    OUT.mkdir(parents=True, exist_ok=True)
    state = OUT / "posted_news.json"
    links_now = [n["link"] for n in news if n.get("link")]
    if not state.exists():   # primera corrida: sembrar sin publicar
        state.write_text(json.dumps(links_now[:2000], ensure_ascii=False), encoding="utf-8")
        print("news: primera corrida — marcadas como vistas, sin publicar")
        return
    posted = read_json(state, [])
    seen = set(posted)
    nuevas = [n for n in news if n.get("link") and n["link"] not in seen]
    nuevas.sort(key=lambda n: n.get("date", ""))   # de la más vieja a la más nueva
    sent = 0
    for n in nuevas[:max_per_run]:
        cves = " ".join(n.get("cves", [])[:4])
        extra = f" · {_esc_html(cves)}" if cves else ""
        msg = f"📰 <b>{_esc_html(n['title'])}</b>\n{_esc_html(n.get('source', ''))}{extra}\n{n['link']}"
        try:
            send_telegram_message(token, chat, msg)
            posted.append(n["link"]); seen.add(n["link"]); sent += 1
        except Exception as e:
            print(f"news: fallo al publicar: {e}")
            break
    state.write_text(json.dumps(posted[-3000:], ensure_ascii=False), encoding="utf-8")
    print(f"news: {sent} noticia(s) nueva(s) publicada(s) en Telegram ({len(nuevas)} pendientes en total)")


def _card_signature(top):
    """Firma del contenido de la tarjeta: el conjunto de CVEs que muestra."""
    return ",".join(r.get("id", "") for r in top)


def _already_posted(kind, sig):
    """True si esta tarjeta (misma firma) ya se publicó en este canal la última vez."""
    f = OUT / f"posted_{kind}.json"
    return read_json(f, {}).get("sig") == sig


def _mark_posted(kind, sig):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"posted_{kind}.json").write_text(
        json.dumps({"sig": sig}, ensure_ascii=False), encoding="utf-8")


def _cve_is_important(r):
    """Señal de alto valor: explotada (KEV), con exploit/PoC, o usada en ransomware.
    Con CVE_FEED_CRITICAL=1 también incluye las críticas por CVSS (>=9)."""
    if r.get("kev") or r.get("exploit") in ("active", "poc") or r.get("ransomware"):
        return True
    if os.environ.get("CVE_FEED_CRITICAL", "").strip() in ("1", "true", "yes"):
        return (r.get("score") or 0) >= 9
    return False


def sync_cves_telegram(site_url="", max_per_run=40, pause=1.5):
    """Publica en Telegram las CVEs nuevas (una vez cada una, sin repetir nunca).
    Por defecto publica TODAS las CVEs (CVE_FEED_MODE=all). Con CVE_FEED_MODE=important
    solo las explotadas/PoC/ransomware (y críticas si CVE_FEED_CRITICAL=1).
    Primera corrida: siembra sin publicar, para no mandar todo el backlog de golpe."""
    token = os.environ.get("TELEGRAM_TOKEN", "").strip()
    chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not (token and chat):
        return
    recent = read_json(DATA / "recent.json", [])
    if not recent:
        return
    OUT.mkdir(parents=True, exist_ok=True)
    state = OUT / "posted_cves.json"
    mode = os.environ.get("CVE_FEED_MODE", "all").strip().lower()
    keep = (lambda r: True) if mode != "important" else _cve_is_important
    try:
        cap = int(os.environ.get("CVE_FEED_MAX", "").strip() or max_per_run)
    except ValueError:
        cap = max_per_run
    candidatas = [r for r in recent if keep(r)]
    ids_now = [r["id"] for r in candidatas]
    if not state.exists():   # primera corrida: sembrar sin publicar
        state.write_text(json.dumps(ids_now[:12000], ensure_ascii=False), encoding="utf-8")
        print(f"cves: primera corrida — {len(ids_now)} marcadas como vistas, sin publicar")
        return
    posted = read_json(state, [])
    seen = set(posted)
    nuevas = [r for r in candidatas if r["id"] not in seen]
    nuevas.sort(key=lambda r: r.get("published", ""))   # de la más vieja a la más nueva
    base = (site_url or "").rstrip("/")
    sent = 0
    for r in nuevas[:cap]:
        tags = []
        if r.get("kev") or r.get("exploit") == "active":
            tags.append("🔴 EXPLOTADA")
        if r.get("exploit") == "poc":
            tags.append("🟠 PoC público")
        if r.get("ransomware"):
            tags.append("🟣 Ransomware")
        sev = (r.get("severity") or "").upper()
        sev_icon = {"CRITICAL": "🔴 Crítica", "HIGH": "🟠 Alta",
                    "MEDIUM": "🟡 Media", "LOW": "🟢 Baja"}.get(sev, "⚪ Sin severidad")
        if not tags:
            tags.append(sev_icon)
        tag = " · ".join(tags)
        score = r.get("score")
        head = f"🛡️ <b>{_esc_html(r['id'])}</b>" + (f" — CVSS {score}" if score is not None else "")
        desc = _esc_html((r.get("desc_es") or r.get("desc") or "")[:220])
        link = f"{base}/#/cve/{r['id']}" if base else ""
        msg = f"{head}\n{tag}\n\n{desc}" + (f"\n\n🔗 {link}" if link else "")
        try:
            send_telegram_message(token, chat, msg, preview=False)
            posted.append(r["id"]); seen.add(r["id"]); sent += 1
            if pause and sent < cap:
                time.sleep(pause)
        except Exception as e:
            print(f"cves: fallo al publicar: {e}")
            break
    state.write_text(json.dumps(posted[-15000:], ensure_ascii=False), encoding="utf-8")
    print(f"cves: {sent} CVE(s) nueva(s) publicada(s) en Telegram ({len(nuevas)} pendientes en total)")


def send_telegram_photo(token, chat_id, img_path, caption):
    """Publica la imagen con pie en Telegram (multipart/form-data, solo stdlib)."""
    url = f"https://api.telegram.org/bot{token}/sendPhoto"
    boundary = uuid.uuid4().hex
    data = img_path.read_bytes()
    parts = []
    def field(name, value):
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode())
    field("chat_id", chat_id)
    field("caption", caption[:1024])
    ctype = mimetypes.guess_type(str(img_path))[0] or "image/png"
    parts.append((f"--{boundary}\r\nContent-Disposition: form-data; name=\"photo\"; filename=\"{img_path.name}\"\r\n"
                  f"Content-Type: {ctype}\r\n\r\n").encode())
    parts.append(data + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)
    req = urllib.request.Request(url, data=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
        return r.status == 200


# ───────────────────────── DEEP-DIVE EDUCATIVO (carrusel Instagram) ─────────────────────────
# Biblioteca de explicaciones por tipo de falla (CWE). Educativo y DEFENSIVO:
# explica cómo funciona la CLASE de vulnerabilidad y cómo protegerse, sin exploits ni pasos de ataque.

_F_INJ = [("Atacante", "envía datos\npreparados", "crit"),
          ("Sistema", "no separa\ndato de orden", "high"),
          ("Resultado", "ejecuta la\nacción", "acc")]

CWE_LIB = {
    "CWE-89": {"nombre": "Inyección SQL",
        "flow": [("Usuario", "entrada\nmaliciosa", "crit"), ("Aplicación", "no separa\ndato de orden", "high"), ("Base de datos", "ejecuta el\ncomando", "acc")],
        "como": ["La aplicación arma las consultas a la base de datos pegando directamente lo que escribe el usuario, sin separar la instrucción de los datos.",
                 "El atacante envía un texto preparado que la base interpreta como un comando, no como un dato, y así cambia la consulta original a su favor."],
        "impacto": ["Leer toda la base: usuarios, contraseñas, datos de clientes.", "Modificar o borrar registros.", "En muchos casos, escalar hasta tomar control del servidor."],
        "proteger": ["Consultas parametrizadas (prepared statements)", "Validar y limitar la entrada del usuario", "Cuenta de base de datos con mínimos privilegios", "Un WAF como capa extra de defensa"]},
    "CWE-79": {"nombre": "Cross-Site Scripting (XSS)",
        "flow": [("Atacante", "inyecta\nscript", "crit"), ("Sitio web", "lo guarda o\nrefleja", "high"), ("Víctima", "lo ejecuta en\nsu navegador", "acc")],
        "como": ["El sitio muestra contenido del usuario sin limpiarlo, así que un atacante logra insertar código que corre en el navegador de otras víctimas.",
                 "Cuando la víctima abre la página, ese código se ejecuta con su sesión y sus permisos."],
        "impacto": ["Robo de cookies y secuestro de sesión.", "Acciones en nombre de la víctima.", "Redirección a sitios falsos o robo de credenciales."],
        "proteger": ["Escapar/sanitizar toda salida hacia el HTML", "Content-Security-Policy (CSP)", "Marcar las cookies como HttpOnly", "Validar la entrada del lado del servidor"]},
    "CWE-78": {"nombre": "Inyección de comandos del sistema",
        "flow": _F_INJ,
        "como": ["La aplicación construye un comando del sistema operativo usando datos del usuario sin sanitizarlos.",
                 "El atacante agrega sus propios comandos, que el servidor termina ejecutando con sus permisos."],
        "impacto": ["Ejecución de comandos en el servidor.", "Robo o borrado de archivos.", "Control total del equipo afectado."],
        "proteger": ["Evitar llamar al shell; usar APIs seguras", "Listas blancas de valores permitidos", "Separar argumentos de datos", "Mínimos privilegios del proceso"]},
    "CWE-77": {"nombre": "Inyección de comandos", "flow": _F_INJ,
        "como": ["La aplicación mete datos del usuario dentro de un comando o instrucción sin separarlos de la orden.",
                 "El atacante inserta instrucciones propias que el sistema ejecuta."],
        "impacto": ["Ejecución de acciones no previstas.", "Acceso o modificación de datos.", "Posible control del sistema."],
        "proteger": ["Separar datos de instrucciones", "Validar con listas blancas", "Evitar intérpretes dinámicos", "Mínimos privilegios"]},
    "CWE-94": {"nombre": "Inyección de código", "flow": _F_INJ,
        "como": ["La aplicación interpreta como código datos que vienen del usuario.",
                 "El atacante logra que su propio código se ejecute dentro del programa."],
        "impacto": ["Ejecución de código arbitrario.", "Compromiso de la aplicación.", "Acceso a datos y sistemas conectados."],
        "proteger": ["No evaluar entrada como código (evitar eval)", "Validar y restringir la entrada", "Aislar la ejecución (sandbox)", "Mínimos privilegios"]},
    "CWE-22": {"nombre": "Path Traversal (salto de directorios)",
        "flow": [("Atacante", "pide una ruta\ncon ../", "crit"), ("Servidor", "no valida la\nruta", "high"), ("Archivos", "entrega lo\nque no debía", "acc")],
        "como": ["La aplicación usa un nombre de archivo que da el usuario para abrir recursos, sin controlar que se salga de la carpeta permitida.",
                 "Con secuencias como ../ el atacante navega a otras carpetas y accede a archivos que no debería ver."],
        "impacto": ["Lectura de archivos sensibles (config, credenciales).", "En algunos casos, escritura de archivos.", "Exposición de información del sistema."],
        "proteger": ["Normalizar y validar las rutas", "Trabajar sobre una carpeta base fija", "Listas blancas de nombres permitidos", "Mínimos privilegios del proceso"]},
    "CWE-434": {"nombre": "Subida de archivos sin restricción",
        "flow": [("Atacante", "sube un\narchivo peligroso", "crit"), ("Servidor", "no valida el\ntipo", "high"), ("Servidor", "lo ejecuta o\nsirve", "acc")],
        "como": ["El sitio permite subir archivos sin verificar bien el tipo ni dónde se guardan.",
                 "El atacante sube un archivo malicioso y luego logra que el servidor lo ejecute."],
        "impacto": ["Ejecución de código en el servidor.", "Instalación de webshells.", "Compromiso del sitio completo."],
        "proteger": ["Validar tipo y extensión reales", "Guardar fuera de la raíz web", "Renombrar y no permitir ejecución", "Analizar los archivos subidos"]},
    "CWE-502": {"nombre": "Deserialización insegura",
        "flow": [("Atacante", "envía objeto\nmanipulado", "crit"), ("Aplicación", "lo reconstruye\nsin validar", "high"), ("Sistema", "ejecuta código\nal cargar", "acc")],
        "como": ["La aplicación reconstruye objetos a partir de datos que llegan de afuera, confiando en ellos.",
                 "Un objeto manipulado puede disparar código al momento de cargarse."],
        "impacto": ["Ejecución remota de código.", "Compromiso del servidor.", "Muy usada por grupos de ransomware."],
        "proteger": ["Evitar deserializar datos no confiables", "Firmar/validar los datos", "Usar formatos simples (JSON) con esquema", "Listas blancas de clases permitidas"]},
    "CWE-918": {"nombre": "Server-Side Request Forgery (SSRF)",
        "flow": [("Atacante", "pide una URL\ninterna", "crit"), ("Servidor", "la consulta sin\nvalidar", "high"), ("Red interna", "responde datos\nprivados", "acc")],
        "como": ["La aplicación pide URLs que indica el usuario, sin controlar el destino.",
                 "El atacante la hace consultar servicios internos a los que no debería llegar."],
        "impacto": ["Acceso a servicios internos.", "Robo de credenciales de la nube (metadata).", "Mapeo de la red interna."],
        "proteger": ["Listas blancas de destinos", "Bloquear direcciones internas", "No reenviar respuestas crudas", "Segmentar la red"]},
    "CWE-287": {"nombre": "Autenticación incorrecta",
        "flow": [("Atacante", "evita el\nlogin", "crit"), ("Sistema", "no verifica\nbien", "high"), ("Cuenta", "acceso no\nautorizado", "acc")],
        "como": ["El mecanismo que verifica la identidad tiene fallas y se puede sortear.",
                 "El atacante accede como si fuera un usuario válido sin credenciales legítimas."],
        "impacto": ["Acceso no autorizado a cuentas.", "Exposición de datos privados.", "Acciones con identidad ajena."],
        "proteger": ["Mecanismos de autenticación probados", "MFA (doble factor)", "Políticas de contraseñas y bloqueo", "Gestión segura de sesiones"]},
    "CWE-306": {"nombre": "Falta de autenticación",
        "flow": [("Atacante", "accede a una\nfunción", "crit"), ("Sistema", "no pide\nlogin", "high"), ("Función", "queda\nexpuesta", "acc")],
        "como": ["Una función crítica queda accesible sin pedir autenticación.",
                 "Cualquiera que conozca la ruta puede usarla directamente."],
        "impacto": ["Acceso directo a funciones sensibles.", "Cambios de configuración.", "Exposición de datos o controles."],
        "proteger": ["Exigir autenticación en todo endpoint sensible", "Revisar controles por defecto", "Negar por defecto", "Auditar rutas expuestas"]},
    "CWE-862": {"nombre": "Falta de autorización",
        "flow": [("Usuario", "pide un\nrecurso ajeno", "crit"), ("Sistema", "no verifica\npermisos", "high"), ("Recurso", "se entrega\nigual", "acc")],
        "como": ["La aplicación verifica quién sos, pero no si tenés permiso para ese recurso.",
                 "Cambiando un identificador, un usuario accede a datos de otros."],
        "impacto": ["Acceso a datos de otros usuarios.", "Modificación de recursos ajenos.", "Fuga masiva de información."],
        "proteger": ["Verificar permisos en cada acción", "Control de acceso del lado servidor", "Negar por defecto", "Pruebas de acceso entre usuarios"]},
    "CWE-269": {"nombre": "Gestión incorrecta de privilegios",
        "flow": [("Atacante", "abusa de un\npermiso", "crit"), ("Sistema", "asigna de\nmás", "high"), ("Atacante", "gana más\ncontrol", "acc")],
        "como": ["El sistema otorga más permisos de los necesarios o no los controla bien.",
                 "El atacante aprovecha eso para escalar privilegios."],
        "impacto": ["Escalada a administrador.", "Control de funciones críticas.", "Compromiso del sistema."],
        "proteger": ["Principio de mínimos privilegios", "Separar roles y funciones", "Revisar asignaciones de permisos", "Auditar cambios de privilegios"]},
    "CWE-416": {"nombre": "Uso después de liberar (Use-After-Free)",
        "flow": [("Atacante", "fuerza una\ncondición", "crit"), ("Programa", "usa memoria\nya liberada", "high"), ("Programa", "ejecuta código\ndel atacante", "acc")],
        "como": ["El programa sigue usando un espacio de memoria que ya había liberado.",
                 "Controlando ese espacio, el atacante puede desviar la ejecución."],
        "impacto": ["Caída del programa (DoS).", "Ejecución de código.", "Compromiso del equipo."],
        "proteger": ["Actualizar a la versión parcheada", "Lenguajes/seguros de memoria", "Mitigaciones del SO (ASLR/DEP)", "Pruebas con sanitizers"]},
    "CWE-787": {"nombre": "Escritura fuera de límites (Buffer Overflow)",
        "flow": [("Atacante", "envía datos\nmás largos", "crit"), ("Programa", "escribe fuera\ndel buffer", "high"), ("Programa", "corrompe la\nmemoria", "acc")],
        "como": ["El programa escribe más datos de los que caben en el espacio reservado.",
                 "Eso corrompe memoria vecina y puede redirigir la ejecución."],
        "impacto": ["Caída del programa (DoS).", "Ejecución de código.", "Compromiso del sistema."],
        "proteger": ["Actualizar a la versión parcheada", "Validar tamaños de entrada", "Lenguajes seguros de memoria", "Mitigaciones del compilador y SO"]},
    "CWE-125": {"nombre": "Lectura fuera de límites",
        "flow": [("Atacante", "pide leer\nde más", "crit"), ("Programa", "lee memoria\nvecina", "high"), ("Atacante", "obtiene datos\nprivados", "acc")],
        "como": ["El programa lee más allá del espacio reservado.",
                 "El atacante obtiene información de memoria que no debería ver."],
        "impacto": ["Fuga de datos sensibles (claves, tokens).", "Caída del programa.", "Ayuda a otros ataques."],
        "proteger": ["Actualizar a la versión parcheada", "Validar índices y tamaños", "Lenguajes seguros de memoria", "Pruebas con sanitizers"]},
    "CWE-352": {"nombre": "Cross-Site Request Forgery (CSRF)",
        "flow": [("Atacante", "engaña a la\nvíctima", "crit"), ("Navegador", "envía la acción\ncon su sesión", "high"), ("Sitio", "la ejecuta\ncomo válida", "acc")],
        "como": ["El sitio no verifica que una acción haya sido iniciada a propósito por el usuario.",
                 "El atacante hace que el navegador de la víctima envíe acciones usando su sesión."],
        "impacto": ["Acciones no deseadas con la cuenta de la víctima.", "Cambios de datos o configuración.", "Transferencias o compras fraudulentas."],
        "proteger": ["Tokens anti-CSRF", "Cookies SameSite", "Reautenticar acciones sensibles", "Verificar el origen de la petición"]},
    "CWE-200": {"nombre": "Exposición de información",
        "flow": [("Atacante", "consulta el\nsistema", "crit"), ("Aplicación", "revela datos\nde más", "high"), ("Atacante", "usa esa\ninfo", "acc")],
        "como": ["La aplicación entrega información sensible a quien no debería.",
                 "El atacante la usa para preparar ataques más precisos."],
        "impacto": ["Fuga de datos internos o personales.", "Exposición de rutas, versiones o claves.", "Facilita ataques posteriores."],
        "proteger": ["Mostrar solo lo necesario", "Mensajes de error genéricos", "Revisar cabeceras y respuestas", "Clasificar y proteger datos sensibles"]},
    "CWE-20": {"nombre": "Validación incorrecta de entrada",
        "flow": _F_INJ,
        "como": ["La aplicación confía en datos de entrada sin validarlos correctamente.",
                 "Datos inesperados provocan comportamientos no previstos."],
        "impacto": ["Errores, caídas o estados inseguros.", "Puerta de entrada a otros ataques.", "Resultados no confiables."],
        "proteger": ["Validar tipo, rango y formato", "Listas blancas", "Rechazar por defecto", "Validar del lado servidor"]},
}
_CWE_ALIAS = {"CWE-791": "CWE-79", "CWE-80": "CWE-79", "CWE-88": "CWE-78", "CWE-23": "CWE-22", "CWE-36": "CWE-22",
              "CWE-284": "CWE-862", "CWE-285": "CWE-862", "CWE-863": "CWE-862", "CWE-668": "CWE-200", "CWE-120": "CWE-787", "CWE-119": "CWE-787"}


def cwe_info(cve):
    """Devuelve la plantilla educativa para la primera CWE conocida del CVE, o None."""
    for raw in (cve.get("cwe") or []):
        key = str(raw).strip().upper()
        key = _CWE_ALIAS.get(key, key)
        if key in CWE_LIB:
            return CWE_LIB[key]
    return None


def _dd_color(role):
    return {"crit": SEV_COLOR["CRITICAL"], "high": SEV_COLOR["HIGH"], "acc": ACC}.get(role, ACC)


def _dd_bg():
    W, H = 1080, 1350
    img = Image.new("RGB", (W, H), BG)
    g = Image.new("RGB", (W, H), BG); gd = ImageDraw.Draw(g)
    gd.ellipse([W * 0.4, -300, W * 1.2, 300], fill=(10, 40, 33))
    img = Image.blend(img, g, 0.5); d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 8], fill=ACC)
    M = 80
    shield(d, M + 22, 92, 26, ACC)
    d.text((M + 60, 70), "Vuln", font=font(42, True), fill=ACC)
    vw = d.textlength("Vuln", font=font(42, True))
    d.text((M + 60 + vw, 70), "Watch", font=font(42, True), fill=TX)
    today = datetime.now(timezone.utc)
    fecha = f"{today.day} de {MONTHS_ES[today.month - 1]}"
    d.text((W - M - d.textlength(fecha, font=font(30)), 82), fecha, font=font(30), fill=TX3)
    return img, d, W, H, M


def _dd_para(d, x, y, items, fnt, fill, maxw, lh):
    for src in items:
        for ln in wrap(d, src, fnt, maxw):
            d.text((x, y), ln, font=fnt, fill=fill); y += lh
        y += 14
    return y


def _dd_dots(d, W, H, active, n=4):
    r = 9; gap = 34; tot = (n - 1) * gap; x0 = W // 2 - tot // 2; y = H - 70
    for i in range(n):
        d.ellipse([x0 + i * gap - r, y - r, x0 + i * gap + r, y + r],
                  fill=ACC if i == active else (60, 72, 92))


def _dd_footer(d, W, H, M):
    fy = H - 150
    d.line([(M, fy), (W - M, fy)], fill=LINE, width=1)
    d.text((M, fy + 24), SOCIAL_IG_HANDLE, font=font(32, True), fill=ACC)
    r = "Todas las CVEs → link en la bio"
    d.text((W - M - d.textlength(r, font=font(28)), fy + 28), r, font=font(28), fill=TX2)


SOCIAL_IG_HANDLE = os.environ.get("IG_HANDLE", "").strip() or "@upsecuritycybernews"


def build_deepdive_slides(cve, info):
    """Devuelve 4 imágenes PIL: portada, cómo funciona, impacto, cómo protegerse."""
    sev = (cve.get("severity") or "NONE").upper()
    sev_col = SEV_COLOR.get(sev, SEV_COLOR["NONE"])
    score = cve.get("score")
    product = (cve.get("products") or ["Varios productos"])[0]
    t = tag_for(cve)
    imgs = []

    # 1) portada
    img, d, W, H, M = _dd_bg()
    d.text((M, 200), "¿Cómo funciona?", font=font(44, True), fill=ACC)
    d.text((M, 270), cve.get("id", ""), font=font(84, True), fill=TX)
    px = pill(d, (M, 390), f"CVSS {score}" if score is not None else "Sin puntaje", font(30, True), sev_col,
              fg=(20, 16, 0) if sev == "MEDIUM" else (255, 255, 255))
    if t:
        px = pill(d, (px + 12, 390), t[0], font(30, True), t[1])
    pill(d, (M, 460), info["nombre"], font(30, True), (37, 44, 61), fg=ACC)
    d.text((M, 560), "Producto afectado", font=font(30), fill=TX3)
    for i, ln in enumerate(wrap(d, product, font(46, True), W - 2 * M)[:2]):
        d.text((M, 602 + i * 56), ln, font=font(46, True), fill=TX)
    d.text((M, 740), "Una vulnerabilidad del día explicada", font=font(34), fill=TX2)
    d.text((M, 784), "simple y en modo defensa.", font=font(34), fill=TX2)
    d.text((M, 1140), "Deslizá para entenderla  →", font=font(36, True), fill=ACC)
    _dd_dots(d, W, H, 0)
    imgs.append(img)

    # 2) cómo funciona
    img, d, W, H, M = _dd_bg()
    pill(d, (M, 180), "PASO A PASO", font(26, True), (37, 44, 61), fg=TX2)
    d.text((M, 240), "Cómo funciona", font=font(70, True), fill=TX)
    d.text((M, 336), info["nombre"], font=font(40, True), fill=ACC)
    flow = info.get("flow") or _F_INJ
    dy = 430; bw = 270; bh = 120; gap = (W - 2 * M - 3 * bw) // 2; x = M
    for i, (tt, sub, role) in enumerate(flow):
        col = _dd_color(role)
        d.rounded_rectangle([x, dy, x + bw, dy + bh], radius=16, fill=CARD, outline=col, width=2)
        d.text((x + bw / 2 - d.textlength(tt, font=font(30, True)) / 2, dy + 22), tt, font=font(30, True), fill=TX)
        yy = dy + 64
        for s in sub.split("\n"):
            d.text((x + bw / 2 - d.textlength(s, font=font(24)) / 2, yy), s, font=font(24), fill=TX2); yy += 28
        if i < 2:
            d.text((x + bw + gap / 2 - 12, dy + bh / 2 - 20), "→", font=font(48, True), fill=TX3)
        x += bw + gap
    _dd_para(d, M, 610, info["como"], font(34), TX2, W - 2 * M, 44)
    _dd_footer(d, W, H, M); _dd_dots(d, W, H, 1)
    imgs.append(img)

    # 3) impacto
    img, d, W, H, M = _dd_bg()
    pill(d, (M, 180), "POR QUÉ IMPORTA", font(26, True), (40, 12, 20), fg=(255, 150, 165))
    d.text((M, 240), "El impacto", font=font(70, True), fill=TX)
    y = 380
    for it in info["impacto"]:
        d.ellipse([M, y + 10, M + 18, y + 28], fill=SEV_COLOR["CRITICAL"])
        y = _dd_para(d, M + 42, y, [it], font(36), TX, W - 2 * M - 42, 46) + 6
    d.rounded_rectangle([M, y + 30, W - M, y + 170], radius=18, fill=CARD, outline=LINE, width=1)
    d.text((M + 30, y + 54), "En este caso", font=font(28), fill=TX3)
    tags = []
    if score is not None:
        tags.append(f"CVSS {score}")
    tags.append({"CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja"}.get(sev, "Sin severidad"))
    if t:
        tags.append(t[0].capitalize())
    d.text((M + 30, y + 96), " · ".join(tags), font=font(32, True), fill=TX)
    _dd_footer(d, W, H, M); _dd_dots(d, W, H, 2)
    imgs.append(img)

    # 4) cómo protegerse
    img, d, W, H, M = _dd_bg()
    pill(d, (M, 180), "DEFENSA", font(26, True), (10, 40, 33), fg=ACC)
    d.text((M, 240), "Cómo protegerte", font=font(70, True), fill=TX)
    y = 380
    for it in info["proteger"]:
        shield(d, M + 14, y + 22, 16, ACC)
        y = _dd_para(d, M + 48, y, [it], font(36), TX, W - 2 * M - 48, 46) + 8
    d.rounded_rectangle([M, y + 30, W - M, y + 150], radius=18, fill=(10, 40, 33), outline=ACC, width=2)
    d.text((M + 30, y + 54), "Detalle completo de esta y todas las", font=font(30), fill=TX)
    d.text((M + 30, y + 92), "CVEs del día en VulnWatch.", font=font(30), fill=TX)
    _dd_footer(d, W, H, M); _dd_dots(d, W, H, 3)
    imgs.append(img)
    return imgs


def build_deepdive_caption(cve, info, site_url):
    sev = (cve.get("severity") or "NONE").upper()
    sev_es = {"CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja"}.get(sev, "")
    score = cve.get("score")
    head = f"🛡️ {cve.get('id','')} — {info['nombre']}"
    meta = " · ".join([x for x in [f"CVSS {score}" if score is not None else "", sev_es] if x])
    link = f"{(site_url or '').rstrip('/')}/#/cve/{cve.get('id','')}" if site_url else ""
    cuerpo = (f"{head}\n{meta}\n\n"
              f"Qué es: {info['como'][0]}\n\n"
              f"Impacto: {info['impacto'][0]}\n\n"
              f"Cómo protegerte: {info['proteger'][0]}; {info['proteger'][1].lower()}.\n\n"
              f"📌 Contenido educativo y defensivo. Detalle completo → link en la bio.")
    if link:
        cuerpo += f"\n{link}"
    cuerpo += ("\n\n#ciberseguridad #infosec #seguridadinformatica #vulnerabilidades "
               "#cve #pentesting #hacking #ethicalhacking #ciberseguridadhoy")
    return cuerpo[:2200]


def publish_instagram_carousel(ig_user_id, token, image_urls, caption):
    """Publica un carrusel (varias imágenes) en Instagram vía Graph API. Devuelve el id del post."""
    base = os.environ.get("IG_API_BASE", "").strip() or "https://graph.facebook.com/v21.0"
    try:
        children = []
        for u in image_urls:
            c = _graph(f"{base}/{ig_user_id}/media",
                       {"image_url": u, "is_carousel_item": "true", "access_token": token})
            if not c.get("id"):
                raise RuntimeError(f"hijo del carrusel sin id: {c}")
            _wait_container_ready(base, c["id"], token)   # esperar a que la imagen hija procese
            children.append(c["id"])
        cont = _graph(f"{base}/{ig_user_id}/media",
                      {"media_type": "CAROUSEL", "children": ",".join(children),
                       "caption": caption[:2200], "access_token": token})
        cid = cont.get("id")
        if not cid:
            raise RuntimeError(f"carrusel sin creation_id: {cont}")
        # Esperar a que el contenedor del carrusel esté listo antes de publicar (evita el error 9007).
        _wait_container_ready(base, cid, token)
        last = None
        for _ in range(6):   # reintentos cortos por si aún dice "no está listo"
            try:
                out = _graph(f"{base}/{ig_user_id}/media_publish",
                             {"creation_id": cid, "access_token": token})
                return out.get("id")
            except urllib.error.HTTPError as e:
                last = e.read().decode(errors="replace")[:300]
                if "2207027" in last or "not ready" in last or "9007" in last:
                    time.sleep(5); continue
                raise RuntimeError(f"HTTP {e.code}: {last}") from None
        raise RuntimeError(f"no se pudo publicar tras reintentos: {last}")
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        raise RuntimeError(f"HTTP {e.code}: {detail}") from None


def pick_deepdive(recent, posted_ids):
    seen = set(posted_ids)
    cand = []
    for r in recent:
        if r.get("id") in seen:
            continue
        info = cwe_info(r)
        if info is None:
            continue
        if (r.get("score") or 0) >= 7 or r.get("kev") or r.get("exploit") in ("active", "poc"):
            cand.append(r)
    cand.sort(key=priority, reverse=True)
    return cand[0] if cand else None


def deepdive(phase, base_url="", site_url=""):
    """phase 'prepare': elige la próxima CVE y genera las 4 placas a disco.
       phase 'publish': publica el carrusel en Instagram usando URLs públicas (base_url)."""
    recent = read_json(DATA / "recent.json", [])
    OUT.mkdir(parents=True, exist_ok=True)
    pend = OUT / "deep_pending.json"
    posted_f = OUT / "posted_deepdives.json"
    ddir = OUT / "deep"

    if phase == "prepare":
        posted = read_json(posted_f, [])
        chosen = pick_deepdive(recent, posted)
        if not chosen:
            if pend.exists():
                pend.unlink()
            print("deepdive: no hay CVE nueva que califique para deep-dive")
            return
        info = cwe_info(chosen)
        imgs = build_deepdive_slides(chosen, info)
        ddir.mkdir(parents=True, exist_ok=True)
        slides = []
        for i, im in enumerate(imgs, 1):
            p = ddir / f"{i}.jpg"
            im.convert("RGB").save(p, "JPEG", quality=92)
            slides.append(f"social/deep/{i}.jpg")   # ruta relativa a la raíz de la rama 'data'
        pend.write_text(json.dumps({"id": chosen["id"], "slides": slides}, ensure_ascii=False), encoding="utf-8")
        print(f"deepdive: preparado {chosen['id']} ({info['nombre']})")
        return

    if phase == "publish":
        if not pend.exists():
            print("deepdive: nada preparado para publicar")
            return
        meta = read_json(pend, {})
        ig_id = os.environ.get("IG_USER_ID", "").strip()
        token = os.environ.get("IG_ACCESS_TOKEN", "").strip()
        if not (ig_id and token and base_url):
            print("deepdive: falta IG_USER_ID / IG_ACCESS_TOKEN / base_url")
            return
        posted = read_json(posted_f, [])
        if meta.get("id") in set(posted):
            print("deepdive: ya publicado antes; no se repite")
            pend.unlink()
            return
        urls = [base_url.rstrip("/") + "/" + s for s in meta.get("slides", [])]
        cve = next((r for r in recent if r.get("id") == meta.get("id")), {"id": meta.get("id"), "cwe": []})
        info = cwe_info(cve) or next(iter(CWE_LIB.values()))
        caption = build_deepdive_caption(cve, info, site_url)
        try:
            post_id = publish_instagram_carousel(ig_id, token, urls, caption)
            posted.append(meta["id"])
            posted_f.write_text(json.dumps(posted[-2000:], ensure_ascii=False), encoding="utf-8")
            pend.unlink()
            print(f"deepdive: publicado {meta['id']} (post {post_id})")
        except Exception as e:
            print(f"deepdive: fallo al publicar: {e}")
        return



def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--handle", default=os.environ.get("SOCIAL_HANDLE", "@UP_Ciberseguridad"))
    ap.add_argument("--site-url", default=os.environ.get("SITE_URL", "").strip() or "https://ulisespignatelli.github.io/vulnwatch")
    ap.add_argument("--telegram", action="store_true", help="publicar la imagen en Telegram")
    ap.add_argument("--instagram", action="store_true", help="publicar la imagen en Instagram (Graph API)")
    ap.add_argument("--image-url", default="", help="URL pública del JPEG para Instagram")
    ap.add_argument("--deepdive", action="store_true", help="modo deep-dive educativo (carrusel)")
    ap.add_argument("--phase", default="prepare", help="deep-dive: 'prepare' o 'publish'")
    ap.add_argument("--base-url", default="", help="deep-dive: URL base pública de las placas")
    a = ap.parse_args()

    # Modo deep-dive educativo (carrusel de Instagram), independiente de la placa diaria.
    if a.deepdive:
        deepdive(a.phase, base_url=a.base_url, site_url=a.site_url)
        return 0

    meta = read_json(DATA / "meta.json", {})
    recent = read_json(DATA / "recent.json", [])
    if not recent:
        print("social: no hay datos (recent.json vacío); nada que generar")
        return 0
    top = pick_top(recent, 3)
    OUT.mkdir(parents=True, exist_ok=True)

    img = build_image(meta, top, a.handle)
    img_path = OUT / "today.png"
    img.save(img_path, "PNG")
    jpg_path = OUT / "today.jpg"           # Instagram requiere JPEG
    img.convert("RGB").save(jpg_path, "JPEG", quality=92)
    caption = build_caption(top, a.handle, a.site_url)
    (OUT / "today.txt").write_text(caption, encoding="utf-8")
    print(f"social: imagen y texto generados ({', '.join(r.get('id','') for r in top)})")

    sig = _card_signature(top)

    if a.telegram:
        token = os.environ.get("TELEGRAM_TOKEN", "").strip()
        chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
        if not (token and chat):
            print("social: Telegram no configurado (faltan TELEGRAM_TOKEN / TELEGRAM_CHAT_ID)")
        elif _already_posted("tg", sig):
            print("social: placa de Telegram sin cambios respecto a la última; no se repite")
        else:
            try:
                send_telegram_photo(token, chat, img_path, caption)
                _mark_posted("tg", sig)
                print("social: publicado en Telegram")
            except Exception as e:
                print(f"social: fallo al publicar en Telegram: {e}")

    # Feeds nuevos → Telegram. Corren en el paso de la placa (cada hora), no en el de Instagram.
    if not a.instagram:
        sync_cves_telegram(site_url=a.site_url)
        sync_news_telegram()

    if a.instagram:
        ig_id = os.environ.get("IG_USER_ID", "").strip()
        ig_token = os.environ.get("IG_ACCESS_TOKEN", "").strip()
        if not (ig_id and ig_token and a.image_url):
            print("social: Instagram no configurado (faltan IG_USER_ID / IG_ACCESS_TOKEN / --image-url)")
        elif _already_posted("ig", sig):
            print("social: tarjeta de Instagram sin cambios respecto a la última; no se repite")
        else:
            try:
                post_id = publish_instagram(ig_id, ig_token, a.image_url, caption)
                _mark_posted("ig", sig)
                print(f"social: publicado en Instagram (id {post_id})")
            except Exception as e:
                print(f"social: fallo al publicar en Instagram: {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
