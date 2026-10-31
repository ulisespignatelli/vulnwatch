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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--handle", default=os.environ.get("SOCIAL_HANDLE", "@UP_Ciberseguridad"))
    ap.add_argument("--site-url", default=os.environ.get("SITE_URL", "").strip() or "https://ulisespignatelli.github.io/vulnwatch")
    ap.add_argument("--telegram", action="store_true", help="publicar la imagen en Telegram")
    ap.add_argument("--instagram", action="store_true", help="publicar la imagen en Instagram (Graph API)")
    ap.add_argument("--image-url", default="", help="URL pública del JPEG para Instagram")
    a = ap.parse_args()

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

    if a.telegram:
        token = os.environ.get("TELEGRAM_TOKEN", "").strip()
        chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
        if token and chat:
            try:
                send_telegram_photo(token, chat, img_path, caption)
                print("social: publicado en Telegram")
            except Exception as e:
                print(f"social: fallo al publicar en Telegram: {e}")
        else:
            print("social: Telegram no configurado (faltan TELEGRAM_TOKEN / TELEGRAM_CHAT_ID)")

    # Feeds nuevos → Telegram. Corren en el paso de la placa (cada hora), no en el de Instagram.
    if not a.instagram:
        sync_cves_telegram(site_url=a.site_url)
        sync_news_telegram()

    if a.instagram:
        ig_id = os.environ.get("IG_USER_ID", "").strip()
        ig_token = os.environ.get("IG_ACCESS_TOKEN", "").strip()
        if ig_id and ig_token and a.image_url:
            try:
                post_id = publish_instagram(ig_id, ig_token, a.image_url, caption)
                print(f"social: publicado en Instagram (id {post_id})")
            except Exception as e:
                print(f"social: fallo al publicar en Instagram: {e}")
        else:
            print("social: Instagram no configurado (faltan IG_USER_ID / IG_ACCESS_TOKEN / --image-url)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
