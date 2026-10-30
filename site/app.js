/* VulnWatch – frontend estático. Lee los JSON de ./data/ generados por scripts/fetch.py */
(() => {
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
// sólo enlaces http(s): evita XSS con "javascript:" u otros esquemas provenientes de feeds
const safeUrl = u => /^https?:\/\//i.test(String(u || "").trim()) ? esc(u) : "#";
const SEV = ["CRITICAL","HIGH","MEDIUM","LOW","NONE"];
const SEV_ES = {CRITICAL:"Crítica",HIGH:"Alta",MEDIUM:"Media",LOW:"Baja",NONE:"Sin puntaje"};
const SEV_COL = {CRITICAL:"#ff4d6d",HIGH:"#ff8c42",MEDIUM:"#f2c94c",LOW:"#4cc9f0",NONE:"#3a4458"};
const PAGE = 50;

// ---------- almacenamiento local (seguro) ----------
const store = {
  get(k, d) { try { const v = localStorage.getItem("vw:" + k); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem("vw:" + k, JSON.stringify(v)); } catch {} }
};

const S = {
  meta: null, recent: [], kev: {items: []}, kevMap: new Map(), news: [],
  months: new Map(),            // "YYYY-MM" -> rows
  watch: store.get("watch", []),
  reviewed: new Set(store.get("reviewed", [])),
  f: Object.assign({q:"", sev:[], kev:false, rw:false, poc:false, watch:false, hideRev:false, epss:0, src:"recent", sort:"published", dir:-1, page:0}, store.get("filters", {})),
};
S.f.page = 0;

async function getJSON(path) {
  const r = await fetch(path, {cache: "no-cache"});
  if (!r.ok) throw new Error(path + " → " + r.status);
  return r.json();
}

// ---------- helpers de dominio ----------
function priority(r) {
  // combina explotación activa (KEV), probabilidad (EPSS) y severidad (CVSS)
  let p = (r.score || 0) * 4 + (r.epss || 0) * 45;
  if (r.kev) p += 60;
  else if (r.exploit === "active") p += 45;
  else if (r.exploit === "poc") p += 15;
  if (r.ransomware) p += 15;
  return Math.round(p);
}
function prioLabel(r) {
  const p = priority(r);
  if (r.kev || r.exploit === "active" || p >= 70) return ["p4", "URGENTE"];
  if (p >= 40 || (r.score || 0) >= 9) return ["p3", "ALTA"];
  if (p >= 22) return ["p2", "MEDIA"];
  return ["p1", "BAJA"];
}
const isWatched = r => {
  if (!S.watch.length) return false;
  const hay = ((r.desc || "") + " " + (r.products || []).join(" ") + " " + r.id).toLowerCase();
  return S.watch.some(w => hay.includes(w));
};
const fmtDate = s => s ? new Date(s.length <= 10 ? s + "T12:00:00Z" : s + (s.endsWith("Z") ? "" : "Z")).toLocaleDateString("es-AR", {day:"2-digit", month:"short", year:"numeric"}) : "–";
const fmtShort = s => s ? s.slice(8,10) + "/" + s.slice(5,7) + "/" + s.slice(2,4) : "–";
const fmtDT = s => s ? new Date(s + (s.endsWith("Z") ? "" : "Z")).toLocaleString("es-AR", {day:"2-digit", month:"short", hour:"2-digit", minute:"2-digit"}) : "–";
function ago(s) {
  const d = (Date.now() - new Date(s + (s.endsWith("Z") ? "" : "Z"))) / 1000;
  if (d < 3600) return Math.max(1, Math.round(d / 60)) + " min";
  if (d < 86400) return Math.round(d / 3600) + " h";
  return Math.round(d / 86400) + " d";
}
const sevBadge = r => `<span class="sev ${esc(r.severity || "NONE")}">${r.score != null ? esc(r.score) : "–"} ${esc(SEV_ES[r.severity] || "—")}</span>`;
const epssTxt = r => r.epss == null ? "–" : (r.epss * 100).toFixed(r.epss < 0.01 ? 2 : 1) + "%";
const prodTxt = r => (r.products || []).slice(0, 3).map(p => esc(p.replace(":", " · "))).join("<br>") || '<span class="note">—</span>';
function tags(r) {
  let t = "";
  if (r.kev) t += `<span class="tag kev" title="En el catálogo KEV de CISA: explotada activamente">EXPLOTADA</span>`;
  if (!r.kev && r.exploit === "active") t += `<span class="tag kev" title="CISA indica explotación activa (SSVC)">EXPLOTADA</span>`;
  if (r.exploit === "poc") t += `<span class="tag poc" title="Existe código de ataque público (PoC) según CISA">PoC PÚBLICO</span>`;
  if (r.origin === "cve.org") t += `<span class="tag new" title="Recién publicada en CVE.org, todavía sin análisis de la NVD">NUEVA</span>`;
  if (r.ransomware) t += `<span class="tag rw" title="Usada en campañas de ransomware">RANSOMWARE</span>`;
  if (isWatched(r)) t += `<span class="tag watch">MI LISTA</span>`;
  return t;
}

// ---------- carga de datos ----------
async function loadMonth(key) {
  if (!S.months.has(key)) S.months.set(key, await getJSON(`data/cves/${key}.json`));
  return S.months.get(key);
}
function allLoaded() {
  const seen = new Map();
  for (const r of S.recent) seen.set(r.id, r);
  for (const rows of S.months.values()) for (const r of rows) seen.set(r.id, r);
  return seen;
}
async function findCVE(id) {
  id = id.toUpperCase();
  let r = allLoaded().get(id);
  if (r) return r;
  const year = id.split("-")[1];
  for (const m of (S.meta?.months || []).map(x => x.month).filter(m => m.slice(0, 4) >= year).sort()) {
    const rows = await loadMonth(m);
    r = rows.find(x => x.id === id);
    if (r) return r;
  }
  return null;
}

// ---------- vistas ----------
const views = {};

views.hoy = () => {
  const m = S.meta || {};
  const day = Date.now() - 864e5, week = Date.now() - 7 * 864e5;
  const t = s => new Date(s + "Z").getTime();
  const last24 = S.recent.filter(r => t(r.published) >= day);
  const crit24 = last24.filter(r => r.severity === "CRITICAL");
  const kev7 = S.kev.items.filter(k => new Date(k.added + "T23:59:59Z").getTime() >= week);
  const poc7 = S.recent.filter(r => t(r.published) >= week && (r.exploit || r.kev)).length;
  const watch7 = S.recent.filter(r => t(r.published) >= week && isWatched(r));
  const top = [...S.recent].sort((a, b) => priority(b) - priority(a)).slice(0, 12);

  // gráfico 14 días apilado por severidad
  const days = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date(Date.now() - i * 864e5).toISOString().slice(0, 10);
    days.push({d, c: Object.fromEntries(SEV.map(s => [s, 0]))});
  }
  const idx = Object.fromEntries(days.map((x, i) => [x.d, i]));
  for (const r of S.recent) { const i = idx[r.published.slice(0, 10)]; if (i != null) days[i].c[r.severity || "NONE"]++; }
  const max = Math.max(1, ...days.map(x => SEV.reduce((a, s) => a + x.c[s], 0)));
  const W = 700, H = 150, bw = W / days.length;
  let bars = "";
  days.forEach((x, i) => {
    let y = H;
    const tot = SEV.reduce((a, s) => a + x.c[s], 0);
    for (const s of [...SEV].reverse()) {
      const h = x.c[s] / max * (H - 18);
      if (h > 0) { y -= h; bars += `<rect x="${i * bw + 4}" y="${y}" width="${bw - 8}" height="${h}" fill="${SEV_COL[s]}" rx="1.5"><title>${x.d} · ${SEV_ES[s]}: ${x.c[s]}</title></rect>`; }
    }
    bars += `<text x="${i * bw + bw / 2}" y="${y - 4}" text-anchor="middle" font-size="10" fill="#9aa6bb">${tot || ""}</text>`;
    if (i % 2 === 1 || days.length < 10) bars += `<text x="${i * bw + bw / 2}" y="${H + 14}" text-anchor="middle" font-size="10" fill="#6b778c">${x.d.slice(8)}/${x.d.slice(5, 7)}</text>`;
  });

  const sevCounts = Object.fromEntries(SEV.map(s => [s, 0]));
  S.recent.forEach(r => sevCounts[r.severity || "NONE"]++);
  const sevMax = Math.max(1, ...Object.values(sevCounts));

  return `
  <h1>Resumen de hoy</h1>
  <p class="sub">${new Date().toLocaleDateString("es-AR", {weekday:"long", day:"numeric", month:"long", year:"numeric"})} · ${(m.total_cves || 0).toLocaleString("es-AR")} CVEs en la base</p>
  ${(m.errors || []).length ? `<div class="warn">Última actualización con errores: ${esc(m.errors.join(" · "))}</div>` : ""}
  <div class="grid kpis">
    <div class="card kpi acc"><div class="lbl">Nuevas · 24 h</div><div class="val">${last24.length}</div><div class="hint">CVEs publicadas</div></div>
    <div class="card kpi red"><div class="lbl">Críticas · 24 h</div><div class="val">${crit24.length}</div><div class="hint">CVSS ≥ 9.0</div></div>
    <div class="card kpi kev"><div class="lbl">Explotadas · 7 días</div><div class="val">${kev7.length}</div><div class="hint">agregadas a CISA KEV</div></div>
    <div class="card kpi"><div class="lbl">Mi lista · 7 días</div><div class="val">${S.watch.length ? watch7.length : "–"}</div><div class="hint">${S.watch.length ? "coinciden con tus productos" : '<a href="#/config">configurar</a>'}</div></div>
    <div class="card kpi"><div class="lbl">Últimos 14 días</div><div class="val">${S.recent.length.toLocaleString("es-AR")}</div><div class="hint">${poc7} con exploit/PoC en 7 días</div></div>
  </div>
  <div class="grid cols">
    <div class="grid" style="align-content:start">
      <div class="card">
        <div class="card-h"><h2>Atender primero</h2><a href="#/cves" data-sort="prio">ver todas →</a></div>
        <p class="note" style="margin:-6px 0 8px">Últimos 14 días ordenadas por prioridad (explotación activa + EPSS + CVSS)</p>
        <div class="rows">${top.map(rowHTML).join("") || '<div class="empty">Sin datos</div>'}</div>
      </div>
      <div class="card">
        <div class="card-h"><h2>CVEs publicadas por día</h2><div class="legend">${SEV.map(s => `<span><i style="background:${SEV_COL[s]}"></i>${SEV_ES[s]}</span>`).join("")}</div></div>
        <svg class="chart" viewBox="0 0 ${W} ${H + 18}" preserveAspectRatio="none">${bars}</svg>
      </div>
    </div>
    <div class="grid" style="align-content:start">
      <div class="card">
        <div class="card-h"><h2>🔥 Recién agregadas a KEV</h2><a href="#/kev">catálogo →</a></div>
        <div class="rows">${S.kev.items.slice(0, 8).map(k => `
          <div class="row" data-cve="${esc(k.id)}">
            <div><span class="cveid">${esc(k.id)}</span></div>
            <div><div class="meta"><b>${esc(k.vendor)}</b> ${esc(k.product)} ${k.ransomware === "Known" ? '<span class="tag rw">RANSOMWARE</span>' : ""}</div><div class="d">${esc(k.name)}</div></div>
            <div class="r">${fmtDate(k.added)}</div>
          </div>`).join("")}</div>
      </div>
      <div class="card">
        <div class="card-h"><h2>Severidad · 14 días</h2></div>
        <div class="sevbars">${SEV.map(s => `<div class="l"><span>${SEV_ES[s]}</span><div class="t"><i style="width:${sevCounts[s] / sevMax * 100}%;background:${SEV_COL[s]}"></i></div><span style="text-align:right">${sevCounts[s]}</span></div>`).join("")}</div>
      </div>
      <div class="card">
        <div class="card-h"><h2>📰 Últimas noticias</h2><a href="#/noticias">todas →</a></div>
        ${S.news.slice(0, 7).map(newsHTML).join("") || '<div class="empty">Sin noticias</div>'}
      </div>
    </div>
  </div>`;
};

function rowHTML(r) {
  const [pc, pl] = prioLabel(r);
  return `<div class="row" data-cve="${esc(r.id)}">
    <div><span class="prio ${pc}">${pl}</span></div>
    <div><div class="meta"><span class="cveid">${esc(r.id)}</span>${sevBadge(r)}${tags(r)}${r.epss != null ? `<span class="tag" title="Probabilidad de explotación (EPSS)">EPSS ${epssTxt(r)}</span>` : ""}</div>
    <div class="d">${esc(r.desc)}</div></div>
    <div class="r">hace ${ago(r.published)}</div></div>`;
}
function newsHTML(n) {
  return `<a class="news" href="${safeUrl(n.link)}" target="_blank" rel="noopener">
    <div class="t">${esc(n.title)}</div>
    <div class="s">${esc(n.source)} · hace ${ago(n.date)}</div>
    ${n.cves?.length ? `<div class="chips">${n.cves.slice(0, 8).map(c => `<span class="chip-cve" data-cve="${esc(c)}">${esc(c)}</span>`).join("")}</div>` : ""}
  </a>`;
}

// ---------- listado de CVEs ----------
function sourceRows() {
  if (S.f.src === "recent") return S.recent;
  if (S.f.src === "loaded") return [...allLoaded().values()];
  return S.months.get(S.f.src) || [];
}
function filtered() {
  const f = S.f, q = f.q.trim().toLowerCase();
  const terms = q.split(/\s+/).filter(Boolean);
  let rows = sourceRows().filter(r => {
    if (f.sev.length && !f.sev.includes(r.severity || "NONE")) return false;
    if (f.kev && !r.kev) return false;
    if (f.rw && !r.ransomware) return false;
    if (f.poc && !(r.kev || r.exploit)) return false;
    if (f.epss && (r.epss || 0) * 100 < f.epss) return false;
    if (f.watch && !isWatched(r)) return false;
    if (f.hideRev && S.reviewed.has(r.id)) return false;
    if (terms.length) {
      const hay = (r.id + " " + (r.title || "") + " " + r.desc + " " + (r.products || []).join(" ") + " " + (r.cwe || []).join(" ")).toLowerCase();
      if (!terms.every(t => hay.includes(t))) return false;
    }
    return true;
  });
  const key = {published: r => r.published, prio: priority, score: r => r.score || 0, epss: r => r.epss || 0, id: r => r.id}[f.sort] || (r => r.published);
  rows.sort((a, b) => { const x = key(a), y = key(b); return (x < y ? -1 : x > y ? 1 : 0) * f.dir; });
  return rows;
}

views.cves = () => {
  const f = S.f, rows = filtered();
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  f.page = Math.min(f.page, pages - 1);
  const slice = rows.slice(f.page * PAGE, f.page * PAGE + PAGE);
  const months = S.meta?.months || [];
  const th = (k, l, cls = "") => `<th class="${cls} ${f.sort === k ? "on" : ""}" data-sort="${k}">${l}${f.sort === k ? (f.dir < 0 ? " ↓" : " ↑") : ""}</th>`;
  return `
  <h1>Vulnerabilidades</h1>
  <p class="sub">Todas las CVEs publicadas, enriquecidas con explotación activa (KEV) y probabilidad de explotación (EPSS).</p>
  <div class="filters">
    <input type="search" id="fq" placeholder="Buscar: fortinet, rce, CVE-2026-, wordpress plugin…" value="${esc(f.q)}">
    <select id="fsrc" title="Período">
      <option value="recent" ${f.src === "recent" ? "selected" : ""}>Últimos 14 días</option>
      ${months.map(m => `<option value="${m.month}" ${f.src === m.month ? "selected" : ""}>${m.month} (${m.count.toLocaleString("es-AR")})</option>`).join("")}
      <option value="loaded" ${f.src === "loaded" ? "selected" : ""}>Todo lo cargado en memoria</option>
    </select>
    <button class="btn" id="loadall" title="Descarga todos los meses (puede tardar)">Cargar historial completo</button>
  </div>
  <div class="filters">
    <div class="seg" id="fsev">${SEV.map(s => `<button data-s="${s}" class="${f.sev.includes(s) ? "on" : ""}">${SEV_ES[s]}</button>`).join("")}</div>
    <label class="ck"><input type="checkbox" id="fkev" ${f.kev ? "checked" : ""}> Sólo explotadas (KEV)</label>
    <label class="ck"><input type="checkbox" id="fpoc" ${f.poc ? "checked" : ""}> Con exploit / PoC</label>
    <label class="ck"><input type="checkbox" id="frw" ${f.rw ? "checked" : ""}> Ransomware</label>
    <label class="ck"><input type="checkbox" id="fwatch" ${f.watch ? "checked" : ""}> Mi lista</label>
    <label class="ck"><input type="checkbox" id="frev" ${f.hideRev ? "checked" : ""}> Ocultar revisadas</label>
    <label class="ck">EPSS ≥ <input type="number" id="fepss" min="0" max="100" step="1" value="${f.epss}" style="width:64px">%</label>
    <button class="btn" id="fclear">Limpiar</button>
    <button class="btn" id="fcsv">Exportar CSV</button>
  </div>
  <p class="count">${rows.length.toLocaleString("es-AR")} resultado(s) · página ${f.page + 1} de ${pages}</p>
  <div class="card" style="padding:0 8px;overflow-x:auto">
  <table>
    <thead><tr>${th("prio", "Prioridad")}${th("id", "CVE")}${th("score", "CVSS")}${th("epss", "EPSS", "epsscol")}<th class="prod">Producto</th><th>Descripción</th>${th("published", "Publicada")}</tr></thead>
    <tbody>${slice.map(r => { const [pc, pl] = prioLabel(r); return `<tr data-cve="${esc(r.id)}" class="${S.reviewed.has(r.id) ? "rev" : ""}">
      <td><span class="prio ${pc}">${pl}</span></td>
      <td><span class="cveid">${esc(r.id)}</span><div class="chips">${tags(r)}</div></td>
      <td>${sevBadge(r)}</td>
      <td class="num epsscol">${epssTxt(r)}${r.epss != null ? `<span class="bar"><i style="width:${Math.min(100, (r.epss_pct || 0) * 100)}%"></i></span>` : ""}</td>
      <td class="prod">${prodTxt(r)}</td>
      <td class="desc"><div class="clamp">${esc(r.desc)}</div></td>
      <td class="num" title="${esc(fmtDT(r.published))}">${fmtShort(r.published)}</td></tr>`; }).join("") || `<tr><td colspan="7" class="empty">No hay resultados con esos filtros</td></tr>`}</tbody>
  </table></div>
  <div class="pager">
    <button class="btn" data-pg="-1" ${f.page === 0 ? "disabled" : ""}>← Anterior</button>
    <span>${f.page + 1} / ${pages}</span>
    <button class="btn" data-pg="1" ${f.page >= pages - 1 ? "disabled" : ""}>Siguiente →</button>
  </div>`;
};

function bindCves() {
  const f = S.f, save = () => { store.set("filters", {...f, page: 0}); render(); };
  let tmr;
  $("#fq").addEventListener("input", e => { clearTimeout(tmr); tmr = setTimeout(() => { f.q = e.target.value; f.page = 0; save(); const el = $("#fq"); el.focus(); el.setSelectionRange(el.value.length, el.value.length); }, 250); });
  $("#fsrc").addEventListener("change", async e => {
    f.src = e.target.value; f.page = 0;
    if (/^\d{4}-\d{2}$/.test(f.src)) { $("#app").insertAdjacentHTML("afterbegin", '<div class="loading">Cargando mes…</div>'); await loadMonth(f.src); }
    save();
  });
  $("#loadall").addEventListener("click", async e => {
    const ms = (S.meta?.months || []).map(m => m.month);
    const b = e.target; b.disabled = true;
    for (let i = 0; i < ms.length; i++) { b.textContent = `Cargando ${i + 1}/${ms.length}…`; await loadMonth(ms[i]); }
    f.src = "loaded"; f.page = 0; save();
  });
  $("#fsev").addEventListener("click", e => { const s = e.target.dataset.s; if (!s) return; f.sev = f.sev.includes(s) ? f.sev.filter(x => x !== s) : [...f.sev, s]; f.page = 0; save(); });
  for (const [id, k] of [["#fkev", "kev"], ["#fpoc", "poc"], ["#frw", "rw"], ["#fwatch", "watch"], ["#frev", "hideRev"]]) $(id).addEventListener("change", e => { f[k] = e.target.checked; f.page = 0; save(); });
  $("#fepss").addEventListener("change", e => { f.epss = +e.target.value || 0; f.page = 0; save(); });
  $("#fclear").addEventListener("click", () => { Object.assign(f, {q:"", sev:[], kev:false, rw:false, poc:false, watch:false, hideRev:false, epss:0, page:0}); save(); });
  $("#fcsv").addEventListener("click", () => exportCSV(filtered()));
  document.querySelectorAll("th[data-sort]").forEach(th => th.addEventListener("click", () => {
    const k = th.dataset.sort; if (f.sort === k) f.dir *= -1; else { f.sort = k; f.dir = k === "id" ? 1 : -1; } f.page = 0; save();
  }));
  document.querySelectorAll("[data-pg]").forEach(b => b.addEventListener("click", () => { f.page += +b.dataset.pg; render(); window.scrollTo(0, 0); }));
}

function exportCSV(rows) {
  const cols = ["id", "published", "severity", "score", "epss", "kev", "ransomware", "products", "cwe", "desc"];
  const q = v => `"${String(Array.isArray(v) ? v.join(" | ") : v ?? "").replace(/"/g, '""')}"`;
  const csv = "﻿" + [cols.join(","), ...rows.map(r => cols.map(c => q(r[c])).join(","))].join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], {type: "text/csv;charset=utf-8"}));
  a.download = `vulnwatch-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
}

// ---------- KEV ----------
let kevQ = "", kevRW = false, kevPage = 0;
views.kev = () => {
  const terms = kevQ.toLowerCase().split(/\s+/).filter(Boolean);
  const rows = S.kev.items.filter(k => (!kevRW || k.ransomware === "Known") &&
    terms.every(t => (k.id + " " + k.vendor + " " + k.product + " " + k.name).toLowerCase().includes(t)));
  const pages = Math.max(1, Math.ceil(rows.length / PAGE)); kevPage = Math.min(kevPage, pages - 1);
  const today = new Date().toISOString().slice(0, 10);
  return `
  <h1>Vulnerabilidades explotadas activamente</h1>
  <p class="sub">Catálogo KEV de CISA (${esc(S.kev.version || "")}): ${S.kev.items.length.toLocaleString("es-AR")} vulnerabilidades con explotación confirmada. Son las que hay que parchear primero.</p>
  <div class="filters">
    <input type="search" id="kq" placeholder="Buscar proveedor, producto, CVE…" value="${esc(kevQ)}">
    <label class="ck"><input type="checkbox" id="krw" ${kevRW ? "checked" : ""}> Sólo usadas en ransomware</label>
  </div>
  <p class="count">${rows.length.toLocaleString("es-AR")} resultado(s)</p>
  <div class="card" style="padding:0 8px;overflow-x:auto"><table>
    <thead><tr><th>CVE</th><th>Proveedor / producto</th><th>Vulnerabilidad</th><th>Agregada</th><th>Plazo CISA</th></tr></thead>
    <tbody>${rows.slice(kevPage * PAGE, kevPage * PAGE + PAGE).map(k => `<tr data-cve="${esc(k.id)}">
      <td><span class="cveid">${esc(k.id)}</span><div class="chips">${k.ransomware === "Known" ? '<span class="tag rw">RANSOMWARE</span>' : ""}${isWatched({desc: k.vendor + " " + k.product + " " + k.name, id: k.id}) ? '<span class="tag watch">MI LISTA</span>' : ""}</div></td>
      <td><b>${esc(k.vendor)}</b><br><span class="note">${esc(k.product)}</span></td>
      <td class="desc"><div class="clamp">${esc(k.name)}</div></td>
      <td class="num">${fmtShort(k.added)}</td>
      <td class="num" style="color:${k.due >= today ? "var(--med)" : "var(--tx3)"}">${fmtShort(k.due)}</td></tr>`).join("")}</tbody>
  </table></div>
  <div class="pager"><button class="btn" data-kpg="-1" ${kevPage === 0 ? "disabled" : ""}>← Anterior</button><span>${kevPage + 1} / ${pages}</span><button class="btn" data-kpg="1" ${kevPage >= pages - 1 ? "disabled" : ""}>Siguiente →</button></div>`;
};
function bindKev() {
  let t;
  $("#kq").addEventListener("input", e => { clearTimeout(t); t = setTimeout(() => { kevQ = e.target.value; kevPage = 0; render(); const el = $("#kq"); el.focus(); el.setSelectionRange(el.value.length, el.value.length); }, 200); });
  $("#krw").addEventListener("change", e => { kevRW = e.target.checked; kevPage = 0; render(); });
  document.querySelectorAll("[data-kpg]").forEach(b => b.addEventListener("click", () => { kevPage += +b.dataset.kpg; render(); window.scrollTo(0, 0); }));
}

// ---------- noticias ----------
let newsSrc = "", newsQ = "", newsCVE = false;
views.noticias = () => {
  const sources = [...new Set(S.news.map(n => n.source))].sort();
  const terms = newsQ.toLowerCase().split(/\s+/).filter(Boolean);
  const rows = S.news.filter(n => (!newsSrc || n.source === newsSrc) && (!newsCVE || n.cves?.length) &&
    terms.every(t => (n.title + " " + n.summary + " " + (n.cves || []).join(" ")).toLowerCase().includes(t)));
  return `
  <h1>Noticias de seguridad</h1>
  <p class="sub">Últimas novedades de ${sources.length} fuentes. Los CVEs mencionados se pueden abrir directamente.</p>
  <div class="filters">
    <input type="search" id="nq" placeholder="Buscar en noticias…" value="${esc(newsQ)}">
    <select id="nsrc"><option value="">Todas las fuentes</option>${sources.map(s => `<option ${s === newsSrc ? "selected" : ""}>${esc(s)}</option>`).join("")}</select>
    <label class="ck"><input type="checkbox" id="ncve" ${newsCVE ? "checked" : ""}> Sólo las que mencionan CVEs</label>
  </div>
  <p class="count">${rows.length} noticia(s)</p>
  <div class="card">${rows.slice(0, 200).map(n => newsHTML(n).replace('<div class="s">', `<div class="sm">${esc(n.summary)}</div><div class="s">`)).join("") || '<div class="empty">Sin resultados</div>'}</div>`;
};
function bindNews() {
  let t;
  $("#nq").addEventListener("input", e => { clearTimeout(t); t = setTimeout(() => { newsQ = e.target.value; render(); const el = $("#nq"); el.focus(); el.setSelectionRange(el.value.length, el.value.length); }, 200); });
  $("#nsrc").addEventListener("change", e => { newsSrc = e.target.value; render(); });
  $("#ncve").addEventListener("change", e => { newsCVE = e.target.checked; render(); });
}

// ---------- configuración / mi lista ----------
views.config = () => `
  <h1>Mi lista de vigilancia</h1>
  <p class="sub">Escribí los proveedores, productos o palabras que te interesan. Las CVEs que coincidan se marcan con <span class="tag watch">MI LISTA</span> y aparecen en el resumen.</p>
  <div class="card cfg" style="max-width:760px">
    <h2>Palabras clave</h2>
    <p class="note">Separadas por coma. Se busca en la descripción, los productos (CPE) y el ID. Ej: <span class="mono">fortinet, fortios, windows server, exchange, wordpress, apache, cisco ios, vmware</span></p>
    <textarea id="wl">${esc(S.watch.join(", "))}</textarea>
    <div style="display:flex;gap:8px;margin-top:10px"><button class="btn pri" id="wlsave">Guardar</button><span id="wlok" class="note" style="align-self:center"></span></div>
    <h2 style="margin-top:24px">Revisadas</h2>
    <p class="note">Tenés ${S.reviewed.size} CVE(s) marcadas como revisadas en este navegador.</p>
    <button class="btn" id="revclear">Borrar marcas de revisado</button>
    <h2 style="margin-top:24px">Estado de los datos</h2>
    <p class="note">Última actualización: ${fmtDT(S.meta?.updated)} UTC · CVEs en base: ${(S.meta?.total_cves || 0).toLocaleString("es-AR")} · meses: ${(S.meta?.months || []).length} · KEV: ${S.kev.items.length} · noticias: ${S.news.length}</p>
    <p class="note">La lista y las marcas se guardan sólo en este navegador. Para recibir alertas por Telegram con tu lista, configurá la variable <span class="mono">WATCHLIST</span> en GitHub (ver README).</p>
  </div>`;
function bindConfig() {
  $("#wlsave").addEventListener("click", () => {
    S.watch = $("#wl").value.split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
    store.set("watch", S.watch); $("#wlok").textContent = `Guardado (${S.watch.length} palabra(s))`;
  });
  $("#revclear").addEventListener("click", () => { S.reviewed.clear(); store.set("reviewed", []); render(); });
}

// ---------- detalle ----------
async function openCVE(id) {
  const modal = $("#modal"), body = $("#mbody");
  modal.hidden = false; document.body.style.overflow = "hidden";
  body.innerHTML = '<div class="loading">Buscando ' + esc(id) + '…</div>';
  const r = await findCVE(id).catch(() => null);
  const k = S.kevMap.get(id.toUpperCase());
  const news = S.news.filter(n => n.cves?.includes(id.toUpperCase()));
  if (!r && !k) {
    body.innerHTML = `<div class="det"><h1>${esc(id)}</h1><p>No está en la base local (puede ser anterior al período cargado o muy reciente).</p>
      <div class="actions"><a class="btn" target="_blank" rel="noopener" href="https://nvd.nist.gov/vuln/detail/${esc(id)}">Ver en NVD</a><a class="btn" target="_blank" rel="noopener" href="https://www.cve.org/CVERecord?id=${esc(id)}">Ver en CVE.org</a></div></div>`;
    return;
  }
  const x = r || {id: k.id, desc: k.desc, severity: "NONE", score: null, kev: 1, ransomware: k.ransomware === "Known" ? 1 : 0, products: [`${k.vendor}:${k.product}`], refs: [], cwe: k.cwe};
  const [pc, pl] = prioLabel(x);
  const rev = S.reviewed.has(x.id);
  body.innerHTML = `<div class="det">
    <h1>${esc(x.id)} ${sevBadge(x)} <span class="prio ${pc}">${pl}</span> ${tags(x)}</h1>
    <div class="note">${x.published ? `Publicada ${fmtDT(x.published)} · modificada ${fmtDT(x.modified)} · ` : ""}${esc(x.status || "")}${x.source ? " · CNA: " + esc(x.source) : ""}</div>
    <div class="facts">
      <div class="fact"><div class="k">CVSS ${esc(x.cvss_version || "")}</div><div class="v">${x.score ?? "–"}</div></div>
      <div class="fact"><div class="k">EPSS (prob. 30 días)</div><div class="v">${epssTxt(x)}</div></div>
      <div class="fact"><div class="k">Percentil EPSS</div><div class="v">${x.epss_pct != null ? Math.round(x.epss_pct * 100) + "°" : "–"}</div></div>
      <div class="fact"><div class="k">Prioridad</div><div class="v">${priority(x)}</div></div>
    </div>
    ${x.title ? `<p style="font-weight:600;margin-bottom:0">${esc(x.title)}</p>` : ""}
    <p class="desc">${esc(x.desc_es || x.desc)}</p>
    ${x.origin === "cve.org" ? `<p class="note">Datos preliminares de CVE.org (puntaje del fabricante/CNA). Se completa automáticamente cuando la NVD la analiza.</p>` : ""}
    ${x.exploit ? `<p class="note">Indicador CISA (SSVC): explotación <b>${x.exploit === "active" ? "ACTIVA" : "con PoC público"}</b>.</p>` : ""}
    ${x.vector ? `<div class="vec">${esc(x.vector)}</div>` : ""}
    ${k ? `<h3>Explotación activa (CISA KEV)</h3><div class="kevbox"><b>${esc(k.name)}</b><br>
      Agregada el ${fmtDate(k.added)} · plazo de remediación ${fmtDate(k.due)} · ransomware: ${k.ransomware === "Known" ? "<b>SÍ</b>" : "desconocido"}<br>
      <span class="note">Acción requerida: ${esc(k.action)}</span></div>` : ""}
    ${(x.products || []).length ? `<h3>Productos afectados</h3><div class="chips">${x.products.map(p => `<span class="tag">${esc(p.replace(":", " · "))}</span>`).join("")}</div>` : ""}
    ${(x.cwe || []).length ? `<h3>Debilidad (CWE)</h3><div class="chips">${x.cwe.map(c => `<a class="tag" target="_blank" rel="noopener" href="https://cwe.mitre.org/data/definitions/${esc(c.replace("CWE-", ""))}.html">${esc(c)}</a>`).join("")}</div>` : ""}
    ${news.length ? `<h3>Noticias relacionadas</h3>${news.map(newsHTML).join("")}` : ""}
    ${(x.refs || []).length ? `<h3>Referencias</h3><ul class="refs">${x.refs.map(u => `<li><a href="${safeUrl(u.url)}" target="_blank" rel="noopener">${esc(u.url)}</a> ${(u.tags || []).map(t => `<span class="tag">${esc(t)}</span>`).join(" ")}</li>`).join("")}</ul>` : ""}
    <div class="actions">
      <button class="btn ${rev ? "" : "pri"}" id="mrev">${rev ? "✓ Revisada (desmarcar)" : "Marcar como revisada"}</button>
      <a class="btn" target="_blank" rel="noopener" href="https://nvd.nist.gov/vuln/detail/${esc(x.id)}">NVD</a>
      <a class="btn" target="_blank" rel="noopener" href="https://www.cve.org/CVERecord?id=${esc(x.id)}">CVE.org</a>
      <a class="btn" target="_blank" rel="noopener" href="https://github.com/search?q=${esc(x.id)}&type=code">Buscar PoC en GitHub</a>
      <button class="btn" id="mcopy">Copiar enlace</button>
    </div></div>`;
  $("#mrev").onclick = () => {
    rev ? S.reviewed.delete(x.id) : S.reviewed.add(x.id);
    store.set("reviewed", [...S.reviewed]); openCVE(x.id); if (route().v === "cves") render(true);
  };
  $("#mcopy").onclick = e => { navigator.clipboard?.writeText(location.href.split("#")[0] + "#/cve/" + x.id); e.target.textContent = "¡Copiado!"; };
}
function closeModal() {
  $("#modal").hidden = true; document.body.style.overflow = "";
  if (location.hash.startsWith("#/cve/")) history.replaceState(null, "", S.back || "#/hoy");
}

// ---------- router ----------
function route() {
  const h = location.hash.replace(/^#\/?/, "");
  const [v, arg] = h.split("/");
  return {v: v || "hoy", arg};
}
function render(keepScroll) {
  const {v, arg} = route();
  if (v === "cve" && arg) {
    if (!$("#app").dataset.v) { $("#app").innerHTML = views.hoy(); $("#app").dataset.v = "hoy"; }
    openCVE(decodeURIComponent(arg)); return;
  }
  const view = views[v] ? v : "hoy";
  const y = window.scrollY;
  $("#app").innerHTML = views[view]();
  $("#app").dataset.v = view;
  document.querySelectorAll("#nav a").forEach(a => a.classList.toggle("on", a.dataset.r === view));
  ({cves: bindCves, kev: bindKev, noticias: bindNews, config: bindConfig})[view]?.();
  if (keepScroll) window.scrollTo(0, y);
}

document.addEventListener("click", e => {
  const s = e.target.closest("[data-sort='prio'][href]");
  if (s) { S.f.sort = "prio"; S.f.dir = -1; S.f.src = "recent"; }
  const el = e.target.closest("[data-cve]");
  if (el && !e.target.closest("a[href]:not([data-cve])") ) {
    if (el.classList.contains("chip-cve")) e.preventDefault();
    S.back = location.hash.startsWith("#/cve/") ? S.back : (location.hash || "#/hoy");
    location.hash = "#/cve/" + el.dataset.cve;
  }
});
$("#mclose").addEventListener("click", closeModal);
$("#modal").addEventListener("click", e => { if (e.target.id === "modal") closeModal(); });
document.addEventListener("keydown", e => {
  if (e.key === "Escape" && !$("#modal").hidden) closeModal();
  if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) { e.preventDefault(); $("#gq").focus(); }
});
$("#gsearch").addEventListener("submit", e => {
  e.preventDefault();
  const q = $("#gq").value.trim();
  if (/^CVE-\d{4}-\d+$/i.test(q)) { S.back = location.hash; location.hash = "#/cve/" + q.toUpperCase(); return; }
  S.f.q = q; S.f.page = 0; store.set("filters", S.f);
  if (location.hash === "#/cves") render(); else location.hash = "#/cves";
});
window.addEventListener("hashchange", () => {
  if (!location.hash.startsWith("#/cve/") && !$("#modal").hidden) { $("#modal").hidden = true; document.body.style.overflow = ""; }
  render();
});

// ---------- inicio ----------
(async () => {
  try {
    const [meta, recent, kev, news] = await Promise.all([
      getJSON("data/meta.json"), getJSON("data/recent.json"),
      getJSON("data/kev.json").catch(() => ({items: []})), getJSON("data/news.json").catch(() => []),
    ]);
    Object.assign(S, {meta, recent, kev, news});
    S.kevMap = new Map(kev.items.map(k => [k.id, k]));
    $("#updated").textContent = "Actualizado " + fmtDT(meta.updated);
    if (/^\d{4}-\d{2}$/.test(S.f.src)) await loadMonth(S.f.src).catch(() => { S.f.src = "recent"; });
    if (S.f.src === "loaded") S.f.src = "recent";
    render();
  } catch (err) {
    $("#app").innerHTML = `<div class="empty"><h2>Todavía no hay datos</h2><p>Ejecutá el workflow <b>Actualizar datos</b> en GitHub Actions (o <span class="mono">python scripts/fetch.py</span> localmente).</p><p class="note">${esc(err.message)}</p></div>`;
  }
})();
})();
