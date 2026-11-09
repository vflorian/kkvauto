/* CapScope UI – vanilla JS, no external resources. All capture-derived text goes through textContent. */
"use strict";

const S = {
  cid: null, cap: null, system: null,
  filter: null, twin: null, tunnel: null, page: null, selected: new Set(),
  detailFrame: null, detailMode: "context", incident: null, txnSub: "txn",
};

// ---------------------------------------------------------------- helpers
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "html") throw new Error("no html");
    else if (k === "style") e.style.cssText = v;  // CSSOM: allowed under the strict CSP
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return e;
}
const $ = (s) => document.querySelector(s);
const fmtN = (n) => (n === null || n === undefined) ? "–" : Number(n).toLocaleString("hu-HU");
function fmtBytes(b) {
  if (b === null || b === undefined) return "–";
  const u = ["B", "KiB", "MiB", "GiB", "TiB"]; let i = 0; let v = Number(b);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}
const fmtMs = (ns) => (ns === null || ns === undefined) ? "–" : `${(ns / 1e6).toFixed(1)} ms`;
const utc = (s) => s ? s.replace("T", " ").replace("Z", "") : "–";
const hex8 = (n) => "0x" + Number(n).toString(16).padStart(8, "0");
const STATE_HU = { observed: "megfigyelt", inferred: "következtetett", undetermined: "nem eldönthető" };
const NO_RSP = "A válasz nem látszik a vizsgált capture-ben.";
function stateChip(st, rule) { return el("span", { class: `chip ${st || ""}`, title: rule || "" }, STATE_HU[st] || st || "–"); }
function sevChip(s) { return el("span", { class: "chip " + ({ error: "err", warn: "warn", info: "" }[s] || "") }, { error: "hiba", warn: "figyelmeztetés", info: "info" }[s] || s); }
function frameLink(f, label) {
  if (!f) return "–";
  return el("button", { class: "link mono", title: "Ugrás a csomagra", onclick: (ev) => { ev.stopPropagation(); gotoPacket(f); } }, label || `#${f}`);
}
function framesLinks(list, max = 8) {
  const out = [];
  (list || []).slice(0, max).forEach((f, i) => { if (i) out.push(" "); out.push(frameLink(f)); });
  if ((list || []).length > max) out.push(` … (+${list.length - max})`);
  return out.length ? out : "–";
}
function toast(msg, ms = 3500) {
  const t = $("#toast"); t.textContent = msg; t.classList.remove("hidden");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add("hidden"), ms);
}
async function api(path, opts = {}) {
  const o = { method: opts.method || "GET", headers: { "X-CapScope": "1" } };
  if (opts.body !== undefined) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(opts.body); }
  const r = await fetch(path, o);
  let j = null; try { j = await r.json(); } catch (_) { j = null; }
  if (!r.ok) { const e = new Error((j && j.error) || `${r.status} ${r.statusText}`); e.data = j; throw e; }
  return j;
}
const post = (p, body) => api(p, { method: "POST", body: body || {} });
function modal(...content) { const b = $("#modal-body"); b.replaceChildren(...content); $("#modal").classList.remove("hidden"); }
$("#modal-close").onclick = () => $("#modal").classList.add("hidden");
$("#modal").onclick = (e) => { if (e.target.id === "modal") $("#modal").classList.add("hidden"); };
function qs(o) { const p = new URLSearchParams(); for (const [k, v] of Object.entries(o)) if (v !== null && v !== undefined && v !== "") p.set(k, v); return p.toString(); }
function table(cols, rows, onRow) {
  const thead = el("thead", null, el("tr", null, cols.map(c => el("th", { class: c.num ? "num" : null }, c.t))));
  const tb = el("tbody");
  for (const r of rows) {
    const tr = el("tr", { class: onRow ? "clickable" : null, onclick: onRow ? () => onRow(r, tr) : null },
      cols.map(c => el("td", { class: (c.num ? "num " : "") + (c.mono ? "mono" : "") }, c.f ? c.f(r) : (r[c.k] ?? "–"))));
    tb.append(tr);
  }
  return el("table", null, thead, tb);
}

// ---------------------------------------------------------------- tabs
document.querySelectorAll("#tabs button").forEach(b => b.onclick = () => showTab(b.dataset.tab));
function showTab(name) {
  document.querySelectorAll("#tabs button").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".tab").forEach(s => s.classList.toggle("active", s.id === `tab-${name}`));
  S.tab = name;
  if (!S.cid && name !== "incident") return;
  ({ overview: renderOverview, sim: renderSim, txn: renderTxn, packets: renderPackets, incident: renderIncident }[name])();
}

// ---------------------------------------------------------------- jobs
const tracked = new Map();
function trackJob(job, onDone) {
  if (!job) return;
  tracked.set(job.id, { job, onDone });
  drawJobs();
  if (!trackJob._timer) trackJob._timer = setInterval(pollJobs, 700);
}
async function pollJobs() {
  if (!tracked.size) { clearInterval(trackJob._timer); trackJob._timer = null; return; }
  for (const [id, t] of tracked) {
    try { t.job = await api(`/api/jobs/${id}`); } catch (e) { tracked.delete(id); continue; }
    if (!["queued", "running"].includes(t.job.state)) {
      tracked.delete(id);
      const msg = { done: "Kész", cancelled: "Megszakítva", failed: "Hiba", partial: "Részleges" }[t.job.state] || t.job.state;
      toast(`${t.job.title}: ${msg}${t.job.error ? " – " + t.job.error : ""}`, t.job.error ? 8000 : 3500);
      if (t.onDone) t.onDone(t.job);
    }
  }
  drawJobs();
}
function drawJobs() {
  const box = $("#jobs"); box.replaceChildren();
  for (const { job } of tracked.values()) {
    const p = job.progress;
    const bar = el("div", { class: "pbar" + (p === null || p === undefined ? " indet" : "") }, el("div", { style: `width:${Math.round((p || 0) * 100)}%` }));
    box.append(el("div", { class: "job" }, el("b", null, job.title), bar,
      el("span", { class: "small muted" }, `${job.message || job.state} · ${job.elapsed_s ?? 0} s`),
      el("button", { class: "danger", onclick: async () => { await post(`/api/jobs/${job.id}/cancel`); toast("Megszakítás kérve…"); } }, "Megszakítás")));
  }
}

// ---------------------------------------------------------------- captures
async function loadCaptures(selectId) {
  const caps = await api("/api/captures");
  const sel = $("#capture-select");
  sel.replaceChildren(el("option", { value: "" }, "– válassz –"),
    ...caps.map(c => el("option", { value: c.id }, `#${c.id} ${c.name} (${statusHu(c.status)}, ${fmtN(c.frames)} cs.)`)));
  if (selectId) sel.value = String(selectId);
  for (const c of caps) for (const j of c.running_jobs || []) if (!tracked.has(j.id)) trackJob(j, () => selectCapture(c.id));
  return caps;
}
function statusHu(s) { return { ready: "kész", partial: "részleges", cancelled: "megszakítva", indexing: "indexelés", queued: "várakozik", failed: "hiba", interrupted: "megszakadt" }[s] || s; }
$("#capture-select").onchange = (e) => selectCapture(e.target.value ? Number(e.target.value) : null);
async function selectCapture(cid) {
  S.cid = cid; S.filter = null; S.twin = null; S.tunnel = null; S.selected.clear(); S.detailFrame = null; S.page = null;
  if (!cid) { S.cap = null; drawBanners(); return; }
  S.cap = await api(`/api/captures/${cid}`);
  $("#capture-select").value = String(cid);
  const st = $("#cap-status"); st.textContent = statusHu(S.cap.status);
  st.className = "chip " + ({ ready: "ok", partial: "warn", cancelled: "warn", interrupted: "warn", failed: "err" }[S.cap.status] || "");
  drawBanners();
  showTab(S.tab || "overview");
}
function drawBanners() {
  const b = $("#banners"); b.replaceChildren();
  const c = S.cap; if (!c) return;
  if (["partial", "cancelled", "interrupted"].includes(c.status))
    b.append(el("div", { class: "banner warn" }, el("b", null, "Részleges elemzés: "), c.partial_reason || "Az index nem teljes.",
      ` Indexelt csomagok: ${fmtN(c.frames)}. A vágás közeli kérések „nem eldönthető” állapotúak.`,
      " ", el("button", { onclick: () => reindex() }, "Újraindexelés")));
  if (c.status === "failed") b.append(el("div", { class: "banner err" }, el("b", null, "Hiba: "), c.error || "Az indexelés nem sikerült.", " ", el("button", { onclick: () => reindex() }, "Újrapróbálás")));
  if (c.file_changed) b.append(el("div", { class: "banner err" }, el("b", null, "A fájl megváltozott vagy nem elérhető az indexelés óta. "), "A csomagtartalom és az export le van tiltva, amíg újra nem indexeled.", " ", el("button", { onclick: () => reindex() }, "Újraindexelés")));
  const info = c.info || {};
  for (const w of info.warnings || []) b.append(el("div", { class: "banner info" }, w));
  if ((info.dsb || []).length) b.append(el("div", { class: "banner warn" }, el("b", null, "Beágyazott dekriptálási titkok (DSB): "), info.dsb.map(d => `${d.kind} (${d.length} B)`).join(", "), ". Exportból alapértelmezésben kimaradnak."));
}
async function reindex() {
  if (!S.cid) return;
  const r = await post(`/api/captures/${S.cid}/reindex`, {});
  trackJob(r.job, () => { loadCaptures(S.cid); selectCapture(S.cid); });
}
$("#btn-open").onclick = async () => {
  const path = $("#open-path").value.trim();
  if (!path) { toast("Adj meg egy fájlútvonalat."); return; }
  try {
    const r = await post("/api/captures", { path, max_packets: $("#open-max").value || null });
    await loadCaptures(r.capture.id);
    if (r.existing) { toast("Ez a fájl már indexelve van – a meglévő indexet nyitom meg."); selectCapture(r.capture.id); }
    else { S.cid = r.capture.id; trackJob(r.job, () => { loadCaptures(r.capture.id); selectCapture(r.capture.id); }); selectCapture(r.capture.id); }
  } catch (e) { toast(e.message, 7000); }
};
$("#btn-browse").onclick = async () => {
  toast("Fájlválasztó megnyitása (lehet, hogy a böngésző mögött jelenik meg)…");
  const r = await post("/api/browse");
  if (r.path) $("#open-path").value = r.path; else if (r.error) toast(r.error, 6000);
};
$("#open-path").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#btn-open").click(); });

// ---------------------------------------------------------------- 1. overview
async function renderOverview() {
  const root = $("#tab-overview");
  if (!S.cap || !["ready", "partial", "cancelled", "interrupted"].includes(S.cap.status)) {
    root.replaceChildren(el("div", { class: "empty" }, S.cap ? `Állapot: ${statusHu(S.cap.status)}. Az eredmények az indexelés után jelennek meg.` : "Nyiss meg egy capture-t."));
    return;
  }
  const o = await api(`/api/captures/${S.cid}/overview`);
  const c = o.capture, info = c.info || {};
  const sum = (arr, f) => arr.filter(f).reduce((a, x) => a + x.n, 0);
  const meta = el("div", { class: "card" }, el("h3", null, "Capture metaadatok"), el("dl", { class: "kv" },
    el("dt", null, "Fájl"), el("dd", { class: "mono" }, c.path),
    el("dt", null, "Méret"), el("dd", null, fmtBytes(c.size)),
    el("dt", null, "Formátum"), el("dd", null, `${info.format || c.format}${info.compressed ? " (gzip)" : ""}`),
    el("dt", null, "SHA-256"), el("dd", { class: "mono small" }, c.sha256 || "– (megszakított import)"),
    el("dt", null, "Index"), el("dd", null, `${statusHu(c.status)} · ${c.index_seconds ?? "–"} s · TShark ${c.tshark_version || "?"}`),
    ...(info.sections || []).flatMap(s => [el("dt", null, `Szekció ${s.section}`), el("dd", { class: "small" }, [s.comment, s.hardware, s.os, s.userappl].filter(Boolean).join(" · ") || "–")])));
  const time = el("div", { class: "card" }, el("h3", null, "Időtartam (UTC)"), el("dl", { class: "kv" },
    el("dt", null, "Első csomag"), el("dd", { class: "mono" }, utc(o.first_utc)),
    el("dt", null, "Utolsó csomag"), el("dd", { class: "mono" }, utc(o.last_utc)),
    el("dt", null, "Időtartam"), el("dd", null, o.duration_s !== null ? `${o.duration_s.toFixed(3)} s` : "–"),
    el("dt", null, "Csomagszám"), el("dd", null, fmtN(c.frames)),
    el("dt", null, "Bájt (frame.len)"), el("dd", null, fmtBytes(o.bytes)),
    el("dt", null, "Snaplen-csonkolt"), el("dd", null, info.snaplen_truncated ? `${fmtN(info.snaplen_truncated)} csomag` : "0"),
    el("dt", null, "Csonka fájl"), el("dd", null, info.truncated ? `igen – ${info.truncation_note}` : "nem")));
  const res = el("div", { class: "card" }, el("h3", null, "Elemzési eredmények"), el("dl", { class: "kv" },
    el("dt", null, "Megállapítások"), el("dd", null, `${sum(o.findings, x => x.severity === "error")} hiba · ${sum(o.findings, x => x.severity === "warn")} figyelmeztetés · ${sum(o.findings, x => x.severity === "info")} info`),
    el("dt", null, "DNS tranzakciók"), el("dd", null, `${sum(o.transactions, x => x.proto === "dns")} (válasz nélkül: ${sum(o.transactions, x => x.proto === "dns" && x.status === "unanswered")})`),
    el("dt", null, "GTP-C tranzakciók"), el("dd", null, `${sum(o.transactions, x => x.proto !== "dns")} (válasz nélkül: ${sum(o.transactions, x => x.proto !== "dns" && x.status === "unanswered")})`),
    el("dt", null, "GTP sessionök"), el("dd", null, o.sessions.map(s => `${s.status}: ${s.n}`).join(" · ") || "0"),
    el("dt", null, "Flow-k"), el("dd", null, fmtN(o.flows))),
    el("button", { onclick: () => { S.txnSub = "findings"; showTab("txn"); } }, "Megállapítások megnyitása"));
  const ifs = el("div", { class: "card" }, el("h3", null, "Interfészek"), table([
    { t: "Szekció", f: r => r.section ?? "–" }, { t: "ID", k: "iface" }, { t: "Név", f: r => r.name || "–" },
    { t: "Leírás", f: r => r.description || "–" }, { t: "Linktype", k: "linktype" }, { t: "Snaplen", k: "snaplen", num: true },
    { t: "Időfelbontás", f: r => r.tsresol >= 0 ? `10^-${r.tsresol} s` : `2^${r.tsresol} s` },
    { t: "Eldobott (ISB ifdrop)", f: r => r.ifdrop === null || r.ifdrop === undefined ? el("span", { class: "chip" }, "Nincs adat") : fmtN(r.ifdrop) },
    { t: "OS drop", f: r => r.osdrop === null || r.osdrop === undefined ? el("span", { class: "chip" }, "Nincs adat") : fmtN(r.osdrop) },
  ], o.interfaces));
  const chart = el("div", { class: "card" }, el("h3", null, "Forgalmi idővonal (UTC) – kattints egy oszlopra a csomagokhoz"), timelineSvg(o.timeline));
  const phsMax = Math.max(1, ...o.phs.map(p => p.pkts));
  const phs = el("div", { class: "card" }, el("h3", null, "Protokollhierarchia"), el("div", { class: "scroll", style: "max-height:360px" }, table([
    { t: "Protokoll", f: r => el("span", { style: `padding-left:${r.depth * 12}px` }, r.path.split(":").pop()) },
    { t: "Csomag", k: "pkts", num: true, f: r => fmtN(r.pkts) }, { t: "Bájt", num: true, f: r => fmtBytes(r.bytes) },
    { t: "", f: r => el("div", { class: "barcell" }, el("div", { style: `width:${Math.round(r.pkts / phsMax * 100)}%` })) },
  ], o.phs, r => applyFilterAndGo(r.path.split(":").pop()))));
  phs.querySelector("table").classList.add("phs");
  const talk = (title, rows) => el("div", { class: "card" }, el("h3", null, title), rows.length ? table([
    { t: "IP", k: "ip", mono: true }, { t: "Küldött cs.", num: true, f: r => fmtN(r.pkts_tx) }, { t: "Fogadott cs.", num: true, f: r => fmtN(r.pkts_rx) },
    { t: "Küldött", num: true, f: r => fmtBytes(r.bytes_tx) }, { t: "Fogadott", num: true, f: r => fmtBytes(r.bytes_rx) },
  ], rows, r => applyFilterAndGo(r.ip.includes(":") ? `ipv6.addr == ${r.ip}` : `ip.addr == ${r.ip}`)) : el("div", { class: "muted" }, "Nincs adat"));
  root.replaceChildren(el("div", { class: "grid" }, meta, time, res), ifs, chart,
    el("div", { class: "grid" }, phs, talk("Top talkers – külső / tunnel IP", o.talkers.outer), talk("Top talkers – belső (payload) IP", o.talkers.inner)));
}
function timelineSvg(tl) {
  const W = 1000, H = 150, pad = 24;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`); svg.setAttribute("class", "svgchart"); svg.setAttribute("preserveAspectRatio", "none");
  if (!tl.length) return el("div", { class: "muted" }, "Nincs adat");
  const max = Math.max(...tl.map(b => b.pkts)), bw = (W - pad) / tl.length;
  tl.forEach((b, i) => {
    const h = Math.max(1, (b.pkts / max) * (H - 30));
    const r = document.createElementNS(svg.namespaceURI, "rect");
    r.setAttribute("x", pad + i * bw); r.setAttribute("y", H - 16 - h); r.setAttribute("width", Math.max(1, bw - 1)); r.setAttribute("height", h);
    r.setAttribute("class", "bar");
    const t = document.createElementNS(svg.namespaceURI, "title");
    const d = new Date(b.t * 1000).toISOString().replace("T", " ").replace(".000Z", "");
    t.textContent = `${d} UTC (+${b.w} s): ${b.pkts} csomag, ${fmtBytes(b.bytes)}`;
    r.append(t);
    r.addEventListener("click", () => { S.twin = { t0: `${b.t}000000000`, t1: `${b.t + b.w}000000000`, label: `${d} UTC + ${b.w} s` }; S.page = null; showTab("packets"); });
    svg.append(r);
  });
  const lab = (x, txt, anchor) => { const t = document.createElementNS(svg.namespaceURI, "text"); t.setAttribute("x", x); t.setAttribute("y", H - 3); t.setAttribute("text-anchor", anchor); t.textContent = txt; svg.append(t); };
  lab(pad, new Date(tl[0].t * 1000).toISOString().slice(11, 19), "start");
  lab(W, new Date((tl[tl.length - 1].t + tl[tl.length - 1].w) * 1000).toISOString().slice(11, 19), "end");
  const m = document.createElementNS(svg.namespaceURI, "text"); m.setAttribute("x", 2); m.setAttribute("y", 12); m.textContent = `max ${max} cs./oszlop`; svg.append(m);
  return svg;
}
function applyFilterAndGo(expr) { S.pendingFilter = expr; S.page = null; showTab("packets"); }

// ---------------------------------------------------------------- 2. SIM & session
async function renderSim() {
  const root = $("#tab-sim");
  if (!root.dataset.built || root.dataset.cid !== String(S.cid)) {
    root.dataset.built = "1"; root.dataset.cid = String(S.cid);
    const q = el("input", { type: "text", id: "sim-q", placeholder: "IMSI, MSISDN, APN, kiosztott IP vagy TEID (0x… / decimális)", style: "flex:1" });
    const f = el("select", { id: "sim-f" }, ["any:Bármely", "imsi:IMSI", "msisdn:MSISDN", "apn:APN", "ip:Kiosztott / tunnel IP", "teid:TEID"].map(x => { const [v, t] = x.split(":"); return el("option", { value: v }, t); }));
    q.addEventListener("keydown", e => { if (e.key === "Enter") simSearch(); });
    root.replaceChildren(el("div", { class: "toolbar" }, q, f, el("button", { class: "primary", onclick: simSearch }, "Keresés")),
      el("div", { class: "note" }, "A GTP-U forgalom csak akkor kerül egy sessionhöz, ha a külső cél-IP (fogadó tunnelvégpont) + TEID egy, a GTP-C-ben ugyanannak a sessionnek jelzett user-plane F-TEID-del egyezik, és a csomag a session érvényességi ablakába esik. Azonos TEID más végponton vagy csak egyező IP nem elég. Több jelöltnél „nem eldönthető”."),
      el("div", { id: "sim-list" }), el("div", { id: "sim-detail" }));
  }
  simSearch();
}
async function simSearch() {
  const q = $("#sim-q").value.trim(), field = $("#sim-f").value;
  const r = await api(`/api/captures/${S.cid}/sessions?${qs({ q, field, limit: 500 })}`);
  const list = $("#sim-list");
  const parts = [el("div", { class: "card" }, el("h3", null, `Sessionök (${r.total})`), r.rows.length ? el("div", { class: "scroll", style: "max-height:320px" }, table([
    { t: "#", k: "id" }, { t: "GTP", f: x => `v${x.version}` }, { t: "Interfész", f: x => x.leg || "–" },
    { t: "IMSI", k: "imsi", mono: true }, { t: "MSISDN", k: "msisdn", mono: true }, { t: "APN", k: "apn" },
    { t: "UE IP", f: x => x.ue_ipv4 || x.ue_ipv6 || "–", mono: true }, { t: "Állapot", f: x => sessStatus(x.status) },
    { t: "Létrehozva (UTC)", f: x => utc(x.created_utc), mono: true }, { t: "Cause", f: x => x.cause !== null ? `${x.cause} ${x.cause_text || ""}` : "–" },
    { t: "GTP-U cs.", num: true, f: x => fmtN(x.u_pkts) },
  ], r.rows, x => simDetail(x.id))) : el("div", { class: "muted" }, q ? "Nincs találat." : "Nincs GTP-C session a capture-ben."))];
  if (r.unattributed_tunnels && r.unattributed_tunnels.length)
    parts.push(el("div", { class: "card" }, el("h3", null, "Session nélküli GTP-U tunnelek (a keresésre illeszkednek)"), tunnelTable(r.unattributed_tunnels)));
  list.replaceChildren(...parts);
  $("#sim-detail").replaceChildren();
  if (r.rows.length === 1) simDetail(r.rows[0].id);
}
function sessStatus(s) {
  const m = { active: ["ok", "aktív"], deleted: ["", "bontva"], rejected: ["err", "elutasítva"], pending: ["warn", "folyamatban"],
    no_response: ["err", "válasz nélkül"], unknown_start: ["warn", "kezdete nem látszik"], deleting: ["warn", "bontás alatt"], undetermined: ["warn", "nem eldönthető"] }[s] || ["", s];
  return el("span", { class: `chip ${m[0]}` }, m[1]);
}
function tunnelTable(rows) {
  return table([
    { t: "Irány", f: t => t.direction === "uplink" ? el("b", { class: "dir-up" }, "↑ uplink") : t.direction === "downlink" ? el("b", { class: "dir-down" }, "↓ downlink") : (t.direction || "–") },
    { t: "Külső (tunnel) IP", mono: true, f: t => `${t.outer_src} → ${t.outer_dst}` }, { t: "TEID", mono: true, f: t => hex8(t.teid) },
    { t: "Csomag / bájt", num: true, f: t => `${fmtN(t.pkts)} / ${fmtBytes(t.bytes)}` },
    { t: "Belső (payload) IP-párok", f: t => (t.inner || []).length ? el("div", { class: "mono small" }, t.inner.map(i => el("div", null, `${i.inner_src} → ${i.inner_dst} ${i.proto} (${i.pkts} cs.)`))) : "–" },
    { t: "Állapot", f: t => [stateChip(t.state, t.rule), t.note ? el("div", { class: "small muted" }, t.note) : null] },
    { t: "Csomagok", f: t => [frameLink(t.first_frame), " … ", frameLink(t.last_frame), " ", el("button", { onclick: (e) => { e.stopPropagation(); S.tunnel = { id: t.id, label: `GTP-U ${t.outer_src}→${t.outer_dst} ${hex8(t.teid)}` }; S.filter = null; S.twin = null; S.page = null; showTab("packets"); } }, "lista")] },
    { t: "", f: t => incBtn("tunnel", { ref_id: t.id }) },
  ], rows);
}
async function simDetail(sid) {
  const d = await api(`/api/captures/${S.cid}/sessions/${sid}`);
  const s = d.session;
  const up = d.tunnels.filter(t => t.direction === "uplink"), dn = d.tunnels.filter(t => t.direction === "downlink"), other = d.tunnels.filter(t => !["uplink", "downlink"].includes(t.direction));
  $("#sim-detail").replaceChildren(el("div", { class: "card" },
    el("h3", null, `Session #${s.id} – GTPv${s.version} ${s.leg || ""} `, sessStatus(s.status), " ", incBtn("session", { ref_id: s.id })),
    s.note ? el("div", { class: "note" }, s.note) : null,
    el("dl", { class: "kv" }, el("dt", null, "IMSI"), el("dd", { class: "mono" }, s.imsi || "–"), el("dt", null, "MSISDN"), el("dd", { class: "mono" }, s.msisdn || "–"),
      el("dt", null, "IMEI(SV)"), el("dd", { class: "mono" }, s.imei || "–"), el("dt", null, "APN"), el("dd", null, s.apn || "–"),
      el("dt", null, "Kiosztott IP (PAA / End User Address)"), el("dd", { class: "mono" }, [s.ue_ipv4, s.ue_ipv6].filter(Boolean).join(", ") || "–"),
      el("dt", null, "RAT"), el("dd", null, s.rat ?? "–"),
      el("dt", null, "Létrehozás"), el("dd", null, frameLink(s.created_frame), ` ${utc(s.created_utc)}`),
      el("dt", null, "Elfogadás"), el("dd", null, s.accepted_frame ? frameLink(s.accepted_frame) : "–"),
      el("dt", null, "Bontás"), el("dd", null, s.deleted_frame ? [frameLink(s.deleted_frame), ` ${utc(s.deleted_utc)}`] : "–"),
      el("dt", null, "Cause"), el("dd", null, s.cause !== null ? `${s.cause} ${s.cause_text || ""}` : "–")),
    el("h4", null, "Felépítés, módosítás, bontás (GTP-C üzenetek)"),
    table([{ t: "Csomag", f: e => frameLink(e.frame) }, { t: "Idő (UTC)", mono: true, f: e => utc(e.ts_utc) }, { t: "Üzenet", k: "msg_name" },
      { t: "Szerep", f: e => ({ request: "kérés", response: "válasz", retransmission: "ismétlés", other: "egyéb" }[e.role] || e.role) },
      { t: "Forrás → cél", mono: true, f: e => `${e.src} → ${e.dst}` }, { t: "Header TEID", k: "header_teid", mono: true }, { t: "Seq", k: "seq", mono: true },
      { t: "Cause", f: e => e.cause !== null ? el("span", { class: (e.version === 2 ? (e.cause >= 64) : (e.cause >= 192)) ? "noresp" : "" }, `${e.cause} ${e.cause_text || ""}`) : "–" },
      { t: "Hozzárendelés", f: e => stateChip(e.state, e.rule) }], d.events),
    el("h4", null, "Tranzakciók"),
    txnTable(d.transactions),
    el("h4", null, "F-TEID-ek (C-plane és user-plane külön)"),
    table([{ t: "Sík", f: f => f.plane === "C" ? "C-plane" : "U-plane" }, { t: "Interfész", f: f => f.iface_name || (f.iface_type ?? "–") },
      { t: "Fogadó végpont IP", k: "ip", mono: true }, { t: "TEID", k: "teid_hex", mono: true }, { t: "EBI/NSAPI", f: f => f.ebi ?? "–" },
      { t: "Irány", f: f => f.direction || "–" }, { t: "Érvényes (UTC)", mono: true, f: f => `${utc(f.valid_from_utc)} → ${f.valid_to_utc ? utc(f.valid_to_utc) : "(capture végéig)"}` },
      { t: "Forrás", f: f => frameLink(f.source_frame) }, { t: "Vége", f: f => f.end_frame ? [frameLink(f.end_frame), ` ${f.end_reason || ""}`] : "–" }], d.fteids),
    el("h4", null, "Hozzárendelt GTP-U forgalom – uplink"), up.length ? tunnelTable(up) : el("div", { class: "muted" }, "Nincs"),
    el("h4", null, "Hozzárendelt GTP-U forgalom – downlink"), dn.length ? tunnelTable(dn) : el("div", { class: "muted" }, "Nincs"),
    other.length ? [el("h4", null, "Egyéb (forwarding / ismeretlen irány)"), tunnelTable(other)] : null,
    d.ambiguous_tunnels.length ? [el("h4", null, "Bizonytalan: több session is jelölt"), tunnelTable(d.ambiguous_tunnels)] : null));
}

// ---------------------------------------------------------------- 3. transactions & flows
async function renderTxn() {
  const root = $("#tab-txn");
  const sub = el("div", { class: "subtabs" }, [["txn", "Tranzakciók (DNS, GTP)"], ["flows", "Flow-k (TCP/UDP)"], ["findings", "Megállapítások"]].map(([k, t]) =>
    el("button", { class: S.txnSub === k ? "active" : "", onclick: () => { S.txnSub = k; renderTxn(); } }, t)));
  const body = el("div");
  root.replaceChildren(sub, body);
  if (S.txnSub === "txn") return renderTxnList(body);
  if (S.txnSub === "flows") return renderFlows(body);
  return renderFindings(body);
}
function txnTable(rows) {
  return table([
    { t: "Idő (UTC)", mono: true, f: r => utc(r.ts_utc) }, { t: "Protokoll", f: r => ({ dns: "DNS", gtpv2c: "GTPv2-C", gtpv1c: "GTPv1-C" }[r.proto] || r.proto) },
    { t: "Tárgy", f: r => r.summary || r.kind }, { t: "Kliens → szerver", mono: true, f: r => `${r.client}:${r.client_port ?? ""} → ${r.server}${r.server_port ? ":" + r.server_port : ""}` },
    { t: "ID/seq", k: "txn_id", mono: true }, { t: "Kérés", f: r => r.req_frame ? frameLink(r.req_frame) : el("span", { class: "muted" }, "nem látszik") },
    { t: "Válasz", f: r => r.rsp_frame ? frameLink(r.rsp_frame) : el("span", { class: "noresp" }, NO_RSP) },
    { t: "Válaszidő", num: true, f: r => fmtMs(r.rtt_ns) }, { t: "Eredmény", f: r => r.result ? el("span", { class: r.result_ok === 0 ? "noresp" : "" }, r.result) : "–" },
    { t: "Ismétlés", f: r => r.retrans ? [`${r.retrans}× `, framesLinks(r.retrans_frames, 4)] : "–" },
    { t: "Állapot", f: r => [stateChip(r.state, r.rule), r.note ? el("div", { class: "small muted" }, r.note) : null] },
    { t: "", f: r => incBtn("transaction", { ref_id: r.id }) },
  ], rows || []);
}
async function renderTxnList(body) {
  const st = S.txnF || (S.txnF = { proto: "", status: "", q: "", offset: 0 });
  const proto = el("select", { onchange: e => { st.proto = e.target.value; st.offset = 0; renderTxnList(body); } }, [["", "Minden protokoll"], ["dns", "DNS"], ["gtpv2c", "GTPv2-C"], ["gtpv1c", "GTPv1-C"]].map(([v, t]) => el("option", { value: v, selected: st.proto === v }, t)));
  const status = el("select", { onchange: e => { st.status = e.target.value; st.offset = 0; renderTxnList(body); } }, [["", "Minden állapot"], ["answered", "Megválaszolt"], ["unanswered", "Válasz nélkül"], ["orphan_response", "Kérés nélküli válasz"]].map(([v, t]) => el("option", { value: v, selected: st.status === v }, t)));
  const q = el("input", { type: "text", value: st.q, placeholder: "Keresés (név, IP, ID, IMSI, eredmény)", onkeydown: e => { if (e.key === "Enter") { st.q = e.target.value; st.offset = 0; renderTxnList(body); } } });
  const r = await api(`/api/captures/${S.cid}/transactions?${qs({ proto: st.proto, status: st.status, q: st.q, offset: st.offset, limit: 200 })}`);
  body.replaceChildren(el("div", { class: "toolbar" }, proto, status, q, el("span", { class: "muted small" }, `${r.total} tranzakció`),
      el("span", { class: "grow" }), exportBtns("transactions")),
    el("div", { class: "note" }, "Párosítás: protokoll-tranzakcióazonosító (DNS ID / GTP sequence) + végpontok + irány + időablak. Az ismételt kérések a tranzakción belül, külön számolva jelennek meg; a capture-ben válasz nélkül maradt kérések külön állapotot kapnak."),
    el("div", { class: "scroll" }, txnTable(r.rows)), pager(r, st, () => renderTxnList(body)));
}
function pager(r, st, redraw) {
  return el("div", { class: "pager" }, el("button", { disabled: st.offset <= 0, onclick: () => { st.offset = Math.max(0, st.offset - r.rows.length - (r.rows.length ? 0 : 200)); redraw(); } }, "‹ Előző"),
    el("span", { class: "small muted" }, `${r.total ? st.offset + 1 : 0}–${st.offset + r.rows.length} / ${r.total}`),
    el("button", { disabled: st.offset + r.rows.length >= r.total, onclick: () => { st.offset += r.rows.length; redraw(); } }, "Következő ›"));
}
async function renderFlows(body) {
  const st = S.flowF || (S.flowF = { l4: "", flag: "", q: "", sort: "first_ts", offset: 0 });
  const mk = (key, opts) => el("select", { onchange: e => { st[key] = e.target.value; st.offset = 0; renderFlows(body); } }, opts.map(([v, t]) => el("option", { value: v, selected: st[key] === v }, t)));
  const r = await api(`/api/captures/${S.cid}/flows?${qs({ l4: st.l4, flag: st.flag, q: st.q, sort: st.sort, offset: st.offset, limit: 200 })}`);
  body.replaceChildren(el("div", { class: "toolbar" },
      mk("l4", [["", "TCP + UDP"], ["tcp", "TCP"], ["udp", "UDP"]]),
      mk("flag", [["", "Minden flow"], ["incomplete", "Befejezetlen kézfogás"], ["rst", "Reset"], ["retrans", "Újraküldés"], ["tls", "TLS kézfogás"], ["alert", "TLS alert"], ["icmp", "ICMP-jelzés"], ["tunneled", "GTP-U-n belül"]]),
      mk("sort", [["first_ts", "Idő szerint"], ["bytes", "Bájt szerint"], ["pkts", "Csomag szerint"]]),
      el("input", { type: "text", value: st.q, placeholder: "IP, port vagy SNI", onkeydown: e => { if (e.key === "Enter") { st.q = e.target.value; st.offset = 0; renderFlows(body); } } }),
      el("span", { class: "muted small" }, `${r.total} flow`), el("span", { class: "grow" }), exportBtns("flows")),
    el("div", { class: "scroll" }, table([
      { t: "Kezdet (UTC)", mono: true, f: x => utc(x.ts_utc) }, { t: "L4", f: x => x.l4.toUpperCase() + (x.tunneled ? " (GTP-U)" : "") },
      { t: "A → B", mono: true, f: x => [`${x.a_ip}:${x.a_port} → ${x.b_ip}:${x.b_port}`, x.initiator_known ? null : el("div", { class: "small muted" }, "kezdeményező nem látszik")] },
      { t: "A→B cs./bájt", num: true, f: x => `${fmtN(x.pkts_ab)} / ${fmtBytes(x.bytes_ab)}` }, { t: "B→A cs./bájt", num: true, f: x => `${fmtN(x.pkts_ba)} / ${fmtBytes(x.bytes_ba)}` },
      { t: "Hossz", num: true, f: x => fmtMs(x.duration_ms * 1e6) },
      { t: "Kézfogás", f: x => x.l4 !== "tcp" ? "–" : [el("span", { class: "chip " + (x.handshake === "complete" ? "ok" : x.handshake === "midstream" ? "" : "warn") }, { complete: "teljes", syn_synack: "SYN+SYN/ACK", syn_only: "csak SYN", synack_only: "csak SYN/ACK", midstream: "közben indult" }[x.handshake] || x.handshake), " ", frameLink(x.syn_frame, "SYN"), " ", frameLink(x.synack_frame, "S/A"), " ", frameLink(x.ack_frame, "ACK")] },
      { t: "RST", f: x => x.rst_count ? [el("span", { class: "noresp" }, `${x.rst_count}× `), framesLinks(x.rst_frames, 3)] : "–" },
      { t: "Újraküldés", f: x => x.retrans ? [`${x.retrans}× `, framesLinks(x.retrans_frames, 3)] : "–" },
      { t: "TLS", f: x => x.tls_ch_frame || x.tls_sh_frame ? el("div", { class: "small" }, `SNI: ${x.tls_sni || "–"} ${x.tls_version || ""}`, el("br"), frameLink(x.tls_ch_frame, "ClientHello"), " ", frameLink(x.tls_sh_frame, "ServerHello"), x.tls_alert ? [el("br"), el("span", { class: "noresp" }, `alert: ${x.tls_alert} `), frameLink(x.tls_alert_frame)] : null) : "–" },
      { t: "ICMP", f: x => x.icmp_count ? framesLinks(x.icmp_frames, 3) : "–" },
      { t: "", f: x => el("div", null, el("button", { onclick: e => { e.stopPropagation(); applyFilterAndGo(`${x.l4}.stream eq ${x.stream}`); } }, "Csomagok"), " ", el("button", { onclick: e => { e.stopPropagation(); followStream(x.l4, x.stream); } }, "Követés"), " ", incBtn("flow", { ref_id: x.id })) },
    ], r.rows)), pager(r, st, () => renderFlows(body)));
}
async function renderFindings(body) {
  const st = S.findF || (S.findF = { state: "", severity: "", analyzer: "", offset: 0 });
  const mk = (key, opts) => el("select", { onchange: e => { st[key] = e.target.value; st.offset = 0; renderFindings(body); } }, opts.map(([v, t]) => el("option", { value: v, selected: st[key] === v }, t)));
  const r = await api(`/api/captures/${S.cid}/findings?${qs({ state: st.state, severity: st.severity, analyzer: st.analyzer, offset: st.offset, limit: 300 })}`);
  body.replaceChildren(el("div", { class: "toolbar" }, mk("severity", [["", "Minden súlyosság"], ["error", "Hiba"], ["warn", "Figyelmeztetés"], ["info", "Info"]]),
      mk("state", [["", "Minden állapot"], ["observed", "Megfigyelt"], ["inferred", "Következtetett"], ["undetermined", "Nem eldönthető"]]),
      mk("analyzer", [["", "Minden modul"], ...((S.system && S.system.analyzers) || []).map(a => [a.name, a.title])]),
      el("span", { class: "muted small" }, `${r.total} megállapítás`), el("span", { class: "grow" }), exportBtns("findings")),
    el("div", { class: "scroll" }, table([
      { t: "Súlyosság", f: x => sevChip(x.severity) }, { t: "Állapot", f: x => stateChip(x.state, x.rule) }, { t: "Idő (UTC)", mono: true, f: x => utc(x.ts_utc) },
      { t: "Megállapítás", f: x => [el("b", null, x.title), el("div", { class: "small muted" }, x.detail)] }, { t: "Szabály", k: "rule", mono: true },
      { t: "Bizonyíték", f: x => framesLinks(x.frames, 6) }, { t: "", f: x => incBtn("finding", { ref_id: x.id }) },
    ], r.rows)), pager(r, st, () => renderFindings(body)));
}
function exportBtns(kind) {
  const mask = el("input", { type: "checkbox", checked: true, title: "IMSI/MSISDN/IMEI maszkolása" });
  const go = async (fmt) => {
    const m = mask.checked ? { imsi: 1, msisdn: 1, imei: 1 } : {};
    const r = await post(`/api/captures/${S.cid}/export/table`, { kind, format: fmt, mask: m });
    toast(`Export kész: ${r.file}`); location.href = `/api/exports/${r.id}/download`;
  };
  return el("span", { class: "small" }, el("label", { class: "inline" }, mask, "maszkolt"), " ", el("button", { onclick: () => go("csv") }, "CSV"), " ", el("button", { onclick: () => go("json") }, "JSON"));
}

// ---------------------------------------------------------------- 4. packets
function renderPackets() {
  const root = $("#tab-packets");
  if (!root.dataset.built || root.dataset.cid !== String(S.cid)) {
    root.dataset.built = "1"; root.dataset.cid = String(S.cid);
    const inp = el("input", { type: "text", id: "flt", class: "filter-input", placeholder: "Wireshark display filter, pl. dns.flags.rcode != 0 || gtpv2.cause > 63", spellcheck: "false" });
    inp.addEventListener("keydown", e => { if (e.key === "Enter") applyFilter(); });
    inp.addEventListener("input", () => { clearTimeout(inp._t); inp._t = setTimeout(validateFilter, 500); });
    root.replaceChildren(
      el("div", { class: "toolbar" }, inp, el("label", { class: "inline small", title: "Két menetes dekódolás (-2): a szűrő a későbbi csomagokra mutató mezőket is látja (pl. dns.response_in), lassabb." }, el("input", { type: "checkbox", id: "flt2" }), "két menetes (-2)"),
        el("button", { class: "primary", onclick: applyFilter }, "Szűrés"), el("button", { onclick: () => { inp.value = ""; S.filter = null; S.page = null; inp.className = "filter-input"; $("#flt-err").replaceChildren(); loadPackets({}); } }, "Törlés")),
      el("div", { id: "flt-err" }),
      el("details", { class: "note" }, el("summary", null, "Szűrés vs. dekódolási előzmények – mit jelent a szűrt lista?"),
        el("p", null, "A display filter csak azt dönti el, mely csomagok jelennek meg a listában. A TShark dekódolása ettől függetlenül a teljes capture-ön, sorrendben fut: a TCP-reassembly, az IP-defragmentálás és a kérés–válasz állapot a szűrőnek nem megfelelő korábbi csomagokból is felépül."),
        el("p", null, "A részletes nézet „Kontextus” módban az 1…N. csomagot dekódolja (helyes előzmények), „Izolált” módban csak az adott csomagot (előzmények nélkül – így látszik, mi múlik az előzményeken). A részletek alatt felsoroljuk azokat az előzmény-csomagokat (pl. tcp.segment, ip.fragment), amelyekre a csomag dekódolása épül, és jelöljük, ha nincsenek a szűrt listában."),
        el("p", null, "Exportnál a „reassembly-előzmények is” opció ezeket a csomagokat is beteszi, különben a szűrt export önmagában nem feltétlenül dekódolható ugyanígy.")),
      el("div", { id: "pk-chips", class: "toolbar" }),
      el("div", { class: "split" }, el("div", null, el("div", { id: "pk-pager" }), el("div", { class: "scroll", id: "pk-list" }), el("div", { id: "pk-actions", class: "toolbar", style: "margin-top:8px" })),
        el("div", { id: "pk-detail" }, el("div", { class: "muted" }, "Válassz egy csomagot a listából."))));
  }
  if (S.pendingFilter !== undefined && S.pendingFilter !== null) { $("#flt").value = S.pendingFilter; S.pendingFilter = null; applyFilter(); return; }
  if (S.pendingFrame) { const f = S.pendingFrame; S.pendingFrame = null; loadPackets({ around: f }, f); return; }
  if (!S.page) loadPackets({});
  else drawPackets();
}
async function validateFilter() {
  const v = $("#flt").value.trim(); const inp = $("#flt");
  if (!v) { inp.className = "filter-input"; $("#flt-err").replaceChildren(); return; }
  const r = await post("/api/filter/validate", { expr: v });
  inp.className = "filter-input " + (r.ok ? "good" : "bad");
  $("#flt-err").replaceChildren(r.ok ? "" : el("div", { class: "errbox" }, el("b", null, r.error), r.tshark ? el("pre", null, r.tshark) : null));
}
async function applyFilter() {
  const expr = $("#flt").value.trim();
  $("#flt-err").replaceChildren();
  if (!expr) { S.filter = null; S.page = null; return loadPackets({}); }
  const r = await post(`/api/captures/${S.cid}/filters`, { expr, two_pass: $("#flt2").checked });
  if (!r.ok) { $("#flt").className = "filter-input bad"; $("#flt-err").replaceChildren(el("div", { class: "errbox" }, el("b", null, r.error), r.tshark ? el("pre", null, r.tshark) : null)); return; }
  $("#flt").className = "filter-input good";
  S.filter = r.filter; S.page = null;
  if (r.job) { drawPackets(true); trackJob(r.job, async () => { S.filter = await api(`/api/captures/${S.cid}/filters/${r.filter.id}`); loadPackets({}); }); }
  else loadPackets({});
}
async function loadPackets(nav, highlight) {
  const p = { filter_id: S.filter && S.filter.id, t0: S.twin && S.twin.t0, t1: S.twin && S.twin.t1, tunnel_id: S.tunnel && S.tunnel.id, limit: 100, ...nav };
  S.page = await api(`/api/captures/${S.cid}/packets?${qs(p)}`);
  if (S.page.filter) S.filter = S.page.filter;
  drawPackets();
  if (highlight) openDetail(highlight);
}
function drawPackets(waiting) {
  const chips = $("#pk-chips"); chips.replaceChildren();
  if (S.filter) chips.append(el("span", { class: "chip " + (S.filter.status === "done" ? "ok" : S.filter.status === "partial" ? "warn" : "") }, `Szűrő: ${S.filter.expr} – ${S.filter.status === "running" ? "fut…" : `${fmtN(S.filter.hits)} találat`}${S.filter.elapsed_s ? `, ${S.filter.elapsed_s} s` : ""}${S.filter.two_pass ? " (-2)" : ""}`));
  if (S.filter && S.filter.partial_reason) chips.append(el("span", { class: "chip warn" }, `Részleges: ${S.filter.partial_reason}`));
  if (S.filter && S.filter.status === "failed") chips.append(el("span", { class: "chip err" }, S.filter.partial_reason || "hiba"));
  if (S.twin) chips.append(el("span", { class: "chip" }, `Időablak: ${S.twin.label} `, el("button", { class: "link", onclick: () => { S.twin = null; loadPackets({}); } }, "✕")));
  if (S.tunnel) chips.append(el("span", { class: "chip" }, `Tunnel: ${S.tunnel.label} `, el("button", { class: "link", onclick: () => { S.tunnel = null; loadPackets({}); } }, "✕")));
  if (S.cap && S.cap.partial) chips.append(el("span", { class: "chip warn" }, `Részleges index: csak az első ${fmtN(S.cap.frames)} csomag`));
  const list = $("#pk-list");
  if (waiting || !S.page) { list.replaceChildren(el("div", { class: "empty" }, "Szűrés folyamatban… (a TShark a teljes capture-ön fut; megszakítható a fenti sávban)")); $("#pk-pager").replaceChildren(); return; }
  const pg = S.page;
  const goto = el("input", { type: "number", min: 1, placeholder: "csomag #", style: "width:100px", onkeydown: e => { if (e.key === "Enter" && e.target.value) gotoPacket(Number(e.target.value), true); } });
  $("#pk-pager").replaceChildren(el("div", { class: "pager" },
    el("button", { onclick: () => loadPackets({}) }, "« Első"), el("button", { disabled: !pg.has_prev, onclick: () => loadPackets({ before: pg.rows[0].frame_no }) }, "‹ Előző"),
    el("button", { disabled: !pg.has_next, onclick: () => loadPackets({ after: pg.rows[pg.rows.length - 1].frame_no }) }, "Következő ›"),
    el("span", { class: "small muted" }, pg.rows.length ? `${fmtN(pg.position + 1)}–${fmtN(pg.position + pg.rows.length)} / ${fmtN(pg.total)}` : `0 / ${fmtN(pg.total)}`),
    goto, pg.around_found === false ? el("span", { class: "chip warn" }, "A keresett csomag nincs a jelenlegi listában") : null));
  const tb = el("tbody");
  for (const r of pg.rows) {
    const cb = el("input", { type: "checkbox", checked: S.selected.has(r.frame_no), onclick: e => { e.stopPropagation(); e.target.checked ? S.selected.add(r.frame_no) : S.selected.delete(r.frame_no); drawActions(); } });
    const tr = el("tr", { class: "clickable" + (S.detailFrame === r.frame_no ? " selected" : ""), "data-f": r.frame_no, onclick: () => openDetail(r.frame_no) },
      el("td", null, cb), el("td", { class: "num mono" }, r.frame_no), el("td", { class: "mono" }, utc(r.ts_utc).slice(11)),
      el("td", { class: "small muted" }, `${r.section ?? "–"}/${r.iface ?? "–"}`),
      el("td", { class: "mono" }, r.src || "–", r.osrc ? el("div", { class: "small muted" }, `↳ ${r.osrc}`) : null),
      el("td", { class: "mono" }, r.dst || "–", r.odst ? el("div", { class: "small muted" }, `↳ ${r.odst}`) : null),
      el("td", null, r.proto), el("td", { class: "num" }, r.len), el("td", { class: "small" }, r.info));
    tb.append(tr);
  }
  list.replaceChildren(el("table", null, el("thead", null, el("tr", null, ["", "#", "Idő (UTC)", "Sz/If", "Forrás (↳ tunnel)", "Cél (↳ tunnel)", "Protokoll", "Hossz", "Info"].map(t => el("th", null, t)))), tb));
  drawActions();
}
function drawActions() {
  const a = $("#pk-actions"); if (!a) return;
  const n = S.selected.size;
  const deps = el("input", { type: "checkbox", id: "exp-deps" });
  const hasDsb = S.cap && S.cap.info && (S.cap.info.dsb || []).length;
  const sec = el("input", { type: "checkbox", id: "exp-sec", disabled: !hasDsb });
  const doExport = async (sel) => {
    let confirm = "";
    if (sec.checked) {
      confirm = prompt("A nyers export beágyazott dekriptálási titkokat (DSB) fog tartalmazni. Megerősítéshez írd be: TITKOKKAL") || "";
      if (confirm !== "TITKOKKAL") { toast("Nincs megerősítés – az export nem indult el."); return; }
    }
    try {
      const r = await post(`/api/captures/${S.cid}/export/pcap`, { ...sel, include_deps: deps.checked, include_secrets: sec.checked, confirm });
      trackJob(r.job, j => { if (j.result && j.result.export) { toast(`Export kész: ${j.result.export.file}`); location.href = `/api/exports/${j.result.export.id}/download`; } });
    } catch (e) { toast(e.message, 7000); }
  };
  const listSel = { filter_id: S.filter && S.filter.id, t0: S.twin && S.twin.t0, t1: S.twin && S.twin.t1 };
  a.replaceChildren(el("span", { class: "small muted" }, `Kijelölve: ${n}`),
    el("button", { disabled: !n, onclick: async () => { for (const f of S.selected) await post(`/api/incidents/${await incId()}/items`, { kind: "packet", capture_id: S.cid, frame: f }); toast(`${n} csomag az incidenshez adva`); refreshIncCount(); } }, "Kijelöltek → incidens"),
    el("button", { disabled: !n, onclick: () => doExport({ frames: [...S.selected] }) }, "Kijelöltek exportja (pcapng)"),
    el("button", { disabled: !(S.filter || S.twin) || S.tunnel, title: "A teljes szűrt lista / időablak", onclick: () => doExport(listSel) }, "Szűrt lista exportja (pcapng)"),
    el("label", { class: "inline small", title: "tcp.segment / ip.fragment alapján a reassemblyhez szükséges csomagok is" }, deps, "reassembly-előzmények is"),
    el("label", { class: "inline small", title: hasDsb ? "Csak megerősítéssel" : "A fájl nem tartalmaz DSB-t" }, sec, "dekriptálási titkokkal (DSB)"),
    el("span", { class: "small muted" }, "A nyers capture-export nem maszkolt; minden csomag kommentje az eredeti csomagszámot hordozza."));
}
async function gotoPacket(frame, keepFilter) {
  if (!S.cid) return;
  if (!keepFilter && (S.filter || S.twin || S.tunnel)) { S.filter = null; S.twin = null; S.tunnel = null; toast("Szűrő/időablak törölve a bizonyíték megjelenítéséhez."); const f = $("#flt"); if (f) { f.value = ""; f.className = "filter-input"; } }
  S.pendingFrame = frame; S.page = null;
  showTab("packets");
}
async function openDetail(frame) {
  S.detailFrame = frame;
  document.querySelectorAll("#pk-list tr.selected").forEach(t => t.classList.remove("selected"));
  const tr = document.querySelector(`#pk-list tr[data-f="${frame}"]`); if (tr) { tr.classList.add("selected"); tr.scrollIntoView({ block: "nearest" }); }
  const box = $("#pk-detail");
  box.replaceChildren(el("div", { class: "muted" }, `#${frame} dekódolása…`));
  let d;
  try { d = await api(`/api/captures/${S.cid}/packets/${frame}?mode=${S.detailMode}`); }
  catch (e) { box.replaceChildren(el("div", { class: "errbox" }, e.message)); return; }
  const p = d.packet;
  const inList = new Set((S.page ? S.page.rows : []).map(r => r.frame_no));
  const modeSel = el("select", { onchange: e => { S.detailMode = e.target.value; openDetail(frame); } },
    el("option", { value: "context", selected: S.detailMode === "context" }, "Kontextus (előzményekkel)"), el("option", { value: "isolated", selected: S.detailMode === "isolated" }, "Izolált (csak ez a csomag)"));
  const hexBox = el("div", { class: "hex scroll", style: "max-height:30vh" });
  const bytes = d.hex ? d.hex.match(/../g) || [] : [];
  const spans = [];
  if (bytes.length) {
    for (let i = 0; i < bytes.length; i += 16) {
      const line = el("div", null, el("span", { class: "off" }, i.toString(16).padStart(4, "0") + "  "));
      let asc = "";
      for (let j = i; j < Math.min(i + 16, bytes.length); j++) {
        const s = el("span", { class: "b" }, bytes[j]); spans[j] = s; line.append(s, " ");
        const c = parseInt(bytes[j], 16); asc += c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
      }
      line.append(" ".repeat((16 - Math.min(16, bytes.length - i)) * 3) + " " + asc);
      hexBox.append(line);
    }
  } else hexBox.append(el("div", { class: "muted" }, "Hex nézet nem érhető el (tömörített fájl vagy hiányzó offset)."));
  const hl = (pos, size, span) => {
    spans.forEach(s => s && s.classList.remove("hl")); document.querySelectorAll(".tree span.hl").forEach(s => s.classList.remove("hl"));
    if (span) span.classList.add("hl");
    if (pos === undefined) return;
    for (let k = pos; k < pos + size && k < spans.length; k++) spans[k] && spans[k].classList.add("hl");
    if (spans[pos]) spans[pos].scrollIntoView({ block: "nearest" });
  };
  const mkTree = (nodes, depth) => el("ul", null, nodes.map((n, idx) => {
    const kids = n.children && n.children.length;
    const open = depth === 0 && idx === nodes.length - 1;  // like Wireshark: expand only the top protocol layer
    const li = el("li", { class: kids && !open ? "closed" : "" });
    const lab = el("span", { onclick: (e) => { e.stopPropagation(); if (kids) li.classList.toggle("closed"); hl(n.pos, n.size, lab); }, title: n.name },
      el("span", { class: "tog" }, kids ? "▸" : ""), n.text);
    li.append(lab); if (kids) li.append(mkTree(n.children, depth + 1));
    return li;
  }));
  const deps = d.deps.filter(x => x.frame !== frame);
  const l4 = p.tcp_stream !== null ? ["tcp", p.tcp_stream] : p.udp_stream !== null ? ["udp", p.udp_stream] : null;
  box.replaceChildren(el("div", { class: "card" },
    el("h3", null, `Csomag #${frame} `, el("span", { class: "muted small" }, `${utc(p.ts_utc)} UTC · szekció ${p.section ?? "–"} · interfész ${p.iface ?? "–"} · ${p.len} B (capt. ${p.caplen} B)`)),
    el("div", { class: "toolbar" }, modeSel, l4 ? el("button", { onclick: () => followStream(l4[0], l4[1]) }, `${l4[0].toUpperCase()} stream ${l4[1]} követése`) : null,
      incBtn("packet", { frame }), el("span", { class: "small muted" }, `dekódolás: ${d.elapsed_s} s`)),
    el("div", { class: "note" }, d.note),
    deps.length ? el("div", { class: "note" }, el("b", null, "Előzmények / kapcsolódó csomagok: "), deps.map(x => el("span", null, frameLink(x.frame), ` ${x.role}`, inList.has(x.frame) || !S.filter ? "" : el("span", { class: "chip warn" }, "nincs a szűrt listában"), "  "))) : null,
    d.tshark_error ? el("div", { class: "errbox" }, d.tshark_error) : null,
    el("h4", null, "Mezőfa"), el("div", { class: "tree scroll", style: "max-height:36vh" }, mkTree(d.tree, 0)),
    el("h4", null, "Hex"), hexBox));
}
async function followStream(l4, stream) {
  modal(el("div", { class: "muted" }, `${l4.toUpperCase()} stream ${stream} követése (teljes capture-pass)…`));
  let r;
  try { r = await api(`/api/captures/${S.cid}/follow/${l4}/${stream}`); } catch (e) { modal(el("div", { class: "errbox" }, e.message)); return; }
  let mode = "text";
  const body = el("div", { class: "follow" });
  const draw = () => body.replaceChildren(...r.chunks.map(c => el("pre", { class: `peer${c.peer}` }, el("span", { class: "muted" }, frameLink(c.frame), ` ${c.peer === 0 ? "A→B" : "B→A"} ${c.len} B\n`), mode === "text" ? c.text : (c.hex.match(/.{1,32}/g) || []).map(x => x.match(/../g).join(" ")).join("\n"))));
  draw();
  const peers = r.peers.map(p => `${p.peer === 0 ? "A" : "B"}: ${p.host}:${p.port}`).join("   ");
  modal(el("h3", null, `${l4.toUpperCase()} stream ${stream}`), el("div", { class: "toolbar" }, el("span", { class: "mono small" }, peers),
    el("select", { onchange: e => { mode = e.target.value; draw(); } }, el("option", { value: "text" }, "ASCII"), el("option", { value: "hex" }, "Hex")),
    el("span", { class: "small muted" }, `${fmtBytes(r.bytes)} · ${r.chunks.length} szegmens · ${r.elapsed_s} s`), r.truncated ? el("span", { class: "chip warn" }, `Megjelenítési korlát (${fmtBytes(r.limit)}) elérve – a stream csonkolva látszik`) : null), body);
  body.querySelectorAll("button.link").forEach(b => b.addEventListener("click", () => $("#modal").classList.add("hidden")));
}

// ---------------------------------------------------------------- 5. incident
async function incId() {
  if (S.incident) return S.incident;
  const list = await api("/api/incidents"); S.incident = list[0].id; return S.incident;
}
function incBtn(kind, extra) {
  return el("button", { class: "small", title: "Hozzáadás az incidenshez", onclick: async (e) => {
    e.stopPropagation();
    try { const r = await post(`/api/incidents/${await incId()}/items`, { kind, capture_id: S.cid, ...extra }); toast(r.duplicate ? "Már szerepel az incidensben." : "Hozzáadva az incidenshez."); refreshIncCount(); }
    catch (err) { toast(err.message, 6000); }
  } }, "+ incidens");
}
async function refreshIncCount() { try { const d = await api(`/api/incidents/${await incId()}`); $("#inc-count").textContent = d.items.length || ""; } catch (_) { } }
async function renderIncident() {
  const root = $("#tab-incident");
  const iid = await incId();
  const [inc, all, exps] = await Promise.all([api(`/api/incidents/${iid}`), api("/api/incidents"), api(`/api/exports?incident_id=${iid}`)]);
  $("#inc-count").textContent = inc.items.length || "";
  const sel = el("select", { onchange: e => { S.incident = Number(e.target.value); renderIncident(); } }, all.map(i => el("option", { value: i.id, selected: i.id === iid }, `#${i.id} ${i.title} (${i.items})`)));
  const title = el("input", { type: "text", value: inc.title, style: "flex:1" });
  const desc = el("textarea", { placeholder: "Elemzői összefoglaló (a riportba „Analyst summary” néven kerül; angolul javasolt)" }, inc.description || "");
  const save = async () => { await api(`/api/incidents/${iid}`, { method: "PUT", body: { title: title.value, description: desc.value } }); toast("Mentve"); };
  const noteT = el("input", { type: "text", placeholder: "Új megfigyelés (szabad szöveg)", style: "flex:1" });
  const items = table([
    { t: "Idő (UTC)", mono: true, f: x => utc(x.ts_utc) }, { t: "Capture", f: x => x.capture_id ? `#${x.capture_id}` : "–" },
    { t: "Típus", f: x => ({ packet: "csomag", finding: "megállapítás", transaction: "tranzakció", session: "session", flow: "flow", tunnel: "GTP-U tunnel", note: "megfigyelés" }[x.kind] || x.kind) },
    { t: "Elem", f: x => [el("div", null, x.title), x.title_en && x.title_en !== x.title ? el("div", { class: "small muted" }, `EN: ${x.title_en}`) : null] },
    { t: "Állapot", f: x => stateChip(x.state, x.rule) },
    { t: "Csomagok", f: x => x.capture_id ? x.frames.slice(0, 6).map(f => el("button", { class: "link mono", onclick: async () => { if (S.cid !== x.capture_id) await selectCapture(x.capture_id); gotoPacket(f); } }, `#${f} `)) : "–" },
    { t: "Megjegyzés", f: x => { const t = el("input", { type: "text", value: x.note || "", style: "width:100%" }); t.addEventListener("change", () => api(`/api/incident-items/${x.id}`, { method: "PUT", body: { note: t.value } })); return t; } },
    { t: "", f: x => el("button", { class: "danger", onclick: async () => { await api(`/api/incident-items/${x.id}`, { method: "DELETE" }); renderIncident(); } }, "✕") },
  ], inc.items);
  const mk = (k, t, on) => el("label", { class: "inline" }, el("input", { type: "checkbox", "data-k": k, checked: on }), t);
  const maskBox = el("div", { class: "toolbar" }, mk("imsi", "IMSI", true), mk("msisdn", "MSISDN", true), mk("imei", "IMEI/IMEISV", true), mk("ue_ip", "UE IP (kiosztott)", false), mk("all_ip", "minden IP", false));
  const preview = el("div");
  const genReport = async (masked) => {
    const mask = {}; if (masked) maskBox.querySelectorAll("input").forEach(i => mask[i.dataset.k] = i.checked ? 1 : 0);
    const r = await post(`/api/incidents/${iid}/report`, { mask });
    preview.replaceChildren(el("div", { class: "toolbar" }, el("b", null, masked ? "Maszkolt riport (előnézet)" : "Maszkolatlan riport (előnézet)"), ...r.exports.map(x => el("a", { href: `/api/exports/${x.id}/download` }, x.file))), el("div", { class: "md" }, r.markdown));
    renderExportList();
  };
  const depsCb = el("input", { type: "checkbox" }), secCb = el("input", { type: "checkbox" });
  const rawExport = async () => {
    let confirm = "";
    if (secCb.checked) { confirm = prompt("A nyers export beágyazott dekriptálási titkokat tartalmazhat. Megerősítéshez írd be: TITKOKKAL") || ""; if (confirm !== "TITKOKKAL") { toast("Nincs megerősítés."); return; } }
    try { const r = await post(`/api/incidents/${iid}/export/pcap`, { include_deps: depsCb.checked, include_secrets: secCb.checked, confirm }); r.jobs.forEach(j => trackJob(j, () => renderExportList())); }
    catch (e) { toast(e.message, 6000); }
  };
  const expMasked = el("div"), expRaw = el("div");
  const renderExportList = async () => {
    const ex = await api(`/api/exports?incident_id=${iid}`);
    const row = x => el("div", { class: "small" }, el("a", { href: `/api/exports/${x.id}/download` }, x.file), ` · ${x.created_at} · ${x.note || ""}`, x.contains_secrets ? el("span", { class: "chip err" }, " DEKRIPTÁLÁSI TITKOKAT TARTALMAZ") : null);
    expMasked.replaceChildren(...ex.filter(x => x.kind.startsWith("report")).map(row));
    expRaw.replaceChildren(...ex.filter(x => x.kind === "pcapng").map(row));
  };
  root.replaceChildren(
    el("div", { class: "toolbar" }, sel, el("button", { onclick: async () => { const t = prompt("Új incidens címe:", "Incident"); if (t) { S.incident = (await post("/api/incidents", { title: t })).id; renderIncident(); } } }, "Új incidens")),
    el("div", { class: "card" }, el("div", { class: "toolbar" }, el("b", null, "Cím"), title, el("button", { onclick: save }, "Mentés")), desc),
    el("div", { class: "card" }, el("h3", null, `Gyűjtött elemek (${inc.items.length})`), el("div", { class: "muted small" }, "Elemeket a többi nézet „+ incidens” gombjaival vagy a csomaglista kijelöléseivel adhatsz hozzá. Az elemek pillanatképként tárolódnak (eredeti capture-azonosító + csomagszám)."),
      el("div", { class: "scroll", style: "max-height:42vh" }, items),
      el("div", { class: "toolbar", style: "margin-top:8px" }, noteT, el("button", { onclick: async () => { if (!noteT.value.trim()) return; await post(`/api/incidents/${iid}/items`, { kind: "note", title: noteT.value.trim() }); renderIncident(); } }, "Megfigyelés hozzáadása"))),
    el("div", { class: "grid" },
      el("div", { class: "card exportgroup masked" }, el("h3", null, "Riport – angol összefoglaló (szöveges export)"),
        el("div", { class: "small" }, "Sablon alapján, helyben készül: UTC-idővonal, csomaghivatkozások, állapot (observed/inferred/undetermined), szabályok és vizsgálati korlátok. Markdown + JSON."),
        el("h4", null, "Maszkolás hatóköre"), maskBox,
        el("div", { class: "small muted" }, "A maszkolás csak erre a szöveges riportra (és a CSV/JSON táblaexportokra) vonatkozik: mezők + szabad szöveg (ismert azonosítók és 14–16 jegyű számsorok). A nyers capture-export soha nem maszkolt."),
        el("div", { class: "toolbar", style: "margin-top:6px" }, el("button", { class: "primary", onclick: () => genReport(true) }, "Maszkolt riport készítése"), el("button", { onclick: () => genReport(false) }, "Maszkolatlan riport")),
        el("h4", null, "Riport-exportok"), expMasked),
      el("div", { class: "card exportgroup raw" }, el("h3", null, "Nyers capture-export (maszkolatlan csomagtartalom)"),
        el("div", { class: "small" }, "Az incidens csomaghivatkozásaiból capture-önként egy pcapng. A csomagbájtok változatlanok; minden csomag kommentje: capscope-ref file=… sha256=… frame=N. Beágyazott dekriptálási titkok (DSB) csak megerősítéssel."),
        el("div", { class: "toolbar", style: "margin-top:6px" }, el("label", { class: "inline small" }, depsCb, "reassembly-előzmények is"), el("label", { class: "inline small" }, secCb, "dekriptálási titkokkal (DSB)"), el("button", { onclick: rawExport }, "Nyers capture-export")),
        el("h4", null, "Capture-exportok"), expRaw)),
    preview);
  renderExportList();
  void exps;
}

// ---------------------------------------------------------------- boot
(async function boot() {
  try {
    S.system = await api("/api/system");
    $("#ver").textContent = `v${S.system.version} · TShark ${S.system.tshark.version || "–"}`;
    if (S.system.tshark.error) $("#banners").append(el("div", { class: "banner err" }, S.system.tshark.error));
    const caps = await loadCaptures();
    refreshIncCount();
    if (caps.length) selectCapture(caps[0].id);
  } catch (e) { $("#banners").append(el("div", { class: "banner err" }, e.message)); }
})();
