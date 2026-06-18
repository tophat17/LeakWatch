"use strict";

const RULE_OPTIONS = [
  ["auto", "Auto-detect"],
  ["vpn", "Should use VPN"],
  ["server", "Should use server IP"],
  ["ignore", "Ignore"],
];

const LEVEL_BADGE = {
  critical: ["VPN required", "rb-crit"],
  gateway: ["VPN gateway", "rb-gw"],
  recommended: ["VPN recommended", "rb-rec"],
  server: ["No VPN needed", "rb-srv"],
  optional: ["VPN optional", "rb-opt"],
  unknown: ["Unrecognised", "rb-unk"],
};

const CHECK_ICON = {
  pass: ["check-pass", "PASS"],
  fail: ["check-fail", "FAIL"],
  warn: ["check-warn", "WARN"],
  info: ["check-info", "INFO"],
  skip: ["check-skip", "SKIP"],
};

const $ = (sel) => document.querySelector(sel);
let scanning = false;
let lastData = { containers: [], host: null };

async function api(path, opts = {}) {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (e) {}
    throw new Error(detail);
  }
  return res.json();
}

function toast(msg, isErr = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  setTimeout(() => { t.className = "toast hidden"; }, 3500);
}

function fmtTime(ts) {
  if (!ts) return "Never scanned";
  return "Last scan: " + new Date(ts * 1000).toLocaleString();
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (ch) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]
  ));
}

// ---------- rendering ---------- //
function renderHost(host) {
  if (!host) { $("#hostIp").textContent = "— (run a scan)"; return; }
  $("#hostIp").textContent = host.public_ip || "unknown";
  const geo = host.geo || {};
  const bits = [geo.isp || geo.org, [geo.city, geo.country].filter(Boolean).join(", ")].filter(Boolean);
  if (host.ipv6) bits.push("IPv6: " + host.ipv6);
  $("#hostOrg").textContent = bits.join(" · ");
  $("#hostNote").textContent = host.error ? "⚠ " + host.error : "";
}

function renderSummary(containers) {
  const counts = { OK: 0, WARNING: 0, CRITICAL: 0, UNKNOWN: 0, IGNORED: 0 };
  containers.forEach((c) => {
    const s = c.verdict && c.verdict.status;
    if (s && counts[s] !== undefined) counts[s]++;
  });
  const map = [
    ["crit", "Critical", counts.CRITICAL], ["warn", "Warning", counts.WARNING],
    ["ok", "OK", counts.OK], ["unknown", "Unknown", counts.UNKNOWN],
    ["ignored", "Ignored", counts.IGNORED],
  ];
  $("#summary").innerHTML = map.map(([cls, label, n]) =>
    `<div class="chip"><span class="dot ${cls}"></span>${label}<span class="count">${n}</span></div>`
  ).join("");

  const banner = $("#banner");
  if (counts.CRITICAL > 0) {
    banner.className = "banner crit";
    banner.textContent = `🚨 ${counts.CRITICAL} container(s) LEAKING — expected behind a VPN but using your server IP.`;
  } else if (counts.WARNING > 0) {
    banner.className = "banner warnb";
    banner.textContent = `⚠ ${counts.WARNING} warning(s) — hover a status to see which checks failed.`;
  } else if (containers.some((c) => c.verdict)) {
    banner.className = "banner ok";
    banner.textContent = "✅ No VPN leaks detected on the must-be-VPN list.";
  } else {
    banner.className = "banner hidden";
  }
}

function recBadge(c) {
  const app = c.app || {};
  const lvl = app.level || "unknown";
  const [label, cls] = LEVEL_BADGE[lvl] || ["", ""];
  if (!label) return "";
  return `<span class="rec-badge ${cls} has-tip" data-tip="why" data-name="${esc(c.name)}">${label}</span>`;
}

function providerCell(c) {
  const v = c.verdict || {};
  const p = v.provider || {};
  if (v.behavior === "server_ip") return `<span class="muted">— (server)</span>`;
  if (p.is_mesh) return `<span class="muted">${esc(p.name || "mesh")} (mesh)</span>`;
  if (!p.confidence || p.confidence === "unknown") {
    return p.confidence === "hosting"
      ? `<span class="provider-name">Datacenter</span><div class="provider-conf">non-residential</div>`
      : `<span class="muted">—</span>`;
  }
  const conf = { confirmed: "confirmed", likely: "likely", hosting: "non-residential" }[p.confidence] || "";
  return `<span class="provider-name">${esc(p.name || "—")}</span>` +
         (conf ? `<div class="provider-conf">${esc(conf)}${p.asn ? " · " + esc(p.asn) : ""}</div>` : "");
}

function networkCell(c) {
  if (c.routed_through) return `<span class="muted">via ${esc(c.routed_through)}</span>`;
  return `<span class="muted">${esc(c.network_mode || "—")}</span>`;
}

function leakChips(v) {
  let out = "";
  if (v.ipv6_leak) out += `<span class="tag leak-tag">IPv6 leak</span>`;
  return out;
}

function checksSummary(v) {
  const ch = v.checks || [];
  if (!ch.length) return "";
  const pass = ch.filter((x) => x.status === "pass").length;
  const fail = ch.filter((x) => x.status === "fail").length;
  const warn = ch.filter((x) => x.status === "warn").length;
  let s = `${pass}✓`;
  if (warn) s += ` ${warn}!`;
  if (fail) s += ` ${fail}✗`;
  return `<span class="checks-pill">${s} · scans</span>`;
}

function statusCell(c) {
  const v = c.verdict;
  if (!v) return `<span class="badge UNKNOWN">NOT SCANNED</span>`;
  const showMsg = v.status !== "OK" || v.protected;
  const msgCls = v.leaking ? "status-msg leak" : "status-msg";
  const msg = (showMsg && v.message) ? `<div class="${msgCls}">${esc(v.message)}</div>` : "";
  const prot = v.protected ? `<span class="prot-chip">Protected</span>` : "";
  return `<div class="status-wrap has-tip" data-tip="checks" data-name="${esc(c.name)}">` +
         `<span class="badge ${esc(v.status)}">${esc(v.status)}</span>${prot}${leakChips(v)} ${checksSummary(v)}${msg}</div>`;
}

function ipCell(c) {
  const t = c.test || {};
  if (t.public_ip) {
    const conf = t.confident ? "" : ` <span class="tag">low conf</span>`;
    const v6 = t.ipv6 ? `<div class="provider-conf">v6: ${esc(t.ipv6)}</div>` : "";
    return `<span class="ip">${esc(t.public_ip)}</span>${conf}${v6}`;
  }
  return `<span class="muted">—</span>`;
}

function renderRows(containers) {
  const tbody = $("#rows");
  if (!containers.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty">No containers found.</td></tr>`;
    return;
  }
  tbody.innerHTML = containers.map((c) => {
    const v = c.verdict || {};
    const rowCls = v.status === "CRITICAL" ? "row-crit" : (v.status === "WARNING" ? "row-warn" : "");
    const selfTag = c.is_self ? `<span class="tag">self</span>` : "";
    return `<tr class="${rowCls}">
      <td class="col-name">
        <div class="cname link" data-detail="${esc(c.name)}">${esc(c.name)}</div>
        <div class="cmeta">${esc(c.image)} · ${esc(c.state)}</div>
        <div class="badge-row">${recBadge(c)}${selfTag}</div>
      </td>
      <td>${ipCell(c)}</td>
      <td>${providerCell(c)}</td>
      <td>${networkCell(c)}</td>
      <td>${statusCell(c)}</td>
      <td class="col-act">
        <button class="btn btn-sm rescan" data-name="${esc(c.name)}"${c.is_self ? " disabled" : ""}>Rescan</button>
      </td>
    </tr>`;
  }).join("");

  tbody.querySelectorAll("button.rescan").forEach((b) =>
    b.addEventListener("click", (e) => onRescan(e.target.dataset.name)));
  tbody.querySelectorAll(".cname.link").forEach((d) =>
    d.addEventListener("click", (e) => openDrawer(e.target.dataset.detail)));
}

function render(state) {
  lastData = state;
  renderHost(state.host);
  renderSummary(state.containers || []);
  renderRows(state.containers || []);
  $("#lastScan").textContent = fmtTime(state.last_scan);
}

// ---------- tooltips ---------- //
function checkRow(x) {
  const [cls, lab] = CHECK_ICON[x.status] || CHECK_ICON.info;
  return `<div class="ck"><span class="ck-badge ${cls}">${lab}</span>` +
         `<span class="ck-body"><b>${esc(x.label)}</b><br>${esc(x.detail)}</span></div>`;
}

function buildTip(type, name) {
  const c = (lastData.containers || []).find((x) => x.name === name);
  if (!c) return "";
  if (type === "why") {
    const a = c.app || {};
    if (!a.level) return "";
    let h = `<div class="tip-h">${esc(a.level_label || "")}</div>`;
    h += `<div class="tip-sub">${esc(a.category || "")}</div>`;
    if (a.why) h += `<p>${esc(a.why)}</p>`;
    if (a.what_to_do) h += `<p class="tip-do"><b>What to do:</b> ${esc(a.what_to_do)}</p>`;
    h += `<div class="tip-foot">Click the name to learn more</div>`;
    return h;
  }
  if (type === "checks") {
    const v = c.verdict || {};
    const ch = v.checks || [];
    if (!ch.length) return `<div class="tip-h">No scans yet</div><p>Run a scan to see results.</p>`;
    let h = `<div class="tip-h">Leak scans for ${esc(c.name)}</div>`;
    h += ch.map(checkRow).join("");
    return h;
  }
  return "";
}

let tipHideTimer = null;
function showTip(el, html) {
  if (!html) return;
  clearTimeout(tipHideTimer);
  const t = $("#tooltip");
  t.innerHTML = html;
  t.classList.remove("hidden");
  const r = el.getBoundingClientRect();
  const tw = t.offsetWidth, th = t.offsetHeight;
  let left = r.left;
  let top = r.bottom + 8;
  if (left + tw > window.innerWidth - 12) left = window.innerWidth - tw - 12;
  if (top + th > window.innerHeight - 12) top = Math.max(8, r.top - th - 8);
  t.style.left = Math.max(8, left) + "px";
  t.style.top = Math.max(8, top) + "px";
}
function hideTip() {
  tipHideTimer = setTimeout(() => $("#tooltip").classList.add("hidden"), 80);
}

document.addEventListener("mouseover", (e) => {
  const el = e.target.closest("[data-tip]");
  if (!el) return;
  showTip(el, buildTip(el.dataset.tip, el.dataset.name));
});
document.addEventListener("mouseout", (e) => {
  const el = e.target.closest("[data-tip]");
  if (!el) return;
  if (e.relatedTarget && el.contains(e.relatedTarget)) return;
  hideTip();
});
window.addEventListener("scroll", () => $("#tooltip").classList.add("hidden"), true);

// ---------- detail drawer ---------- //
function kv(label, value) {
  if (value === undefined || value === null || value === "") return "";
  return `<div class="drow"><div class="dk">${esc(label)}</div><div class="dv">${value}</div></div>`;
}

function openDrawer(name) {
  const c = (lastData.containers || []).find((x) => x.name === name);
  if (!c) return;
  const t = c.test || {};
  const v = c.verdict || {};
  const p = v.provider || {};
  const geo = t.geo || {};
  const a = c.app || {};

  $("#drawerTitle").textContent = c.name;
  $("#drawerSub").innerHTML =
    `<span class="badge ${esc(v.status || "UNKNOWN")}">${esc(v.status || "—")}</span>${leakChips(v)}` +
    `<span class="drawer-img">${esc(c.image)}</span>`;

  let body = "";

  // About this app
  if (a.level) {
    const [label, cls] = LEVEL_BADGE[a.level] || ["", ""];
    body += `<h3>About this app</h3>`;
    body += `<div class="about-head">${label ? `<span class="rec-badge ${cls}">${label}</span>` : ""}<span class="about-cat">${esc(a.category || "")}</span></div>`;
    if (a.why) body += `<p class="about-p">${esc(a.why)}</p>`;
    if (a.what_to_do) body += `<p class="about-p"><b>What to do:</b> ${esc(a.what_to_do)}</p>`;
    if (a.learn_more) body += `<p class="about-p about-more">${esc(a.learn_more)}</p>`;
  }

  if (v.message) body += `<div class="dsec">${esc(v.message)}</div>`;
  if (v.notes && v.notes.length) body += `<div class="dsec notes">${v.notes.map(esc).join("<br>")}</div>`;

  // Scans / checks
  if (v.checks && v.checks.length) {
    body += `<h3>Leak scans</h3>`;
    body += `<div class="checks-list">${v.checks.map(checkRow).join("")}</div>`;
  }

  body += `<h3>Result</h3>`;
  body += kv("Exit IPv4", t.public_ip ? `<span class="mono">${esc(t.public_ip)}</span>` : "—");
  body += kv("Exit IPv6", t.ipv6 ? `<span class="mono">${esc(t.ipv6)}</span>` : "none");
  body += kv("Provider", p.name ? `${esc(p.name)} <span class="muted">(${esc(p.confidence)})</span>` : "—");
  body += kv("ASN", p.asn);
  body += kv("Tor exit", t.tor === true ? "Yes" : (t.tor === false ? "No" : "—"));

  body += `<h3>Network</h3>`;
  body += kv("Mode", c.network_mode);
  body += kv("Routed through", c.routed_through);
  body += kv("Privacy tunnel", t.tunnel_present ? "Yes (tun/wg)" : "No");
  body += kv("Mesh overlay", t.mesh_present ? esc((t.mesh_names || []).join(", ")) : "No");
  body += kv("Interfaces", t.interfaces && t.interfaces.length ? `<span class="mono">${esc(t.interfaces.join(", "))}</span>` : "—");

  body += `<h3>Cross-check</h3>`;
  const sampled = t.sampled_ips || {};
  body += kv("Sampled IPs", Object.keys(sampled).length
    ? Object.entries(sampled).map(([k, ip]) => `${esc(k)}: <span class="mono">${esc(ip)}</span>`).join("<br>") : "—");
  body += kv("Sources agree", t.services_agree ? "Yes" : "No");
  body += kv("Method", t.method);

  body += `<h3>Geo</h3>`;
  body += kv("ISP", geo.isp);
  body += kv("Org / ASN", geo.org);
  body += kv("Reverse DNS", geo.hostname);
  body += kv("Location", [geo.city, geo.region, geo.country].filter(Boolean).join(", "));

  body += `<div class="dsec muted">Scanned: ${c.scanned_at ? new Date(c.scanned_at * 1000).toLocaleString() : "—"}</div>`;
  $("#drawerBody").innerHTML = body;

  $("#drawer").classList.remove("hidden");
  $("#overlay").classList.remove("hidden");
}

function closeDrawer() {
  $("#drawer").classList.add("hidden");
  $("#overlay").classList.add("hidden");
}

// ---------- actions ---------- //
async function loadState() {
  try { render(await api("/api/containers")); }
  catch (e) {
    toast("Could not load containers: " + e.message, true);
    $("#rows").innerHTML = `<tr><td colspan="6" class="empty">${esc(e.message)}</td></tr>`;
  }
}

async function scanAll() {
  if (scanning) return;
  scanning = true;
  const btn = $("#scanBtn");
  btn.disabled = true;
  btn.innerHTML = `<span class="spin">↻</span> Scanning…`;
  try { render(await api("/api/scan", { method: "POST" })); toast("Scan complete."); }
  catch (e) { toast("Scan failed: " + e.message, true); }
  finally { scanning = false; btn.disabled = false; btn.textContent = "Scan all"; }
}

async function onRescan(name) {
  try {
    await api("/api/scan/" + encodeURIComponent(name), { method: "POST" });
    await loadState();
    toast(name + " rescanned.");
  } catch (e) { toast("Rescan failed: " + e.message, true); }
}

// ---------- init ---------- //
$("#scanBtn").addEventListener("click", scanAll);
$("#drawerClose").addEventListener("click", closeDrawer);
$("#overlay").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

api("/api/version").then((d) => { $("#appVersion").textContent = "LeakWatch v" + d.version; }).catch(() => {});

// Show cached results instantly, then run a fresh scan automatically on load.
loadState().then(() => scanAll());
