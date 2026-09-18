/* Discovr UI - vanilla JavaScript, no build step, no dependencies.
 *
 * Talks to the local REST API in discovr/server.py. Everything shown here (hostnames,
 * mDNS names, AD attributes, cloud tags) may be attacker-controlled, so the DOM is built
 * with createElement/textContent only - never innerHTML with data (XSS-safe by construction).
 */
"use strict";

// ------------------------------------------------------------------ constants
const RISKS = [
  { key: "Critical", css: "critical", icon: "i-critical" },
  { key: "High", css: "high", icon: "i-high" },
  { key: "Medium", css: "medium", icon: "i-medium" },
  { key: "Low", css: "low", icon: "i-low" },
];
const SEVERITY = { Critical: 3, High: 2, Medium: 1, Low: 0 };
const KINDS = {
  network: { noun: "network scan", icon: "i-network" },
  passive: { noun: "passive listen", icon: "i-passive" },
  ad: { noun: "directory query", icon: "i-ad" },
  aws: { noun: "AWS discovery", icon: "i-cloud" },
  azure: { noun: "Azure discovery", icon: "i-cloud" },
  gcp: { noun: "GCP discovery", icon: "i-cloud" },
};
const INTENSITY_HINTS = {
  gentle: "64 probes in flight, 2 s timeout - for sensitive networks.",
  normal: "512 probes in flight, 1 s timeout.",
  aggressive: "2,048 probes in flight, 0.5 s timeout - fastest and noisiest.",
};
const COLUMNS = [
  ["risk", "Risk"], ["ip", "IP address"], ["hostname", "Hostname"], ["os", "Operating system"],
  ["tag", "Type"], ["ports", "Ports"], ["agent", "Agent"], ["source", "Source"],
];
const STATUS = {
  partial: ["Incomplete", "i-info"],
  running: ["Running", "i-play"], done: ["Done", "i-low"], cancelled: ["Stopped", "i-stop"], error: ["Failed", "i-critical"],
};
const PAGE = 300;          // table rows rendered per "page" - keeps huge inventories snappy
const FAST_POLL = 700;     // ms between state polls while a scan runs
const SLOW_POLL = 3000;    // ms when idle

// ------------------------------------------------------------------ DOM helpers
const $ = (id) => document.getElementById(id);
const SVG_NS = "http://www.w3.org/2000/svg";

/** el("td", { className: "mono", "aria-pressed": true, onclick: fn }, child, "text", ...) */
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null) continue;
    if (key.startsWith("aria-")) node.setAttribute(key, String(value));
    else if (value === false) continue;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (["className", "textContent", "type", "value", "title", "disabled", "hidden"].includes(key)) node[key] = value;
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

/** Inline SVG icon referencing the sprite in index.html. */
function icon(id, extraClass = "") {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", `icon ${extraClass}`.trim());
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(SVG_NS, "use");
  use.setAttribute("href", `#${id}`);
  svg.append(use);
  return svg;
}

const numberFmt = new Intl.NumberFormat();
const compactFmt = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });
const count = (n) => (n >= 10000 ? compactFmt.format(n) : numberFmt.format(n));
const pct = (part, whole) => (whole ? `${Math.round((part / whole) * 100)}%` : "0%");
const plural = (n, word) => `${count(n)} ${word}${n === 1 ? "" : "s"}`;
const tagName = (tag) => String(tag || "[Unknown]").replace(/[[\]]/g, "");
const lower = (v) => String(v ?? "").toLowerCase();
const sourcesOf = (a) => String(a.Source || "").split(",").map((s) => s.trim()).filter(Boolean);
const riskOf = (a) => RISKS.find((r) => r.key === a.Risk) || RISKS[2];
/** "InternetExposed" -> "Internet Exposed", "VMAgent" -> "VM Agent", "IAMRole" -> "IAM Role". */
const humanize = (key) => key.replace(/([a-z\d])([A-Z])/g, "$1 $2").replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2");

/** Numeric sort key for IPv4 strings; anything else sorts last. */
function ipNumber(ip) {
  const parts = String(ip).split(".");
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p))) return Infinity;
  return parts.reduce((acc, p) => acc * 256 + Number(p), 0);
}

// ------------------------------------------------------------------ session token + API
/** Token arrives in the URL fragment (never sent to servers); kept only for this tab. */
const token = (() => {
  const match = location.hash.match(/token=([\w-]+)/);
  let value = match ? match[1] : "";
  try {
    if (value) sessionStorage.setItem("discovr.token", value);
    else value = sessionStorage.getItem("discovr.token") || "";
  } catch { /* storage blocked (private mode): the token still works for this page load */ }
  if (match) history.replaceState(null, "", location.pathname);  // keep the secret out of the address bar
  return value;
})();

/** fetch() wrapper: adds the session token, turns API errors into Error(message, field). */
async function api(path, { method = "GET", body } = {}) {
  const headers = { "X-Discovr-Token": token };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, {
    method, headers, cache: "no-store", body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401) {
    state.unauthorized = true;   // stops polling: retrying cannot succeed without the link
    $("auth-gate").hidden = false;
    throw new Error("Session token missing or invalid");
  }
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    const error = new Error(detail.error || `Request failed (${res.status})`);
    error.field = detail.field;
    throw error;
  }
  return res;
}

// ------------------------------------------------------------------ state
const state = {
  info: null,
  assets: [],              // inventory from the server; each carries _id and a _search string
  version: -1,
  lastAssetsFetch: 0,
  jobs: [],
  seq: 0,                  // last activity-log line received
  announced: null,         // job ids whose completion was already announced
  filters: { q: "", risks: new Set(), type: "", source: "", agentOnly: false },
  sort: { key: "risk", dir: "desc" },
  limit: PAGE,
  detailId: null,
  unauthorized: false,
  stopped: false,
};

// ------------------------------------------------------------------ toasts
/** Short, auto-dismissing message; announced politely to screen readers. */
function toast(message, kind = "info") {
  const node = el("div", { className: `toast ${kind}` }, icon(kind === "error" ? "i-critical" : "i-info"), message);
  $("toasts").append(node);
  setTimeout(() => node.remove(), kind === "error" ? 7000 : 4000);
}

// ------------------------------------------------------------------ theme
function currentTheme() {
  return document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
}

function applyTheme(theme, persist) {
  document.documentElement.dataset.theme = theme;
  const next = theme === "dark" ? "light" : "dark";
  const button = $("theme-toggle");
  button.setAttribute("aria-label", `Switch to ${next} theme`);
  button.replaceChildren(icon(next === "light" ? "i-sun" : "i-moon"));
  if (persist) {
    try { localStorage.setItem("discovr.theme", theme); } catch { /* preference simply not remembered */ }
  }
}

// ------------------------------------------------------------------ host info & form setup
async function loadInfo() {
  const info = await (await api("/api/info")).json();
  state.info = info;
  $("version").textContent = `v${info.version}`;
  const fact = (text, level) => el("li", { className: "fact" }, el("span", { className: `dot ${level || ""}` }), text);
  $("host-facts").replaceChildren(
    fact(info.hostname), fact(info.os),
    fact("Ready · no installation needed", "ok"),
  );
  if (!$("f-target").value && info.subnet) $("f-target").value = info.subnet;

  for (const [kind, installed] of Object.entries(info.providers || {})) {
    const radio = document.querySelector(`input[name="kind"][value="${kind}"]`);
    if (radio && !installed) radio.disabled = true;
  }
  updateKind();
  renderAll();
}

/** Show the fieldset for the chosen source; disabled fieldsets are neither validated nor submitted. */
function updateKind() {
  const kind = document.querySelector('input[name="kind"]:checked').value;
  for (const fs of document.querySelectorAll("fieldset.fields")) {
    const active = fs.dataset.kind === kind;
    fs.hidden = !active;
    fs.disabled = !active;
  }
  $("start-label").textContent = `Start ${KINDS[kind].noun}`;
  clearErrors();
}

function clearErrors() {
  $("form-error").hidden = true;
  for (const node of document.querySelectorAll(".field-error")) node.remove();
  for (const input of document.querySelectorAll('[aria-invalid="true"]')) {
    input.removeAttribute("aria-invalid");
    input.removeAttribute("aria-errormessage");
  }
}

/** Put a validation message right under the offending field and move focus there. */
function showFieldError(name, message) {
  const input = document.querySelector(`fieldset.fields:not([disabled]) [name="${name}"]`);
  if (!input) {
    const box = $("form-error");
    box.replaceChildren(icon("i-critical"), el("span", {}, message));
    box.hidden = false;
    return;
  }
  const id = `err-${name}`;
  input.setAttribute("aria-invalid", "true");
  input.setAttribute("aria-errormessage", id);
  const anchor = input.closest(".input-with-button") || input;
  anchor.after(el("p", { className: "field-error", id }, icon("i-critical"), message));
  input.focus();
}

async function submitScan(event) {
  event.preventDefault();
  clearErrors();
  const form = $("scan-form");
  const data = Object.fromEntries(new FormData(form));
  data.ldaps = "ldaps" in data;
  if (data.portsMode !== "custom") delete data.ports;
  delete data.portsMode;
  if (data.kind === "ad" && !data.password) return showFieldError("password", "Password is required");

  const button = $("start-btn");
  button.disabled = true;
  button.prepend(el("span", { className: "spinner", "aria-hidden": "true" }));
  try {
    const job = await (await api("/api/scans", { method: "POST", body: data })).json();
    toast(`Started ${job.label}`);
    $("f-password").value = "";   // never keep a secret around longer than needed
    for (const id of ["f-access-key", "f-secret-key", "f-session-token", "f-client-secret"]) $(id).value = "";
    pollSoon();
  } catch (error) {
    if (error.field) showFieldError(error.field, error.message);
    else showFieldError("", error.message);
  } finally {
    button.disabled = false;
    button.querySelector(".spinner")?.remove();
  }
}

// ------------------------------------------------------------------ polling
let pollTimer = null;

function pollSoon(delay = 0) {
  clearTimeout(pollTimer);
  if (!token || state.unauthorized || state.stopped) return;
  pollTimer = setTimeout(poll, delay);
}

async function poll() {
  let running = false;
  try {
    const s = await (await api(`/api/state?since=${state.seq}`)).json();
    $("offline-banner").hidden = true;
    state.jobs = s.jobs;
    running = s.jobs.some((j) => j.status === "running");
    appendActivity(s.activity);
    announceFinished(s.jobs);
    renderJobs();
    // Refetch assets when they changed - at most every 1.5 s while a scan streams results.
    if (s.version !== state.version && (!running || Date.now() - state.lastAssetsFetch > 1500)) await loadAssets();
  } catch (error) {
    if (error.message !== "Session token missing or invalid") $("offline-banner").hidden = false;
  } finally {
    const delay = document.hidden ? SLOW_POLL * 2 : running ? FAST_POLL : SLOW_POLL;
    pollSoon(delay);
  }
}

async function loadAssets() {
  const data = await (await api("/api/assets")).json();
  state.lastAssetsFetch = Date.now();
  state.version = data.version;
  for (const asset of data.assets) {
    // One lower-cased string per asset makes search a cheap substring test.
    asset._search = Object.entries(asset).filter(([k]) => !k.startsWith("_"))
      .map(([, v]) => (typeof v === "object" ? JSON.stringify(v) : String(v))).join(" ").toLowerCase();
  }
  state.assets = data.assets;
  renderAll();
}

function announceFinished(jobs) {
  const done = jobs.filter((j) => j.status !== "running");
  if (state.announced === null) {           // first poll after a page load: history, not news
    state.announced = new Set(done.map((j) => j.id));
    return;
  }
  for (const job of done) {
    if (state.announced.has(job.id)) continue;
    state.announced.add(job.id);
    if (job.status === "error") toast(`${job.label} failed: ${job.error}`, "error");
    else if (job.status === "partial") toast(`${job.label}: incomplete coverage. Review the scan warnings.`, "error");
    else toast(`${job.label} ${job.status === "cancelled" ? "stopped" : "finished"}: ${plural(job.found, "asset")}`);
  }
}

function appendActivity(lines) {
  if (!lines.length) return;
  state.seq = lines[lines.length - 1].seq;
  const pre = $("log");
  const stamp = (t) => new Date(t * 1000).toLocaleTimeString([], { hour12: false });
  const text = lines.map((l) => `[${stamp(l.time)}] ${l.message}`).join("\n");
  const kept = (pre.textContent ? `${pre.textContent}\n${text}` : text).split("\n").slice(-300);
  pre.textContent = kept.join("\n");
  pre.scrollTop = pre.scrollHeight;
}

// ------------------------------------------------------------------ scan cards (updated in place)
const jobNodes = new Map();

function renderJobs() {
  $("jobs-empty").hidden = state.jobs.length > 0;
  const activeIds = new Set(state.jobs.map((job) => job.id));
  for (const [id, node] of jobNodes) {
    if (!activeIds.has(id)) { node.root.remove(); jobNodes.delete(id); }
  }
  for (const job of [...state.jobs].sort((a, b) => a.started - b.started)) {
    let node = jobNodes.get(job.id);
    if (!node) {
      node = createJobNode(job);
      jobNodes.set(job.id, node);
      $("jobs").prepend(node.root);   // newest first, existing cards never move (no animation restarts)
    }
    updateJobNode(node, job);
  }
}

function createJobNode(job) {
  const pill = el("span", { className: "pill" });
  const fill = el("span");
  const bar = el("div", { className: "progress", role: "progressbar", "aria-label": `${job.label} progress` }, fill);
  const stage = el("span", { className: "stage" });
  const found = el("span");
  const elapsed = el("span");
  const error = el("p", { className: "job-error", role: "alert", hidden: true });
  const stop = el("button", {
    type: "button", className: "btn small ghost",
    onclick: async () => {
      stop.disabled = true;
      try { await api(`/api/scans/${job.id}/cancel`, { method: "POST", body: {} }); } catch (e) { toast(e.message, "error"); }
      pollSoon();
    },
  }, icon("i-stop"), "Stop");
  const root = el("li", { className: "job" },
    el("div", { className: "job-head" }, icon(KINDS[job.kind]?.icon || "i-network"),
      el("span", { className: "job-title", title: job.label }, job.label), pill),
    bar,
    el("div", { className: "job-meta" }, stage, found, elapsed),
    error,
    el("div", { className: "job-actions" }, stop));
  return { root, pill, bar, fill, stage, found, elapsed, error, stop };
}

function updateJobNode(node, job) {
  const [label, iconId] = STATUS[job.status] || STATUS.running;
  if (node.pill.dataset.status !== job.status) {
    node.pill.dataset.status = job.status;
    node.pill.className = `pill ${job.status}`;
    node.pill.replaceChildren(icon(iconId), label);
  }
  const running = job.status === "running";
  const determinate = running && job.total > 0;
  node.bar.classList.toggle("indeterminate", running && !determinate);
  const value = !running ? 100 : determinate ? Math.min(100, (job.done / job.total) * 100) : 0;
  node.fill.style.width = `${value}%`;
  if (determinate || !running) node.bar.setAttribute("aria-valuenow", String(Math.round(value)));
  else node.bar.removeAttribute("aria-valuenow");
  node.stage.textContent = job.stage || "";
  node.found.textContent = `${count(job.found)} found`;
  const seconds = Math.max(0, Math.round((job.finished || Date.now() / 1000) - job.started));
  node.elapsed.textContent = `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
  const warnings = (job.warnings || []).join("\n");
  node.error.hidden = !job.error && !warnings;
  node.error.textContent = job.error || warnings;
  node.stop.hidden = !running;
}

// ------------------------------------------------------------------ filtering & sorting
/** Apply the filter row; ``skip`` leaves one facet out so its own counts stay meaningful. */
function applyFilters(assets, skip = "") {
  const { q, risks, type, source, agentOnly } = state.filters;
  const terms = lower(q).split(/\s+/).filter(Boolean);
  return assets.filter((a) =>
    (skip === "risk" || !risks.size || risks.has(a.Risk)) &&
    (skip === "type" || !type || a.Tag === type) &&
    (!source || sourcesOf(a).includes(source)) &&
    (!agentOnly || a.AgentCapable) &&
    terms.every((t) => a._search.includes(t)));
}

const SORT_VALUE = {
  risk: (a) => SEVERITY[a.Risk] ?? 1,
  ip: (a) => ipNumber(a.IP),
  hostname: (a) => lower(a.Hostname),
  os: (a) => lower(a.OS),
  tag: (a) => lower(tagName(a.Tag)),
  ports: (a) => (/^[\d,]+$/.test(String(a.Ports)) ? String(a.Ports).split(",").length : 0),
  agent: (a) => (a.AgentCapable ? 1 : 0),
  source: (a) => lower(a.Source),
};

function sortAssets(list) {
  const { key, dir } = state.sort;
  const value = SORT_VALUE[key];
  const sign = dir === "asc" ? 1 : -1;
  return [...list].sort((a, b) => {
    const x = value(a);
    const y = value(b);
    if (x < y) return -sign;
    if (x > y) return sign;
    return ipNumber(a.IP) - ipNumber(b.IP);   // stable, readable tie-break
  });
}

function filtersActive() {
  const f = state.filters;
  return Boolean(f.q || f.risks.size || f.type || f.source || f.agentOnly);
}

function resetFilters() {
  state.filters = { q: "", risks: new Set(), type: "", source: "", agentOnly: false };
  $("search").value = "";
  $("type-filter").value = "";
  $("source-filter").value = "";
  $("agent-only").checked = false;
  state.limit = PAGE;
  renderAll();
}

function toggleRisk(level) {
  const risks = state.filters.risks;
  if (risks.has(level)) risks.delete(level);
  else risks.add(level);
  state.limit = PAGE;
  renderAll();
}

function setType(tag) {
  state.filters.type = state.filters.type === tag ? "" : tag;
  $("type-filter").value = state.filters.type;
  state.limit = PAGE;
  renderAll();
}

// ------------------------------------------------------------------ rendering
function renderAll() {
  const filtered = applyFilters(state.assets);
  renderFilterControls();
  renderKpis(filtered);
  renderRiskBars(applyFilters(state.assets, "risk"));
  renderTypeBars(applyFilters(state.assets, "type"));
  renderTable(filtered);
}

function renderFilterControls() {
  $("risk-filter").replaceChildren(...RISKS.map((r) => el("button", {
    type: "button", className: "chip", "aria-pressed": state.filters.risks.has(r.key), onclick: () => toggleRisk(r.key),
  }, icon(r.icon, `risk-icon ${r.css}`), r.key)));

  // Options come from the data, so the selects only offer values that exist.
  const fillSelect = (select, values, allLabel, labelFor) => {
    const current = select.value;
    select.replaceChildren(el("option", { value: "" }, allLabel),
      ...values.map((v) => el("option", { value: v }, labelFor(v))));
    select.value = values.includes(current) ? current : "";
  };
  const tags = [...new Set(state.assets.map((a) => a.Tag).filter(Boolean))].sort();
  fillSelect($("type-filter"), tags, "All types", tagName);
  const sources = [...new Set(state.assets.flatMap(sourcesOf))].sort();
  fillSelect($("source-filter"), sources, "All sources", (s) => s);
  $("reset-filters").hidden = !filtersActive();
}

function renderKpis(list) {
  const agents = list.filter((a) => a.AgentCapable).length;
  const urgent = list.filter((a) => a.Risk === "Critical" || a.Risk === "High").length;
  const exposed = list.filter((a) => a.InternetExposed).length;
  const sources = new Set(list.flatMap(sourcesOf)).size;
  const tiles = [
    ["Assets", "i-layers", list.length, `from ${sources} source${sources === 1 ? "" : "s"}`],
    ["Agent-capable", "i-agent", agents, `${pct(agents, list.length)} likely agent candidates`],
    ["Critical or high risk", "i-high", urgent, urgent ? "triage these first" : "nothing urgent"],
    ["Potential exposure", "i-globe", exposed, "public address with an internet allow rule"],
  ];
  $("kpis").replaceChildren(...tiles.map(([label, iconId, value, sub]) => el("div", { className: "kpi" },
    el("div", { className: "kpi-label" }, icon(iconId), label),
    el("div", { className: "kpi-value" }, count(value)),
    el("div", { className: "kpi-sub" }, sub))));
}

/** One bar-list row: icon + label, thin bar, count and share - all values visible (no hover needed). */
function barRow({ label, iconNode, fillClass, n, total, pressed, onclick }) {
  const fill = el("span", { className: `bar-fill ${fillClass || ""}` });
  fill.style.width = total ? `${(n / total) * 100}%` : "0%";   // CSSOM styling is allowed by the CSP
  return el("li", {}, el("button", { type: "button", className: "bar-row", "aria-pressed": pressed, onclick },
    el("span", { className: "bar-label" }, iconNode, el("span", {}, label)),
    el("span", { className: "bar-track", "aria-hidden": "true" }, fill),
    el("span", { className: "bar-count" }, count(n)),
    el("span", { className: "bar-pct" }, pct(n, total))));
}

function renderRiskBars(list) {
  $("risk-bars").replaceChildren(...RISKS.map((r) => barRow({
    label: r.key, iconNode: icon(r.icon, `risk-icon ${r.css}`), fillClass: r.css,
    n: list.filter((a) => a.Risk === r.key).length, total: list.length,
    pressed: state.filters.risks.has(r.key), onclick: () => toggleRisk(r.key),
  })));
}

function renderTypeBars(list) {
  const counts = new Map();
  for (const a of list) counts.set(a.Tag, (counts.get(a.Tag) || 0) + 1);
  const rows = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  if (!rows.length) {
    $("type-bars").replaceChildren(el("li", { className: "none" }, "No assets yet."));
    return;
  }
  $("type-bars").replaceChildren(...rows.map(([tag, n]) => barRow({
    label: tagName(tag), iconNode: null, n, total: list.length,
    pressed: state.filters.type === tag, onclick: () => setType(tag),
  })));
}

function renderHeader() {
  $("table-header").replaceChildren(...COLUMNS.map(([key, label]) => {
    const th = el("th", { scope: "col" }, el("button", {
      type: "button", onclick: () => {
        const same = state.sort.key === key;
        const firstDir = ["risk", "agent", "ports"].includes(key) ? "desc" : "asc";
        state.sort = { key, dir: same ? (state.sort.dir === "asc" ? "desc" : "asc") : firstDir };
        renderHeader();
        renderAll();
      },
    }, label, icon("i-chevron")));
    if (state.sort.key === key) th.setAttribute("aria-sort", state.sort.dir === "asc" ? "ascending" : "descending");
    return th;
  }));
}

function renderTable(list) {
  const sorted = sortAssets(list);
  const frag = document.createDocumentFragment();
  for (const asset of sorted.slice(0, state.limit)) frag.append(assetRow(asset));
  $("rows").replaceChildren(frag);
  $("asset-count").textContent = list.length === state.assets.length
    ? count(list.length) : `${count(list.length)} of ${count(state.assets.length)}`;
  const remaining = sorted.length - state.limit;
  $("more").hidden = remaining <= 0;
  $("more-btn").textContent = `Show ${count(Math.min(PAGE, remaining))} more`;
  renderEmpty(list);
}

function assetRow(a) {
  const risk = riskOf(a);
  const host = a.Hostname && a.Hostname !== "Unknown" ? a.Hostname : "(unnamed)";
  return el("tr", { "data-id": a._id },
    el("td", {}, el("span", { className: "cell-risk" }, icon(risk.icon, `risk-icon ${risk.css}`), a.Risk || "Medium")),
    el("td", { className: "mono" }, a.IP),
    el("td", {},
      el("button", { type: "button", className: "cell-host", "data-open": a._id }, host),
      a.InternetExposed ? el("span", { className: "exposed" }, icon("i-globe"), "Exposed") : null),
    el("td", { className: "cell-os" }, a.OS),
    el("td", {}, el("span", { className: "tag" }, tagName(a.Tag))),
    el("td", { className: "mono cell-ports", title: String(a.Ports ?? "") }, a.Ports),
    el("td", {}, a.AgentCapable
      ? el("span", { className: "cell-agent" }, icon("i-agent"), "Yes")
      : el("span", { className: "cell-agent no" }, "No")),
    el("td", {}, a.Source));
}

function renderEmpty(list) {
  const box = $("empty");
  box.hidden = list.length > 0;
  if (list.length) return;
  if (!state.assets.length) {
    const subnet = state.info?.subnet;
    box.replaceChildren(icon("i-network"), el("h3", {}, "No assets yet"),
      el("p", {}, "Start a scan from the panel on the left, or import a Discovr JSON report."),
      subnet ? el("button", { type: "button", className: "btn primary", onclick: () => quickScan(subnet) },
        icon("i-play"), `Scan ${subnet}`) : null);
  } else {
    box.replaceChildren(icon("i-search"), el("h3", {}, "No assets match these filters"),
      el("p", {}, "Try another search term or reset the filters."),
      el("button", { type: "button", className: "btn", onclick: resetFilters }, "Reset filters"));
  }
}

function quickScan(subnet) {
  document.querySelector('input[name="kind"][value="network"]').checked = true;
  updateKind();
  $("f-target").value = subnet;
  $("scan-form").requestSubmit();
}

// ------------------------------------------------------------------ details drawer
function valueNode(value) {
  if (value === true) return "Yes";
  if (value === false) return "No";
  if (Array.isArray(value)) {
    return value.length ? value.map((v) => (typeof v === "object" ? JSON.stringify(v) : String(v))).join(", ") : "-";
  }
  if (value && typeof value === "object") {
    return Object.keys(value).length ? el("pre", {}, JSON.stringify(value, null, 2)) : "-";
  }
  return value === null || value === "" ? "-" : String(value);
}

function openDetails(id) {
  const a = state.assets.find((x) => x._id === id);
  if (!a) return;
  state.detailId = id;
  const risk = riskOf(a);
  $("detail-title").textContent = a.Hostname && a.Hostname !== "Unknown" ? a.Hostname : a.IP;
  $("detail-sub").textContent = [a.IP, a.MAC && a.MAC !== "N/A" ? a.MAC : ""].filter(Boolean).join("  ·  ");
  const summary = el("div", { className: "detail-summary" },
    el("span", { className: "pill" }, icon(risk.icon, `risk-icon ${risk.css}`), `${a.Risk} risk`),
    el("span", { className: "pill" }, tagName(a.Tag)),
    el("span", { className: "pill" }, a.AgentCapable ? "Likely agent-capable" : "Not identified as agent-capable"),
    a.InternetExposed ? el("span", { className: "pill" }, icon("i-globe", "risk-icon high"), "Potential internet exposure") : null);
  const hidden = new Set(["Hostname", "Risk", "Tag", "AgentCapable"]);
  const fields = Object.entries(a).filter(([k]) => !k.startsWith("_") && !hidden.has(k))
    .sort(([x], [y]) => x.localeCompare(y));
  const dl = el("dl", { className: "kv" },
    ...fields.flatMap(([k, v]) => [el("dt", {}, humanize(k)), el("dd", {}, valueNode(v))]));
  $("detail-body").replaceChildren(summary,
    el("section", { className: "detail-section" }, el("h3", {}, "All fields"), dl));
  $("detail").showModal();
}

async function copyDetails() {
  const a = state.assets.find((x) => x._id === state.detailId);
  if (!a) return;
  const clean = Object.fromEntries(Object.entries(a).filter(([k]) => !k.startsWith("_")));
  try {
    await navigator.clipboard.writeText(JSON.stringify(clean, null, 2));
    toast("Asset copied as JSON");
  } catch {
    toast("Clipboard is not available in this browser", "error");
  }
}

// ------------------------------------------------------------------ import / export / clear
async function exportAssets(format) {
  $("export-menu").open = false;
  const ids = sortAssets(applyFilters(state.assets)).map((a) => a._id);
  if (!ids.length) return toast("Nothing to export - no assets match the current filters", "error");
  try {
    const res = await api("/api/export", { method: "POST", body: { format, ids } });
    const name = (res.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/)?.[1] || `discovr.${format}`;
    const url = URL.createObjectURL(await res.blob());
    el("a", { href: url, download: name }).click();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    toast(`Exported ${plural(ids.length, "asset")} as ${format.toUpperCase()}`);
  } catch (error) {
    toast(error.message, "error");
  }
}

async function importFile(file) {
  try {
    if (file.size > 30 * 1024 * 1024) throw new Error("Choose a JSON report smaller than 30 MB");
    const parsed = JSON.parse(await file.text());
    const assets = Array.isArray(parsed) ? parsed : parsed?.assets;
    if (!Array.isArray(assets)) throw new Error("This file is not a Discovr JSON report");
    const result = await (await api("/api/assets/import", { method: "POST", body: { assets } })).json();
    toast(`Imported ${plural(result.imported, "asset")} from ${file.name}`);
    await loadAssets();
  } catch (error) {
    toast(error instanceof SyntaxError ? "That file is not valid JSON" : error.message, "error");
  }
}

function confirmClear() {
  if (!state.assets.length) return;
  $("confirm-text").textContent = `This removes all ${count(state.assets.length)} assets from this session. Saved report files are not affected.`;
  $("confirm").returnValue = "";
  $("confirm").showModal();
}

// ------------------------------------------------------------------ wiring
function wire() {
  let saved = null;
  try { saved = localStorage.getItem("discovr.theme"); } catch { /* ignore */ }
  applyTheme(saved || currentTheme(), false);
  $("theme-toggle").addEventListener("click", () => applyTheme(currentTheme() === "dark" ? "light" : "dark", true));

  for (const radio of document.querySelectorAll('input[name="kind"]')) radio.addEventListener("change", updateKind);
  for (const radio of document.querySelectorAll('input[name="intensity"]')) {
    radio.addEventListener("change", () => { $("intensity-hint").textContent = INTENSITY_HINTS[radio.value]; });
  }
  $("f-ports-mode").addEventListener("change", (e) => {
    $("custom-ports").hidden = e.target.value !== "custom";
    if (e.target.value === "custom") $("f-ports").focus();
  });
  $("toggle-password").addEventListener("click", (e) => {
    const input = $("f-password");
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    e.currentTarget.setAttribute("aria-pressed", String(show));
    e.currentTarget.setAttribute("aria-label", show ? "Hide password" : "Show password");
  });
  $("scan-form").addEventListener("submit", submitScan);

  let searchTimer = null;
  $("search").addEventListener("input", (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.filters.q = e.target.value; state.limit = PAGE; renderAll(); }, 120);
  });
  $("type-filter").addEventListener("change", (e) => { state.filters.type = e.target.value; state.limit = PAGE; renderAll(); });
  $("source-filter").addEventListener("change", (e) => { state.filters.source = e.target.value; state.limit = PAGE; renderAll(); });
  $("agent-only").addEventListener("change", (e) => { state.filters.agentOnly = e.target.checked; state.limit = PAGE; renderAll(); });
  $("reset-filters").addEventListener("click", resetFilters);
  $("more-btn").addEventListener("click", () => { state.limit += PAGE; renderAll(); });

  // Whole row opens details for mouse users; the hostname button is the keyboard path.
  $("rows").addEventListener("click", (e) => {
    const row = e.target.closest("tr[data-id]");
    if (row) openDetails(row.dataset.id);
  });
  $("detail-close").addEventListener("click", () => $("detail").close());
  $("detail-copy").addEventListener("click", copyDetails);
  $("detail").addEventListener("click", (e) => {   // click on the backdrop closes the drawer
    const box = $("detail").getBoundingClientRect();
    if (e.target === $("detail") && (e.clientX < box.left || e.clientX > box.right)) $("detail").close();
  });

  $("import-btn").addEventListener("click", () => $("import-file").click());
  $("import-file").addEventListener("change", (e) => {
    if (e.target.files[0]) importFile(e.target.files[0]);
    e.target.value = "";
  });
  for (const button of document.querySelectorAll("#export-menu [data-format]")) {
    button.addEventListener("click", () => exportAssets(button.dataset.format));
  }
  document.addEventListener("click", (e) => {   // close the export menu when clicking elsewhere
    if (!e.target.closest("#export-menu")) $("export-menu").open = false;
  });
  $("clear-btn").addEventListener("click", confirmClear);
  $("quit-btn").addEventListener("click", () => {
    $("quit-confirm").returnValue = "";
    $("quit-confirm").showModal();
  });
  $("quit-confirm").addEventListener("close", async () => {
    if ($("quit-confirm").returnValue !== "ok") return;
    try {
      await api("/api/shutdown", { method: "POST", body: {} });
      state.stopped = true;
      clearTimeout(pollTimer);
      // Prevent keyboard and screen-reader users reaching controls after shutdown.
      document.querySelector(".layout").inert = true;
      document.querySelector(".topbar").inert = true;
      $("quit-gate").hidden = false;
      $("quit-gate").setAttribute("tabindex", "-1");
      $("quit-gate").focus();
    } catch (error) { toast(error.message, "error"); }
  });
  $("confirm").addEventListener("close", async () => {
    if ($("confirm").returnValue !== "ok") return;
    try {
      await api("/api/assets", { method: "DELETE" });
      toast("All assets cleared");
      await loadAssets();
    } catch (error) {
      toast(error.message, "error");
    }
  });

  document.addEventListener("keydown", (e) => {   // "/" jumps to search, like most dashboards
    const typing = e.target.closest("input, select, textarea, dialog");
    if (e.key === "/" && !typing) {
      e.preventDefault();
      $("search").focus();
    }
  });
  document.addEventListener("visibilitychange", () => { if (!document.hidden) pollSoon(); });
}

async function start() {
  wire();
  renderHeader();
  renderAll();
  if (!token) {
    $("auth-gate").hidden = false;
    return;
  }
  try {
    await loadInfo();
  } catch (error) {
    if (error.message !== "Session token missing or invalid") toast(error.message, "error");
  }
  poll();
}

start();
