"use strict";

const state = {
  programs: [],
  currentProgramId: null,
  pollTimer: null,
  assets: [],
  assetSort: { key: "subdomain", dir: "asc" },
  currentScanId: null,
  bounties: [],
  vulns: [],
  scans: [],
  fuzzHits: [],
  archivedURLs: [],
  paramHits: [],
  jsFindings: [],
  corsFindings: [],
  githubFindings: [],
  cloudFindings: [],
  takeoverFindings: [],
  tlsFindings: [],
  dnsFindings: [],
  crawledURLs: [],
  assetPage: 0,
};

const ASSET_PAGE_SIZE = 100;

const el = (sel) => document.querySelector(sel);

// debounce returns a wrapper that delays calling fn until `ms` have passed
// without another call - keeps expensive renders (e.g. filtering thousands of
// assets on every keystroke) from firing on each input event.
function debounce(fn, ms) {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

// filterBySearch reads inputSel's current value and, if non-empty, keeps
// only rows whose fields(row) values (an array of strings, falsy entries
// dropped) contain it as a case-insensitive substring - the same debounced
// free-text search the Assets tab already has (renderAssets), applied to
// every findings table so none of them are stuck un-searchable in a long
// scan's results. A missing/empty query returns rows unchanged.
function filterBySearch(rows, inputSel, fields) {
  const input = el(inputSel);
  const query = input ? input.value.trim().toLowerCase() : "";
  if (!query) return rows;
  return rows.filter((r) => fields(r).filter(Boolean).join(" ").toLowerCase().includes(query));
}

// formatLocal converts a "YYYY-MM-DD HH:MM:SS" timestamp - as produced by
// SQLite's datetime('now'), which is always UTC - into the browser's local
// time for display. Schedule fields (schedule_next_run_at/last_run_at) are
// already stored in local time by the backend and must NOT be passed through
// this function, or they'd be shifted twice.
function formatLocal(utcString) {
  if (!utcString) return "";
  const d = new Date(utcString.replace(" ", "T") + "Z");
  if (Number.isNaN(d.getTime())) return utcString;
  return d.toLocaleString();
}

// td builds a <td> safely via textContent (never innerHTML), so values that
// originate from untrusted sources (e.g. a scanned target's HTTP response)
// can never be interpreted as HTML/script.
function td(text, opts = {}) {
  const cell = document.createElement("td");
  cell.textContent = text;
  if (opts.title) cell.title = opts.title;
  if (opts.className) cell.className = opts.className;
  return cell;
}

// ---------- Toasts ----------

// showToast renders a small auto-dismissing notification, in addition to (not
// replacing) the existing inline status text spots that already report
// success/failure.
function showToast(message, kind = "info") {
  const container = el("#toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = "toast toast-" + kind;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 4500);
}

// ---------- Tabs ----------

function showTab(name) {
  document.querySelectorAll("#program-view .tab-section").forEach((section) => {
    section.classList.toggle("hidden", section.dataset.tab !== name);
  });
  document.querySelectorAll("#tab-bar .tab-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === name);
  });
}

document.querySelectorAll("#tab-bar .tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => showTab(btn.dataset.tab));
});

async function api(path, opts) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (res.status === 204) return null;
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const msg = (body && body.error) || `request failed (${res.status})`;
    throw new Error(msg);
  }
  return body;
}

// ---------- Programs ----------

async function loadPrograms() {
  state.programs = await api("/api/programs");
  renderProgramList();
}

function renderProgramList() {
  const list = el("#program-list");
  list.innerHTML = "";
  for (const p of state.programs) {
    const li = document.createElement("li");
    li.textContent = p.name;
    if (p.platform) {
      const span = document.createElement("span");
      span.className = "platform";
      span.textContent = p.platform;
      li.appendChild(span);
    }
    if (p.id === state.currentProgramId) li.classList.add("active");
    li.addEventListener("click", () => selectProgram(p.id));
    list.appendChild(li);
  }
}

async function selectProgram(id) {
  state.currentProgramId = id;
  stopPolling();
  renderProgramList();

  const program = state.programs.find((p) => p.id === id);
  if (!program) return;

  el("#dashboard-nav-btn").classList.remove("active");
  el("#learn-nav-btn").classList.remove("active");
  el("#empty-state").classList.add("hidden");
  el("#dashboard-view").classList.add("hidden");
  el("#learn-view").classList.add("hidden");
  el("#program-view").classList.remove("hidden");
  el("#program-name").textContent = program.name;
  el("#program-meta").textContent = [program.platform, program.url]
    .filter(Boolean)
    .join(" · ");
  el("#scan-status").textContent = "";
  showTab("overview");
  renderScheduleForm(program);
  setupExportLinks(id);

  await Promise.all([
    loadScopes(id), loadAssets(id), loadScans(id), loadBounties(id), loadVulnerabilities(id), loadFuzzHits(id),
    loadArchivedURLs(id), loadParamHits(id), loadJSFindings(id), loadCORSFindings(id), loadGitHubFindings(id),
    loadCloudFindings(id), loadTakeoverFindings(id), loadTLSFindings(id), loadDNSFindings(id), loadCrawledURLs(id),
  ]);
  renderOverview();
}

// ---------- Dashboard (cross-program overview) ----------

// showDashboard deselects any program and shows the aggregate view: one
// GET /api/dashboard call (handlers_dashboard.go) instead of the frontend
// fanning out to N programs x 9+ per-program endpoints.
async function showDashboard() {
  state.currentProgramId = null;
  stopPolling();
  renderProgramList();
  el("#dashboard-nav-btn").classList.add("active");
  el("#learn-nav-btn").classList.remove("active");
  el("#empty-state").classList.add("hidden");
  el("#program-view").classList.add("hidden");
  el("#learn-view").classList.add("hidden");
  el("#dashboard-view").classList.remove("hidden");
  try {
    await loadDashboard();
  } catch (err) {
    showToast("Error: " + err.message, "error");
  }
}

// lastDashboardData caches the last GET /api/dashboard response so the
// search/severity/show-resolved filters can re-render instantly from memory
// instead of re-fetching all programs' findings on every keystroke.
let lastDashboardData = null;

async function loadDashboard() {
  lastDashboardData = await api("/api/dashboard");
  renderDashboardPrograms(lastDashboardData.programs);
  renderDashboardFindings(lastDashboardData);
}

function renderDashboardPrograms(programs) {
  const container = el("#dashboard-programs");
  container.innerHTML = "";
  if (!programs.length) {
    container.innerHTML = '<p class="muted">No programs yet.</p>';
    return;
  }
  for (const p of programs) {
    const card = document.createElement("div");
    card.className = "dashboard-program-card";
    card.addEventListener("click", () => selectProgram(p.id));

    const title = document.createElement("h4");
    title.textContent = p.name;
    card.appendChild(title);

    if (p.platform) {
      const plat = document.createElement("p");
      plat.className = "muted";
      plat.textContent = p.platform;
      card.appendChild(plat);
    }

    const stats = document.createElement("p");
    stats.className = "dashboard-program-stats";
    stats.textContent = `${p.asset_count} asset${p.asset_count === 1 ? "" : "s"}`;
    card.appendChild(stats);

    const scanLine = document.createElement("p");
    scanLine.className = "muted";
    scanLine.textContent = p.last_scan
      ? `Last scan: ${p.last_scan.status} · ${formatLocal(p.last_scan.started_at)}`
      : "No scans yet";
    card.appendChild(scanLine);

    container.appendChild(card);
  }
}

// DASHBOARD_FINDING_MAP maps each FINDING_SOURCES type key to the matching
// field in GET /api/dashboard's response, so buildUnifiedFindings (defined
// further down, next to FINDING_SOURCES) can be reused unchanged for the
// cross-program inbox - same severity/title/detail derivation per type, just
// fed a different data source.
const DASHBOARD_FINDING_MAP = {
  vuln: "vulnerabilities",
  github: "github_findings",
  cloud: "cloud_findings",
  cors: "cors_findings",
  js: "js_findings",
  fuzz: "fuzz_hits",
  param: "param_hits",
  takeover: "takeover_findings",
  tls: "tls_findings",
  dns: "dns_findings",
};

function renderDashboardFindings(data) {
  const tbody = el("#dashboard-findings-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";

  const overrideData = {};
  for (const [type, key] of Object.entries(DASHBOARD_FINDING_MAP)) {
    overrideData[type] = data[key] || [];
  }
  let all = buildUnifiedFindings(overrideData);

  const showResolved = el("#dashboard-findings-show-resolved")?.checked;
  if (!showResolved) all = all.filter((f) => !RESOLVED_STATUSES.has(f.status));
  if (el("#dashboard-findings-quick-wins")?.checked) all = all.filter((f) => f.quickWin);

  const query = el("#dashboard-findings-search").value.trim().toLowerCase();
  if (query) {
    all = all.filter((f) =>
      [f.title, f.detail, f.host, f.programName].filter(Boolean).join(" ").toLowerCase().includes(query));
  }
  const sevFilter = el("#dashboard-findings-severity").value;
  if (sevFilter) all = all.filter((f) => f.severity === sevFilter);

  const shown = all.slice(0, UNIFIED_FINDINGS_LIMIT);
  for (const f of shown) {
    const tr = document.createElement("tr");

    const sevTd = document.createElement("td");
    const sevBadge = document.createElement("span");
    sevBadge.className = "sev-badge sev-" + f.severity;
    sevBadge.textContent = f.severity;
    sevTd.appendChild(sevBadge);
    tr.appendChild(sevTd);

    const typeTd = document.createElement("td");
    const typeBadge = document.createElement("span");
    typeBadge.className = "finding-type-badge";
    typeBadge.textContent = f.type;
    typeBadge.title = `Go to ${f.programName || "program"}'s ${f.tab} tab`;
    typeBadge.addEventListener("click", async () => {
      if (f.programId == null) return;
      await selectProgram(f.programId);
      showTab(f.tab);
    });
    typeTd.appendChild(typeBadge);
    tr.appendChild(typeTd);

    tr.appendChild(quickWinTitleTd(f));
    tr.appendChild(td(f.detail, { title: f.detail }));
    tr.appendChild(td(f.host, { title: f.host }));
    tr.appendChild(td(f.programName || "", { title: f.programName || "" }));
    appendReportCell(tr, f.kind, f.row, f.programName);
    tbody.appendChild(tr);
  }

  const more = el("#dashboard-findings-more");
  if (more) {
    more.textContent = all.length > UNIFIED_FINDINGS_LIMIT
      ? `Showing top ${UNIFIED_FINDINGS_LIMIT} of ${all.length} findings.`
      : "";
  }
}

// Filter changes re-render from the cached response (no network round trip);
// only showDashboard() itself re-fetches.
function rerenderDashboardFindings() {
  if (lastDashboardData) renderDashboardFindings(lastDashboardData);
}
el("#dashboard-nav-btn").addEventListener("click", showDashboard);
el("#dashboard-findings-show-resolved").addEventListener("change", rerenderDashboardFindings);
el("#dashboard-findings-severity").addEventListener("change", rerenderDashboardFindings);
el("#dashboard-findings-quick-wins").addEventListener("change", rerenderDashboardFindings);
el("#dashboard-findings-search").addEventListener("input", debounce(rerenderDashboardFindings, 200));

// ---------- Auto-scan schedule ----------

function renderScheduleForm(program) {
  el("#sched-enabled").checked = !!program.schedule_enabled;
  el("#sched-interval").value = String(program.schedule_interval_days || 7);
  el("#sched-time").value = program.schedule_time_of_day || "03:00";
  el("#sched-subfinder").checked = !!program.schedule_run_subfinder;
  el("#sched-httpx").checked = !!program.schedule_run_httpx;
  el("#sched-screenshot").checked = !!program.schedule_screenshot;
  el("#sched-nuclei").checked = !!program.schedule_run_nuclei;
  el("#sched-fuzz").checked = !!program.schedule_run_fuzz;
  el("#sched-fuzz-wordlist").value = program.schedule_fuzz_wordlist_path || "";
  el("#sched-fuzz-wordlist").disabled = !program.schedule_run_fuzz;
  el("#sched-wayback").checked = !!program.schedule_run_wayback;
  el("#sched-params").checked = !!program.schedule_run_params;
  el("#sched-params-wordlist").value = program.schedule_params_wordlist_path || "";
  el("#sched-params-wordlist").disabled = !program.schedule_run_params;
  el("#sched-jsanalysis").checked = !!program.schedule_run_jsanalysis;
  el("#sched-cors").checked = !!program.schedule_run_cors;
  el("#sched-cors-wordlist").value = program.schedule_cors_wordlist_path || "";
  el("#sched-cors-wordlist").disabled = !program.schedule_run_cors;
  el("#sched-github").checked = !!program.schedule_run_github_dork;
  el("#sched-cloud").checked = !!program.schedule_run_cloud_enum;
  el("#sched-takeover").checked = !!program.schedule_run_takeover;
  el("#sched-tls").checked = !!program.schedule_run_tls;
  el("#sched-dns").checked = !!program.schedule_run_dns;
  el("#sched-uncover").checked = !!program.schedule_run_uncover;
  el("#sched-crawl").checked = !!program.schedule_run_crawl;

  const parts = [];
  if (program.schedule_enabled) {
    parts.push(`Next run: ${program.schedule_next_run_at || "pending"}`);
  }
  if (program.schedule_last_run_at) {
    parts.push(`Last run: ${program.schedule_last_run_at}`);
  }
  el("#schedule-status").textContent = parts.join(" · ");
}

el("#schedule-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = state.currentProgramId;
  if (id == null) return;
  const body = {
    enabled: el("#sched-enabled").checked,
    interval_days: parseInt(el("#sched-interval").value, 10),
    time_of_day: el("#sched-time").value,
    run_subfinder: el("#sched-subfinder").checked,
    run_httpx: el("#sched-httpx").checked,
    screenshot: el("#sched-screenshot").checked,
    run_nuclei: el("#sched-nuclei").checked,
    run_fuzz: el("#sched-fuzz").checked,
    fuzz_wordlist_path: el("#sched-fuzz-wordlist").value.trim(),
    run_wayback: el("#sched-wayback").checked,
    run_params: el("#sched-params").checked,
    params_wordlist_path: el("#sched-params-wordlist").value.trim(),
    run_jsanalysis: el("#sched-jsanalysis").checked,
    run_cors: el("#sched-cors").checked,
    cors_wordlist_path: el("#sched-cors-wordlist").value.trim(),
    run_github_dork: el("#sched-github").checked,
    run_cloud_enum: el("#sched-cloud").checked,
    run_takeover: el("#sched-takeover").checked,
    run_tls: el("#sched-tls").checked,
    run_dns: el("#sched-dns").checked,
    run_uncover: el("#sched-uncover").checked,
    run_crawl: el("#sched-crawl").checked,
  };
  try {
    const updated = await api(`/api/programs/${id}/schedule`, {
      method: "PUT",
      body: JSON.stringify(body),
    });
    const idx = state.programs.findIndex((p) => p.id === id);
    if (idx !== -1) state.programs[idx] = updated;
    renderScheduleForm(updated);
  } catch (err) {
    el("#schedule-status").textContent = "Error: " + err.message;
    showToast("Error: " + err.message, "error");
  }
});

el("#program-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const data = Object.fromEntries(new FormData(form).entries());
  await api("/api/programs", { method: "POST", body: JSON.stringify(data) });
  form.reset();
  await loadPrograms();
  if (!el("#dashboard-view").classList.contains("hidden")) await loadDashboard();
});

el("#delete-program-btn").addEventListener("click", async () => {
  const id = state.currentProgramId;
  if (id == null) return;
  if (!confirm("Delete this program and all its data?")) return;
  await api(`/api/programs/${id}`, { method: "DELETE" });
  await loadPrograms();
  await showDashboard();
});

// ---------- Scopes ----------

async function loadScopes(programId) {
  const scopes = await api(`/api/programs/${programId}/scopes`);
  const tbody = el("#scope-table tbody");
  tbody.innerHTML = "";
  for (const sc of scopes) {
    const tr = document.createElement("tr");

    const domainTd = document.createElement("td");
    domainTd.textContent = sc.domain;
    tr.appendChild(domainTd);

    const typeTd = document.createElement("td");
    typeTd.textContent = sc.type;
    tr.appendChild(typeTd);

    const actionTd = document.createElement("td");
    const delBtn = document.createElement("button");
    delBtn.className = "icon-btn";
    delBtn.textContent = "Delete";
    delBtn.addEventListener("click", async () => {
      await api(`/api/scopes/${sc.id}`, { method: "DELETE" });
      await loadScopes(programId);
    });
    actionTd.appendChild(delBtn);
    tr.appendChild(actionTd);

    tbody.appendChild(tr);
  }
}

el("#scope-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = state.currentProgramId;
  if (id == null) return;
  const form = e.target;
  const data = Object.fromEntries(new FormData(form).entries());
  await api(`/api/programs/${id}/scopes`, {
    method: "POST",
    body: JSON.stringify(data),
  });
  form.reset();
  await loadScopes(id);
});

function reportScopeImport(imported, skipped) {
  el("#scope-import-status").textContent = `Imported ${imported}, skipped ${skipped} (already in scope).`;
}

el("#scope-import-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = state.currentProgramId;
  if (id == null) return;
  try {
    const { imported, skipped } = await api(`/api/programs/${id}/scopes/import`, {
      method: "POST",
      body: JSON.stringify({ text: el("#scope-import-text").value, type: el("#scope-import-type").value }),
    });
    el("#scope-import-text").value = "";
    reportScopeImport(imported, skipped);
    await loadScopes(id);
  } catch (err) {
    showToast("Error: " + err.message, "error");
  }
});

el("#scope-import-h1-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = state.currentProgramId;
  if (id == null) return;
  try {
    const { imported, skipped } = await api(`/api/programs/${id}/scopes/import-hackerone`, {
      method: "POST",
      body: JSON.stringify({ handle: el("#scope-import-h1-handle").value.trim() }),
    });
    reportScopeImport(imported, skipped);
    await loadScopes(id);
  } catch (err) {
    showToast("Error: " + err.message, "error");
  }
});

// ---------- Assets ----------

function statusClass(code) {
  if (!code) return "";
  if (code >= 500) return "status-5xx";
  if (code >= 400) return "status-4xx";
  if (code >= 300) return "status-3xx";
  if (code >= 200) return "status-2xx";
  return "";
}

async function loadAssets(programId) {
  state.assets = await api(`/api/programs/${programId}/assets`);
  state.assetPage = 0;
  renderAssets();
  renderGallery();
}

const NUMERIC_SORT_KEYS = new Set(["probe.status_code", "probe.content_length"]);

function sortValue(row, key) {
  if (key.startsWith("probe.")) return row.probe ? row.probe[key.slice(6)] : null;
  return row[key];
}

function compareAssets(a, b, key, dir) {
  const av = sortValue(a, key);
  const bv = sortValue(b, key);
  const aMissing = av === null || av === undefined || av === "";
  const bMissing = bv === null || bv === undefined || bv === "";
  if (aMissing && bMissing) return 0;
  if (aMissing) return 1;
  if (bMissing) return -1;
  const cmp = NUMERIC_SORT_KEYS.has(key)
    ? av - bv
    : String(av).localeCompare(String(bv), undefined, { numeric: true, sensitivity: "base" });
  return dir === "desc" ? -cmp : cmp;
}

// assetNotesCell returns a <td> with a free-text notes input for an asset,
// saved on blur via PATCH /api/assets/{id}/notes - same debounce-on-blur
// pattern as findings triage notes (appendTriageCells).
function assetNotesCell(a) {
  const td_ = document.createElement("td");
  const input = document.createElement("input");
  input.type = "text";
  input.className = "triage-notes";
  input.value = a.notes || "";
  input.placeholder = "notes...";
  input.addEventListener("blur", async () => {
    if (input.value === (a.notes || "")) return;
    try {
      await api(`/api/assets/${a.id}/notes`, {
        method: "PATCH",
        body: JSON.stringify({ notes: input.value }),
      });
      a.notes = input.value;
    } catch (err) {
      showToast("Error: " + err.message, "error");
    }
  });
  td_.appendChild(input);
  return td_;
}

function renderAssets() {
  const query = el("#asset-search").value.trim().toLowerCase();
  const liveOnly = el("#asset-live-only").checked;

  let rows = state.assets.filter((a) => {
    const p = a.probe || {};
    if (liveOnly && !a.probe) return false;
    if (query) {
      const haystack = [a.subdomain, p.title, p.tech].filter(Boolean).join(" ").toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  });

  const { key, dir } = state.assetSort;
  rows = rows.slice().sort((a, b) => compareAssets(a, b, key, dir));

  document.querySelectorAll("#asset-table thead th[data-sort]").forEach((th) => {
    th.classList.toggle("sort-asc", th.dataset.sort === key && dir === "asc");
    th.classList.toggle("sort-desc", th.dataset.sort === key && dir === "desc");
  });

  // Paginate: only the active page's rows go into the DOM, so a program with
  // tens of thousands of assets doesn't build tens of thousands of <tr>.
  const total = rows.length;
  const pageCount = Math.max(1, Math.ceil(total / ASSET_PAGE_SIZE));
  if (state.assetPage >= pageCount) state.assetPage = pageCount - 1;
  if (state.assetPage < 0) state.assetPage = 0;
  const start = state.assetPage * ASSET_PAGE_SIZE;
  const pageRows = rows.slice(start, start + ASSET_PAGE_SIZE);
  renderAssetPagination(total, start, pageRows.length, pageCount);

  const tbody = el("#asset-table tbody");
  tbody.innerHTML = "";
  for (const a of pageRows) {
    const p = a.probe || {};
    const tr = document.createElement("tr");

    const subdomainTd = document.createElement("td");
    subdomainTd.title = a.subdomain;
    subdomainTd.append(a.subdomain);
    if (a.is_new) {
      const badge = document.createElement("span");
      badge.className = "badge-new";
      badge.textContent = "new";
      subdomainTd.append(" ", badge);
    }
    tr.appendChild(subdomainTd);

    tr.appendChild(td(p.url || "", { title: p.url || "" }));
    tr.appendChild(td(p.status_code || "", { className: statusClass(p.status_code) }));
    tr.appendChild(td(p.title || "", { title: p.title || "" }));
    tr.appendChild(td(p.tech || "", { title: p.tech || "" }));
    tr.appendChild(td(p.webserver || ""));
    tr.appendChild(td(formatLocal(a.first_seen)));

    const shotTd = document.createElement("td");
    if (p.has_screenshot) {
      const img = document.createElement("img");
      img.className = "thumb";
      img.src = `/api/assets/${a.id}/screenshot`;
      img.alt = "screenshot";
      shotTd.appendChild(img);
    }
    tr.appendChild(shotTd);

    tr.appendChild(assetNotesCell(a));

    const actionTd = document.createElement("td");
    const rescanBtn = document.createElement("button");
    rescanBtn.type = "button";
    rescanBtn.className = "icon-btn";
    rescanBtn.textContent = "Rescan";
    rescanBtn.title = "Rescan just this asset with the checked tools above";
    rescanBtn.addEventListener("click", () => rescanAsset(a.id));
    actionTd.appendChild(rescanBtn);
    tr.appendChild(actionTd);

    tbody.appendChild(tr);
  }
}

// renderAssetPagination draws the Prev / "X–Y of N" / Next controls under the
// asset table, or hides them when everything fits on one page.
function renderAssetPagination(total, start, pageLen, pageCount) {
  const box = el("#asset-pagination");
  if (!box) return;
  if (total <= ASSET_PAGE_SIZE) {
    box.classList.add("hidden");
    box.innerHTML = "";
    return;
  }
  box.classList.remove("hidden");
  box.innerHTML = "";

  const prev = document.createElement("button");
  prev.className = "btn-secondary";
  prev.textContent = "Prev";
  prev.disabled = state.assetPage <= 0;
  prev.addEventListener("click", () => { state.assetPage--; renderAssets(); });

  const info = document.createElement("span");
  info.textContent = pageLen
    ? `${start + 1}–${start + pageLen} of ${total}`
    : `0 of ${total}`;

  const next = document.createElement("button");
  next.className = "btn-secondary";
  next.textContent = "Next";
  next.disabled = state.assetPage >= pageCount - 1;
  next.addEventListener("click", () => { state.assetPage++; renderAssets(); });

  box.append(prev, info, next);
}

// A filter/search change resets to the first page; a sort keeps you where you
// are but re-slices. Search is debounced so huge lists aren't re-filtered on
// every keystroke.
const renderAssetsDebounced = debounce(renderAssets, 200);
el("#asset-search").addEventListener("input", () => { state.assetPage = 0; renderAssetsDebounced(); });
el("#asset-live-only").addEventListener("change", () => { state.assetPage = 0; renderAssets(); });

document.querySelectorAll("#asset-table thead th[data-sort]").forEach((th) => {
  th.addEventListener("click", () => {
    const key = th.dataset.sort;
    state.assetSort = state.assetSort.key === key
      ? { key, dir: state.assetSort.dir === "asc" ? "desc" : "asc" }
      : { key, dir: "asc" };
    state.assetPage = 0;
    renderAssets();
  });
});

el("#asset-table tbody").addEventListener("click", (e) => {
  const img = e.target.closest("img.thumb");
  if (!img) return;
  el("#screenshot-modal-img").src = img.src;
  el("#screenshot-modal").classList.remove("hidden");
});

el("#screenshot-modal").addEventListener("click", () => {
  el("#screenshot-modal").classList.add("hidden");
});

// ---------- Screenshot gallery ----------
//
// Pure frontend view over state.assets - no new endpoint. Every asset whose
// probe.has_screenshot is true (see renderAssets' thumbnail column) gets a
// grid tile; clicking one reuses the existing #screenshot-modal lightbox.

function renderGallery() {
  const grid = el("#gallery-grid");
  if (!grid) return;
  grid.innerHTML = "";

  const query = el("#gallery-search")?.value.trim().toLowerCase() || "";
  const shots = state.assets.filter((a) => {
    if (!a.probe || !a.probe.has_screenshot) return false;
    if (!query) return true;
    const haystack = [a.subdomain, a.probe.title].filter(Boolean).join(" ").toLowerCase();
    return haystack.includes(query);
  });

  if (!shots.length) return; // CSS :empty::after shows the data-empty message

  for (const a of shots) {
    const tile = document.createElement("div");
    tile.className = "gallery-tile";

    const img = document.createElement("img");
    img.src = `/api/assets/${a.id}/screenshot`;
    img.alt = a.subdomain;
    img.addEventListener("click", () => {
      el("#screenshot-modal-img").src = img.src;
      el("#screenshot-modal").classList.remove("hidden");
    });
    tile.appendChild(img);

    const caption = document.createElement("p");
    caption.className = "gallery-caption";
    caption.title = a.probe.title || a.subdomain;
    caption.textContent = a.probe.title ? `${a.subdomain} — ${a.probe.title}` : a.subdomain;
    tile.appendChild(caption);

    grid.appendChild(tile);
  }
}

el("#gallery-search")?.addEventListener("input", debounce(renderGallery, 200));

el("#opt-httpx").addEventListener("change", () => {
  const on = el("#opt-httpx").checked;
  el("#opt-screenshot").disabled = !on;
  el("#opt-nuclei").disabled = !on;
  el("#opt-fuzz").disabled = !on;
  el("#opt-params").disabled = !on;
  el("#opt-jsanalysis").disabled = !on;
  el("#opt-crawl").disabled = !on;
  el("#opt-cors").disabled = !on;
  if (!on) {
    el("#opt-screenshot").checked = false;
    el("#opt-nuclei").checked = false;
    el("#opt-fuzz").checked = false;
    el("#opt-fuzz-wordlist").disabled = true;
    el("#opt-params").checked = false;
    el("#opt-params-wordlist").disabled = true;
    el("#opt-jsanalysis").checked = false;
    el("#opt-crawl").checked = false;
    el("#opt-cors").checked = false;
    el("#opt-cors-wordlist").disabled = true;
  }
});

el("#opt-fuzz").addEventListener("change", () => {
  el("#opt-fuzz-wordlist").disabled = !el("#opt-fuzz").checked;
});

el("#opt-params").addEventListener("change", () => {
  el("#opt-params-wordlist").disabled = !el("#opt-params").checked;
});

el("#opt-cors").addEventListener("change", () => {
  el("#opt-cors-wordlist").disabled = !el("#opt-cors").checked;
});

el("#sched-fuzz").addEventListener("change", () => {
  el("#sched-fuzz-wordlist").disabled = !el("#sched-fuzz").checked;
});

el("#sched-params").addEventListener("change", () => {
  el("#sched-params-wordlist").disabled = !el("#sched-params").checked;
});

el("#sched-cors").addEventListener("change", () => {
  el("#sched-cors-wordlist").disabled = !el("#sched-cors").checked;
});

// ---------- Scans ----------

// buildAssetScanBody reads the host-oriented subset of the scan-options
// toolbar (httpx and everything that depends on it, plus takeover/TLS/DNS) -
// shared by the whole-program "Scan" button and the Assets tab's per-row
// "Rescan" button. Domain-scoped tools (subfinder/wayback/GitHub dork/cloud
// enum/uncover) are read separately since they don't apply to a single asset.
function buildAssetScanBody() {
  return {
    run_httpx: el("#opt-httpx").checked,
    screenshot: el("#opt-screenshot").checked,
    run_nuclei: el("#opt-nuclei").checked,
    run_fuzz: el("#opt-fuzz").checked,
    fuzz_wordlist_path: el("#opt-fuzz-wordlist").value.trim(),
    run_params: el("#opt-params").checked,
    params_wordlist_path: el("#opt-params-wordlist").value.trim(),
    run_jsanalysis: el("#opt-jsanalysis").checked,
    run_crawl: el("#opt-crawl").checked,
    run_cors: el("#opt-cors").checked,
    cors_wordlist_path: el("#opt-cors-wordlist").value.trim(),
    run_takeover: el("#opt-takeover").checked,
    run_tls: el("#opt-tls").checked,
    run_dns: el("#opt-dns").checked,
  };
}

el("#scan-btn").addEventListener("click", async () => {
  const id = state.currentProgramId;
  if (id == null) return;
  const btn = el("#scan-btn");
  btn.disabled = true;
  el("#scan-status").textContent = "Starting scan...";
  try {
    const body = {
      ...buildAssetScanBody(),
      run_subfinder: el("#opt-subfinder").checked,
      run_wayback: el("#opt-wayback").checked,
      run_github_dork: el("#opt-github").checked,
      run_cloud_enum: el("#opt-cloud").checked,
      run_uncover: el("#opt-uncover").checked,
    };
    const { scan_id } = await api(`/api/programs/${id}/scans`, {
      method: "POST",
      body: JSON.stringify(body),
    });
    pollScan(id, scan_id);
  } catch (err) {
    el("#scan-status").textContent = "Error: " + err.message;
    showToast("Error: " + err.message, "error");
    btn.disabled = false;
  }
});

// rescanAsset starts a scan scoped to one asset (POST /api/assets/{id}/scan),
// reusing the same toolbar checkboxes and the same pollScan status
// line/refresh logic as a whole-program scan - only one scan runs per
// program at a time regardless of scope, so there's no separate progress UI
// to build.
async function rescanAsset(assetID) {
  const programId = state.currentProgramId;
  if (programId == null) return;
  try {
    const { scan_id } = await api(`/api/assets/${assetID}/scan`, {
      method: "POST",
      body: JSON.stringify(buildAssetScanBody()),
    });
    pollScan(programId, scan_id);
  } catch (err) {
    showToast("Error: " + err.message, "error");
  }
}

el("#stop-scan-btn").addEventListener("click", async () => {
  if (!state.currentScanId) return;
  el("#stop-scan-btn").disabled = true;
  try {
    await api(`/api/scans/${state.currentScanId}/stop`, { method: "POST" });
    el("#scan-status").textContent = "Stopping scan...";
  } catch (err) {
    el("#scan-status").textContent = "Error: " + err.message;
  } finally {
    el("#stop-scan-btn").disabled = false;
  }
});

function scanDuration(scan) {
  if (!scan.finished_at) return "";
  const start = new Date(scan.started_at.replace(" ", "T") + "Z");
  const end = new Date(scan.finished_at.replace(" ", "T") + "Z");
  const secs = Math.round((end - start) / 1000);
  if (!Number.isFinite(secs) || secs < 0) return "";
  return `${secs}s`;
}

async function loadScans(programId) {
  const scans = await api(`/api/programs/${programId}/scans`);
  state.scans = scans; // most-recent-first (ORDER BY id DESC server-side)
  const tbody = el("#scan-table tbody");
  tbody.innerHTML = "";
  for (const sc of scans) {
    const tr = document.createElement("tr");
    tr.className = "clickable-row";
    tr.dataset.scanId = sc.id;
    tr.title = "Click to see what this scan found";
    tr.innerHTML = `
      <td>${formatLocal(sc.started_at)}</td>
      <td>${sc.status}</td>
      <td>${sc.triggered_by}</td>
      <td>${sc.new_assets_count}</td>
      <td>${scanDuration(sc)}</td>
    `;
    tbody.appendChild(tr);
  }
}

// ---------- Scan diff (what a scan found: new/changed assets, new vulns) ----------

async function loadScanEvents(scanId) {
  const events = await api(`/api/scans/${scanId}/events`);
  renderScanDiff(events);
  el("#scan-diff-modal").classList.remove("hidden");
}

function renderScanDiff(events) {
  const body = el("#scan-diff-body");
  body.innerHTML = "";

  if (!events.length) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "No changes detected in this scan.";
    body.appendChild(p);
    return;
  }

  const sections = [
    { kind: "new_asset", title: "New assets", empty: "No new assets in this scan." },
    { kind: "changed_asset", title: "Changed assets", empty: "No asset changes in this scan." },
    { kind: "new_vuln", title: "New vulnerabilities", empty: "No new vulnerabilities in this scan." },
    { kind: "new_fuzz_hit", title: "New paths found", empty: "No new fuzz hits in this scan." },
    { kind: "new_archived_url", title: "New archived URLs", empty: "No new archived URLs in this scan." },
    { kind: "new_param_hit", title: "New hidden parameters", empty: "No new hidden parameters in this scan." },
    { kind: "new_endpoint", title: "New JS endpoints", empty: "No new JS endpoints in this scan." },
    { kind: "new_secret", title: "New secrets found", empty: "No new secrets in this scan." },
    { kind: "new_cors_finding", title: "New CORS findings", empty: "No new CORS findings in this scan." },
    { kind: "new_takeover_finding", title: "New takeover findings", empty: "No new takeover findings in this scan." },
    { kind: "new_tls_finding", title: "New TLS findings", empty: "No new TLS findings in this scan." },
    { kind: "new_dns_finding", title: "New DNS findings", empty: "No new DNS findings in this scan." },
    { kind: "new_crawled_url", title: "New crawled URLs", empty: "No new crawled URLs in this scan." },
  ];

  for (const sec of sections) {
    const group = events.filter((e) => e.kind === sec.kind);

    const section = document.createElement("div");
    section.className = "scan-diff-section";
    const h4 = document.createElement("h4");
    h4.textContent = `${sec.title} (${group.length})`;
    section.appendChild(h4);

    if (!group.length) {
      const p = document.createElement("p");
      p.className = "muted";
      p.textContent = sec.empty;
      section.appendChild(p);
    } else {
      const ul = document.createElement("ul");
      ul.className = "scan-diff-list";
      for (const e of group) {
        const li = document.createElement("li");
        const host = document.createElement("span");
        host.className = "scan-diff-host";
        host.textContent = e.subdomain;
        li.appendChild(host);

        const change = document.createElement("span");
        change.className = "scan-diff-change";
        change.textContent = e.kind === "changed_asset" ? `${e.old_value} → ${e.new_value}` : e.new_value;
        li.appendChild(change);

        ul.appendChild(li);
      }
      section.appendChild(ul);
    }
    body.appendChild(section);
  }
}

el("#scan-table tbody").addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-scan-id]");
  if (!tr) return;
  loadScanEvents(tr.dataset.scanId).catch((err) => {
    showToast("Error: " + err.message, "error");
  });
});

el("#scan-diff-modal").addEventListener("click", (e) => {
  if (e.target === el("#scan-diff-modal") || e.target.id === "scan-diff-close-btn") {
    el("#scan-diff-modal").classList.add("hidden");
  }
});

function stopPolling() {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
  el("#scan-btn").disabled = false;
  el("#stop-scan-btn").classList.add("hidden");
  el("#scan-progress").classList.add("hidden");
  state.currentScanId = null;
}

function pollScan(programId, scanId) {
  el("#scan-status").textContent = "Scan running...";
  stopPolling();
  state.currentScanId = scanId;
  el("#scan-btn").disabled = true;
  el("#stop-scan-btn").classList.remove("hidden");
  el("#stop-scan-btn").disabled = false;
  el("#scan-progress").classList.remove("hidden");
  state.pollTimer = setInterval(async () => {
    let scan;
    try {
      scan = await api(`/api/scans/${scanId}`);
    } catch (err) {
      el("#scan-status").textContent = "Error: " + err.message;
      showToast("Error: " + err.message, "error");
      stopPolling();
      return;
    }
    if (scan.status === "running") {
      el("#scan-status").textContent = scan.active_phases && scan.active_phases.length
        ? "Scan running... (" + scan.active_phases.join(", ") + ")"
        : "Scan running...";
      return;
    }

    stopPolling();
    if (scan.status === "done") {
      const msg = `Scan complete: ${scan.new_assets_count} new asset(s).`;
      el("#scan-status").textContent = msg;
      showToast(msg, "success");
    } else if (scan.status === "cancelled") {
      el("#scan-status").textContent = "Scan cancelled.";
      showToast("Scan cancelled.", "info");
    } else {
      const msg = "Scan failed: " + (scan.error || "unknown error");
      el("#scan-status").textContent = msg;
      showToast(msg, "error");
    }
    if (state.currentProgramId === programId) {
      await Promise.all([
        loadAssets(programId), loadScans(programId), loadVulnerabilities(programId), loadFuzzHits(programId),
        loadArchivedURLs(programId), loadParamHits(programId), loadJSFindings(programId), loadCORSFindings(programId),
        loadGitHubFindings(programId), loadCloudFindings(programId), loadTakeoverFindings(programId), loadTLSFindings(programId),
        loadDNSFindings(programId), loadCrawledURLs(programId),
      ]);
      renderOverview();
    }
  }, 2000);
}

// ---------- Bounties ----------

async function loadBounties(programId) {
  state.bounties = await api(`/api/programs/${programId}/bounties`);
  renderBounties();
}

function renderBounties() {
  const tbody = el("#bounty-table tbody");
  tbody.innerHTML = "";
  for (const b of state.bounties) {
    const tr = document.createElement("tr");
    tr.appendChild(td(b.title));
    tr.appendChild(td(b.severity));
    tr.appendChild(td(b.status));
    tr.appendChild(td(b.reward_amount ? `${b.reward_amount} ${b.currency}` : ""));
    tr.appendChild(td(b.submitted_at || ""));
    tr.appendChild(td(b.resolved_at || ""));

    const actionsTd = document.createElement("td");
    const editBtn = document.createElement("button");
    editBtn.className = "icon-btn";
    editBtn.textContent = "Edit";
    editBtn.addEventListener("click", () => startEditBounty(b));
    const delBtn = document.createElement("button");
    delBtn.className = "icon-btn";
    delBtn.textContent = "Delete";
    delBtn.addEventListener("click", async () => {
      await api(`/api/bounties/${b.id}`, { method: "DELETE" });
      await loadBounties(state.currentProgramId);
      await loadTotalEarnings();
    });
    actionsTd.append(editBtn, delBtn);
    tr.appendChild(actionsTd);

    tbody.appendChild(tr);
  }
}

function startEditBounty(b) {
  const form = el("#bounty-form");
  form.elements["id"].value = b.id;
  form.elements["title"].value = b.title;
  form.elements["severity"].value = b.severity;
  form.elements["status"].value = b.status;
  form.elements["reward_amount"].value = b.reward_amount || "";
  form.elements["currency"].value = b.currency;
  form.elements["submitted_at"].value = b.submitted_at || "";
  form.elements["resolved_at"].value = b.resolved_at || "";
  form.elements["notes"].value = b.notes || "";
  el("#bounty-submit-btn").textContent = "Save bounty";
  el("#bounty-cancel-edit-btn").classList.remove("hidden");
}

function resetBountyForm() {
  const form = el("#bounty-form");
  form.reset();
  form.elements["id"].value = "";
  el("#bounty-submit-btn").textContent = "Add bounty";
  el("#bounty-cancel-edit-btn").classList.add("hidden");
}

el("#bounty-cancel-edit-btn").addEventListener("click", resetBountyForm);

el("#bounty-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const programId = state.currentProgramId;
  if (programId == null) return;
  const form = e.target;
  const data = Object.fromEntries(new FormData(form).entries());
  const id = data.id;
  delete data.id;
  data.reward_amount = data.reward_amount ? parseFloat(data.reward_amount) : 0;
  if (id) {
    await api(`/api/bounties/${id}`, { method: "PUT", body: JSON.stringify(data) });
  } else {
    await api(`/api/programs/${programId}/bounties`, { method: "POST", body: JSON.stringify(data) });
  }
  resetBountyForm();
  await loadBounties(programId);
  await loadTotalEarnings();
});

async function loadTotalEarnings() {
  const summary = await api("/api/earnings");
  const totalEl = el("#total-earnings");
  if (!summary.overall.length) {
    totalEl.textContent = "";
    return;
  }
  totalEl.textContent = "Total: " + summary.overall.map((c) => `${c.total} ${c.currency}`).join(", ");
}

// ---------- Findings triage (status/notes), shared across every findings table ----------

const TRIAGE_STATUSES = ["open", "accepted_risk", "false_positive", "fixed"];

// appendTriageCells adds a status <select> + notes <input> pair to tr, backed
// by PATCH /api/findings/{kind}/{id} - the same generic endpoint and widget
// pair for all 9 findings tables, so triage state (reviewed/dismissed/notes)
// doesn't get re-implemented per table.
function appendTriageCells(tr, kind, row) {
  const statusTd = document.createElement("td");
  const select = document.createElement("select");
  select.className = "triage-select";
  for (const s of TRIAGE_STATUSES) {
    const opt = document.createElement("option");
    opt.value = s;
    opt.textContent = s;
    select.appendChild(opt);
  }
  select.value = row.status || "open";

  const notesTd = document.createElement("td");
  const notesInput = document.createElement("input");
  notesInput.type = "text";
  notesInput.className = "triage-notes";
  notesInput.value = row.triage_notes || "";
  notesInput.placeholder = "notes...";

  const saveTriage = async () => {
    try {
      await api(`/api/findings/${kind}/${row.id}`, {
        method: "PATCH",
        body: JSON.stringify({ status: select.value, notes: notesInput.value.trim() }),
      });
      row.status = select.value;
      row.triage_notes = notesInput.value.trim();
      renderOverview();
    } catch (err) {
      showToast("Error: " + err.message, "error");
    }
  };
  select.addEventListener("change", saveTriage);
  notesInput.addEventListener("blur", saveTriage);

  statusTd.appendChild(select);
  notesTd.appendChild(notesInput);
  tr.appendChild(statusTd);
  tr.appendChild(notesTd);
}

// ---------- Report draft ----------
//
// A "Draft report" button per finding row generates a copy-pasteable
// markdown skeleton - title, affected asset, a per-type description filled
// from fields already on the row, and Steps-to-Reproduce/Impact
// placeholders for the hunter to fill in. Entirely client-side (no new
// endpoint): every field used here is already loaded into state.* or the
// dashboard payload, and speed-to-submission is the point, so there's
// nothing to gain from a server round trip. One template function per
// finding kind, keyed the same as the triage PATCH endpoint's `kind`
// (see store/triage.go's triageTables), so call sites can reuse the same
// kind string they already pass to appendTriageCells.
const REPORT_TEMPLATES = {
  vulnerabilities: (v) => ({
    title: v.name || v.template_id,
    asset: v.subdomain,
    description: `Nuclei template \`${v.template_id}\` (${v.name}, severity: ${v.severity || "info"}) matched at ${v.matched_at || v.subdomain}.`,
  }),
  cors: (f) => ({
    title: `CORS misconfiguration: ${f.issue}`,
    asset: f.subdomain || f.url,
    description: `Sending \`Origin: ${f.origin_sent}\` to \`${f.url}\` returns \`Access-Control-Allow-Origin: ${f.acao_value}\`${f.acac_allowed ? " with `Access-Control-Allow-Credentials: true`" : ""}, indicating a CORS misconfiguration (\`${f.issue}\`).`,
  }),
  fuzz: (f) => ({
    title: `Exposed path: ${f.path}`,
    asset: f.subdomain || f.url,
    description: `Requesting \`${f.url}\` returned an unexpected non-404 response (HTTP ${f.status_code}, ${f.content_length} bytes).`,
  }),
  github: (f) => ({
    title: f.kind === "secret" ? `Leaked secret in ${f.repo}` : `Sensitive file match in ${f.repo}`,
    asset: f.repo,
    description: `A ${f.kind === "secret" ? "secret" : "sensitive file/dork match (" + f.dork + ")"} was found in the public GitHub repository \`${f.repo}\` at \`${f.path}\`:\n\n\`\`\`\n${f.value}\n\`\`\`\n\n${f.html_url || ""}`,
  }),
  cloud: (f) => ({
    title: `${f.kind === "open_listable" ? "Publicly listable" : "Exposed"} ${f.provider.toUpperCase()} storage: ${f.bucket}`,
    asset: f.url,
    description: `The ${f.provider.toUpperCase()} storage bucket/container \`${f.bucket}\` at ${f.url} is ${f.kind === "open_listable" ? "publicly listable" : "confirmed to exist and returns 403 (private, but its existence/name is now known)"}.`,
  }),
  js: (f) => ({
    title: f.kind === "secret" ? "Leaked secret in JS" : "Endpoint disclosed in JS",
    asset: f.subdomain || f.source_url,
    description: `A ${f.kind} was found in JavaScript served from \`${f.source_url}\`:\n\n\`\`\`\n${f.value}\n\`\`\``,
  }),
  params: (f) => ({
    title: `Hidden parameter: ${f.param}`,
    asset: f.subdomain || f.url,
    description: `Adding the parameter \`${f.param}\` to \`${f.url}\` changes the response from (status ${f.baseline_status}, ${f.baseline_length}b) to (status ${f.hit_status}, ${f.hit_length}b), suggesting this hidden parameter is processed by the server and worth manual follow-up.`,
  }),
  takeover: (f) => ({
    title: `Subdomain takeover: ${f.subdomain || f.host}`,
    asset: f.subdomain || f.host,
    description: `Host \`${f.subdomain || f.host}\` has a CNAME pointing to \`${f.cname}\`, which resolves to an unclaimed/reclaimable service (\`${f.kind}\`${f.service ? ", " + f.service : ""}).${f.evidence ? " Evidence: " + f.evidence : ""}`,
  }),
  tls: (f) => ({
    title: `TLS issue: ${f.issue}`,
    asset: f.subdomain || f.host,
    description: `TLS issue \`${f.issue}\` found on \`${f.subdomain || f.host}\`: ${f.detail || "(no further detail)"}.`,
  }),
  dns: (f) => ({
    title: f.kind === "zone_transfer" ? `Zone transfer allowed: ${f.subdomain || f.host}` : `DNS finding: ${f.kind}`,
    asset: f.subdomain || f.host,
    description: f.kind === "zone_transfer"
      ? `The authoritative DNS server for \`${f.subdomain || f.host}\` allows an unauthenticated AXFR zone transfer: ${f.value}.`
      : `DNS finding (\`${f.kind}\`${f.detail ? ", " + f.detail : ""}) on \`${f.subdomain || f.host}\`: ${f.value}.`,
  }),
};

// buildReportMarkdown renders the full markdown skeleton for one finding.
// programName is best-effort (the per-program tables know it from
// state.programs; the dashboard's rows already carry it as program_name).
function buildReportMarkdown(kind, row, programName) {
  const tmpl = REPORT_TEMPLATES[kind];
  const { title, asset, description } = tmpl
    ? tmpl(row)
    : { title: "Finding", asset: row.subdomain || row.host || "", description: "(no report template for this finding type)" };
  return `# ${title}

**Program:** ${programName || "-"}
**Affected asset:** ${asset || "-"}
**Found:** ${row.found_at || "-"}

## Description

${description}

## Steps to Reproduce

1.
2.
3.

## Impact

(describe the real-world impact of this finding for this program)
`;
}

function currentProgramName() {
  return state.programs.find((p) => p.id === state.currentProgramId)?.name || "";
}

function openReportModal(kind, row, programName) {
  const markdown = buildReportMarkdown(kind, row, programName ?? currentProgramName());
  el("#report-modal-text").value = markdown;
  el("#report-modal-copied").textContent = "";
  el("#report-modal").classList.remove("hidden");
}

// appendReportCell adds a "Draft report" button to tr - the same kind
// string already passed to appendTriageCells at every call site.
function appendReportCell(tr, kind, row, programName) {
  const reportTd = document.createElement("td");
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "icon-btn";
  btn.textContent = "Draft report";
  btn.addEventListener("click", () => openReportModal(kind, row, programName));
  reportTd.appendChild(btn);
  tr.appendChild(reportTd);
}

el("#report-modal-close-btn").addEventListener("click", () => {
  el("#report-modal").classList.add("hidden");
});
el("#report-modal").addEventListener("click", (e) => {
  if (e.target.id === "report-modal") el("#report-modal").classList.add("hidden");
});
el("#report-modal-copy-btn").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(el("#report-modal-text").value);
    el("#report-modal-copied").textContent = "Copied.";
  } catch {
    // Clipboard API unavailable (e.g. non-secure context) - fall back to a
    // manual select so the user can still Ctrl+C themselves.
    el("#report-modal-text").select();
    el("#report-modal-copied").textContent = "Select-all done - press Ctrl+C.";
  }
});

// ---------- Vulnerabilities (nuclei findings) ----------

async function loadVulnerabilities(programId) {
  const vulns = await api(`/api/programs/${programId}/vulnerabilities`);
  state.vulns = vulns;
  renderVulnerabilities(vulns);
}

function renderVulnerabilities(vulns) {
  const tbody = el("#vuln-table tbody");
  tbody.innerHTML = "";
  vulns = filterBySearch(vulns, "#vuln-search", (v) => [v.name, v.template_id, v.subdomain]);
  for (const v of vulns) {
    const tr = document.createElement("tr");

    const sevTd = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "sev-badge sev-" + (v.severity || "info");
    badge.textContent = v.severity || "info";
    sevTd.appendChild(badge);
    tr.appendChild(sevTd);

    tr.appendChild(td(v.name));
    tr.appendChild(td(v.template_id));
    tr.appendChild(td(v.subdomain, { title: v.matched_at }));
    tr.appendChild(td(formatLocal(v.found_at)));
    appendTriageCells(tr, "vulnerabilities", v);
    appendReportCell(tr, "vulnerabilities", v);
    tbody.appendChild(tr);
  }
}

// ---------- Fuzzing (directory/file discovery hits) ----------

async function loadFuzzHits(programId) {
  const hits = await api(`/api/programs/${programId}/fuzz-hits`);
  state.fuzzHits = hits;
  renderFuzzHits(hits);
}

function renderFuzzHits(hits) {
  const tbody = el("#fuzz-table tbody");
  tbody.innerHTML = "";
  hits = filterBySearch(hits, "#fuzz-search", (h) => [h.path, h.subdomain]);
  for (const h of hits) {
    const tr = document.createElement("tr");
    tr.appendChild(td(h.path, { title: h.url }));
    tr.appendChild(td(h.status_code || "", { className: statusClass(h.status_code) }));
    tr.appendChild(td(h.content_length || ""));
    tr.appendChild(td(h.subdomain));
    tr.appendChild(td(formatLocal(h.found_at)));
    appendTriageCells(tr, "fuzz", h);
    appendReportCell(tr, "fuzz", h);
    tbody.appendChild(tr);
  }
}

// ---------- Archived URLs (Wayback) ----------

async function loadArchivedURLs(programId) {
  const urls = await api(`/api/programs/${programId}/archived-urls`);
  state.archivedURLs = urls;
  renderArchivedURLs(urls);
}

function renderArchivedURLs(urls) {
  const tbody = el("#wayback-table tbody");
  tbody.innerHTML = "";
  for (const u of urls) {
    const tr = document.createElement("tr");
    tr.appendChild(td(u.url, { title: u.url }));
    tr.appendChild(td(u.host));
    tr.appendChild(td(formatLocal(u.first_seen)));
    tbody.appendChild(tr);
  }
}

// ---------- Crawled URLs (katana) ----------

async function loadCrawledURLs(programId) {
  const urls = await api(`/api/programs/${programId}/crawled-urls`);
  state.crawledURLs = urls;
  renderCrawledURLs(urls);
}

function renderCrawledURLs(urls) {
  const tbody = el("#crawled-table tbody");
  tbody.innerHTML = "";
  urls = filterBySearch(urls, "#crawled-search", (u) => [u.url, u.subdomain]);
  for (const u of urls) {
    const tr = document.createElement("tr");
    tr.appendChild(td(u.url, { title: u.url }));
    tr.appendChild(td(u.subdomain));
    tr.appendChild(td(formatLocal(u.found_at)));
    tbody.appendChild(tr);
  }
}

// ---------- Hidden Params ----------

async function loadParamHits(programId) {
  const hits = await api(`/api/programs/${programId}/param-hits`);
  state.paramHits = hits;
  renderParamHits(hits);
}

function renderParamHits(hits) {
  const tbody = el("#params-table tbody");
  tbody.innerHTML = "";
  hits = filterBySearch(hits, "#params-search", (h) => [h.param, h.subdomain]);
  for (const h of hits) {
    const tr = document.createElement("tr");
    tr.appendChild(td(h.param, { title: h.url }));
    tr.appendChild(td(h.subdomain));
    tr.appendChild(td(`${h.baseline_status}, ${h.baseline_length}b`));
    tr.appendChild(td(`${h.hit_status}, ${h.hit_length}b`));
    tr.appendChild(td(formatLocal(h.found_at)));
    appendTriageCells(tr, "params", h);
    appendReportCell(tr, "params", h);
    tbody.appendChild(tr);
  }
}

// ---------- JS Findings (endpoints + secrets) ----------

async function loadJSFindings(programId) {
  const findings = await api(`/api/programs/${programId}/js-findings`);
  state.jsFindings = findings;
  renderJSFindings(findings);
}

function renderJSFindings(findings) {
  const tbody = el("#jsfindings-table tbody");
  tbody.innerHTML = "";
  findings = filterBySearch(findings, "#jsfindings-search", (f) => [f.value, f.source_url, f.subdomain]);
  for (const f of findings) {
    const tr = document.createElement("tr");

    const kindTd = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "sev-badge " + (f.kind === "secret" ? "sev-critical" : "sev-info");
    badge.textContent = f.kind;
    kindTd.appendChild(badge);
    tr.appendChild(kindTd);

    tr.appendChild(td(f.value, { title: f.value }));
    tr.appendChild(td(f.source_url, { title: f.source_url }));
    tr.appendChild(td(f.subdomain));
    tr.appendChild(td(formatLocal(f.found_at)));
    appendTriageCells(tr, "js", f);
    appendReportCell(tr, "js", f);
    tbody.appendChild(tr);
  }
}

// ---------- CORS Findings ----------

async function loadCORSFindings(programId) {
  const findings = await api(`/api/programs/${programId}/cors-findings`);
  state.corsFindings = findings;
  renderCORSFindings(findings);
}

function corsSeverityClass(f) {
  if (f.acac_allowed) return "sev-critical";
  if (f.issue === "reflects_arbitrary_origin" || f.issue === "subdomain_bypass") return "sev-high";
  if (f.issue === "wildcard_with_credentials") return "sev-medium";
  return "sev-info";
}

function renderCORSFindings(findings) {
  const tbody = el("#cors-table tbody");
  tbody.innerHTML = "";
  findings = filterBySearch(findings, "#cors-search", (f) => [f.issue, f.subdomain, f.origin_sent]);
  for (const f of findings) {
    const tr = document.createElement("tr");

    const issueTd = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "sev-badge " + corsSeverityClass(f);
    badge.textContent = f.issue;
    issueTd.appendChild(badge);
    tr.appendChild(issueTd);

    tr.appendChild(td(f.subdomain, { title: f.url }));
    tr.appendChild(td(f.origin_sent, { title: f.origin_sent }));
    tr.appendChild(td(f.acao_value, { title: f.acao_value }));
    tr.appendChild(td(f.acac_allowed ? "yes" : "no"));
    tr.appendChild(td(formatLocal(f.found_at)));
    appendTriageCells(tr, "cors", f);
    appendReportCell(tr, "cors", f);
    tbody.appendChild(tr);
  }
}

// ---------- GitHub Findings (dorking) ----------

async function loadGitHubFindings(programId) {
  const findings = await api(`/api/programs/${programId}/github-findings`);
  state.githubFindings = findings;
  renderGitHubFindings(findings);
}

function renderGitHubFindings(findings) {
  const tbody = el("#github-table tbody");
  tbody.innerHTML = "";
  findings = filterBySearch(findings, "#github-search", (f) => [f.value, f.repo, f.path]);
  for (const f of findings) {
    const tr = document.createElement("tr");

    const kindTd = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "sev-badge " + (f.kind === "secret" ? "sev-critical" : "sev-info");
    badge.textContent = f.kind;
    kindTd.appendChild(badge);
    tr.appendChild(kindTd);

    tr.appendChild(td(f.value, { title: f.value }));

    const repoTd = document.createElement("td");
    if (f.html_url) {
      const a = document.createElement("a");
      a.href = f.html_url;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = f.repo;
      repoTd.appendChild(a);
    } else {
      repoTd.textContent = f.repo;
    }
    tr.appendChild(repoTd);

    tr.appendChild(td(f.path, { title: f.path }));
    tr.appendChild(td(f.dork));
    tr.appendChild(td(formatLocal(f.found_at)));
    appendTriageCells(tr, "github", f);
    appendReportCell(tr, "github", f);
    tbody.appendChild(tr);
  }
}

// ---------- Cloud Storage (S3/GCS/Azure enumeration) ----------

async function loadCloudFindings(programId) {
  const findings = await api(`/api/programs/${programId}/cloud-findings`);
  state.cloudFindings = findings;
  renderCloudFindings(findings);
}

function renderCloudFindings(findings) {
  const tbody = el("#cloud-table tbody");
  tbody.innerHTML = "";
  findings = filterBySearch(findings, "#cloud-search", (f) => [f.provider, f.bucket, f.url]);
  for (const f of findings) {
    const tr = document.createElement("tr");

    const kindTd = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "sev-badge " + (f.kind === "open_listable" ? "sev-critical" : "sev-info");
    badge.textContent = f.kind;
    kindTd.appendChild(badge);
    tr.appendChild(kindTd);

    tr.appendChild(td(f.provider));
    tr.appendChild(td(f.bucket, { title: f.bucket }));

    const urlTd = document.createElement("td");
    const a = document.createElement("a");
    a.href = f.url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.textContent = f.url;
    urlTd.appendChild(a);
    tr.appendChild(urlTd);

    tr.appendChild(td(formatLocal(f.found_at)));
    appendTriageCells(tr, "cloud", f);
    appendReportCell(tr, "cloud", f);
    tbody.appendChild(tr);
  }
}

// ---------- Subdomain Takeover ----------

async function loadTakeoverFindings(programId) {
  const findings = await api(`/api/programs/${programId}/takeover-findings`);
  state.takeoverFindings = findings;
  renderTakeoverFindings(findings);
}

function takeoverSeverityClass(f) {
  if (f.kind === "fingerprint_match") return "sev-critical";
  if (f.kind === "nxdomain") return "sev-high";
  return "sev-medium"; // cname_match - needs manual confirmation
}

function renderTakeoverFindings(findings) {
  const tbody = el("#takeover-table tbody");
  tbody.innerHTML = "";
  findings = filterBySearch(findings, "#takeover-search", (f) => [f.subdomain, f.cname, f.service]);
  for (const f of findings) {
    const tr = document.createElement("tr");

    const kindTd = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "sev-badge " + takeoverSeverityClass(f);
    badge.textContent = f.kind;
    kindTd.appendChild(badge);
    tr.appendChild(kindTd);

    tr.appendChild(td(f.subdomain));
    tr.appendChild(td(f.cname, { title: f.cname }));
    tr.appendChild(td(f.service));
    tr.appendChild(td(f.evidence, { title: f.evidence }));
    tr.appendChild(td(formatLocal(f.found_at)));
    appendTriageCells(tr, "takeover", f);
    appendReportCell(tr, "takeover", f);
    tbody.appendChild(tr);
  }
}

// ---------- TLS Findings ----------

async function loadTLSFindings(programId) {
  const findings = await api(`/api/programs/${programId}/tls-findings`);
  state.tlsFindings = findings;
  renderTLSFindings(findings);
}

function tlsSeverityClass(issue) {
  if (issue === "expired" || issue === "self_signed") return "sev-high";
  if (issue === "expiring_soon" || issue === "hostname_mismatch" || issue === "weak_protocol") return "sev-medium";
  return "sev-info"; // new_san_subdomain
}

function renderTLSFindings(findings) {
  const tbody = el("#tls-table tbody");
  tbody.innerHTML = "";
  findings = filterBySearch(findings, "#tls-search", (f) => [f.subdomain, f.issue, f.detail]);
  for (const f of findings) {
    const tr = document.createElement("tr");

    const issueTd = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "sev-badge " + tlsSeverityClass(f.issue);
    badge.textContent = f.issue;
    issueTd.appendChild(badge);
    tr.appendChild(issueTd);

    tr.appendChild(td(f.subdomain));
    tr.appendChild(td(f.detail, { title: f.detail }));
    tr.appendChild(td(formatLocal(f.found_at)));
    appendTriageCells(tr, "tls", f);
    appendReportCell(tr, "tls", f);
    tbody.appendChild(tr);
  }
}

// ---------- DNS/Infrastructure Findings ----------

async function loadDNSFindings(programId) {
  const findings = await api(`/api/programs/${programId}/dns-findings`);
  state.dnsFindings = findings;
  renderDNSFindings(findings);
}

function dnsSeverityClass(f) {
  if (f.kind === "zone_transfer") return "sev-critical";
  if (f.kind === "waf" || f.kind === "cdn" || f.kind === "cloud" || f.kind === "asn") return "sev-info";
  return "sev-info"; // record
}

function renderDNSFindings(findings) {
  const tbody = el("#dns-table tbody");
  tbody.innerHTML = "";
  findings = filterBySearch(findings, "#dns-search", (f) => [f.subdomain, f.detail, f.value]);
  for (const f of findings) {
    const tr = document.createElement("tr");

    const kindTd = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = "sev-badge " + dnsSeverityClass(f);
    badge.textContent = f.kind;
    kindTd.appendChild(badge);
    tr.appendChild(kindTd);

    tr.appendChild(td(f.subdomain));
    tr.appendChild(td(f.detail));
    tr.appendChild(td(f.value, { title: f.value }));
    tr.appendChild(td(formatLocal(f.found_at)));
    appendTriageCells(tr, "dns", f);
    appendReportCell(tr, "dns", f);
    tbody.appendChild(tr);
  }
}

// Wire each findings table's search box: debounced, re-renders from the
// full state.* array (filterBySearch inside each render* function re-reads
// the box and re-filters) rather than fetching again - same shape as the
// Assets tab's own search wiring.
[
  ["#vuln-search", () => renderVulnerabilities(state.vulns)],
  ["#fuzz-search", () => renderFuzzHits(state.fuzzHits)],
  ["#params-search", () => renderParamHits(state.paramHits)],
  ["#jsfindings-search", () => renderJSFindings(state.jsFindings)],
  ["#cors-search", () => renderCORSFindings(state.corsFindings)],
  ["#github-search", () => renderGitHubFindings(state.githubFindings)],
  ["#cloud-search", () => renderCloudFindings(state.cloudFindings)],
  ["#takeover-search", () => renderTakeoverFindings(state.takeoverFindings)],
  ["#tls-search", () => renderTLSFindings(state.tlsFindings)],
  ["#dns-search", () => renderDNSFindings(state.dnsFindings)],
  ["#crawled-search", () => renderCrawledURLs(state.crawledURLs)],
].forEach(([sel, rerender]) => {
  el(sel)?.addEventListener("input", debounce(rerender, 200));
});

// ---------- Overview (dashboard) ----------
//
// Everything here is computed purely from data already retained in `state`
// (state.assets/state.vulns/state.scans/state.bounties) - no new API calls.
// Called once after selectProgram's Promise.all resolves, and again whenever
// a scan finishes (pollScan refreshes assets/scans first).

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

function severityCounts(vulns) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const v of vulns) {
    const key = (v.severity || "info").toLowerCase();
    if (Object.prototype.hasOwnProperty.call(counts, key)) counts[key]++;
    else counts.info++;
  }
  return counts;
}

function chartEmpty(message) {
  const p = document.createElement("p");
  p.className = "chart-empty";
  p.textContent = message;
  return p;
}

function statCard(label, value, sub) {
  const card = document.createElement("div");
  card.className = "stat-card";
  const l = document.createElement("p");
  l.className = "stat-label";
  l.textContent = label;
  const v = document.createElement("p");
  v.className = "stat-value";
  v.textContent = value;
  card.append(l, v);
  if (sub) {
    const s = document.createElement("p");
    s.className = "stat-sub";
    s.textContent = sub;
    card.appendChild(s);
  }
  return card;
}

function renderOverview() {
  if (state.currentProgramId == null) return;
  renderOverviewStats();
  renderSeverityChart();
  renderAssetSparkline();
  renderEarningsChart();
  renderUnifiedFindings();
}

el("#all-findings-show-resolved")?.addEventListener("change", renderUnifiedFindings);
el("#all-findings-severity")?.addEventListener("change", renderUnifiedFindings);
el("#all-findings-quick-wins")?.addEventListener("change", renderUnifiedFindings);
el("#all-findings-search")?.addEventListener("input", debounce(renderUnifiedFindings, 200));

// EXPORT_TYPES maps a tab's data-tab to the CSV export `type` for that table.
const EXPORT_TYPES = {
  assets: "assets",
  vulns: "vulnerabilities",
  fuzz: "fuzz-hits",
  wayback: "archived-urls",
  crawled: "crawled-urls",
  params: "param-hits",
  jsfindings: "js-findings",
  cors: "cors-findings",
  github: "github-findings",
  cloud: "cloud-findings",
  takeover: "takeover-findings",
  tls: "tls-findings",
  dns: "dns-findings",
  bounties: "bounties",
};

// setupExportLinks injects (or updates) an "Export CSV" link plus a "Print /
// PDF" button into each exportable tab's .panel-header, pointing at that
// program's export endpoint. Print uses the browser's own print-to-PDF (see
// the @media print rules in style.css) - no new dependency, no server work.
function setupExportLinks(programId) {
  for (const [tab, type] of Object.entries(EXPORT_TYPES)) {
    const header = document.querySelector(`.tab-section[data-tab="${tab}"] .panel-header`);
    if (!header) continue;
    let link = header.querySelector("a.export-csv");
    if (!link) {
      link = document.createElement("a");
      link.className = "export-csv";
      link.textContent = "Export CSV";
      header.appendChild(link);
    }
    link.href = `/api/programs/${programId}/export?type=${type}`;

    if (!header.querySelector("button.print-btn")) {
      const printBtn = document.createElement("button");
      printBtn.type = "button";
      printBtn.className = "icon-btn print-btn";
      printBtn.textContent = "Print / PDF";
      printBtn.addEventListener("click", () => {
        showTab(tab);
        window.print();
      });
      header.appendChild(printBtn);
    }
  }
}

// FINDING_SOURCES describes how each finding type maps into the unified list:
// which state array, which tab it lives in, and how to derive a severity,
// title, and detail from a row.
const FINDING_SOURCES = [
  {
    type: "vuln", tab: "vulns", get: () => state.vulns,
    severity: (v) => (v.severity || "info").toLowerCase(),
    title: (v) => v.name || v.template_id,
    detail: (v) => v.matched_at || "",
    host: (v) => v.subdomain || "",
  },
  {
    type: "github", tab: "github", get: () => state.githubFindings,
    severity: (f) => (f.kind === "secret" ? "critical" : "low"),
    title: (f) => f.value,
    detail: (f) => `${f.repo}/${f.path}`,
    host: (f) => f.repo || "",
  },
  {
    type: "cloud", tab: "cloud", get: () => state.cloudFindings,
    severity: (f) => (f.kind === "open_listable" ? "high" : "info"),
    title: (f) => `${f.provider}: ${f.bucket}`,
    detail: (f) => f.kind,
    host: (f) => f.url || "",
  },
  {
    type: "cors", tab: "cors", get: () => state.corsFindings,
    severity: (f) => (f.acac_allowed ? "high" : (f.issue === "reflects_arbitrary_origin" || f.issue === "subdomain_bypass") ? "medium" : "low"),
    title: (f) => f.issue,
    detail: (f) => `origin=${f.origin_sent}`,
    host: (f) => f.subdomain || "",
  },
  {
    type: "js", tab: "jsfindings", get: () => state.jsFindings,
    severity: (f) => (f.kind === "secret" ? "high" : "info"),
    title: (f) => f.value,
    detail: (f) => f.kind,
    host: (f) => f.subdomain || "",
  },
  {
    type: "fuzz", tab: "fuzz", get: () => state.fuzzHits,
    severity: () => "info",
    title: (f) => f.path,
    detail: (f) => `${f.status_code}`,
    host: (f) => f.subdomain || "",
  },
  {
    type: "param", tab: "params", get: () => state.paramHits,
    severity: () => "info",
    title: (f) => f.param,
    detail: (f) => `${f.hit_status}, ${f.hit_length}b`,
    host: (f) => f.subdomain || "",
  },
  {
    type: "takeover", tab: "takeover", get: () => state.takeoverFindings,
    severity: (f) => takeoverSeverityClass(f).replace("sev-", ""),
    title: (f) => `${f.kind}${f.service ? " (" + f.service + ")" : ""}`,
    detail: (f) => f.evidence || f.cname || "",
    host: (f) => f.subdomain || "",
  },
  {
    type: "tls", tab: "tls", get: () => state.tlsFindings,
    severity: (f) => tlsSeverityClass(f.issue).replace("sev-", ""),
    title: (f) => f.issue,
    detail: (f) => f.detail || "",
    host: (f) => f.subdomain || "",
  },
  {
    type: "dns", tab: "dns", get: () => state.dnsFindings,
    severity: (f) => dnsSeverityClass(f).replace("sev-", ""),
    title: (f) => `${f.kind}${f.detail ? " (" + f.detail + ")" : ""}`,
    detail: (f) => f.value || "",
    host: (f) => f.subdomain || "",
  },
];

const UNIFIED_FINDINGS_LIMIT = 100;

// isQuickWin flags findings that are typically a complete, submittable bug
// with little further manual work: a confirmed subdomain takeover, a
// publicly listable cloud storage bucket, a leaked secret (JS or GitHub),
// or a CORS misconfig that actually allows credentials. This is a much
// narrower bar than "high severity" - a critical nuclei CVE match often
// still needs real exploitation before it's reportable, while these four
// are frequently reportable as-is. Pure classification of fields already on
// the row; no new scanning or backend data.
function isQuickWin(type, row) {
  switch (type) {
    case "takeover": return row.kind === "fingerprint_match";
    case "cloud": return row.kind === "open_listable";
    case "github": case "js": return row.kind === "secret";
    case "cors": return !!row.acac_allowed;
    default: return false;
  }
}

// UNIFIED_TYPE_TO_KIND bridges FINDING_SOURCES' short type keys ("vuln",
// "param") to the triage-endpoint/REPORT_TEMPLATES "kind" strings
// ("vulnerabilities", "params") - the two vocabularies exist because
// FINDING_SOURCES predates the triage PATCH endpoint's kind naming; rather
// than rename one to match the other (touching every findings table),
// this small map lets buildUnifiedFindings's output carry a `kind` field
// so the unified/dashboard views can also offer "Draft report".
const UNIFIED_TYPE_TO_KIND = {
  vuln: "vulnerabilities", github: "github", cloud: "cloud", cors: "cors",
  js: "js", fuzz: "fuzz", param: "params", takeover: "takeover", tls: "tls", dns: "dns",
};

// buildUnifiedFindings merges every finding type into one severity-sortable
// list. With no argument it reads the current program's state (the Overview
// tab's per-program "All findings" panel). Passed a map of
// { [FINDING_SOURCES type]: rows[] } (see DASHBOARD_FINDING_MAP), it instead
// builds the list from that data - reused as-is for the cross-program
// dashboard, which fetches rows already tagged with program_id/program_name
// (see handlers_dashboard.go) instead of reading state.*.
function buildUnifiedFindings(overrideData) {
  const out = [];
  for (const src of FINDING_SOURCES) {
    const rows = overrideData ? (overrideData[src.type] || []) : src.get();
    for (const row of rows) {
      out.push({
        severity: src.severity(row),
        type: src.type,
        kind: UNIFIED_TYPE_TO_KIND[src.type] || src.type,
        tab: src.tab,
        title: src.title(row),
        detail: src.detail(row),
        host: src.host(row),
        status: row.status || "open",
        programId: row.program_id ?? null,
        programName: row.program_name || null,
        quickWin: isQuickWin(src.type, row),
        row,
      });
    }
  }
  const rank = (s) => {
    const i = SEVERITY_ORDER.indexOf(s);
    return i === -1 ? SEVERITY_ORDER.length : i;
  };
  out.sort((a, b) => rank(a.severity) - rank(b.severity));
  return out;
}

// resolvedStatuses are hidden from the unified panel by default - the point
// is to surface what still needs attention, not re-show items already
// triaged as noise; "Show resolved" un-hides them.
const RESOLVED_STATUSES = new Set(["false_positive", "fixed"]);

// quickWinTitleTd builds the "Finding" cell shared by the per-program
// unified panel and the cross-program dashboard - prefixes a ⚡ badge for
// quick-win rows (see isQuickWin) so they're visually distinct at a glance,
// not just filterable.
function quickWinTitleTd(f) {
  const tdEl = document.createElement("td");
  tdEl.title = f.title;
  if (f.quickWin) {
    const badge = document.createElement("span");
    badge.className = "quick-win-badge";
    badge.textContent = "⚡";
    badge.title = "Quick win: usually submittable with little further work";
    tdEl.appendChild(badge);
  }
  tdEl.append(f.title);
  return tdEl;
}

function renderUnifiedFindings() {
  const tbody = el("#all-findings-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  const showResolved = el("#all-findings-show-resolved")?.checked;
  let all = buildUnifiedFindings();
  if (!showResolved) all = all.filter((f) => !RESOLVED_STATUSES.has(f.status));
  if (el("#all-findings-quick-wins")?.checked) all = all.filter((f) => f.quickWin);
  all = filterBySearch(all, "#all-findings-search", (f) => [f.title, f.detail, f.host]);
  const sevFilter = el("#all-findings-severity")?.value;
  if (sevFilter) all = all.filter((f) => f.severity === sevFilter);
  const shown = all.slice(0, UNIFIED_FINDINGS_LIMIT);

  for (const f of shown) {
    const tr = document.createElement("tr");

    const sevTd = document.createElement("td");
    const sevBadge = document.createElement("span");
    sevBadge.className = "sev-badge sev-" + f.severity;
    sevBadge.textContent = f.severity;
    sevTd.appendChild(sevBadge);
    tr.appendChild(sevTd);

    const typeTd = document.createElement("td");
    const typeBadge = document.createElement("span");
    typeBadge.className = "finding-type-badge";
    typeBadge.textContent = f.type;
    typeBadge.title = "Go to the " + f.tab + " tab";
    typeBadge.addEventListener("click", () => showTab(f.tab));
    typeTd.appendChild(typeBadge);
    tr.appendChild(typeTd);

    tr.appendChild(quickWinTitleTd(f));
    tr.appendChild(td(f.detail, { title: f.detail }));
    tr.appendChild(td(f.host, { title: f.host }));
    appendReportCell(tr, f.kind, f.row, currentProgramName());
    tbody.appendChild(tr);
  }

  const more = el("#all-findings-more");
  if (more) {
    more.textContent = all.length > UNIFIED_FINDINGS_LIMIT
      ? `Showing top ${UNIFIED_FINDINGS_LIMIT} of ${all.length} findings — open a specific tab for the full list.`
      : "";
  }
}

function renderOverviewStats() {
  const container = el("#overview-stats");
  if (!container) return;
  container.innerHTML = "";

  // Assets + new count.
  const newCount = state.assets.filter((a) => a.is_new).length;
  container.appendChild(
    statCard("Assets", String(state.assets.length), newCount ? `${newCount} new since last scan` : "No new assets")
  );

  // Vulnerabilities by severity.
  const sevCounts = severityCounts(state.vulns);
  const sevCard = document.createElement("div");
  sevCard.className = "stat-card";
  const sevLabel = document.createElement("p");
  sevLabel.className = "stat-label";
  sevLabel.textContent = "Vulnerabilities";
  const sevValue = document.createElement("p");
  sevValue.className = "stat-value";
  sevValue.textContent = String(state.vulns.length);
  sevCard.append(sevLabel, sevValue);
  if (state.vulns.length) {
    const badgeRow = document.createElement("div");
    badgeRow.className = "stat-sev-row";
    for (const sev of SEVERITY_ORDER) {
      if (!sevCounts[sev]) continue;
      const badge = document.createElement("span");
      badge.className = "sev-badge sev-" + sev;
      badge.textContent = `${sev} ${sevCounts[sev]}`;
      badgeRow.appendChild(badge);
    }
    sevCard.appendChild(badgeRow);
  } else {
    const sub = document.createElement("p");
    sub.className = "stat-sub";
    sub.textContent = "None found yet";
    sevCard.appendChild(sub);
  }
  container.appendChild(sevCard);

  // Most recent scan (state.scans is most-recent-first).
  const lastScan = state.scans[0];
  if (lastScan) {
    container.appendChild(
      statCard("Last scan", lastScan.status, `${lastScan.triggered_by} · ${formatLocal(lastScan.started_at)}`)
    );
  } else {
    container.appendChild(statCard("Last scan", "—", "No scans run yet"));
  }

  // This program's resolved-bounty earnings, grouped by currency.
  const byCurrency = {};
  for (const b of state.bounties) {
    if (b.status !== "resolved" || !b.reward_amount) continue;
    const currency = b.currency || "USD";
    byCurrency[currency] = (byCurrency[currency] || 0) + Number(b.reward_amount);
  }
  const currencyEntries = Object.entries(byCurrency);
  if (currencyEntries.length) {
    container.appendChild(
      statCard(
        "Resolved earnings",
        currencyEntries.map(([currency, total]) => `${total.toFixed(2)} ${currency}`).join(", ")
      )
    );
  } else {
    container.appendChild(statCard("Resolved earnings", "—", "No resolved bounties yet"));
  }

  // Recon-surface finding counts (cloud / GitHub / CORS / JS / fuzz), so the
  // overview summarizes every tool at a glance, not just nuclei vulns.
  const cloudOpen = state.cloudFindings.filter((f) => f.kind === "open_listable").length;
  container.appendChild(statCard("Cloud buckets", String(state.cloudFindings.length),
    cloudOpen ? `${cloudOpen} publicly listable` : "None listable"));
  const ghSecrets = state.githubFindings.filter((f) => f.kind === "secret").length;
  container.appendChild(statCard("GitHub hits", String(state.githubFindings.length),
    ghSecrets ? `${ghSecrets} possible secret(s)` : "No secrets matched"));
  container.appendChild(statCard("CORS issues", String(state.corsFindings.length),
    state.corsFindings.length ? "Misconfigurations found" : "None found"));
  const jsSecrets = state.jsFindings.filter((f) => f.kind === "secret").length;
  container.appendChild(statCard("JS findings", String(state.jsFindings.length),
    jsSecrets ? `${jsSecrets} possible secret(s)` : "Endpoints only"));
  container.appendChild(statCard("Fuzz hits", String(state.fuzzHits.length),
    state.fuzzHits.length ? "Paths discovered" : "None found"));
  const takeoverConfirmed = state.takeoverFindings.filter((f) => f.kind !== "cname_match").length;
  container.appendChild(statCard("Takeover findings", String(state.takeoverFindings.length),
    takeoverConfirmed ? `${takeoverConfirmed} likely exploitable` : (state.takeoverFindings.length ? "Needs manual review" : "None found")));
  const tlsIssues = state.tlsFindings.filter((f) => f.issue !== "new_san_subdomain").length;
  container.appendChild(statCard("TLS findings", String(state.tlsFindings.length),
    tlsIssues ? `${tlsIssues} certificate issue(s)` : "SAN entries only"));
  const zoneTransfers = state.dnsFindings.filter((f) => f.kind === "zone_transfer").length;
  container.appendChild(statCard("DNS findings", String(state.dnsFindings.length),
    zoneTransfers ? `${zoneTransfers} zone transfer(s) allowed!` : "No zone transfer exposure"));
  container.appendChild(statCard("Crawled URLs", String(state.crawledURLs.length),
    state.crawledURLs.length ? "Discovered via crawling" : "None found"));
}

// Horizontal stacked bar: critical -> info order, widths proportional to count.
function renderSeverityChart() {
  const container = el("#chart-severity");
  if (!container) return;
  container.innerHTML = "";

  const counts = severityCounts(state.vulns);
  const total = SEVERITY_ORDER.reduce((sum, sev) => sum + counts[sev], 0);
  if (!total) {
    container.appendChild(chartEmpty("Not enough data yet — no vulnerabilities found."));
    return;
  }

  const bar = document.createElement("div");
  bar.className = "chart-severity-bar";
  for (const sev of SEVERITY_ORDER) {
    if (!counts[sev]) continue;
    const seg = document.createElement("div");
    seg.className = "chart-severity-seg sev-seg-" + sev;
    seg.style.width = ((counts[sev] / total) * 100).toFixed(2) + "%";
    seg.title = `${sev}: ${counts[sev]}`;
    bar.appendChild(seg);
  }
  container.appendChild(bar);

  const legend = document.createElement("div");
  legend.className = "chart-severity-legend";
  for (const sev of SEVERITY_ORDER) {
    if (!counts[sev]) continue;
    const item = document.createElement("span");
    const dot = document.createElement("span");
    dot.className = "dot dot-" + sev;
    item.appendChild(dot);
    item.append(`${sev} (${counts[sev]})`);
    legend.appendChild(item);
  }
  container.appendChild(legend);
}

// Cumulative asset-discovery sparkline (SVG polyline), grouped by first_seen day.
function renderAssetSparkline() {
  const container = el("#chart-assets");
  if (!container) return;
  container.innerHTML = "";

  const byDay = {};
  for (const a of state.assets) {
    if (!a.first_seen) continue;
    const day = a.first_seen.slice(0, 10); // "YYYY-MM-DD" prefix
    byDay[day] = (byDay[day] || 0) + 1;
  }
  const days = Object.keys(byDay).sort();
  if (!days.length) {
    container.appendChild(chartEmpty("Not enough data yet — no assets discovered."));
    return;
  }

  let running = 0;
  const totals = days.map((day) => (running += byDay[day]));
  const max = totals[totals.length - 1] || 1;
  const w = 100;
  const h = 100;

  let coords;
  if (totals.length === 1) {
    const y = (h - (totals[0] / max) * h).toFixed(2);
    coords = `0,${y} ${w},${y}`;
  } else {
    const stepX = w / (totals.length - 1);
    coords = totals
      .map((v, i) => `${(i * stepX).toFixed(2)},${(h - (v / max) * h).toFixed(2)}`)
      .join(" ");
  }

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("class", "chart-sparkline-svg");
  const poly = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
  poly.setAttribute("points", coords);
  poly.setAttribute("fill", "none");
  poly.setAttribute("stroke", "var(--accent)");
  poly.setAttribute("stroke-width", "2");
  poly.setAttribute("vector-effect", "non-scaling-stroke");
  svg.appendChild(poly);
  container.appendChild(svg);

  const caption = document.createElement("p");
  caption.className = "chart-sub";
  caption.textContent = `${totals[totals.length - 1]} total across ${days.length} day(s)`;
  container.appendChild(caption);
}

// Simple bar chart of resolved-bounty rewards grouped by resolved_at month.
// Bars sum reward_amount across all currencies for a single trend line per
// month (currency breakdown is already shown in the "Resolved earnings" stat
// card above) - acceptable simplification for a minimal, non-flashy chart.
function renderEarningsChart() {
  const container = el("#chart-earnings");
  if (!container) return;
  container.innerHTML = "";

  const resolved = state.bounties.filter((b) => b.status === "resolved" && b.resolved_at && b.reward_amount);
  if (!resolved.length) {
    container.appendChild(chartEmpty("Not enough data yet — no resolved bounties with a reward."));
    return;
  }

  const byMonth = {};
  for (const b of resolved) {
    const month = b.resolved_at.slice(0, 7); // "YYYY-MM"
    byMonth[month] = (byMonth[month] || 0) + Number(b.reward_amount);
  }
  const months = Object.keys(byMonth).sort();
  const max = Math.max(...months.map((m) => byMonth[m]));

  const row = document.createElement("div");
  row.className = "chart-bars-row";
  const labels = document.createElement("div");
  labels.className = "chart-bars-labels";
  for (const month of months) {
    const bar = document.createElement("div");
    bar.className = "chart-bar";
    const pct = max > 0 ? (byMonth[month] / max) * 100 : 0;
    bar.style.height = Math.max(pct, 3) + "%";
    bar.title = `${month}: ${byMonth[month].toFixed(2)}`;
    row.appendChild(bar);

    const label = document.createElement("span");
    label.textContent = month;
    labels.appendChild(label);
  }
  container.appendChild(row);
  container.appendChild(labels);
}

// ---------- Learn (disclosed write-ups) ----------

let learnPollTimer = null;
const LEARN_BULK_LIMIT = 20;

// Same view toggle as showDashboard/selectProgram: hides the others.
async function showLearn() {
  state.currentProgramId = null;
  stopPolling();
  renderProgramList();
  el("#dashboard-nav-btn").classList.remove("active");
  el("#learn-nav-btn").classList.add("active");
  el("#empty-state").classList.add("hidden");
  el("#program-view").classList.add("hidden");
  el("#dashboard-view").classList.add("hidden");
  el("#learn-view").classList.remove("hidden");
  try {
    await loadWriteups();
  } catch (err) {
    showToast("Error: " + err.message, "error");
  }
  loadWeekly().catch(() => {}); // a side panel: never blocks or errors the list
}

// "This week": top bug classes among reports disclosed in the last 7 days, and
// what the top class has in common (its analyzed root causes + common tech).
async function loadWeekly() {
  const box = el("#learn-weekly");
  const sum = await api("/api/writeups/weekly?days=7");
  box.innerHTML = "";
  if (!sum.total) {
    box.classList.add("hidden");
    return;
  }
  box.classList.remove("hidden");
  box.appendChild(mk("h4", `This week: ${sum.total} report(s) disclosed`));
  const chips = mk("div", null, "weekly-classes");
  for (const c of sum.classes) chips.appendChild(mk("span", `${c.class} · ${c.count}`, "analysis-tag"));
  box.appendChild(chips);
  if (sum.top_class) {
    const top = sum.classes.find((c) => c.class === sum.top_class);
    box.appendChild(mk("p", `Most common: ${sum.top_class} (${top.count}, ${top.analyzed} analyzed)` +
      (sum.top_tech.length ? " · common tech: " + sum.top_tech.join(", ") : "")));
    if (sum.examples.length) {
      box.appendChild(mk("p", "What these have in common (root causes from analyzed reports):", "muted"));
      const ul = mk("ul");
      for (const e of sum.examples) ul.appendChild(mk("li", `${e.title}: ${e.root_cause}`));
      box.appendChild(ul);
    } else {
      box.appendChild(mk("p", "Analyze some of these reports to see their shared root causes.", "muted"));
    }
  }
}

// ponytail: the quality filter re-fetches from the server; search and the
// class/tech/status filters are client-side over the (server-capped, 500) list.
async function loadWriteups() {
  state.writeups = await api("/api/writeups?quality=" + encodeURIComponent(el("#learn-quality").value));
  fillLearnFilters();
  renderWriteups();
  scheduleLearnPoll();
}

// While a job is queued/running, refresh every 4s; stops by itself once
// nothing is pending or the Learn view is hidden (no hooks in the other views).
function scheduleLearnPoll() {
  clearTimeout(learnPollTimer);
  const pending = (state.writeups || []).some((w) => w.analysis_status === "queued" || w.analysis_status === "analyzing");
  if (!pending || el("#learn-view").classList.contains("hidden")) return;
  learnPollTimer = setTimeout(() => loadWriteups().catch(() => {}), 4000);
}

function fillSelect(sel, allLabel, values) {
  const s = el(sel);
  const cur = s.value;
  s.innerHTML = "";
  s.appendChild(new Option(allLabel, ""));
  const uniq = [...new Set(values)].sort();
  for (const v of uniq) s.appendChild(new Option(v, v));
  s.value = uniq.includes(cur) ? cur : "";
}

function fillLearnFilters() {
  const rows = state.writeups || [];
  fillSelect("#learn-class", "All bug classes", rows.map((w) => w.vuln_class).filter(Boolean));
  fillSelect("#learn-tech", "All technologies", rows.flatMap((w) => w.tech_tags || []));
}

// mk builds an element with textContent only: analysis fields are model
// output and report fields are third-party text, so never innerHTML.
function mk(tag, text, cls) {
  const e = document.createElement(tag);
  if (text != null) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function safeLink(text, url) {
  if (!/^https?:\/\//i.test(url || "")) return mk("span", text);
  const a = mk("a", text);
  a.href = url;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  return a;
}

function renderWriteups() {
  const tbody = el("#learn-table tbody");
  tbody.innerHTML = "";
  const cls = el("#learn-class").value;
  const tech = el("#learn-tech").value;
  const status = el("#learn-status-filter").value;
  const rows = filterBySearch(state.writeups || [], "#learn-search", (w) => [w.title, w.program, w.weakness, w.vuln_class])
    .filter((w) => !cls || w.vuln_class === cls)
    .filter((w) => !tech || (w.tech_tags || []).includes(tech))
    .filter((w) => !status || (status === "done") === (w.analysis_status === "done"));
  for (const w of rows) {
    const tr = document.createElement("tr");
    const titleCell = document.createElement("td");
    titleCell.appendChild(safeLink(w.title, w.url));
    tr.appendChild(titleCell);
    tr.appendChild(td(w.program));
    tr.appendChild(td(w.weakness));
    const sev = document.createElement("td");
    sev.appendChild(mk("span", w.severity || "n/a", "sev-badge sev-" + (w.severity || "info")));
    tr.appendChild(sev);
    tr.appendChild(td(w.bounty ? "$" + w.bounty : ""));
    tr.appendChild(td((w.disclosed_at || "").slice(0, 10)));
    tr.appendChild(td(w.quality_flag === "ok" ? "detailed" : "low"));
    if (w.analysis_status === "done") {
      tr.appendChild(td(w.vuln_class));
    } else {
      // failed/skipped (and queued-after-429): show why, full text in the tooltip
      const err = w.analysis_error || "";
      const short = err.length > 90 ? err.slice(0, 90) + "…" : err;
      tr.appendChild(td(w.analysis_status && err ? `${w.analysis_status}: ${short}` : w.analysis_status, { title: err }));
    }
    const actionCell = document.createElement("td");
    actionCell.appendChild(analysisAction(w));
    tr.appendChild(actionCell);
    tbody.appendChild(tr);
  }
}

function analysisAction(w) {
  const b = mk("button", "Analyze", "btn-secondary");
  b.type = "button";
  switch (w.analysis_status) {
    case "done":
      b.textContent = "View";
      b.addEventListener("click", () => openWriteup(w));
      return b;
    case "queued":
    case "analyzing":
      b.textContent = "Queued…";
      b.disabled = true;
      return b;
    case "skipped":
      b.textContent = "Analyze anyway";
      break;
    case "failed":
      b.textContent = "Retry";
      break;
  }
  b.addEventListener("click", () => analyzeWriteup(w));
  return b;
}

// Without a saved key + analysis model there is nothing to run: point the user
// at the settings field instead of letting the request 400.
function needGeminiSettings() {
  showToast("Save a Gemini API key and model names in Settings first.", "error");
  el("#gemini-key").scrollIntoView({ block: "center" });
  el("#gemini-key").focus();
}

async function analyzeWriteup(w) {
  if (!state.geminiReady) return needGeminiSettings();
  try {
    await api(`/api/writeups/${w.id}/analyze`, { method: "POST" });
    el("#learn-status").textContent = "Analysis queued.";
    await loadWriteups();
  } catch (err) {
    showToast("Error: " + err.message, "error");
  }
}

async function openWriteup(w) {
  const body = el("#writeup-modal-body");
  el("#writeup-modal-title").textContent = w.title;
  body.textContent = "Loading...";
  el("#writeup-modal").classList.remove("hidden");
  try {
    const res = await api(`/api/writeups/${w.id}/analysis`);
    renderAnalysis(body, w, res.analysis);
  } catch (err) {
    body.textContent = "Error: " + err.message;
  }
}

function renderAnalysis(body, w, a) {
  body.innerHTML = ""; // clear only; every node below is built with textContent
  if (!a) {
    body.appendChild(mk("p", "No analysis yet."));
    return;
  }
  const sec = (title, ...nodes) => {
    body.appendChild(mk("h4", title));
    for (const n of nodes) body.appendChild(n);
  };
  const list = (tag, items) => {
    const l = mk(tag);
    for (const it of items || []) l.appendChild(mk("li", it));
    return l;
  };

  const head = mk("p", null, "muted");
  head.append(`${a.vuln_class}${w.program ? " · " + w.program : ""} · `);
  head.appendChild(safeLink("original report", w.url));
  body.appendChild(head);
  if ((a.tech_tags || []).length) {
    const tags = mk("div", null, "analysis-tags");
    for (const t of a.tech_tags) tags.appendChild(mk("span", t, "analysis-tag"));
    body.appendChild(tags);
  }

  sec("Summary", mk("p", a.summary));
  sec("Root cause", mk("p", a.root_cause));

  const flow = mk("ol");
  for (const step of a.attack_flow || []) {
    const li = mk("li", step.action);
    li.appendChild(mk("span", "Why it works: " + step.why_it_works, "analysis-why"));
    flow.appendChild(li);
  }
  sec("Attack flow", flow);

  const fix = a.fix || {};
  const fixNodes = [mk("p", "✗ Wrong: " + fix.wrong, "analysis-wrong"), mk("p", "✓ Right: " + fix.right, "analysis-right")];
  if (fix.code_hint) fixNodes.push(mk("pre", fix.code_hint, "analysis-pre"));
  sec("Fix", ...fixNodes);

  if (a.detection && (a.detection.signals || []).length) {
    sec("Detection" + (a.detection.where ? " (" + a.detection.where + ")" : ""), list("ul", a.detection.signals));
  }
  sec("Test checklist", list("ul", a.test_checklist));

  if ((a.unknowns || []).length) {
    const box = mk("div", null, "unknowns-box");
    box.appendChild(mk("h4", "Assumptions (Tahminler)"));
    box.appendChild(mk("p", "Not stated in the report: inferred by the model, treat with caution.", "muted"));
    box.appendChild(list("ul", a.unknowns));
    body.appendChild(box);
  }
  body.appendChild(mk("p", `Model: ${a.model}${a.quality_score != null ? " · triage score " + a.quality_score + "/10" : ""}`, "muted"));
}

el("#writeup-modal-close-btn").addEventListener("click", () => el("#writeup-modal").classList.add("hidden"));
el("#writeup-modal").addEventListener("click", (e) => {
  if (e.target.id === "writeup-modal") el("#writeup-modal").classList.add("hidden");
});

el("#learn-nav-btn").addEventListener("click", showLearn);
el("#learn-quality").addEventListener("change", () => loadWriteups().catch((e) => showToast("Error: " + e.message, "error")));
for (const id of ["#learn-class", "#learn-tech", "#learn-status-filter"]) el(id).addEventListener("change", renderWriteups);
el("#learn-search").addEventListener("input", debounce(renderWriteups, 200));

el("#learn-bulk-btn").addEventListener("click", async () => {
  if (!state.geminiReady) return needGeminiSettings();
  const btn = el("#learn-bulk-btn");
  btn.disabled = true;
  try {
    const res = await api(`/api/writeups/analyze-bulk?limit=${LEARN_BULK_LIMIT}`, { method: "POST" });
    el("#learn-status").textContent = `Queued ${res.queued} report(s) for triage + analysis (runs one at a time, paced for rate limits).`;
    await loadWriteups();
  } catch (err) {
    showToast("Error: " + err.message, "error");
  } finally {
    btn.disabled = false;
  }
});

el("#learn-sync-btn").addEventListener("click", async () => {
  const btn = el("#learn-sync-btn");
  btn.disabled = true;
  el("#learn-status").textContent = "Syncing...";
  try {
    const res = await api("/api/writeups/sync", { method: "POST" });
    el("#learn-status").textContent = `Synced: ${res.new} new report(s).`;
    await loadWriteups();
    loadWeekly().catch(() => {});
  } catch (err) {
    el("#learn-status").textContent = "Error: " + err.message;
    showToast("Error: " + err.message, "error");
  } finally {
    btn.disabled = false;
  }
});

// ---------- Telegram notification settings (app-wide, not per-program) ----------

// The server never returns saved tokens (GET /api/settings only says
// whether one is set - see settingsView in handlers_settings.go), so token
// inputs are left blank with a placeholder hinting one is already saved.
// Leaving a token field blank on save keeps the existing value; typing a
// new one replaces it.
function tokenPlaceholder(isSet, blank) {
  return isSet ? "•••••••• (saved — leave blank to keep)" : blank;
}

async function loadSettings() {
  const settings = await api("/api/settings");
  el("#tg-enabled").checked = !!settings.telegram_enabled;
  el("#tg-bot-token").value = "";
  el("#tg-bot-token").placeholder = tokenPlaceholder(settings.telegram_bot_token_set, "Bot token");
  el("#tg-chat-id").value = settings.telegram_chat_id || "";
  el("#tg-notify-new").checked = !!settings.telegram_notify_new_assets;
  el("#tg-notify-changes").checked = !!settings.telegram_notify_changes;
  el("#tg-notify-vulns").checked = !!settings.telegram_notify_vulnerabilities;
  el("#gh-token").value = "";
  el("#gh-token").placeholder = tokenPlaceholder(settings.github_token_set, "Personal access token (no special scopes needed)");
  el("#uncover-keys").value = "";
  el("#uncover-keys").placeholder = tokenPlaceholder(settings.uncover_api_keys_set, "One per line: shodan:xxx\ncensys:id:secret\nfofa:email:key");
  el("#scan-retention").value = String(settings.scan_retention_count || 0);
  el("#h1-username").value = settings.hackerone_username || "";
  el("#h1-api-token").value = "";
  el("#h1-api-token").placeholder = tokenPlaceholder(settings.hackerone_api_token_set, "API token");
  el("#gemini-key").value = "";
  el("#gemini-key").placeholder = tokenPlaceholder(settings.gemini_api_key_set, "Gemini API key");
  el("#gemini-triage-model").value = settings.gemini_triage_model || "";
  el("#gemini-analysis-model").value = settings.gemini_analysis_model || "";
  state.geminiReady = !!settings.gemini_api_key_set && !!settings.gemini_analysis_model;
}

// "Remove key" re-submits the whole settings form with an explicit clear flag
// (a blank key alone means "keep"), so no other setting is clobbered.
let clearGeminiKey = false;
el("#gemini-clear-btn").addEventListener("click", () => {
  clearGeminiKey = true;
  el("#settings-form").requestSubmit();
});

el("#settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {
    telegram_enabled: el("#tg-enabled").checked,
    telegram_bot_token: el("#tg-bot-token").value.trim(),
    telegram_chat_id: el("#tg-chat-id").value.trim(),
    telegram_notify_new_assets: el("#tg-notify-new").checked,
    telegram_notify_changes: el("#tg-notify-changes").checked,
    telegram_notify_vulnerabilities: el("#tg-notify-vulns").checked,
    github_token: el("#gh-token").value.trim(),
    uncover_api_keys: el("#uncover-keys").value.trim(),
    scan_retention_count: parseInt(el("#scan-retention").value, 10) || 0,
    hackerone_username: el("#h1-username").value.trim(),
    hackerone_api_token: el("#h1-api-token").value.trim(),
    gemini_api_key: el("#gemini-key").value.trim(),
    clear_gemini_api_key: clearGeminiKey,
    gemini_triage_model: el("#gemini-triage-model").value.trim(),
    gemini_analysis_model: el("#gemini-analysis-model").value.trim(),
  };
  clearGeminiKey = false;
  el("#settings-status").textContent = "";
  try {
    await api("/api/settings", { method: "PUT", body: JSON.stringify(body) });
    await loadSettings();
    el("#settings-status").textContent = "Saved.";
  } catch (err) {
    el("#settings-status").textContent = "Error: " + err.message;
    showToast("Error: " + err.message, "error");
  }
});

el("#tg-test-btn").addEventListener("click", async () => {
  el("#settings-status").textContent = "Sending...";
  try {
    await api("/api/settings/test", { method: "POST" });
    el("#settings-status").textContent = "Test message sent.";
  } catch (err) {
    el("#settings-status").textContent = "Error: " + err.message;
    showToast("Error: " + err.message, "error");
  }
});

// ---------- Init ----------

// The dashboard is the default view (it renders sensibly with zero programs
// too - see renderDashboardPrograms) - #empty-state is now only a fallback
// for when the initial program list fetch itself fails.
loadPrograms()
  .then(() => showDashboard())
  .catch((err) => {
    el("#empty-state").textContent = "Failed to load programs: " + err.message;
  });

loadTotalEarnings().catch(() => {
  el("#total-earnings").textContent = "";
});

loadSettings().catch((err) => {
  el("#settings-status").textContent = "Failed to load settings: " + err.message;
});
