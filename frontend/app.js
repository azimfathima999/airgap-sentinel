/* =========================================================================
   Sentinel Console — app.js
   Vanilla JS, no build step, no external dependencies (works fully offline).

   API contract (per spec, Section 4):
     GET /stats
     GET /logs
     GET /alerts
     GET /alerts/{alert_id}
     GET /reports/{report_id}
     GET /health

   Field-name note for Member 1 / Member 2:
   This UI reads the field names listed in FIELD MAP comments below, with
   a couple of reasonable fallbacks (e.g. "sourceIp" vs "source_ip"). If the
   backend uses different names, either rename in the API or adjust the
   small `pick()` calls in the render functions — everything else is
   unaffected.
   ========================================================================= */

// ---- Config -----------------------------------------------------------
const CONFIG = {
  API_BASE: "http://127.0.0.1:8000", // change if backend runs elsewhere
  DEFAULT_POLL_MS: 7000,
};

document.getElementById("apiBaseLabel").textContent = CONFIG.API_BASE;

// ---- Tiny fetch helper --------------------------------------------------
async function apiGet(path) {
  const res = await fetch(CONFIG.API_BASE + path, { method: "GET" });
  if (!res.ok) {
    throw new Error(`${path} -> HTTP ${res.status}`);
  }
  return res.json();
}

// Reads the first present key from an object, trying several naming
// conventions so small backend/frontend naming mismatches don't break the UI.
function pick(obj, keys, fallback = "—") {
  if (!obj) return fallback;
  for (const k of keys) {
    if (obj[k] !== undefined && obj[k] !== null && obj[k] !== "") return obj[k];
  }
  return fallback;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatTimestamp(ts) {
  if (!ts || ts === "—") return "—";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return String(ts);
  return d.toLocaleString(undefined, {
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function severityBadge(sevRaw) {
  const sev = String(sevRaw || "").toUpperCase();
  const cls = { LOW: "badge-low", MEDIUM: "badge-medium", HIGH: "badge-high", CRITICAL: "badge-critical" }[sev] || "badge-status";
  return `<span class="badge ${cls}">${escapeHtml(sev || "UNKNOWN")}</span>`;
}

function statusBadge(statusRaw) {
  const status = String(statusRaw || "unknown").toLowerCase();
  return `<span class="badge badge-status" data-status="${escapeHtml(status)}">${escapeHtml(status)}</span>`;
}

// ---- Status bar / toasts -------------------------------------------------
function setStatus(msg, isError = false) {
  const el = document.getElementById("statusbarLeft");
  el.textContent = msg;
  el.style.color = isError ? "#ff4d5e" : "";
}

// =========================================================================
// ROUTER
// =========================================================================
const VIEWS = ["dashboard", "alerts", "alert-detail", "report"];
let currentAlertId = null;

function showView(name) {
  VIEWS.forEach((v) => {
    document.getElementById(`view-${v}`).hidden = v !== name;
  });
  document.querySelectorAll(".nav-link").forEach((a) => {
    a.classList.toggle("active", a.dataset.route === name.split("-")[0] && VIEWS[0] !== "alert-detail");
  });
  // Highlight "Alerts" nav item when on alert-detail too
  if (name === "alert-detail") {
    document.querySelectorAll(".nav-link").forEach((a) => a.classList.toggle("active", a.dataset.route === "alerts"));
  }
}

function parseHash() {
  const hash = window.location.hash.replace(/^#\/?/, "");
  const parts = hash.split("/").filter(Boolean);
  return { route: parts[0] || "dashboard", param: parts[1] || null };
}

async function router() {
  const { route, param } = parseHash();

  if (route === "dashboard") {
    showView("dashboard");
    await loadDashboard();
  } else if (route === "alerts") {
    showView("alerts");
    await loadAlerts();
  } else if (route === "alert" && param) {
    showView("alert-detail");
    currentAlertId = param;
    await loadAlertDetail(param);
  } else if (route === "report") {
    showView("report");
    if (param) {
      document.getElementById("reportIdInput").value = param;
      await loadReport(param);
    }
  } else {
    window.location.hash = "#/dashboard";
  }
}

window.addEventListener("hashchange", router);

// =========================================================================
// DASHBOARD VIEW
// FIELD MAP (GET /stats):
//   total_logs | totalLogs
//   total_alerts | totalAlerts
//   high_critical_alerts | highCriticalAlerts  (or derived from severity breakdown)
//   threat_intel_count | threatIntelCount | threat_intel_matches
//   recent_events | recentEvents  -> array of { timestamp, source_ip, event, detail }
// =========================================================================
async function loadDashboard() {
  setStatus("Loading dashboard…");
  try {
    const stats = await apiGet("/stats");

    document.getElementById("statLogs").textContent = pick(stats, ["total_logs", "totalLogs"], "0");
    document.getElementById("statAlerts").textContent = pick(stats, ["total_alerts", "totalAlerts"], "0");
    document.getElementById("statHighCrit").textContent = pick(
      stats,
      ["high_critical_alerts", "highCriticalAlerts", "high_critical_count"],
      "0"
    );
    document.getElementById("statThreatIntel").textContent = pick(
      stats,
      ["threat_intel_count", "threatIntelCount", "threat_intel_matches"],
      "0"
    );

    const events = pick(stats, ["recent_events", "recentEvents"], []) || [];
    renderRecentEvents(Array.isArray(events) ? events : []);

    setStatus(`Dashboard updated ${new Date().toLocaleTimeString()}`);
  } catch (err) {
    setStatus(`Failed to load /stats — ${err.message}`, true);
  }
}

function renderRecentEvents(events) {
  const tbody = document.querySelector("#recentEventsTable tbody");
  const empty = document.getElementById("recentEventsEmpty");
  const meta = document.getElementById("recentEventsMeta");

  tbody.innerHTML = "";
  meta.textContent = `${events.length} shown`;

  if (!events.length) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  for (const ev of events) {
    const ts = pick(ev, ["timestamp", "time"]);
    const ip = pick(ev, ["source_ip", "sourceIp", "ip"]);
    const name = pick(ev, ["event", "event_type", "type"]);
    const detail = pick(ev, ["detail", "message", "description"]);

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${escapeHtml(formatTimestamp(ts))}</td>
      <td class="mono">${escapeHtml(ip)}</td>
      <td>${escapeHtml(name)}</td>
      <td>${escapeHtml(detail)}</td>
    `;
    tbody.appendChild(tr);
  }
}

// =========================================================================
// ALERTS VIEW
// FIELD MAP (GET /alerts) — array of:
//   id | alert_id
//   rule | rule_name
//   source_ip | sourceIp
//   severity
//   reason
//   status
//   timestamp
// =========================================================================
async function loadAlerts() {
  setStatus("Loading alerts…");
  try {
    const alerts = await apiGet("/alerts");
    renderAlerts(Array.isArray(alerts) ? alerts : alerts.alerts || []);
    setStatus(`Alerts updated ${new Date().toLocaleTimeString()}`);
  } catch (err) {
    setStatus(`Failed to load /alerts — ${err.message}`, true);
  }
}

function renderAlerts(alerts) {
  const tbody = document.querySelector("#alertsTable tbody");
  const empty = document.getElementById("alertsEmpty");
  const meta = document.getElementById("alertsMeta");

  tbody.innerHTML = "";
  meta.textContent = `${alerts.length} total`;

  if (!alerts.length) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  for (const a of alerts) {
    const id = pick(a, ["id", "alert_id"]);
    const rule = pick(a, ["rule", "rule_name"]);
    const ip = pick(a, ["source_ip", "sourceIp"]);
    const severity = pick(a, ["severity"]);
    const reason = pick(a, ["reason"]);
    const status = pick(a, ["status"]);
    const ts = pick(a, ["timestamp", "time"]);

    const tr = document.createElement("tr");
    const sevLower = String(severity).toLowerCase();
    if (sevLower === "high") tr.classList.add("row-high");
    if (sevLower === "critical") tr.classList.add("row-critical");

    tr.innerHTML = `
      <td>${severityBadge(severity)}</td>
      <td class="mono">${escapeHtml(rule)}</td>
      <td class="mono">${escapeHtml(ip)}</td>
      <td>${escapeHtml(reason)}</td>
      <td>${statusBadge(status)}</td>
      <td class="mono">${escapeHtml(formatTimestamp(ts))}</td>
    `;
    tr.addEventListener("click", () => {
      window.location.hash = `#/alert/${encodeURIComponent(id)}`;
    });
    tbody.appendChild(tr);
  }
}

document.getElementById("backToAlerts").addEventListener("click", () => {
  window.location.hash = "#/alerts";
});

// =========================================================================
// ALERT DETAIL VIEW
// FIELD MAP (GET /alerts/{id}):
//   id | alert_id
//   rule | rule_name
//   source_ip | sourceIp
//   severity, reason, status
//   timestamp
//   evidence           -> string or object (rendered pretty-printed)
//   response           -> string describing action taken
//   report_id | reportId  (optional link-through to the report view)
// =========================================================================
let currentAlertReportId = null;

async function loadAlertDetail(id) {
  setStatus(`Loading alert ${id}…`);
  document.getElementById("detailAlertId").textContent = `#${id}`;
  try {
    const alert = await apiGet(`/alerts/${encodeURIComponent(id)}`);

    const rows = [
      ["Rule", pick(alert, ["rule", "rule_name"])],
      ["Severity", severityBadge(pick(alert, ["severity"]))],
      ["Status", statusBadge(pick(alert, ["status"]))],
      ["Source IP", pick(alert, ["source_ip", "sourceIp"])],
      ["Timestamp", formatTimestamp(pick(alert, ["timestamp", "time"]))],
      ["Reason", pick(alert, ["reason"])],
    ];

    const summaryEl = document.getElementById("detailSummary");
    summaryEl.innerHTML = rows
      .map(
        ([label, value]) => `
      <div class="kv-row">
        <dt>${escapeHtml(label)}</dt>
        <dd>${label === "Severity" || label === "Status" ? value : escapeHtml(String(value))}</dd>
      </div>`
      )
      .join("");

    const response = pick(alert, ["response", "action_taken"], "No response recorded yet.");
    document.getElementById("detailResponse").textContent = response;

    const evidenceRaw = pick(alert, ["evidence"], null);
    const evidenceText =
      evidenceRaw && typeof evidenceRaw === "object"
        ? JSON.stringify(evidenceRaw, null, 2)
        : String(evidenceRaw ?? "No evidence attached.");
    document.getElementById("detailEvidence").textContent = evidenceText;

    currentAlertReportId = pick(alert, ["report_id", "reportId"], null);
    setStatus(`Alert ${id} loaded ${new Date().toLocaleTimeString()}`);
  } catch (err) {
    setStatus(`Failed to load /alerts/${id} — ${err.message}`, true);
  }
}

document.getElementById("openReportBtn").addEventListener("click", () => {
  const target = currentAlertReportId || currentAlertId;
  window.location.hash = `#/report/${encodeURIComponent(target)}`;
});

// =========================================================================
// REPORT VIEW
// FIELD MAP (GET /reports/{id}):
//   id | report_id
//   title
//   generated_at | timestamp
//   summary        -> plain text incident narrative
//   sections       -> optional array of { heading, body } for a structured report
// =========================================================================
document.getElementById("loadReportBtn").addEventListener("click", () => {
  const id = document.getElementById("reportIdInput").value.trim();
  if (!id) return;
  window.location.hash = `#/report/${encodeURIComponent(id)}`;
});
document.getElementById("reportIdInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") document.getElementById("loadReportBtn").click();
});

async function loadReport(id) {
  setStatus(`Loading report ${id}…`);
  const panel = document.getElementById("reportPanel");
  const empty = document.getElementById("reportEmpty");
  try {
    const report = await apiGet(`/reports/${encodeURIComponent(id)}`);

    document.getElementById("reportTitle").textContent = pick(report, ["title"], `Report ${id}`);
    document.getElementById("reportMeta").textContent = formatTimestamp(pick(report, ["generated_at", "timestamp"]));

    const body = document.getElementById("reportBody");
    const sections = pick(report, ["sections"], null);

    if (Array.isArray(sections) && sections.length) {
      body.innerHTML = sections
        .map(
          (s) => `<h3>${escapeHtml(pick(s, ["heading", "title"]))}</h3><div>${escapeHtml(pick(s, ["body", "text"]))}</div>`
        )
        .join("");
    } else {
      body.textContent = pick(report, ["summary", "body"], "No summary text was returned for this report.");
    }

    panel.hidden = false;
    empty.hidden = true;
    setStatus(`Report ${id} loaded ${new Date().toLocaleTimeString()}`);
  } catch (err) {
    panel.hidden = true;
    empty.hidden = false;
    empty.textContent = `Could not load report "${id}" — ${err.message}`;
    setStatus(`Failed to load /reports/${id} — ${err.message}`, true);
  }
}

// =========================================================================
// HEALTH CHECK
// =========================================================================
async function checkHealth() {
  const pill = document.getElementById("healthPill");
  const label = pill.querySelector(".health-label");
  try {
    await apiGet("/health");
    pill.dataset.state = "ok";
    label.textContent = "backend link OK";
  } catch (err) {
    pill.dataset.state = "down";
    label.textContent = "backend unreachable";
  }
}

// =========================================================================
// REFRESH / POLLING
// =========================================================================
async function refreshCurrentView() {
  const btn = document.getElementById("refreshBtn");
  btn.classList.add("spinning");
  await Promise.all([checkHealth(), router()]);
  setTimeout(() => btn.classList.remove("spinning"), 400);
}

document.getElementById("refreshBtn").addEventListener("click", refreshCurrentView);

let pollHandle = null;
function startPolling() {
  stopPolling();
  const ms = Number(document.getElementById("pollInterval").value) || CONFIG.DEFAULT_POLL_MS;
  pollHandle = setInterval(() => {
    checkHealth();
    // Only auto-refresh data views that make sense to poll continuously.
    const { route } = parseHash();
    if (route === "dashboard" || route === "alerts") router();
  }, ms);
}
function stopPolling() {
  if (pollHandle) clearInterval(pollHandle);
  pollHandle = null;
}

document.getElementById("pollToggle").addEventListener("change", (e) => {
  e.target.checked ? startPolling() : stopPolling();
});
document.getElementById("pollInterval").addEventListener("change", () => {
  if (document.getElementById("pollToggle").checked) startPolling();
});

// =========================================================================
// INIT
// =========================================================================
(async function init() {
  if (!window.location.hash) window.location.hash = "#/dashboard";
  await checkHealth();
  await router();
  startPolling();
})();
