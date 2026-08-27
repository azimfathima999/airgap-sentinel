const API_BASE = "http://127.0.0.1:8000";

const $ = (id) => document.getElementById(id);

function showError(message) {
  const el = $("error");
  el.textContent = message;
  el.classList.remove("hidden");
}

function clearError() {
  $("error").textContent = "";
  $("error").classList.add("hidden");
}

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  if (!response.ok) {
    let detail = `${path} returned HTTP ${response.status}`;

    try {
      const errorData = await response.json();
      if (errorData && errorData.detail) {
        detail += `: ${errorData.detail}`;
      }
    } catch {
      // Keep the HTTP status message if the error response is not JSON.
    }

    throw new Error(detail);
  }

  return response.json();
}

function severityClass(severity) {
  return String(severity || "").toLowerCase();
}

function formatTime(value) {
  if (!value) return "—";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);

  return date.toLocaleString();
}

function getField(obj, ...names) {
  for (const name of names) {
    if (obj && obj[name] !== undefined && obj[name] !== null) {
      return obj[name];
    }
  }
  return "";
}

function showView(viewName) {
  document.querySelectorAll(".view").forEach((view) => {
    view.classList.add("hidden");
  });

  const view = $(viewName);
  if (view) view.classList.remove("hidden");

  document.querySelectorAll("nav button[data-view]").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === viewName);
  });

  const titles = {
    dashboard: "Dashboard",
    alerts: "Alerts",
    detail: "Alert Detail",
    report: "Report"
  };

  $("title").textContent = titles[viewName] || "Dashboard";
}

async function loadHealth() {
  try {
    const data = await api("/health");

    const status = getField(data, "status", "health");

    $("health").textContent =
      status ? `Health: ${status}` : "Backend healthy";
  } catch (error) {
    $("health").textContent = "Backend unavailable";
  }
}

async function loadStats() {
  const data = await api("/stats");

  $("logsCount").textContent =
    getField(data, "total_logs", "logs_count", "logs", "log_count") || 0;

  $("alertsCount").textContent =
    getField(data, "total_alerts", "alerts_count", "alerts", "alert_count") || 0;

  const high =
    getField(data, "high_alerts", "high") || 0;

  const critical =
    getField(data, "critical_alerts", "critical") || 0;

  const highCritical =
    getField(
      data,
      "high_critical_alerts",
      "high_critical",
      "high_critical_count"
    );

  $("hcCount").textContent =
    highCritical !== "" ? highCritical : Number(high) + Number(critical);

  $("breakdown").textContent =
    `${high} HIGH / ${critical} CRITICAL`;

  $("tiCount").textContent =
    getField(
      data,
      "threat_intel_count",
      "threat_intelligence_count",
      "ti_count",
      "indicators"
    ) || 0;

  const rules = data.detection_rules || {};

  $("rules").innerHTML = Object.entries(rules)
    .map(([name, description]) => `
      <div class="rule">
        <span class="rule-id">${name}</span>
        <span>${description}</span>
      </div>
    `)
    .join("");
}

async function loadLogs() {
  const data = await api("/logs");

  const logs = Array.isArray(data)
    ? data
    : getField(data, "logs", "items", "results") || [];

  const tbody = $("recent");
  tbody.innerHTML = "";

  logs.slice(-10).reverse().forEach((log) => {
    const row = document.createElement("tr");

    const time = getField(log, "timestamp", "time", "created_at");
    const event = getField(log, "event", "message", "action", "event_type");
    const user = getField(log, "user", "username", "user_name");
    const ip = getField(log, "source_ip", "src_ip", "ip");
    const severity = getField(log, "severity", "level");

    row.innerHTML = `
      <td>${formatTime(time)}</td>
      <td>${event || "—"}</td>
      <td>${user || "—"}</td>
      <td>${ip || "—"}</td>
      <td>
        <span class="badge ${severityClass(severity)}">
          ${severity || "—"}
        </span>
      </td>
    `;

    tbody.appendChild(row);
  });
}

let allAlerts = [];

async function loadAlerts() {
  const data = await api("/alerts");

  allAlerts = Array.isArray(data)
    ? data
    : getField(data, "alerts", "items", "results") || [];

  renderAlerts();
}

function renderAlerts() {
  const severityFilter = $("sev").value;
  const statusFilter = $("status").value;

  const filtered = allAlerts.filter((alert) => {
    const severity = String(
      getField(alert, "severity", "level")
    ).toUpperCase();

    const status = String(
      getField(alert, "status", "state")
    ).toUpperCase();

    return (
      (!severityFilter || severity === severityFilter) &&
      (!statusFilter || status === statusFilter)
    );
  });

  $("alertTotal").textContent = `${filtered.length} alert(s)`;

  const tbody = $("alertRows");
  tbody.innerHTML = "";

  filtered.forEach((alert) => {
    const row = document.createElement("tr");
    row.className = "clickable";

    const id = getField(alert, "id", "alert_id");
    const severity = getField(alert, "severity", "level");
    const title = getField(alert, "title", "name", "alert", "message");
    const rule = getField(alert, "rule", "rule_name", "detection_rule");
    const ip = getField(alert, "source_ip", "src_ip", "ip");
    const reason = getField(alert, "reason", "description", "detection_reason");
    const status = getField(alert, "status", "state");

    row.innerHTML = `
      <td>
        <span class="badge ${severityClass(severity)}">
          ${severity || "—"}
        </span>
      </td>
      <td>${title || `Alert ${id || ""}`}</td>
      <td>${rule || "—"}</td>
      <td>${ip || "—"}</td>
      <td>${reason || "—"}</td>
      <td>${status || "—"}</td>
    `;

    row.addEventListener("click", () => {
      if (id !== "") loadAlertDetail(id);
    });

    tbody.appendChild(row);
  });
}

async function loadAlertDetail(id) {
  clearError();
  showView("detail");

  $("detail").dataset.alertId = String(id);

  $("dTitle").textContent = "Loading…";
  $("dDesc").textContent = "";
  $("dIp").textContent = "—";
  $("dHost").textContent = "—";
  $("dTime").textContent = "—";
  $("dStatus").textContent = "—";
  $("dRule").textContent = "—";
  $("evidence").textContent = "Loading…";
  $("response").innerHTML = '<span class="muted">Loading…</span>';

  try {
    const alert = await api(`/alerts/${encodeURIComponent(id)}`);

    const severity = getField(alert, "severity", "level");
const status = String(
  getField(alert, "status", "state") || "OPEN"
).toUpperCase();

const acknowledgeButton = $("acknowledgeAlert");
const resolveButton = $("resolveAlert");

if (acknowledgeButton) {
  acknowledgeButton.hidden = status !== "OPEN";
}

if (resolveButton) {
  resolveButton.hidden = !["OPEN", "ACKNOWLEDGED"].includes(status);
}
    $("dTitle").textContent =
      getField(alert, "title", "name", "alert", "message") ||
      `Alert ${id}`;

    $("dSev").textContent = severity || "—";
    $("dSev").className = `badge ${severityClass(severity)}`;

    $("dDesc").textContent =
      getField(alert, "description", "reason", "detection_reason") || "";

    $("dIp").textContent =
      getField(alert, "source_ip", "src_ip", "ip") || "—";

    $("dHost").textContent =
      getField(alert, "hostname", "host") || "—";

    $("dTime").textContent =
      formatTime(getField(alert, "timestamp", "time", "created_at"));

    $("dStatus").textContent = status;

    $("dRule").textContent =
      getField(
        alert,
        "rule_triggered",
        "rule",
        "rule_name",
        "detection_rule"
      ) || "—";

    const sourceLogId = getField(
      alert,
      "source_log_id",
      "log_id"
    );

    if (sourceLogId !== "" && sourceLogId != null) {
      try {
        const sourceLog = await api(
          `/logs/${encodeURIComponent(sourceLogId)}`
        );

        const rawLog = getField(
          sourceLog,
          "raw_log",
          "message"
        );

        $("evidence").textContent =
          rawLog ||
          JSON.stringify(sourceLog, null, 2) ||
          "No evidence supplied.";
      } catch (error) {
        $("evidence").textContent =
          `Could not load source log ${sourceLogId}: ${error.message}`;
      }
    } else {
      $("evidence").textContent = "No source log linked to this alert.";
    }

      let responseRecord = null;

      try {
        const responseData = await api("/responses");
        const responses = Array.isArray(responseData)
          ? responseData
          : getField(responseData, "responses") || [];

        responseRecord = responses.find(
          (item) => String(getField(item, "alert_id")) === String(id)
        );
      } catch (error) {
        console.warn("Could not load response records:", error);
      }

      if (responseRecord) {
        const responseType =
          getField(responseRecord, "response_type") || "—";

        const responseStatus =
          getField(responseRecord, "status") || "—";

        const description =
          getField(responseRecord, "description") || "—";

        const actionResult =
          getField(responseRecord, "action_result") || "—";

        const initiatedBy =
          getField(responseRecord, "initiated_by") || "—";

        const notes =
          getField(responseRecord, "notes") || "—";

        $("response").innerHTML = `
          <div class="response-item">
            <div class="response-header">
              <strong>${responseType}</strong>
              <span class="badge">${responseStatus}</span>
            </div>
            <p>${description}</p>
            <div class="response-field">
              <span>Action result</span>
              <code>${actionResult}</code>
            </div>
            <div class="response-field">
              <span>Initiated by</span>
              <strong>${initiatedBy}</strong>
            </div>
            <div class="response-field">
              <span>Notes</span>
              <p>${notes}</p>
            </div>
          </div>
        `;
      } else {
        $("response").innerHTML =
          '<span class="muted">No recorded response.</span>';
      }

  } catch (error) {
    showError(`Could not load alert ${id}: ${error.message}`);
  }
}


async function updateAlertStatus(id, status) {
  clearError();

  const acknowledgeButton = $("acknowledgeAlert");
  const resolveButton = $("resolveAlert");

  if (acknowledgeButton) acknowledgeButton.disabled = true;
  if (resolveButton) resolveButton.disabled = true;

  try {
    const data = await api(
      `/alerts/${encodeURIComponent(id)}`,
      {
        method: "PATCH",
        body: JSON.stringify({ status })
      }
    );

    const updatedAlert = getField(data, "alert") || data;

    $("dStatus").textContent =
      getField(updatedAlert, "status", "state") || status;

    if (acknowledgeButton) {
      acknowledgeButton.textContent =
        status === "ACKNOWLEDGED" ? "Acknowledged" : "Acknowledge";
    }

    if (resolveButton) {
      resolveButton.textContent =
        status === "RESOLVED" ? "Resolved" : "Resolve";
    }

    await loadAlertDetail(id);
    await loadAlerts();

  } catch (error) {
    showError(`Could not update alert ${id}: ${error.message}`);

    if (acknowledgeButton) acknowledgeButton.disabled = false;
    if (resolveButton) resolveButton.disabled = false;
  }
}

async function loadReport() {
  const reportBody = $("reportBody");
  const meta = $("meta");

  reportBody.innerHTML = "<p>Generating latest security report…</p>";
  meta.innerHTML = "";
  clearError();

  try {
    const response = await api("/reports/generate", {
      method: "POST"
    });

    const report = getField(response, "report") || response;

    const title =
      getField(report, "title", "name") ||
      "Daily Security Summary";

    const generated =
      getField(
        report,
        "generated_at",
        "timestamp",
        "created_at",
        "updated_at"
      );

    let content = getField(report, "content");

    if (typeof content === "string") {
      try {
        content = JSON.parse(content);
      } catch {
        // Keep the original string if it is not JSON.
      }
    }

    const summary =
      content && typeof content === "object"
        ? content.summary || {}
        : {};

    const rules =
      content && typeof content === "object"
        ? content.detection_rules || {}
        : {};

    meta.innerHTML = `
      <span>
        Generated:
        ${generated ? formatTime(generated) : "Just now"}
      </span>
      <span>
        Report ID:
        ${getField(report, "id") || "—"}
      </span>
    `;

    reportBody.innerHTML = `
      <h3>${title}</h3>

      <p>
        ${getField(report, "description") ||
          "Generated security summary from the local detection engine."}
      </p>

      <div class="report-grid">
        <div class="response-field">
          <span>Total logs</span>
          <strong>${summary.total_logs ?? "—"}</strong>
        </div>

        <div class="response-field">
          <span>Total alerts</span>
          <strong>${summary.total_alerts ?? "—"}</strong>
        </div>

        <div class="response-field">
          <span>Critical alerts</span>
          <strong>${summary.critical_alerts ?? "—"}</strong>
        </div>

        <div class="response-field">
          <span>High alerts</span>
          <strong>${summary.high_alerts ?? "—"}</strong>
        </div>

        <div class="response-field">
          <span>Medium alerts</span>
          <strong>${summary.medium_alerts ?? "—"}</strong>
        </div>

        <div class="response-field">
          <span>Open alerts</span>
          <strong>${summary.open_alerts ?? "—"}</strong>
        </div>

        <div class="response-field">
          <span>Failed logins</span>
          <strong>${summary.failed_logins ?? "—"}</strong>
        </div>

        <div class="response-field">
          <span>Successful logins</span>
          <strong>${summary.successful_logins ?? "—"}</strong>
        </div>

        <div class="response-field">
          <span>Threat intelligence</span>
          <strong>${summary.threat_intel_count ?? "—"}</strong>
        </div>
      </div>

      <h4>Detection Rules</h4>

      <div class="rules-list">
        ${Object.entries(rules)
          .map(
            ([rule, description]) => `
              <div class="response-field">
                <span>${rule}</span>
                <code>${description}</code>
              </div>
            `
          )
          .join("")}
      </div>
    `;
  } catch (error) {
    reportBody.innerHTML =
      `<p>Could not generate report: ${error.message}</p>`;
    showError(`Could not generate report: ${error.message}`);
  }
}

async function refresh() {
  clearError();

  $("updated").textContent = "Refreshing…";

  try {
    await Promise.all([
      loadHealth(),
      loadStats(),
      loadLogs(),
      loadAlerts()
    ]);

    $("updated").textContent =
      `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    showError(`Refresh failed: ${error.message}`);
    $("updated").textContent = "Update failed";
  }
}

document.querySelectorAll("[data-view]").forEach((button) => {
  button.addEventListener("click", () => {
    const view = button.dataset.view;

    if (view === "alerts") {
      showView("alerts");
      loadAlerts().catch((error) =>
        showError(`Could not load alerts: ${error.message}`)
      );
    } else if (view === "report") {
      showView("report");
      loadReport();
    } else {
      showView(view);
    }
  });
});

$("refresh").addEventListener("click", refresh);

$("sev").addEventListener("change", renderAlerts);
$("status").addEventListener("change", renderAlerts);

$("back").addEventListener("click", () => {
  showView("alerts");
});

/*
 * Event delegation is intentional here.
 * The detail view can be refreshed/re-rendered, so we listen on document
 * rather than relying on a button element existing at startup.
 */
document.addEventListener("click", (event) => {
  const button = event.target.closest("#acknowledgeAlert, #resolveAlert");

  if (!button) return;

  const id = $("detail").dataset.alertId;

  if (!id) {
    showError("No alert selected.");
    return;
  }

  const newStatus =
    button.id === "acknowledgeAlert"
      ? "ACKNOWLEDGED"
      : "RESOLVED";

  updateAlertStatus(id, newStatus);
});

$("generate").addEventListener("click", loadReport);

showView("dashboard");
refresh();

setInterval(refresh, 10000);
