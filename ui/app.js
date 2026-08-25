const state = {
  token: sessionStorage.getItem("mizan_token") || "",
  origin: sessionStorage.getItem("mizan_origin") || "",
  decisionCursor: null,
  auditCursor: null,
  activeView: "dashboard",
};
const $ = (id) => document.getElementById(id);
const text = (value) => value ?? "—";
function safe(value) {
  const span = document.createElement("span");
  span.textContent = text(value);
  return span.innerHTML;
}
async function api(path, options = {}) {
  if (!state.token) throw new Error("Connect with an operator token first.");
  const response = await fetch(state.origin + path, {
    ...options,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${state.token}`, ...options.headers },
  });
  const body = await response.json().catch(() => ({ detail: "Invalid API response" }));
  if (!response.ok) throw new Error(body.detail || body.title || `Request failed (${response.status})`);
  return body;
}
function setStatus(message, kind = "ok") {
  $("status").textContent = message;
  $("status").className = `status ${kind}`;
}
function query(form) {
  const params = new URLSearchParams();
  for (const [key, value] of new FormData(form)) if (value !== "") params.set(key, value);
  return params;
}
function badge(value) { return `<span class="badge ${safe(value)}">${safe(value)}</span>`; }
function showDetail(title, data) {
  $("detail").innerHTML = `<p class="eyebrow">Evidence detail</p><h2>${safe(title)}</h2><pre>${safe(JSON.stringify(data, null, 2))}</pre>`;
  $("detailDialog").showModal();
}
async function loadDashboard() {
  try {
    const summary = await api("/v1/dashboard/summary");
    const labels = {
      agents: "Agents", tools: "Tools", actions_today: "Actions today",
      denied_actions: "Denied actions", approval_requests: "Approval requests",
      security_alerts: "Security alerts", high_risk_actions: "High-risk actions",
    };
    $("metrics").replaceChildren();
    for (const [key, label] of Object.entries(labels)) {
      const card = document.createElement("article");
      card.className = `metric ${key === "security_alerts" || key === "denied_actions" ? "attention" : ""}`;
      card.innerHTML = `<span>${safe(label)}</span><strong>${safe(Number(summary[key]).toLocaleString())}</strong>`;
      $("metrics").append(card);
    }
    setStatus("Live tenant summary loaded.");
  } catch (error) { setStatus(error.message, "error"); }
}
async function loadAgents() {
  try {
    const page = await api("/v1/agents?limit=200");
    $("agents").replaceChildren();
    for (const agent of page.items) {
      const card = document.createElement("button");
      card.className = "agent-card";
      card.innerHTML = `<span>${badge(agent.risk_tier)} ${badge(agent.lifecycle_state)}</span><strong>${safe(agent.name)}</strong><small>${safe(agent.agent_id)}</small><dl><div><dt>Owner</dt><dd>${safe(agent.owner)}</dd></div><div><dt>Model</dt><dd>${safe(agent.model?.model_id)}</dd></div><div><dt>Tools</dt><dd>${safe(agent.tools?.length || 0)}</dd></div><div><dt>Policies</dt><dd>${safe(agent.policies?.length || 0)}</dd></div></dl>`;
      card.onclick = () => showDetail(`Agent ${agent.agent_id}`, agent);
      $("agents").append(card);
    }
    setStatus(`${page.items.length} governed agents loaded.`);
  } catch (error) { setStatus(error.message, "error"); }
}
async function loadDecisions(append = false) {
  try {
    const params = query($("filters")); params.set("limit", "50");
    if (append && state.decisionCursor) params.set("cursor", state.decisionCursor);
    const page = await api(`/v1/decisions?${params}`);
    if (!append) $("decisions").replaceChildren();
    for (const item of page.items) {
      const row = document.createElement("tr");
      row.innerHTML = `<td>${safe(item.timestamp || item.created_at)}</td><td><strong>${safe(item.agent?.id)}</strong><br>${safe(item.tool?.id)}</td><td>${badge(item.risk?.level)}</td><td>${badge(item.decision)}</td><td class="hash">${safe(item.trace_id)}</td>`;
      row.onclick = () => openDecision(item.decision_id); $("decisions").append(row);
    }
    state.decisionCursor = page.next_cursor;
    $("moreDecisions").classList.toggle("hidden", !page.next_cursor);
    $("decisionCount").textContent = page.items.length;
    setStatus(`${page.items.length} decisions loaded from tenant-scoped evidence.`);
  } catch (error) { setStatus(error.message, "error"); }
}
async function openDecision(id) {
  try { showDetail(`Decision ${id}`, await api(`/v1/decisions/${encodeURIComponent(id)}`)); }
  catch (error) { setStatus(error.message, "error"); }
}
async function loadAudit(append = false) {
  try {
    const params = new URLSearchParams({ limit: "50" });
    if (append && state.auditCursor) params.set("cursor", state.auditCursor);
    const page = await api(`/v1/audit?${params}`);
    if (!append) $("audits").replaceChildren();
    for (const item of page.items) {
      const row = document.createElement("tr");
      row.innerHTML = `<td>${safe(item.timestamp)}</td><td>${safe(item.event_type)}</td><td>${safe(item.actor?.id || item.actor?.subject_id)}</td><td>${safe(item.stream_id)} / ${safe(item.sequence_number)}</td><td class="hash">${safe(item.record_hash?.slice(0, 14))}…</td>`;
      row.onclick = () => showDetail(`Audit ${item.audit_id}`, item); $("audits").append(row);
    }
    state.auditCursor = page.next_cursor;
    $("moreAudit").classList.toggle("hidden", !page.next_cursor);
    setStatus(`${page.items.length} audit events loaded.`);
  } catch (error) { setStatus(error.message, "error"); }
}
const loaders = { dashboard: loadDashboard, agents: loadAgents, decisions: loadDecisions, audit: loadAudit };
document.querySelectorAll(".nav").forEach((button) => button.onclick = () => {
  state.activeView = button.dataset.view;
  document.querySelectorAll(".nav").forEach((item) => item.classList.toggle("active", item === button));
  document.querySelectorAll(".view").forEach((item) => item.classList.add("hidden"));
  $(`${state.activeView}View`).classList.remove("hidden");
  if (loaders[state.activeView]) loaders[state.activeView]();
});
$("filters").onsubmit = (event) => { event.preventDefault(); state.decisionCursor = null; loadDecisions(); };
$("moreDecisions").onclick = () => loadDecisions(true);
$("moreAudit").onclick = () => loadAudit(true);
$("refreshButton").onclick = () => { state.decisionCursor = null; (loaders[state.activeView] || loadDashboard)(); };
$("connectionButton").onclick = () => { $("apiOrigin").value = state.origin; $("apiToken").value = state.token; $("connectionDialog").showModal(); };
$("saveConnection").onclick = () => {
  state.origin = $("apiOrigin").value.replace(/\/$/, ""); state.token = $("apiToken").value.trim();
  sessionStorage.setItem("mizan_origin", state.origin); sessionStorage.setItem("mizan_token", state.token);
  setTimeout(() => (loaders[state.activeView] || loadDashboard)(), 0);
};
$("verifyForm").onsubmit = async (event) => {
  event.preventDefault(); const values = Object.fromEntries(new FormData(event.target));
  const body = { stream_id: values.stream_id, from_sequence: values.from_sequence === "" ? null : Number(values.from_sequence), to_sequence: values.to_sequence === "" ? null : Number(values.to_sequence), verify_anchors: values.verify_anchors === "on" };
  try { const result = await api("/v1/audit/verify", { method: "POST", body: JSON.stringify(body) }); $("verifyResult").textContent = `✓ Chain intact\n${result.checked_records} records independently verified.`; }
  catch (error) { $("verifyResult").textContent = `Verification failed\n${error.message}`; }
};
document.querySelectorAll(".dialog-close").forEach((button) => button.onclick = () => button.closest("dialog").close());
if (state.token) loadDashboard();
