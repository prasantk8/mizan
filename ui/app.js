const state = {
  token: sessionStorage.getItem("mizan_token") || "",
  origin: sessionStorage.getItem("mizan_origin") || "",
  decisionCursor: null,
  auditCursor: null,
  approvalCursor: null,
  approval: null,
  decision: null,
  requesterId: null,
  draftPolicies: [],
  lastReplay: null,
  activeView: "dashboard",
};

const $ = (id) => document.getElementById(id);
const valueOrDash = (value) => value ?? "—";

function element(tag, textValue, className) {
  const node = document.createElement(tag);
  if (textValue !== undefined) node.textContent = valueOrDash(textValue);
  if (className) node.className = className;
  return node;
}

function appendFact(list, label, value) {
  const group = element("div");
  group.append(element("dt", label), element("dd", value));
  list.append(group);
}

function badge(value) {
  return element("span", value, `badge ${String(value || "unknown").toUpperCase()}`);
}

function tokenClaims() {
  try {
    const payload = state.token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(payload));
  } catch (_error) {
    return {};
  }
}

async function api(path, options = {}) {
  if (!state.token) throw new Error("Connect with an operator token first.");
  const response = await fetch(state.origin + path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${state.token}`,
      ...options.headers,
    },
  });
  const body = await response.json().catch(() => ({ detail: "Invalid API response" }));
  if (!response.ok) {
    const error = new Error(body.detail || body.title || `Request failed (${response.status})`);
    error.status = response.status;
    error.problem = body;
    throw error;
  }
  return body;
}

function request(method, contractPath, path = contractPath, body = null) {
  const options = { method };
  if (body !== null) options.body = JSON.stringify(body);
  return api(path, options);
}

function setStatus(message, kind = "ok") {
  $("status").textContent = message;
  $("status").className = `status ${kind}`;
}

function query(form) {
  const params = new URLSearchParams();
  for (const [key, value] of new FormData(form)) {
    if (value !== "") params.set(key, value);
  }
  return params;
}

function showDetail(title, data) {
  const target = $("detail");
  target.replaceChildren(
    element("p", "Evidence detail", "eyebrow"),
    element("h2", title),
    element("pre", JSON.stringify(data, null, 2)),
  );
  $("detailDialog").showModal();
}

function countdown(expiresAt) {
  if (!expiresAt) return "No deadline";
  const remaining = Date.parse(expiresAt) - Date.now();
  if (remaining <= 0) return "Expired";
  const totalMinutes = Math.floor(remaining / 60000);
  const days = Math.floor(totalMinutes / 1440);
  const hours = Math.floor((totalMinutes % 1440) / 60);
  const minutes = totalMinutes % 60;
  return `${days ? `${days}d ` : ""}${hours}h ${minutes}m`;
}

async function loadDashboard() {
  try {
    const summary = await request("GET", "/v1/dashboard/summary");
    const labels = {
      agents: "Agents",
      tools: "Tools",
      actions_today: "Actions today",
      denied_actions: "Denied actions",
      approval_requests: "Approval requests",
      security_alerts: "Security alerts",
      high_risk_actions: "High-risk actions",
    };
    $("metrics").replaceChildren();
    for (const [key, label] of Object.entries(labels)) {
      const card = element("article", undefined, `metric ${key === "security_alerts" || key === "denied_actions" ? "attention" : ""}`);
      card.append(element("span", label), element("strong", Number(summary[key]).toLocaleString()));
      $("metrics").append(card);
    }
    setStatus("Live tenant summary loaded.");
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function loadAgents() {
  try {
    const page = await request("GET", "/v1/agents", "/v1/agents?limit=200");
    $("agents").replaceChildren();
    for (const agent of page.items) {
      const card = element("button", undefined, "agent-card");
      const badges = element("span");
      badges.append(badge(agent.risk_tier), " ", badge(agent.lifecycle_state));
      const facts = element("dl");
      appendFact(facts, "Owner", agent.owner);
      appendFact(facts, "Model", agent.model?.model_id);
      appendFact(facts, "Tools", agent.tools?.length || 0);
      appendFact(facts, "Policies", agent.policies?.length || 0);
      card.append(badges, element("strong", agent.name), element("small", agent.agent_id), facts);
      card.onclick = () => showDetail(`Agent ${agent.agent_id}`, agent);
      $("agents").append(card);
    }
    setStatus(`${page.items.length} governed agents loaded.`);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function loadDecisions(append = false) {
  try {
    const params = query($("filters"));
    params.set("limit", "50");
    if (append && state.decisionCursor) params.set("cursor", state.decisionCursor);
    const page = await request("GET", "/v1/decisions", `/v1/decisions?${params}`);
    if (!append) $("decisions").replaceChildren();
    for (const item of page.items) {
      const row = element("tr");
      const identity = element("td");
      identity.append(element("strong", item.agent?.id), element("br"), document.createTextNode(valueOrDash(item.tool?.id)));
      const risk = element("td");
      risk.append(badge(item.risk?.level));
      const decision = element("td");
      decision.append(badge(item.decision));
      row.append(element("td", item.timestamp || item.created_at), identity, risk, decision, element("td", item.trace_id, "hash"));
      row.onclick = () => openDecision(item.decision_id);
      $("decisions").append(row);
    }
    state.decisionCursor = page.next_cursor;
    $("moreDecisions").classList.toggle("hidden", !page.next_cursor);
    $("decisionCount").textContent = page.items.length;
    setStatus(`${page.items.length} decisions loaded from tenant-scoped evidence.`);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function openDecision(id) {
  try {
    const detail = await request("GET", "/v1/decisions/{decision_id}", `/v1/decisions/${encodeURIComponent(id)}`);
    showDetail(`Decision ${id}`, detail);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function loadAudit(append = false) {
  try {
    const params = new URLSearchParams({ limit: "50" });
    if (append && state.auditCursor) params.set("cursor", state.auditCursor);
    const page = await request("GET", "/v1/audit", `/v1/audit?${params}`);
    if (!append) $("audits").replaceChildren();
    for (const item of page.items) {
      const row = element("tr");
      row.append(
        element("td", item.timestamp),
        element("td", item.event_type),
        element("td", item.actor?.id || item.actor?.subject_id),
        element("td", `${valueOrDash(item.stream_id)} / ${valueOrDash(item.sequence_number)}`),
        element("td", `${valueOrDash(item.record_hash?.slice(0, 14))}…`, "hash"),
      );
      row.onclick = () => showDetail(`Audit ${item.audit_id}`, item);
      $("audits").append(row);
    }
    state.auditCursor = page.next_cursor;
    $("moreAudit").classList.toggle("hidden", !page.next_cursor);
    setStatus(`${page.items.length} audit events loaded.`);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

function resetReplay(message = "Run a replay to compare a draft with immutable decisions.") {
  state.lastReplay = null;
  $("policyFlips").replaceChildren();
  $("replaySummary").textContent = message;
  $("testedEvidence").textContent = "No replay evidence in this session.";
  $("markTested").disabled = true;
}

async function loadPolicyStudio() {
  try {
    const page = await request("GET", "/v1/policies", "/v1/policies?limit=200");
    state.draftPolicies = page.items.filter((policy) => policy.status === "DRAFT");
    const select = $("policyReplay").elements.policy;
    const selected = select.value;
    select.replaceChildren(element("option", "Select a DRAFT policy"));
    select.firstElementChild.value = "";
    for (const policy of state.draftPolicies) {
      const option = element("option", `${policy.name} · ${policy.policy_id} v${policy.version}`);
      option.value = `${policy.policy_id}:${policy.version}`;
      select.append(option);
    }
    if ([...select.options].some((option) => option.value === selected)) select.value = selected;
    setStatus(`${state.draftPolicies.length} draft policies available for replay.`);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function mapLimit(items, concurrency, callback) {
  const results = new Array(items.length);
  let nextIndex = 0;
  async function worker() {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await callback(items[index]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

function renderFlip(flip) {
  const wrapper = element("article", undefined, "flip-card");
  const heading = element("div", undefined, "flip-heading");
  heading.append(
    element("h3", `${flip.from} → ${flip.to}`),
    element("span", `Context ${flip.contextHash}`, "hash"),
  );
  wrapper.append(heading);
  renderDecisionCard(wrapper, flip.detail);
  $("policyFlips").append(wrapper);
}

async function replayPolicy() {
  const values = Object.fromEntries(new FormData($("policyReplay")));
  const policy = state.draftPolicies.find((candidate) => `${candidate.policy_id}:${candidate.version}` === values.policy);
  if (!policy) {
    resetReplay("Select a DRAFT policy before replaying decisions.");
    return;
  }
  resetReplay("Replay running…");
  try {
    const page = await request("GET", "/v1/decisions", `/v1/decisions?limit=${encodeURIComponent(values.limit)}`);
    const comparisons = await mapLimit(page.items, 6, async (decision) => {
      const stored = await request(
        "GET",
        "/v1/decisions/{decision_id}/context",
        `/v1/decisions/${encodeURIComponent(decision.decision_id)}/context`,
      );
      const simulationContext = JSON.parse(JSON.stringify(stored.context));
      simulationContext.tool.arguments = {};
      const simulation = await request(
        "POST",
        "/v1/policies/{policy_id}/simulate",
        `/v1/policies/${encodeURIComponent(policy.policy_id)}/simulate`,
        { version: policy.version, context: simulationContext },
      );
      if (simulation.decision === decision.decision) return null;
      const detail = await request(
        "GET",
        "/v1/decisions/{decision_id}",
        `/v1/decisions/${encodeURIComponent(decision.decision_id)}`,
      );
      return {
        from: decision.decision,
        to: simulation.decision,
        contextHash: stored.context_hash,
        detail,
      };
    });
    const flips = comparisons.filter(Boolean);
    const directions = {};
    for (const flip of flips) {
      const direction = `${flip.from}→${flip.to}`;
      directions[direction] = (directions[direction] || 0) + 1;
      renderFlip(flip);
    }
    const breakdown = Object.entries(directions).map(([direction, count]) => `${direction}: ${count}`).join(" · ");
    $("replaySummary").textContent = `${page.items.length} replayed · ${flips.length} flipped${breakdown ? ` · ${breakdown}` : ""}`;
    $("testedEvidence").textContent = `${page.items.length} contexts replayed, ${flips.length} outcome changes.`;
    state.lastReplay = {
      policyId: policy.policy_id,
      version: policy.version,
      replayed: page.items.length,
      flipped: flips.length,
    };
    $("markTested").disabled = false;
    if (!flips.length) $("policyFlips").append(element("p", "No recorded decision changes under this draft.", "hint"));
    setStatus(`Draft replay completed across ${page.items.length} immutable decisions.`);
  } catch (error) {
    resetReplay(`Replay failed: ${error.message}`);
    setStatus(error.message, "error");
  }
}

async function markPolicyTested() {
  const replay = state.lastReplay;
  if (!replay) return;
  try {
    await request(
      "POST",
      "/v1/policies/{policy_id}/transition",
      `/v1/policies/${encodeURIComponent(replay.policyId)}/transition`,
      { version: replay.version, target_status: "TESTED" },
    );
    $("markTested").disabled = true;
    $("testedEvidence").textContent = `TESTED after ${replay.replayed} replays and ${replay.flipped} flips.`;
    state.lastReplay = null;
    await loadPolicyStudio();
    setStatus(`Policy ${replay.policyId} v${replay.version} transitioned to TESTED.`);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

function queueRow(item) {
  const row = element("tr");
  const epoch = item.epoch;
  row.append(
    element("td", item.requester_id),
    element("td", item.decision_id, "hash"),
    element("td", epoch ? `${epoch.kind} #${epoch.epoch_number}` : item.state),
    element("td", epoch ? `${epoch.votes_cast}/${epoch.quorum}` : "—"),
    element("td", epoch?.approver_roles?.join(", ") || "—"),
    element("td", epoch ? countdown(epoch.expires_at) : "Terminal", "countdown"),
  );
  row.onclick = () => openApproval(item.approval_id, item.decision_id, item.requester_id);
  return row;
}

async function loadApprovals(append = false) {
  try {
    const params = query($("approvalFilters"));
    if (append && state.approvalCursor) params.set("cursor", state.approvalCursor);
    const page = await request("GET", "/v1/approvals", `/v1/approvals?${params}`);
    if (!append) $("approvals").replaceChildren();
    for (const item of page.items) $("approvals").append(queueRow(item));
    state.approvalCursor = page.next_cursor;
    $("moreApprovals").classList.toggle("hidden", !page.next_cursor);
    $("approvalCount").textContent = page.items.length;
    setStatus(`${page.items.length} approval requests loaded.`);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

function activeEpoch(approval) {
  return approval.epochs?.find((epoch) => epoch.epoch_id === approval.current_epoch_id) || null;
}

function renderDecisionCard(container, payload) {
  const decision = payload.decision;
  const card = element("article", undefined, "decision-card");
  const heading = element("div", undefined, "card-heading");
  heading.append(element("h3", "Authorization decision"), badge(decision.decision));
  const facts = element("dl", undefined, "facts");
  appendFact(facts, "Agent", decision.agent?.id);
  appendFact(facts, "Delegation", decision.agent?.delegation_chain?.join(" → "));
  appendFact(facts, "Principal", decision.principal?.id);
  appendFact(facts, "Intent", decision.intent);
  appendFact(facts, "Tool / recorded risk", `${valueOrDash(decision.tool?.id)} · ${valueOrDash(decision.risk?.level)}`);
  appendFact(facts, "Action", typeof decision.action === "string" ? decision.action : JSON.stringify(decision.action));
  appendFact(facts, "Risk", `${valueOrDash(decision.risk?.level)} · floor ${valueOrDash(decision.risk?.floor_source)}`);
  appendFact(facts, "Resource", typeof decision.resource === "string" ? decision.resource : JSON.stringify(decision.resource));
  appendFact(facts, "Classification", decision.resource?.data_classification || decision.resource?.classification);
  appendFact(facts, "Policies", decision.policies?.map((policy) => typeof policy === "string" ? policy : policy.policy_id || policy.id).join(", "));
  appendFact(facts, "Reasons", decision.reasons?.map((reason) => typeof reason === "string" ? reason : reason.code || reason.message).join(", "));
  appendFact(facts, "Parameters hash", decision.tool?.parameters_hash);
  appendFact(facts, "Binding profile", JSON.stringify(decision.tool?.binding_profile));
  card.append(heading, facts);

  const evidence = element("div", undefined, "evidence-links");
  const auditLink = element("button", "Open tenant audit", "quiet");
  auditLink.type = "button";
  auditLink.onclick = () => switchView("audit");
  const verifyLink = element("button", "Open chain verifier", "quiet");
  verifyLink.type = "button";
  verifyLink.onclick = () => switchView("verify");
  evidence.append(auditLink, verifyLink);
  card.append(evidence);

  const commands = element("aside", undefined, "export-help");
  commands.append(
    element("strong", "Portable evidence bundle"),
    element("p", "The control plane exposes evidence reads but no browser export route. Use the shipped authenticated exporter, then verify the downloaded bundle independently."),
    element("code", `mizan-export-evidence --decision-id ${decision.decision_id || state.approval?.decision_id} --output evidence-bundle.json`),
    element("code", "python scripts/verify_evidence_export.py evidence-bundle.json"),
  );
  card.append(commands);
  container.append(card);

  const timeline = element("section", undefined, "timeline");
  timeline.append(element("h3", "Decision history"));
  for (const event of payload.events || []) {
    const entry = element("article");
    entry.append(
      element("span", `#${event.decision_sequence}`, "sequence"),
      element("strong", event.event_type),
      element("span", `${valueOrDash(event.actor?.kind)} · ${valueOrDash(event.actor?.id)}`),
      element("time", event.occurred_at),
    );
    timeline.append(entry);
  }
  container.append(timeline);
}

function applyApprovalGuards() {
  const approval = state.approval;
  const epoch = activeEpoch(approval);
  const controls = $("voteControls");
  const roleSelect = $("approvalActions").elements.role_claim;
  roleSelect.replaceChildren(element("option", "Server selects from snapshot"));
  roleSelect.firstElementChild.value = "";
  for (const role of epoch?.eligibility?.roles || []) {
    const option = element("option", role);
    option.value = role;
    roleSelect.append(option);
  }

  const terminal = approval.state !== "PENDING" && approval.state !== "PARTIALLY_APPROVED";
  const expired = !epoch || Date.parse(epoch.expires_at) <= Date.now();
  const selfApproval = tokenClaims().sub === state.requesterId;
  const members = epoch?.eligibility?.members || [];
  const inSnapshot = members.length === 0 || members.some((member) => (member.id || member.principal_id || member) === tokenClaims().sub);
  const disabled = terminal || expired || selfApproval || !inSnapshot;
  controls.disabled = disabled;
  $("escalateApproval").disabled = terminal || expired;
  $("overrideApproval").disabled = terminal || !epoch;
  $("withdrawApproval").disabled = terminal || tokenClaims().sub !== state.requesterId;

  const reasons = [];
  if (terminal) reasons.push(`Approval is terminal (${approval.state}).`);
  if (expired) reasons.push("The active epoch has expired.");
  if (selfApproval) reasons.push("ADR-007 forbids requesters from approving their own action.");
  if (!inSnapshot) reasons.push("Your principal is not in this epoch's authority snapshot.");
  if (!reasons.length) reasons.push("Your vote is bound to the displayed epoch number and authority snapshot.");
  $("voteGuard").textContent = reasons.join(" ");
}

function renderApproval() {
  const target = $("approvalDetail");
  target.replaceChildren(element("p", "Human authority", "eyebrow"), element("h2", `Approval ${state.approval.approval_id}`));
  const epoch = activeEpoch(state.approval);
  const summary = element("article", undefined, "approval-summary");
  const facts = element("dl", undefined, "facts");
  appendFact(facts, "State", state.approval.state);
  appendFact(facts, "Requester", state.requesterId);
  appendFact(facts, "Decision", state.approval.decision_id);
  appendFact(facts, "Epoch", epoch ? `${epoch.kind} #${epoch.epoch_number}` : "No active epoch");
  appendFact(facts, "Quorum", epoch?.quorum);
  appendFact(facts, "Control domains", epoch?.distinct_control_domains_required);
  appendFact(facts, "Eligible roles", epoch?.eligibility?.roles?.join(", "));
  appendFact(facts, "Members", epoch?.eligibility?.members?.map((member) => member.id || member.principal_id || member).join(", "));
  appendFact(facts, "Votes", `${(epoch?.votes?.length || 0) + (epoch?.carried_votes?.length || 0)}/${valueOrDash(epoch?.quorum)}`);
  const countedDomains = [...(epoch?.carried_votes || []), ...(epoch?.votes || [])]
    .filter((vote) => vote.vote === "APPROVE")
    .map((vote) => vote.control_domain)
    .filter((domain, index, domains) => domain && domains.indexOf(domain) === index);
  appendFact(facts, "Domains counted", countedDomains.join(", ") || "None yet");
  appendFact(facts, "SLA", epoch ? countdown(epoch.expires_at) : "Terminal");
  summary.append(facts);
  target.append(summary);
  renderDecisionCard(target, state.decision);
  applyApprovalGuards();
}

async function openApproval(approvalId, decisionId, requesterId = state.requesterId) {
  try {
    const [approval, decision] = await Promise.all([
      request("GET", "/v1/approvals/{approval_id}", `/v1/approvals/${encodeURIComponent(approvalId)}`),
      request("GET", "/v1/decisions/{decision_id}", `/v1/decisions/${encodeURIComponent(decisionId)}`),
    ]);
    state.approval = approval;
    state.decision = decision;
    state.requesterId = requesterId;
    renderApproval();
    if (!$("approvalDialog").open) $("approvalDialog").showModal();
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function refreshApproval() {
  await openApproval(state.approval.approval_id, state.approval.decision_id, state.requesterId);
}

function voteBody() {
  const values = Object.fromEntries(new FormData($("approvalActions")));
  const epoch = activeEpoch(state.approval);
  return {
    vote: values.vote,
    epoch_number: epoch.epoch_number,
    role_claim: values.role_claim || null,
    justification: values.justification || null,
    comment: values.comment || null,
  };
}

async function castVote(body = voteBody()) {
  try {
    await request(
      "POST",
      "/v1/approvals/{approval_id}/votes",
      `/v1/approvals/${encodeURIComponent(state.approval.approval_id)}/votes`,
      body,
    );
    setStatus("Vote recorded against the displayed epoch.");
    await refreshApproval();
  } catch (error) {
    if (error.status === 409) {
      setStatus("This request was escalated while you were reading it. Reloaded the current epoch; review it before voting again.", "error");
      await refreshApproval();
      return;
    }
    setStatus(error.message, "error");
  }
}

async function escalateApproval() {
  try {
    await request(
      "POST",
      "/v1/approvals/{approval_id}/escalate",
      `/v1/approvals/${encodeURIComponent(state.approval.approval_id)}/escalate`,
    );
    setStatus("Approval escalated into a fresh epoch.");
    await refreshApproval();
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function overrideApproval() {
  const body = voteBody();
  if (!body.justification) {
    setStatus("An override requires a written justification.", "error");
    return;
  }
  try {
    const approval = await request(
      "POST",
      "/v1/approvals/{approval_id}/override",
      `/v1/approvals/${encodeURIComponent(state.approval.approval_id)}/override`,
    );
    state.approval = approval;
    const epoch = activeEpoch(approval);
    await castVote({ ...body, vote: "APPROVE", epoch_number: epoch.epoch_number });
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function withdrawApproval() {
  try {
    await request(
      "POST",
      "/v1/approvals/{approval_id}/withdraw",
      `/v1/approvals/${encodeURIComponent(state.approval.approval_id)}/withdraw`,
    );
    setStatus("Approval request withdrawn by its requester.");
    await refreshApproval();
  } catch (error) {
    setStatus(error.message, "error");
  }
}

const loaders = {
  dashboard: loadDashboard,
  approvals: loadApprovals,
  policyStudio: loadPolicyStudio,
  agents: loadAgents,
  decisions: loadDecisions,
  audit: loadAudit,
};

function switchView(view) {
  state.activeView = view;
  document.querySelectorAll(".nav").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  document.querySelectorAll(".view").forEach((item) => item.classList.add("hidden"));
  $(`${view}View`).classList.remove("hidden");
  $("approvalDialog").close();
  if (loaders[view]) loaders[view]();
}

document.querySelectorAll(".nav").forEach((button) => {
  button.onclick = () => switchView(button.dataset.view);
});
$("filters").onsubmit = (event) => { event.preventDefault(); state.decisionCursor = null; loadDecisions(); };
$("approvalFilters").onsubmit = (event) => { event.preventDefault(); state.approvalCursor = null; loadApprovals(); };
$("approvalActions").onsubmit = (event) => { event.preventDefault(); castVote(); };
$("policyReplay").onsubmit = (event) => { event.preventDefault(); replayPolicy(); };
$("policyReplay").onchange = () => resetReplay();
$("markTested").onclick = markPolicyTested;
$("moreApprovals").onclick = () => loadApprovals(true);
$("moreDecisions").onclick = () => loadDecisions(true);
$("moreAudit").onclick = () => loadAudit(true);
$("escalateApproval").onclick = escalateApproval;
$("overrideApproval").onclick = overrideApproval;
$("withdrawApproval").onclick = withdrawApproval;
$("refreshButton").onclick = () => {
  state.decisionCursor = null;
  state.approvalCursor = null;
  (loaders[state.activeView] || loadDashboard)();
};
$("connectionButton").onclick = () => {
  $("apiOrigin").value = state.origin;
  $("apiToken").value = state.token;
  $("connectionDialog").showModal();
};
$("saveConnection").onclick = () => {
  state.origin = $("apiOrigin").value.replace(/\/$/, "");
  state.token = $("apiToken").value.trim();
  sessionStorage.setItem("mizan_origin", state.origin);
  sessionStorage.setItem("mizan_token", state.token);
  setTimeout(() => (loaders[state.activeView] || loadDashboard)(), 0);
};
$("verifyForm").onsubmit = async (event) => {
  event.preventDefault();
  const values = Object.fromEntries(new FormData(event.target));
  const body = {
    stream_id: values.stream_id,
    from_sequence: values.from_sequence === "" ? null : Number(values.from_sequence),
    to_sequence: values.to_sequence === "" ? null : Number(values.to_sequence),
    verify_anchors: values.verify_anchors === "on",
  };
  try {
    const result = await request("POST", "/v1/audit/verify", "/v1/audit/verify", body);
    $("verifyResult").textContent = `✓ Chain intact\n${result.checked_records} records independently verified.`;
  } catch (error) {
    $("verifyResult").textContent = `Verification failed\n${error.message}`;
  }
};
document.querySelectorAll(".dialog-close").forEach((button) => {
  button.onclick = () => button.closest("dialog").close();
});
setInterval(() => {
  if (state.approval?.current_epoch_id && $("approvalDialog").open) renderApproval();
  else if (state.activeView === "approvals") loadApprovals();
}, 60000);
if (state.token) loadDashboard();
