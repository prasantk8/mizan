const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const UI = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(UI, "index.html"), "utf8");
const source = fs.readFileSync(path.join(UI, "app.js"), "utf8");

class FakeClassList {
  constructor(owner) {
    this.owner = owner;
  }

  add(...names) {
    const classes = new Set(this.owner.className.split(/\s+/).filter(Boolean));
    names.forEach((name) => classes.add(name));
    this.owner.className = [...classes].join(" ");
  }

  remove(...names) {
    const removed = new Set(names);
    this.owner.className = this.owner.className
      .split(/\s+/)
      .filter((name) => name && !removed.has(name))
      .join(" ");
  }

  toggle(name, force) {
    const present = this.owner.className.split(/\s+/).includes(name);
    const enabled = force === undefined ? !present : force;
    if (enabled) this.add(name);
    else this.remove(name);
    return enabled;
  }
}

class FakeNode {
  constructor(tag = "div", text = "") {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.className = "";
    this.dataset = {};
    this.disabled = false;
    this.open = false;
    this.value = "";
    this._text = String(text);
    this.classList = new FakeClassList(this);
    this.elements = new Proxy({}, { get: (_target, key) => new FakeNode(String(key)) });
  }

  get textContent() {
    return this.children.length
      ? this.children.map((child) => child.textContent).join("")
      : this._text;
  }

  set textContent(value) {
    this.children = [];
    this._text = String(value);
  }

  append(...children) {
    this.children.push(...children.map((child) => (
      typeof child === "string" ? new FakeNode("#text", child) : child
    )));
  }

  replaceChildren(...children) {
    this.children = [];
    this._text = "";
    this.append(...children);
  }

  close() {
    this.open = false;
  }

  showModal() {
    this.open = true;
  }

  closest() {
    return this;
  }
}

class FakeDocument {
  constructor() {
    this.nodes = new Map();
  }

  getElementById(id) {
    if (!this.nodes.has(id)) this.nodes.set(id, new FakeNode());
    return this.nodes.get(id);
  }

  createElement(tag) {
    return new FakeNode(tag);
  }

  createTextNode(text) {
    return new FakeNode("#text", text);
  }

  querySelectorAll() {
    return [];
  }
}

function browser({ session = null, responses = {} } = {}) {
  const document = new FakeDocument();
  if (session && !responses["/auth/session"]) {
    responses["/auth/session"] = { status: 200, body: session };
  }
  const requests = [];
  const location = { pathname: "/", search: "", assigned: null, assign(value) { this.assigned = value; } };
  const context = {
    console,
    document,
    FormData: class {},
    URLSearchParams,
    window: { location },
    setInterval() {},
    setTimeout(callback) {
      callback();
    },
    fetch: async (url, options = {}) => {
      const pathname = new URL(url, "https://ui.test").pathname;
      requests.push({ pathname, options });
      const response = responses[pathname];
      if (!response) throw new Error(`unexpected request: ${pathname}`);
      return {
        ok: response.status < 400,
        status: response.status,
        json: async () => response.body,
      };
    },
  };
  vm.createContext(context);
  vm.runInContext(source, context, { filename: "ui/app.js" });
  return { context, document, requests, location };
}

test("the static DOM states only claims the shipped interface can support", () => {
  assert.match(html, /id="environmentStatus"[^>]*>\s*<i><\/i> Environment unverified\s*<\/div>/);
  assert.match(html, /<h1[^>]*>Every governed action, decided before execution\.<\/h1>/);
  assert.match(html, /<span>Every governed action leaves evidence\.<\/span>/);
  assert.match(html, /<p class="eyebrow">Control-plane integrity check<\/p>/);
  assert.match(html, /Full historical decision recomputation is not shipped\./);
  assert.doesNotMatch(html, /Production control plane|without blind spots|Independent integrity check/);
});

test("the runtime DOM says Production without a token only after production readiness is verified", async () => {
  const { document } = browser({
    responses: {
      "/health/ready": {
        status: 200,
        body: {
          status: "ready",
          checks: {
            database: "ok",
            signing_keys: "ok",
            evidence_verifier: "ok",
            evidence_reconciliation: "ok",
            execution_service: "ok",
            anchor_provider: "ok",
            mutual_tls: "ok",
          },
        },
      },
    },
  });
  const target = document.getElementById("environmentStatus");
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(target.textContent, " Production · Connected · Ready");
  assert.equal(target.className, "environment ready");
});

test("the runtime DOM never calls an unready or non-production runtime Production", () => {
  const { context, document } = browser({
    responses: { "/health/ready": { status: 503, body: { status: "not_ready", checks: {} } } },
  });
  const target = document.getElementById("environmentStatus");

  context.renderRuntimeStatus({ status: "ready", checks: { database: "ok" } });
  assert.equal(target.textContent, " Non-production · Connected · Ready");

  context.renderRuntimeStatus({
    status: "not_ready",
    checks: { anchor_provider: "ok", mutual_tls: "ok", database: "unavailable" },
  });
  assert.equal(target.textContent, " Environment unverified · Connected · Not ready");
  assert.doesNotMatch(target.textContent, /Production/);
  assert.equal(target.className, "environment not-ready");
});

test("the dashboard DOM names the counted mizan.security event class", async () => {
  const { document } = browser({
    session: { principal_id: "prn_alice", tenant_id: "tnt_bank-a" },
    responses: {
      "/health/ready": { status: 200, body: { status: "ready", checks: { database: "ok" } } },
      "/v1/dashboard/summary": {
        status: 200,
        body: {
          agents: 1,
          tools: 2,
          actions_today: 3,
          denied_actions: 4,
          approval_requests: 5,
          security_alerts: 6,
          high_risk_actions: 7,
        },
      },
    },
  });
  await new Promise((resolve) => setImmediate(resolve));

  const labels = document.getElementById("metrics").children.map((card) => card.children[0].textContent);
  assert.ok(labels.includes("mizan.security.* audit events today"));
  assert.ok(!labels.includes("Security alerts"));
});

test("the operator UI uses an HttpOnly workforce session and exposes no pasted bearer field", async () => {
  const { document, requests } = browser({
    session: { principal_id: "prn_alice", tenant_id: "tnt_bank-a", roles: ["manager"] },
    responses: {
      "/health/ready": { status: 200, body: { status: "ready", checks: { database: "ok" } } },
      "/v1/dashboard/summary": { status: 200, body: {} },
    },
  });
  await new Promise((resolve) => setImmediate(resolve));

  assert.doesNotMatch(html, /Bearer token|apiToken|connectionDialog/);
  assert.doesNotMatch(source, /sessionStorage|mizan_token|Authorization:\s*`Bearer/);
  assert.equal(document.getElementById("connectionButton").textContent, "Sign out");
  assert.ok(requests.every((request) => request.options.credentials === "same-origin"));
  assert.ok(requests.every((request) => !request.options.headers?.Authorization));
});

test("an anonymous operator is redirected to the customer IdP login entrypoint", async () => {
  const { document, location } = browser({
    responses: { "/health/ready": { status: 503, body: { status: "not_ready", checks: {} } } },
  });
  await new Promise((resolve) => setImmediate(resolve));
  document.getElementById("connectionButton").onclick();
  assert.equal(location.assigned, "/auth/login?return_to=/");
});

test("a high-risk vote refusal redirects the browser through fresh IdP step-up", async () => {
  const { context, location } = browser({
    session: { principal_id: "prn_alice", tenant_id: "tnt_bank-a", roles: ["manager"] },
    responses: {
      "/health/ready": { status: 200, body: { status: "ready", checks: { database: "ok" } } },
      "/v1/dashboard/summary": { status: 200, body: {} },
      "/v1/approvals/apr_test": {
        status: 200,
        body: {
          approval_id: "apr_test",
          decision_id: "dec_test",
          state: "PENDING",
          current_epoch_id: "epc_test",
          epochs: [{ epoch_id: "epc_test", epoch_number: 1, expires_at: "2099-01-01T00:00:00Z", votes: [], eligibility: { members: [] } }],
        },
      },
      "/v1/decisions/dec_test": { status: 200, body: { decision_id: "dec_test" } },
      "/v1/approvals/apr_test/votes": {
        status: 403,
        body: { type: "https://mizan.ai/problems/workforce_step_up_required", detail: "step up" },
      },
    },
  });
  await new Promise((resolve) => setImmediate(resolve));
  await context.openApproval("apr_test", "dec_test", "prn_requester");
  await context.castVote({ vote: "APPROVE", epoch_number: 1 });

  assert.equal(location.assigned, "/auth/step-up?return_to=%2F");
});

test("the policy studio DOM uses simulation language and discloses its limit", () => {
  const { context, document } = browser({
    responses: { "/health/ready": { status: 503, body: { status: "not_ready", checks: {} } } },
  });
  context.resetSimulation();

  assert.equal(
    document.getElementById("simulationSummary").textContent,
    "Run a policy impact preview against recorded contexts.",
  );
  assert.equal(
    document.getElementById("testedEvidence").textContent,
    "No simulation evidence in this session.",
  );
  assert.doesNotMatch(document.getElementById("simulationSummary").textContent, /replay/i);
  assert.match(html, /Full historical decision recomputation is not shipped\./);
});
