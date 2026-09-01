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

function browser({ token = "", responses = {} } = {}) {
  const document = new FakeDocument();
  const context = {
    console,
    document,
    FormData: class {},
    URLSearchParams,
    sessionStorage: {
      getItem(key) {
        return key === "mizan_token" ? token : "";
      },
      setItem() {},
    },
    setInterval() {},
    setTimeout(callback) {
      callback();
    },
    fetch: async (url) => {
      const pathname = new URL(url, "https://ui.test").pathname;
      const response = responses[pathname];
      if (!response) throw new Error(`unexpected request: ${pathname}`);
      return {
        ok: response.status < 400,
        status: response.status,
        json: async () => response.body,
      };
    },
    atob(value) {
      return Buffer.from(value, "base64url").toString("utf8");
    },
  };
  vm.createContext(context);
  vm.runInContext(source, context, { filename: "ui/app.js" });
  return { context, document };
}

test("the static DOM states only claims the shipped interface can support", () => {
  assert.match(html, /id="environmentStatus"[^>]*>\s*<i><\/i> Environment unverified\s*<\/div>/);
  assert.match(html, /<h1[^>]*>Every governed action, decided before execution\.<\/h1>/);
  assert.match(html, /<span>Every governed action leaves evidence\.<\/span>/);
  assert.match(html, /<p class="eyebrow">Control-plane integrity check<\/p>/);
  assert.match(html, /Full historical decision recomputation is not shipped\./);
  assert.doesNotMatch(html, /Production control plane|without blind spots|Independent integrity check/);
});

test("the runtime DOM says Production only when production-only checks and readiness are verified", () => {
  const { context, document } = browser();
  const target = document.getElementById("environmentStatus");

  context.renderRuntimeStatus({
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
  });

  assert.equal(target.textContent, " Production · Connected · Ready");
  assert.equal(target.className, "environment ready");
});

test("the runtime DOM never calls an unready or non-production runtime Production", () => {
  const { context, document } = browser();
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
    token: "header.payload.signature",
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

test("the policy studio DOM uses simulation language and discloses its limit", () => {
  const { context, document } = browser();
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
