"use strict";

const SVGNS = "http://www.w3.org/2000/svg";
const $ = (id) => document.getElementById(id);
const mk = (tag, cls, html) => { const n = document.createElement(tag); if (cls) n.className = cls; if (html != null) n.innerHTML = html; return n; };
const svgEl = (tag) => document.createElementNS(SVGNS, tag);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[c]));
const pretty = (v) => { try { return typeof v === "string" ? v : JSON.stringify(v, null, 2); } catch { return String(v); } };

// ───────── topology definition (1440 x 760 canvas) ─────────
const NODES = [
  { id: "alert_input", kind: "input", icon: "alert", label: "Security Alert", x: 120, y: 360 },
  { id: "triage", kind: "orchestrator", icon: "branch", label: "Triage", x: 360, y: 360, agent: "triage" },
  { id: "f5_proxy", kind: "guardrail", icon: "shield", label: "F5 AI Guardrails", x: 770, y: 90, guardrail: true },
  { id: "llm_model", kind: "model", icon: "chip", label: "LLM Model", x: 1075, y: 90, guardrail: true },
  { id: "threat-intel", kind: "agent", icon: "search", label: "Threat-Intel", x: 705, y: 250, agent: "threat-intel" },
  { id: "remediation", kind: "agent", icon: "bolt", label: "Remediation", x: 705, y: 410, agent: "remediation" },
  { id: "comms", kind: "agent", icon: "send", label: "Comms", x: 705, y: 565, agent: "comms" },
  { id: "summary", kind: "output", icon: "doc", label: "Case Summary", x: 120, y: 585 },
  { id: "red_team", kind: "redteam", icon: "xtarget", label: "Red Team Module", x: 360, y: 165, redteam: true },
  { id: "get_recent_alerts", kind: "tool", icon: "list", label: "get_recent_alerts", x: 1010, y: 175 },
  { id: "check_ip_reputation", kind: "tool", icon: "tool", label: "check_ip_reputation", x: 1250, y: 175 },
  { id: "lookup_ip_geolocation", kind: "tool", icon: "globe", label: "lookup_ip_geolocation", x: 1010, y: 255 },
  { id: "get_alert_details", kind: "tool", icon: "list", label: "get_alert_details", x: 1250, y: 255 },
  { id: "execute_db_query", kind: "tool", icon: "db", label: "execute_db_query", x: 1010, y: 400 },
  { id: "quarantine_host", kind: "tool", icon: "tool", label: "quarantine_host", x: 1250, y: 400 },
  { id: "revoke_credential", kind: "tool", icon: "tool", label: "revoke_credential", x: 1010, y: 475 },
  { id: "a2a:notify-internal", kind: "tool", icon: "send", label: "notify-internal", x: 1010, y: 540 },
  { id: "a2a:notify-external", kind: "tool", icon: "send", label: "notify-external", x: 1010, y: 610 },
];
const NODE = Object.fromEntries(NODES.map((n) => [n.id, n]));

const EDGES = [
  { s: "alert_input", t: "triage", label: "alert" },
  { s: "triage", t: "threat-intel", label: "investigate" },
  { s: "triage", t: "remediation", label: "remediate" },
  { s: "triage", t: "comms", label: "notify" },
  { s: "triage", t: "summary", label: "summary", secondary: true },
  { s: "threat-intel", t: "get_recent_alerts", secondary: true },
  { s: "threat-intel", t: "check_ip_reputation", secondary: true },
  { s: "threat-intel", t: "lookup_ip_geolocation", secondary: true },
  { s: "threat-intel", t: "get_alert_details", secondary: true },
  { s: "remediation", t: "execute_db_query", secondary: true },
  { s: "remediation", t: "quarantine_host", secondary: true },
  { s: "remediation", t: "revoke_credential", secondary: true },
  { s: "comms", t: "a2a:notify-internal", secondary: true },
  { s: "comms", t: "a2a:notify-external", secondary: true },
  { s: "triage", t: "f5_proxy", label: "llm", secondary: true, guardrail: true },
  { s: "threat-intel", t: "f5_proxy", secondary: true, guardrail: true },
  { s: "remediation", t: "f5_proxy", secondary: true, guardrail: true },
  { s: "comms", t: "f5_proxy", secondary: true, guardrail: true },
  { s: "f5_proxy", t: "llm_model", label: "model", guardrail: true },
  { s: "red_team", t: "triage", label: "probe", redteam: true },
];
EDGES.forEach((e) => (e.id = `${e.s}__${e.t}`));
const eid = (s, t) => `${s}__${t}`;

const ICONS = {
  alert: '<path d="M12 3 L22 20 H2 Z"/><path d="M12 10 v4"/><path d="M12 17 h0.01"/>',
  branch: '<circle cx="5" cy="12" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="19" cy="19" r="2"/><path d="M7 12 H13 M13 12 L17 6 M13 12 L17 18"/>',
  search: '<circle cx="10" cy="10" r="6"/><path d="M15 15 L21 21"/>',
  bolt: '<path d="M13 3 L5 13 h5 l-1 8 L18 11 h-5 Z"/>',
  send: '<path d="M22 2 L11 13 M22 2 L15 22 L11 13 L2 9 Z"/>',
  shield: '<path d="M12 3 L20 6 V11 C20 16 16 20 12 21 C8 20 4 16 4 11 V6 Z"/>',
  chip: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 3v3 M15 3v3 M9 18v3 M15 18v3 M3 9h3 M3 15h3 M18 9h3 M18 15h3"/>',
  doc: '<path d="M6 3 h8 l4 4 v14 H6 Z"/><path d="M14 3 v4 h4 M9 13 h6 M9 17 h6"/>',
  tool: '<path d="M14 7 a4 4 0 1 0-3 6 l-6 6 2 2 6-6 a4 4 0 0 0 5-8 l-3 3-2-2 Z"/>',
  db: '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6 v12 c0 1.6 3 3 7 3 s7-1.4 7-3 V6 M5 12 c0 1.6 3 3 7 3 s7-1.4 7-3"/>',
  list: '<path d="M8 6 h12 M8 12 h12 M8 18 h12 M4 6 h0.01 M4 12 h0.01 M4 18 h0.01"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12 h18 M12 3 a15 15 0 0 1 0 18 a15 15 0 0 1 0-18"/>',
  xtarget: '<circle cx="12" cy="12" r="9"/><path d="M8.5 8.5 L15.5 15.5 M15.5 8.5 L8.5 15.5"/>',
};
const icon = (n) => `<svg viewBox="0 0 24 24">${ICONS[n] || ICONS.tool}</svg>`;

const STAGES = [
  { label: "Alert", idle: "Waiting", active: "Received", done: "Received" },
  { label: "Triage", idle: "Waiting", active: "Planning", done: "Planned" },
  { label: "Agent Execution", idle: "Waiting", active: "Running", done: "Complete" },
  { label: "Tool Calls", idle: "Waiting", active: "Executing", done: "Complete" },
  { label: "Response", idle: "Waiting", active: "Synthesizing", done: "Complete" },
];

const AGENTS = { triage: "Planner", "threat-intel": "Investigator", remediation: "Actioner", comms: "Notifier" };

// ───────── state ─────────
const S = {
  outputs: {},        // nodeId -> data for inspector
  agentTools: {},     // agent -> [tool events]
  nodeStatus: {},     // nodeId -> working|done|denied|blocked
  traversed: new Set(),
  liveEdges: new Map(),   // edgeId -> "ok"|"deny"
  selected: null,
  progressIndex: -1,
  progressStatus: "idle",
  zoom: 0.9,
  showGuardrail: true,
  showRedTeam: false,
  running: false,
};

// element refs built once
const nodeEls = {};
const edgeEls = {};    // edgeId -> path
const labelEls = {};   // edgeId -> group
const packetEls = {};  // edgeId -> circle

// ───────── geometry ─────────
function pathD(e) {
  const s = NODE[e.s], t = NODE[e.t];
  if (e.guardrail && !(Math.abs(s.y - t.y) < 6)) {
    const mx = (s.x + t.x) / 2, my = Math.min(s.y, t.y) - 46;
    return `M ${s.x} ${s.y} Q ${mx} ${my} ${t.x} ${t.y}`;
  }
  const dx = Math.abs(t.x - s.x), dy = Math.abs(t.y - s.y);
  if (dx < 28 || dy < 28) return `M ${s.x} ${s.y} L ${t.x} ${t.y}`;
  const mx = (s.x + t.x) / 2;
  return `M ${s.x} ${s.y} L ${mx} ${s.y} L ${mx} ${t.y} L ${t.x} ${t.y}`;
}
function labelPoint(e) {
  const s = NODE[e.s], t = NODE[e.t];
  if (e.guardrail && !(Math.abs(s.y - t.y) < 6)) return { x: (s.x + t.x) / 2, y: Math.min(s.y, t.y) - 46 };
  const dx = Math.abs(t.x - s.x), dy = Math.abs(t.y - s.y);
  const mx = (s.x + t.x) / 2;
  if (dx < 28 || dy < 28) return { x: (s.x + t.x) / 2, y: (s.y + t.y) / 2 };
  return dx >= dy ? { x: mx, y: s.y } : { x: mx, y: (s.y + t.y) / 2 };
}

// ───────── build graph once ─────────
function buildGraph() {
  const svg = $("topoSvg");
  const layer = $("topoNodes");
  // clear (keep defs)
  svg.querySelectorAll(".edge, .elabel-group, .packet").forEach((n) => n.remove());
  layer.innerHTML = "";

  EDGES.forEach((e) => {
    const p = svgEl("path");
    p.setAttribute("id", "p_" + e.id);
    p.setAttribute("d", pathD(e));
    p.setAttribute("class", "edge");
    svg.appendChild(p);
    edgeEls[e.id] = p;
    if (e.label) {
      const g = svgEl("g"); g.setAttribute("class", "elabel-group");
      const lp = labelPoint(e);
      const w = Math.max(34, e.label.length * 8 + 16);
      const rect = svgEl("rect");
      rect.setAttribute("class", "elabel-bg");
      rect.setAttribute("x", lp.x - w / 2); rect.setAttribute("y", lp.y - 12);
      rect.setAttribute("width", w); rect.setAttribute("height", 22); rect.setAttribute("rx", 11);
      const tx = svgEl("text"); tx.setAttribute("class", "elabel");
      tx.setAttribute("x", lp.x); tx.setAttribute("y", lp.y + 4); tx.setAttribute("text-anchor", "middle");
      tx.textContent = e.label;
      g.appendChild(rect); g.appendChild(tx); svg.appendChild(g);
      labelEls[e.id] = g;
    }
  });

  NODES.forEach((n) => {
    const b = document.createElement("button");
    b.type = "button";
    b.style.left = n.x + "px";
    b.style.top = n.y + "px";
    b.dataset.id = n.id;
    b.innerHTML = `<span class="ic">${icon(n.icon)}</span><span class="lbl">${esc(n.label)}</span>`;
    b.addEventListener("click", () => selectNode(n.id));
    layer.appendChild(b);
    nodeEls[n.id] = b;
  });
  updateGraph();
}

// ───────── update classes / packets ─────────
function nodeClass(n) {
  const st = S.nodeStatus[n.id];
  return ["node", `kind-${n.kind}`, n.agent ? `a-${n.agent}` : "",
    n.kind === "tool" && !st ? "is-idle" : "",
    st === "working" ? "working" : "", st === "done" ? "done" : "",
    st === "denied" ? "denied" : "", st === "blocked" ? "blocked" : "",
    S.selected === n.id ? "selected" : ""].filter(Boolean).join(" ");
}
function updateGraph() {
  NODES.forEach((n) => {
    nodeEls[n.id].className = nodeClass(n);
    const hide = (n.guardrail && !S.showGuardrail) || (n.redteam && !S.showRedTeam);
    nodeEls[n.id].style.display = hide ? "none" : "";
  });
  EDGES.forEach((e) => {
    const live = S.liveEdges.get(e.id);
    const cls = e.redteam
      ? ["edge", "redteam"].join(" ")
      : ["edge", e.guardrail ? "guardrail" : (e.secondary ? "secondary" : ""),
         S.traversed.has(e.id) ? "active" : "muted",
         live === "ok" ? "live" : "", live === "deny" ? "live-deny" : ""].filter(Boolean).join(" ");
    edgeEls[e.id].setAttribute("class", cls);
    const hide = (e.guardrail && !S.showGuardrail) || (e.redteam && !S.showRedTeam);
    edgeEls[e.id].style.display = hide ? "none" : "";
    if (labelEls[e.id]) labelEls[e.id].style.display = hide ? "none" : "";
  });
  // packets: reconcile with live edges
  Object.keys(packetEls).forEach((id) => {
    if (!S.liveEdges.has(id) || (NODE[id.split("__")[0]]?.guardrail && !S.showGuardrail)) {
      packetEls[id].remove(); delete packetEls[id];
    }
  });
  S.liveEdges.forEach((kind, id) => {
    const e = EDGES.find((x) => x.id === id);
    if (!e) return;
    if (e.guardrail && !S.showGuardrail) return;
    if (packetEls[id]) { packetEls[id].setAttribute("class", "packet" + (kind === "deny" ? " deny" : "")); return; }
    const c = svgEl("circle"); c.setAttribute("r", "4.5");
    c.setAttribute("class", "packet" + (kind === "deny" ? " deny" : ""));
    const am = svgEl("animateMotion"); am.setAttribute("dur", "0.9s"); am.setAttribute("repeatCount", "indefinite");
    const mp = svgEl("mpath");
    mp.setAttributeNS("http://www.w3.org/1999/xlink", "href", "#p_" + id);
    mp.setAttribute("href", "#p_" + id);
    am.appendChild(mp); c.appendChild(am);
    $("topoSvg").appendChild(c);
    packetEls[id] = c;
  });
}

// ───────── progress strip ─────────
function buildProgress() {
  const c = $("runProgress"); c.innerHTML = "";
  STAGES.forEach((st, i) => {
    let status = "pending", text = st.idle;
    if (S.progressStatus === "blocked") { status = i <= S.progressIndex ? "blocked" : "pending"; text = i <= S.progressIndex ? "Blocked" : st.idle; }
    else if (S.progressStatus === "complete") { status = "complete"; text = st.done; }
    else if (i < S.progressIndex) { status = "complete"; text = st.done; }
    else if (i === S.progressIndex) { status = "active"; text = st.active; }
    const it = mk("div", `rp-item status-${status}`,
      `<span class="rp-idx">${i + 1}</span><span class="rp-copy"><span class="rp-label">${st.label}</span><span class="rp-status">${text}</span></span>`);
    c.appendChild(it);
  });
}
function setProgress(i, status) { S.progressIndex = i; S.progressStatus = status || "running"; buildProgress(); }

// ───────── zoom ─────────
function applyZoom(z) {
  S.zoom = Math.max(0.5, Math.min(1.6, Math.round(z * 100) / 100));
  $("topoScene").style.transform = `scale(${S.zoom})`;
  $("topoCanvas").style.width = 1440 * S.zoom + "px";
  $("topoCanvas").style.height = 760 * S.zoom + "px";
  $("zoomLabel").textContent = Math.round(S.zoom * 100) + "%";
}

// ───────── guardrail chip / mode ─────────
function setGuardrail(state, text) { $("guardrailChip").className = "chip guardrail g-" + state; $("guardrailText").textContent = text; }
function setMode(mock, model) {
  const b = $("modeBadge");
  if (mock) { b.textContent = "MOCK MODE"; b.className = "chip mode"; }
  else { b.textContent = "LIVE · " + (model || "proxy"); b.className = "chip mode live"; }
}

// ───────── inspector ─────────
function initials(label) { return label.split(/[-\s]/).map((w) => w[0]).join("").slice(0, 2).toUpperCase(); }
function toolRows(list) {
  if (!list || !list.length) return "";
  return `<div class="rb-title">tool calls</div>` + list.map((t) => {
    const ok = t.allowed;
    return `<div style="display:grid;gap:6px">
      <div class="toolrow"><span class="tn">${esc(t.tool)}</span>${t.scope ? `<span class="sbadge">${esc(t.scope)}</span>` : ""}<span class="verdict ${ok ? "ok" : "deny"}">${ok ? "ALLOWED" : "DENIED"}</span></div>
      ${t.denied_reason ? `<div class="deny-reason">✕ ${esc(t.denied_reason)}</div>` : ""}</div>`;
  }).join("");
}
function jsonBlock(title, v) { return v == null ? "" : `<div><div class="rb-title">${esc(title)}</div><pre class="json">${esc(pretty(v))}</pre></div>`; }

function renderInspector(nodeId) {
  const insp = $("inspector");
  if (!nodeId) { insp.innerHTML = `<div class="insp-body"><div class="insp-empty">Click any node to inspect its output.</div></div>`; return; }
  const n = NODE[nodeId];
  const st = S.nodeStatus[nodeId];
  const statusText = st === "working" ? "running" : (st || "idle");
  const statusCls = st === "working" ? "running" : (st === "denied" || st === "blocked" ? st : (st ? "ok" : "ok"));
  let body = "";

  if (n.id === "alert_input") {
    body = jsonBlock("alert text", S.outputs.alert || "(no alert yet)");
  } else if (n.agent) {
    const out = S.outputs[n.id] || {};
    if (out.blocked) body += `<div class="gr-banner"><span class="x">✕</span><div class="t"><b>Blocked by F5 AI Guardrails at the proxy.</b> ${out.blocked}</div></div>`;
    if (n.id !== "triage") body += toolRows(S.agentTools[n.id]);
    body += jsonBlock(n.id === "triage" ? "plan" : "output", out.result);
    if (!body) body = `<div class="insp-empty">No output yet — run a scenario.</div>`;
  } else if (n.kind === "tool") {
    const t = S.outputs[n.id];
    if (!t) body = `<div class="insp-empty">This tool hasn't been called in this run.</div>`;
    else {
      if (t.denied_reason) body += `<div class="deny-reason">✕ ${esc(t.denied_reason)}</div>`;
      body += jsonBlock("arguments", t.args);
      body += jsonBlock("result", (() => { try { return JSON.parse(t.result); } catch { return t.result; } })());
    }
  } else if (n.id === "f5_proxy") {
    const g = S.outputs.guardrail;
    if (g && g.blocked) body = `<div class="gr-banner"><span class="x">✕</span><div class="t"><b>${esc(g.agent)} was blocked here.</b> ${esc(g.detail || "")}</div></div>`;
    else body = `<div class="rb-title">role</div><pre class="json">Every agent LLM call is routed through the F5 AI Security proxy.\nGuardrails scan each prompt/response and can block before the model sees it.</pre>`;
  } else if (n.id === "llm_model") {
    body = `<div class="rb-title">role</div><pre class="json">Upstream model behind the guardrail proxy.\nReceives only prompts that clear F5 AI Guardrails.</pre>`;
  } else if (n.id === "red_team") {
    body = `<div class="rb-title">role</div><pre class="json">Adversarial probe source (red-team overlay).\nHooks the Triage agent to test prompt-injection resilience —\nthe same PROBE path a poisoned alert would take into the SOC team.</pre>`;
  } else if (n.id === "summary") {
    body = jsonBlock("case summary", S.outputs.summary || "(run not finished)");
  }

  insp.innerHTML = `
    <div class="insp-head">
      <div class="insp-avatar">${esc(initials(n.label))}</div>
      <div class="insp-title"><div class="t">${esc(n.label)}</div><div class="s">${esc(n.agent ? AGENTS[n.agent] : n.kind)}</div></div>
      ${st ? `<span class="insp-status ${statusCls}">${esc(statusText)}</span>` : ""}
    </div>
    <div class="insp-body">${body}</div>`;
}
function selectNode(id) { S.selected = id; updateGraph(); renderInspector(id); }

// ───────── log ─────────
function log(type, msg, cls) {
  const t = new Date().toLocaleTimeString([], { hour12: false });
  const li = mk("li", null, `<span class="lt">${t}</span><span class="${cls || ""}">${esc(type)}${msg ? " · " + esc(msg) : ""}</span>`);
  $("log").appendChild(li); $("log").scrollTop = $("log").scrollHeight;
}

// ───────── live-edge helpers ─────────
function incomingPrimaryEdge(nodeId) {
  const e = EDGES.find((x) => x.t === nodeId && !x.secondary && !x.guardrail);
  return e ? e.id : null;
}
function setAgentLive(agent) {
  S.liveEdges.clear();
  const inc = incomingPrimaryEdge(agent);
  if (inc) S.liveEdges.set(inc, "ok");
  if (S.showGuardrail) {
    const gp = eid(agent, "f5_proxy"); if (EDGES.find((e) => e.id === gp)) S.liveEdges.set(gp, "ok");
    S.liveEdges.set(eid("f5_proxy", "llm_model"), "ok");
    S.traversed.add(gp); S.traversed.add(eid("f5_proxy", "llm_model"));
  }
}

// ───────── event handling ─────────
function handle(ev) {
  switch (ev.type) {
    case "hello": setMode(ev.mock_mode, ev.model); break;
    case "run_started":
      $("traceId").textContent = ev.trace_id;
      S.outputs.alert = ev.alert;
      S.traversed.add(eid("alert_input", "triage"));
      S.nodeStatus["alert_input"] = "done";
      setProgress(0, "running"); setGuardrail("scan", "scanning"); updateGraph();
      break;
    case "agent_started": {
      const a = ev.agent;
      S.nodeStatus[a] = "working";
      S.agentTools[a] = S.agentTools[a] || [];
      if (a === "triage") setProgress(1, "running");
      else if (S.progressIndex < 2) setProgress(2, "running");
      if (a !== "triage") S.traversed.add(eid("triage", a));
      setAgentLive(a);
      selectNode(a);   // inspector follows the working agent
      log("agent", a + " started");
      break;
    }
    case "agent_input":
      S.outputs[ev.agent] = S.outputs[ev.agent] || {};
      S.outputs[ev.agent].task = ev.text;
      break;
    case "tool_call": {
      const a = ev.agent, tid = ev.tool;
      S.agentTools[a] = S.agentTools[a] || [];
      S.agentTools[a].push(ev);
      S.outputs[tid] = ev;
      S.nodeStatus[tid] = ev.allowed ? "done" : "denied";
      S.traversed.add(eid(a, tid));
      S.liveEdges.set(eid(a, tid), ev.allowed ? "ok" : "deny");
      if (S.progressIndex < 3) setProgress(3, "running");
      if (S.selected === a) renderInspector(a);
      updateGraph();
      log("tool", `${a} · ${tid} · ${ev.allowed ? "allowed" : "DENIED"}`, ev.allowed ? "ok" : "deny");
      break;
    }
    case "agent_message":
      S.outputs[ev.agent] = S.outputs[ev.agent] || {};
      S.outputs[ev.agent].result = ev.content;
      if (S.selected === ev.agent) renderInspector(ev.agent);
      break;
    case "guardrail_blocked": {
      const a = ev.agent;
      const scanners = (ev.failing_scanners || []).filter(Boolean);
      const detail = scanners.length ? `Failing scanners: ${scanners.join(", ")}` : (ev.outcome ? `Outcome: ${ev.outcome}` : "");
      S.outputs[a] = S.outputs[a] || {}; S.outputs[a].blocked = detail;
      S.outputs.guardrail = { blocked: true, agent: a, detail };
      S.nodeStatus[a] = "blocked"; S.nodeStatus["f5_proxy"] = "denied";
      setGuardrail("blocked", "blocked");
      updateGraph(); if (S.selected === a || S.selected === "f5_proxy") renderInspector(S.selected);
      log("guardrail", a + " blocked at proxy", "deny");
      break;
    }
    case "agent_finished": {
      const a = ev.agent;
      S.nodeStatus[a] = ev.status === "ok" ? "done" : (ev.status === "denied" ? "denied" : (ev.status === "blocked" ? "blocked" : "done"));
      S.liveEdges.clear();
      updateGraph();
      log("agent", a + " " + ev.status);
      break;
    }
    case "run_finished":
      S.outputs.summary = ev.summary;
      S.nodeStatus["summary"] = ev.status === "blocked" ? "blocked" : "done";
      S.traversed.add(eid("triage", "summary"));
      S.liveEdges.clear();
      if (ev.status === "blocked") { setProgress(S.progressIndex, "blocked"); setGuardrail("blocked", "blocked"); }
      else { setProgress(4, "complete"); if ($("guardrailChip").className.indexOf("g-blocked") < 0) setGuardrail("clear", "clear"); }
      updateGraph();
      log("run", "finished · " + ev.status, ev.status === "ok" ? "ok" : "deny");
      break;
    case "note": log("note", ev.message); break;
    case "error": log("error", ev.message, "deny"); break;
  }
}

// ───────── run ─────────
function resetRun() {
  S.outputs = {}; S.agentTools = {}; S.nodeStatus = {}; S.traversed = new Set(); S.liveEdges = new Map();
  S.selected = null; S.progressIndex = -1; S.progressStatus = "idle";
  Object.values(packetEls).forEach((c) => c.remove());
  for (const k in packetEls) delete packetEls[k];
  $("traceId").textContent = "—"; setGuardrail("idle", "idle");
  buildProgress(); updateGraph(); renderInspector(null); $("log").innerHTML = "";
}

async function run() {
  const alert = $("alertText").value.trim();
  if (!alert || S.running) return;
  S.running = true; $("runBtn").disabled = true;
  resetRun();
  try {
    const res = await fetch("/api/run/stream", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert, scenario_id: window.__scenario || null }),
    });
    if (!res.ok || !res.body) throw new Error("HTTP " + res.status);
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf("\n\n")) >= 0) {
        const chunk = buf.slice(0, idx); buf = buf.slice(idx + 2);
        const line = chunk.split("\n").find((l) => l.startsWith("data:"));
        if (!line) continue;
        try { handle(JSON.parse(line.slice(5).trim())); } catch (e) {}
      }
    }
  } catch (e) {
    log("error", e.message, "deny");
  } finally {
    S.running = false; $("runBtn").disabled = false;
  }
}

// ───────── scenarios ─────────
async function loadScenarios() {
  const list = $("scenarioList");
  try {
    const res = await fetch("/api/scenarios");
    const scenarios = await res.json();
    list.innerHTML = "";
    scenarios.forEach((sc, i) => {
      const b = mk("button", "scenario-btn", `<strong>${esc(sc.title)}</strong><span>${esc(sc.description)}</span>`);
      b.type = "button";
      b.onclick = () => {
        document.querySelectorAll(".scenario-btn").forEach((x) => x.classList.remove("active"));
        b.classList.add("active"); $("alertText").value = sc.alert; window.__scenario = sc.id;
      };
      list.appendChild(b);
      if (i === 0) b.click();
    });
  } catch (e) { list.innerHTML = `<div style="color:var(--faint);font-size:12px">Could not load scenarios.</div>`; }
}

// ───────── init ─────────
$("runBtn").onclick = run;
$("resetBtn").onclick = resetRun;
$("zoomIn").onclick = () => applyZoom(S.zoom + 0.1);
$("zoomOut").onclick = () => applyZoom(S.zoom - 0.1);
$("zoomReset").onclick = () => applyZoom(0.9);
$("toggleGuardrail").onclick = () => {
  S.showGuardrail = !S.showGuardrail;
  const b = $("toggleGuardrail");
  b.classList.toggle("on", S.showGuardrail);
  b.textContent = S.showGuardrail ? "Hide Guardrail" : "Show Guardrail";
  updateGraph();
};
$("toggleRedTeam").onclick = () => {
  S.showRedTeam = !S.showRedTeam;
  const b = $("toggleRedTeam");
  b.classList.toggle("on", S.showRedTeam);
  b.textContent = S.showRedTeam ? "Hide Red Team" : "Show Red Team";
  updateGraph();
};
buildGraph();
buildProgress();
applyZoom(0.9);
loadScenarios();
