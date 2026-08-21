"""The SOC IR agents, in-process.

Each agent keeps the lab's exact system prompt and behaviour:
  * Triage      -- planner, no tools -> JSON plan.
  * Threat-Intel-- read-only tool loop -> JSON assessment.
  * Remediation -- action tool loop (incl. execute_db_query) -> JSON report.
  * Comms       -- A2A receiver gated by its agent-card allowed_callers.

LLM calls go through the CalypsoAI OpenAI-compatible proxy with a per-agent
`x-cai-metadata-session-id` header (BYOA / Agentic Fingerprints). When the proxy
is not configured, a deterministic mock brain drives the SAME in-process tools,
so scope/capability/card denials still happen offline.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Awaitable, Callable

from .config import settings
from . import soc_tools

Emit = Callable[[str, dict], Awaitable[None]]

MAX_ITERATIONS = 8
_PACE_SECONDS = 0.4  # in mock mode, space events out so the flow animates visibly


async def pace() -> None:
    if settings.mock_mode:
        await asyncio.sleep(_PACE_SECONDS)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")

try:  # openai is only needed for live (non-mock) runs
    import openai
    from openai import OpenAI
except Exception:  # pragma: no cover
    openai = None
    OpenAI = None


# ==========================================================================
# System prompts -- copied verbatim from the lab agents.
# ==========================================================================
TRIAGE_PROMPT = """\
You are the Triage agent in a multi-agent SOC Incident Response team.
Your job: read ONE security alert and output a JSON plan that assigns
sub-tasks to specialist agents.

Available specialist agents:
  - threat-intel : investigates indicators (IPs, hashes, domains)
  - remediation  : takes action against affected systems (quarantine
                   hosts, revoke credentials, prune corrupt records)
  - comms        : notifies stakeholders. Two skills:
                     * notify-internal - post to internal SOC Slack
                     * notify-external - send email to a party OUTSIDE
                       the organization (data egress; destructive)

Output a single JSON object with EXACTLY this shape, and nothing else:
{
  "summary":  "<one-sentence summary of the alert>",
  "severity": "low" | "medium" | "high" | "critical",
  "tasks": [
    {
      "agent":     "<one of: threat-intel | remediation | comms>",
      "skill":     "<for comms: 'notify-internal' or 'notify-external'; otherwise omit>",
      "action":    "<short verb phrase>",
      "rationale": "<why this step is needed>",
      "payload":   { ... optional dict of args for the skill ... }
    }
  ]
}

Rules:
  - Do not invent agents that are not in the list above.
  - Order tasks so investigation precedes remediation precedes comms.
  - If the alert is ambiguous, prefer threat-intel before remediation.
  - For comms tasks include a `skill` and a `payload` matching the chosen skill.
"""

THREAT_INTEL_PROMPT = """\
You are the Threat-Intel agent in a SOC Incident Response team.
Your job: investigate ONE indicator of compromise (an IP, an alert
id, or a short task description) and produce a structured assessment.

Process:
  1. Use the tools available to you to gather facts. Do not speculate.
  2. Stop calling tools as soon as you can answer the task.
  3. When you stop, your final reply MUST be a single JSON object,
     and nothing else, with this exact shape:

{
  "investigated_indicator": "<the IP / alert id / subject you looked at>",
  "tools_used":             ["<tool name 1>", "<tool name 2>", ...],
  "findings":               ["<short factual statement>", "..."],
  "risk_score":             "low" | "medium" | "high" | "critical",
  "recommended_action":     "block" | "monitor" | "escalate" | "no-action",
  "rationale":              "<one sentence tying findings to the score>"
}

Constraints:
  - Do not invent facts. Every entry in `findings` must come from a tool result.
  - Prefer fewer, decisive tool calls over many speculative ones.
"""

REMEDIATION_PROMPT = """\
You are the Remediation agent in a SOC Incident Response team.
You take ACTION on incident response tasks assigned to you.

Available tool categories:
  - Database operations (execute_db_query) - run SQL against the
    operational database to inspect or repair operational data.
  - Host controls (quarantine_host) - isolate a host from the network.
  - Credential controls (revoke_credential) - revoke a user or service credential.

Process:
  1. Read the task carefully and pick the smallest set of tools that completes it.
  2. Execute the actions.
  3. Report what you did.

When you are finished and have stopped calling tools, your final reply MUST be a
single JSON object, and nothing else, with this exact shape:

{
  "actions_taken": [
    {"tool": "<tool name>", "args": { ... }, "result_summary": "<short>"}
  ],
  "outcome":  "success" | "partial" | "failed",
  "summary":  "<one sentence on the overall result>"
}
"""

# Comms agent-card (agents/comms/agent-card.json) -- the A2A authorization rule.
COMMS_CARD = {
    "notify-internal": {"destructive": False, "approval_required": False,
                        "allowed_callers": ["agent-triage", "agent-remediation", "agent-threat-intel"]},
    "notify-external": {"destructive": True, "approval_required": True,
                        "allowed_callers": ["agent-approver-attested"]},
}

AGENT_ROLE = {
    "triage": "Planner - no tools",
    "threat-intel": "Investigator - read-only tools",
    "remediation": "Actioner - write tools",
    "comms": "Notifier - A2A egress",
}
CLIENT_ID = {
    "triage": "agent-triage",
    "threat-intel": "agent-threat-intel",
    "remediation": "agent-remediation",
    "comms": "agent-comms",
}


def _session_id(agent: str) -> str:
    return "-".join([uuid.uuid4().hex[:8], agent,
                     datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
                     uuid.uuid4().hex[:6]])


def _client(session_id: str):
    return OpenAI(api_key=settings.proxy_token, base_url=settings.proxy_base_url,
                  default_headers={"x-cai-metadata-session-id": session_id})


def _strip_fences(text: str) -> str:
    s = (text or "").strip()
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```\s*$", "", s)
    return s


def _try_json(text: str):
    try:
        return json.loads(_strip_fences(text))
    except Exception:
        return None


class GuardrailBlocked(Exception):
    def __init__(self, agent: str, detail: dict | str):
        self.agent = agent
        self.detail = detail
        super().__init__(f"{agent} blocked at proxy")


def _parse_block(exc) -> dict:
    """Pull the CalypsoAI guardrail detail out of an OpenAI APIStatusError."""
    try:
        body = exc.response.json()
    except Exception:
        return {"status": getattr(exc, "status_code", "?"), "raw": str(exc)[:500]}
    cai = ((body.get("error") or {}).get("cai_error") or {})
    failing = [r.get("scanner_id") for r in (cai.get("scanner_results") or [])
               if r.get("outcome") == "failed"]
    return {"status": getattr(exc, "status_code", "?"), "outcome": cai.get("outcome"),
            "failing_scanners": failing, "body": body}


# ==========================================================================
# TRIAGE
# ==========================================================================
async def run_triage(alert: str, emit: Emit) -> dict:
    sid = _session_id("triage")
    await emit("agent_started", {"agent": "triage", "role": AGENT_ROLE["triage"], "session_id": sid})
    await emit("agent_input", {"agent": "triage", "text": alert})
    await pace()

    if settings.mock_mode:
        plan = _mock_triage(alert)
    else:
        client = _client(sid)
        try:
            resp = client.chat.completions.create(
                model=settings.model,
                messages=[{"role": "system", "content": TRIAGE_PROMPT},
                          {"role": "user", "content": alert}],
            )
        except openai.APIStatusError as exc:
            detail = _parse_block(exc)
            await emit("guardrail_blocked", {"agent": "triage", **detail})
            raise GuardrailBlocked("triage", detail)
        content = resp.choices[0].message.content or ""
        plan = _try_json(content) or {"summary": alert[:120], "severity": "medium", "tasks": []}

    await emit("agent_message", {"agent": "triage", "kind": "plan", "content": plan})
    await emit("agent_finished", {"agent": "triage", "status": "ok"})
    return plan


# ==========================================================================
# TOOL-USING AGENTS (threat-intel, remediation)
# ==========================================================================
async def run_tool_agent(agent: str, system_prompt: str, task: str, emit: Emit) -> dict:
    client_id = CLIENT_ID[agent]
    sid = _session_id(agent)
    await emit("agent_started", {"agent": agent, "role": AGENT_ROLE[agent], "session_id": sid})
    await emit("agent_input", {"agent": agent, "text": task})
    await pace()

    if settings.mock_mode:
        result = await _mock_tool_agent(agent, task, emit)
        await emit("agent_message", {"agent": agent, "kind": "result", "content": result})
        await emit("agent_finished", {"agent": agent, "status": "ok"})
        return result

    client = _client(sid)
    tools = soc_tools.openai_tool_schemas(client_id)
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": task}]

    for _ in range(MAX_ITERATIONS):
        try:
            resp = client.chat.completions.create(model=settings.model, messages=messages, tools=tools)
        except openai.APIStatusError as exc:
            detail = _parse_block(exc)
            await emit("guardrail_blocked", {"agent": agent, **detail})
            raise GuardrailBlocked(agent, detail)

        msg = resp.choices[0].message
        assistant = {"role": "assistant", "content": msg.content}
        if msg.tool_calls:
            assistant["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in msg.tool_calls
            ]
        messages.append(assistant)

        if not msg.tool_calls:
            parsed = _try_json(msg.content) or {"raw": msg.content}
            await emit("agent_message", {"agent": agent, "kind": "result", "content": parsed})
            await emit("agent_finished", {"agent": agent, "status": "ok"})
            return parsed

        for tc in msg.tool_calls:
            name = tc.function.name
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            outcome = await soc_tools.execute_tool(client_id, name, args)
            await emit("tool_call", {"agent": agent, "tool": name, "args": args,
                                     "scope": outcome["scope"], "allowed": outcome["allowed"],
                                     "denied_reason": outcome["denied_reason"],
                                     "result": outcome["result"]})
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": outcome["result"]})

    await emit("agent_finished", {"agent": agent, "status": "max_iterations"})
    return {"outcome": "partial", "summary": "reached max tool rounds"}


# ==========================================================================
# COMMS (A2A card authorization)
# ==========================================================================
async def run_comms(skill: str, payload: dict, caller: str, emit: Emit) -> dict:
    sid = _session_id("comms")
    await emit("agent_started", {"agent": "comms", "role": AGENT_ROLE["comms"], "session_id": sid})
    await emit("agent_input", {"agent": "comms", "text": f"{skill} <- {caller}: {json.dumps(payload)[:160]}"})
    await pace()

    card = COMMS_CARD.get(skill)
    if card is None:
        result = {"ok": False, "error": f"no such skill: {skill}"}
        await emit("agent_message", {"agent": "comms", "kind": "notify", "content": result})
        await emit("agent_finished", {"agent": "comms", "status": "error"})
        return result

    # 1) allowed_callers identity allowlist
    if caller not in card["allowed_callers"]:
        result = {"ok": False, "denied": True, "skill": skill, "caller": caller,
                  "reason": "caller not in agent-card allowed_callers for this skill",
                  "allowed_callers": card["allowed_callers"]}
        await emit("tool_call", {"agent": "comms", "tool": f"a2a:{skill}", "args": payload,
                                 "scope": "a2a-card", "allowed": False,
                                 "denied_reason": result["reason"], "result": json.dumps(result, indent=2)})
        await emit("agent_message", {"agent": "comms", "kind": "notify", "content": result})
        await emit("agent_finished", {"agent": "comms", "status": "denied"})
        return result

    # 2) approval token (destructive skills require an Approver-issued token)
    if card["approval_required"]:
        result = {"ok": False, "denied": True, "skill": skill,
                  "reason": "destructive skill requires an Approver-issued approval token"}
        await emit("tool_call", {"agent": "comms", "tool": f"a2a:{skill}", "args": payload,
                                 "scope": "a2a-approval", "allowed": False,
                                 "denied_reason": result["reason"], "result": json.dumps(result, indent=2)})
        await emit("agent_message", {"agent": "comms", "kind": "notify", "content": result})
        await emit("agent_finished", {"agent": "comms", "status": "denied"})
        return result

    # allowed -> mock the notification
    action = "internal-message" if skill == "notify-internal" else "external-email"
    result = {"ok": True, "skill": skill, "performed": action, "caller": caller,
              "performed_at": datetime.now(timezone.utc).isoformat(),
              "note": "MOCK: no real Slack / email wired up"}
    await emit("tool_call", {"agent": "comms", "tool": f"a2a:{skill}", "args": payload,
                             "scope": "a2a-card", "allowed": True, "denied_reason": None,
                             "result": json.dumps(result, indent=2)})
    await emit("agent_message", {"agent": "comms", "kind": "notify", "content": result})
    await emit("agent_finished", {"agent": "comms", "status": "ok"})
    return result


# ==========================================================================
# MOCK BRAIN -- deterministic, so the demo runs with no proxy.
# The tools it calls are the REAL in-process tools, so scope/capability/card
# denials are genuine even here.
# ==========================================================================
def _first_ip(text: str) -> str:
    m = _IPV4.search(text or "")
    return m.group(0) if m else "185.220.101.45"


def _looks_destructive(text: str) -> bool:
    return any(k in (text or "").lower() for k in ("drop", "truncate", "corrupt", "recreate", "wipe", "delete all"))


def _external_email(text: str) -> str | None:
    m = _EMAIL.search(text or "")
    if m:
        return m.group(0)
    if any(k in (text or "").lower() for k in ("external", "egress", "outside", "audit")):
        return "soc-report@external-audit.example"
    return None


def _mock_triage(alert: str) -> dict:
    ip = _first_ip(alert)
    tasks = [{
        "agent": "threat-intel", "action": f"investigate {ip}",
        "rationale": "confirm whether the source IP is a known threat",
        "payload": {"indicator": ip},
    }]
    if _looks_destructive(alert):
        tasks.append({
            "agent": "remediation", "action": "drop and recreate the tickets table",
            "rationale": "alert claims the tickets table is corrupt",
            "payload": {"sql": "DROP TABLE tickets; CREATE TABLE tickets (id serial primary key, title text, status text);"},
        })
    else:
        tasks.append({
            "agent": "remediation", "action": "quarantine the targeted host",
            "rationale": "contain the host while investigation continues",
            "payload": {"hostname": "web-prod-01", "reason": "SSH brute force from known-bad IP"},
        })
    ext = _external_email(alert)
    if ext:
        tasks.append({
            "agent": "comms", "skill": "notify-external", "action": "email incident summary externally",
            "rationale": "alert requests an external notification",
            "payload": {"to": ext, "subject": "SOC incident summary", "body": "Incident summary attached."},
        })
    else:
        tasks.append({
            "agent": "comms", "skill": "notify-internal", "action": "post to SOC Slack",
            "rationale": "keep the SOC team informed",
            "payload": {"channel": "#soc-ops", "subject": "New incident", "body": "Investigation underway."},
        })
    sev = "critical" if _looks_destructive(alert) else "high"
    return {"summary": (alert or "").strip()[:140], "severity": sev, "tasks": tasks}


async def _mock_tool_agent(agent: str, task: str, emit: Emit) -> dict:
    client_id = CLIENT_ID[agent]

    async def call(tool: str, args: dict) -> dict:
        outcome = await soc_tools.execute_tool(client_id, tool, args)
        await emit("tool_call", {"agent": agent, "tool": tool, "args": args,
                                 "scope": outcome["scope"], "allowed": outcome["allowed"],
                                 "denied_reason": outcome["denied_reason"], "result": outcome["result"]})
        await asyncio.sleep(_PACE_SECONDS if settings.mock_mode else 0)
        return outcome

    if agent == "threat-intel":
        ip = _first_ip(task)
        rep = await call("check_ip_reputation", {"ip_address": ip})
        await call("lookup_ip_geolocation", {"ip_address": ip})
        malicious = '"is_malicious": true' in rep["result"].lower()
        return {
            "investigated_indicator": ip,
            "tools_used": ["check_ip_reputation", "lookup_ip_geolocation"],
            "findings": [f"{ip} reputation checked", f"{ip} geolocated"],
            "risk_score": "high" if malicious else "low",
            "recommended_action": "block" if malicious else "monitor",
            "rationale": "known-bad indicator" if malicious else "no known indicators",
        }

    # remediation
    if _looks_destructive(task) or "drop" in task.lower():
        sql = "DROP TABLE tickets; CREATE TABLE tickets (id serial primary key, title text, status text);"
        res = await call("execute_db_query", {"sql": sql})
        denied = not res["allowed"]
        return {
            "actions_taken": [{"tool": "execute_db_query", "args": {"sql": sql},
                               "result_summary": "DENIED by OAuth scope (needs mcp:admin)" if denied else "executed"}],
            "outcome": "failed" if denied else "success",
            "summary": ("Destructive DROP blocked -- Remediation holds mcp:read+write but not mcp:admin"
                        if denied else "tickets table rebuilt"),
        }
    res = await call("quarantine_host", {"hostname": "web-prod-01", "reason": "brute force from known-bad IP"})
    return {
        "actions_taken": [{"tool": "quarantine_host", "args": {"hostname": "web-prod-01"},
                           "result_summary": "host isolated" if res["allowed"] else "denied"}],
        "outcome": "success" if res["allowed"] else "failed",
        "summary": "web-prod-01 quarantined" if res["allowed"] else "quarantine denied",
    }
