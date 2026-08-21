"""agents_http backend (Option C1).

The three agents run as HTTP services (each wraps its real agent.py loop via
c1/shim.py). This module is the orchestrator side: for each agent it POSTs the
task to the agent's `/run` SSE endpoint and relays the streamed events into the
UI's event stream — so the actual agent containers do the real work (real
Keycloak tokens, real MCP session, real Postgres) and the UI is unchanged.

Comms is already an A2A HTTP service, so we call it directly (reusing the real
A2A client from the distributed backend).
"""

from __future__ import annotations

import json
from typing import Awaitable, Callable

import httpx

from .config import settings
from . import agents, distributed

Emit = Callable[[str, dict], Awaitable[None]]

# reuse the real A2A call to the Comms container
run_comms = distributed.run_comms


def _url_for(agent: str) -> str:
    if agent == "triage":
        return settings.triage_url
    if agent == "threat-intel":
        return settings.threat_intel_url
    if agent == "remediation":
        return settings.remediation_url
    raise ValueError(f"no service URL for agent {agent!r}")


async def _relay(agent: str, task: str, task_field: str, emit: Emit) -> dict:
    """POST the task to the agent service and relay its SSE events."""
    await emit("agent_started", {"agent": agent, "role": agents.AGENT_ROLE[agent]})
    await emit("agent_input", {"agent": agent, "text": task})

    url = f"{_url_for(agent).rstrip('/')}/run"
    result: dict = {}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=10.0)) as client:
            async with client.stream("POST", url, json={task_field: task}) as resp:
                if resp.status_code != 200:
                    text = (await resp.aread()).decode("utf-8", "replace")
                    await emit("error", {"message": f"{agent} service HTTP {resp.status_code}: {text[:200]}"})
                    await emit("agent_finished", {"agent": agent, "status": "error"})
                    return {}

                buf = ""
                async for chunk in resp.aiter_text():
                    buf += chunk
                    while "\n\n" in buf:
                        frame, buf = buf.split("\n\n", 1)
                        line = next((l for l in frame.split("\n") if l.startswith("data:")), None)
                        if not line:
                            continue
                        try:
                            ev = json.loads(line[5:].strip())
                        except Exception:
                            continue
                        kind = ev.get("type")

                        if kind == "tool_call":
                            await emit("tool_call", {
                                "agent": agent,
                                "tool": ev.get("tool"), "args": ev.get("args"),
                                "scope": ev.get("scope"), "allowed": ev.get("allowed"),
                                "denied_reason": ev.get("denied_reason"), "result": ev.get("result"),
                            })
                        elif kind == "message":
                            result = ev.get("content")
                            await emit("agent_message", {
                                "agent": agent,
                                "kind": "plan" if agent == "triage" else "result",
                                "content": result,
                            })
                        elif kind == "guardrail_blocked":
                            detail = {k: v for k, v in ev.items() if k != "type"}
                            await emit("guardrail_blocked", {"agent": agent, **detail})
                            await emit("agent_finished", {"agent": agent, "status": "blocked"})
                            raise agents.GuardrailBlocked(agent, detail)
                        elif kind == "error":
                            await emit("error", {"message": f"{agent}: {ev.get('message')}"})
                        # "started" (session_id) is informational; ignore for now
    except agents.GuardrailBlocked:
        raise
    except Exception as exc:  # connection / stream errors
        await emit("error", {"message": f"{agent} service call failed: {exc}"})
        await emit("agent_finished", {"agent": agent, "status": "error"})
        return {}

    await emit("agent_finished", {"agent": agent, "status": "ok"})
    return result if isinstance(result, dict) else {"result": result}


async def run_triage(alert: str, emit: Emit) -> dict:
    return await _relay("triage", alert, "alert", emit)


async def run_tool_agent(agent: str, system_prompt: str, task: str, emit: Emit) -> dict:
    # system_prompt is owned by the agent service; ignored here.
    return await _relay(agent, task, "task", emit)
