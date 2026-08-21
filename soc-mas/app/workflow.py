"""Orchestrator that links the SOC agents together.

Triage reads the alert and plans -> each task is routed to the specialist the
plan names (threat-intel / remediation / comms) -> results are collected. Every
step is streamed to the UI through the `emit` callback so the flow renders live.

The agent logic itself lives in agents.py; this file only sequences it and maps
plan tasks to agent calls.
"""

from __future__ import annotations

import uuid
from typing import Awaitable, Callable

from .config import settings
from . import agents, scenarios

Emit = Callable[[str, dict], Awaitable[None]]


class SocWorkflow:
    def list_scenarios(self) -> list[dict]:
        return scenarios.list_scenarios()

    async def run(self, alert: str, emit: Emit, scenario_id: str | None = None) -> dict:
        trace_id = uuid.uuid4().hex[:12]
        await emit("run_started", {"trace_id": trace_id, "scenario_id": scenario_id, "alert": alert})

        # Pick the implementation per backend. Triage runner differs too:
        # distributed/inprocess plan via the proxy in-process; agents_http hits
        # the triage service.
        if settings.backend == "distributed":
            from . import distributed as impl
            triage_run = agents.run_triage
            if not (settings.proxy_base_url and settings.proxy_token):
                await emit("error", {"message": "distributed backend requires CALYPSOAI_OPENAI_API_BASE + CALYPSOAI_TOKEN for the LLM proxy."})
                await emit("run_finished", {"trace_id": trace_id, "status": "error", "summary": "missing proxy credentials"})
                return {"trace_id": trace_id, "status": "error"}
        elif settings.backend == "agents_http":
            from . import agents_http as impl
            triage_run = impl.run_triage
        else:
            impl = agents
            triage_run = agents.run_triage

        results: list[dict] = []
        try:
            # 1) Triage -> plan
            plan = await triage_run(alert, emit)
            tasks = plan.get("tasks", []) if isinstance(plan, dict) else []

            # 2) Route each task to its specialist
            for task in tasks:
                await agents.pace()
                agent = (task.get("agent") or "").strip()
                payload = task.get("payload") or {}
                action = task.get("action") or ""

                if agent == "threat-intel":
                    indicator = payload.get("indicator") or action or alert
                    r = await impl.run_tool_agent(
                        "threat-intel", agents.THREAT_INTEL_PROMPT,
                        f"Investigate: {indicator}", emit)
                    results.append({"agent": agent, "result": r})

                elif agent == "remediation":
                    if payload.get("sql"):
                        task_text = f"{action}. Use execute_db_query with: {payload['sql']}"
                    elif payload.get("hostname"):
                        task_text = f"{action} (host {payload['hostname']}). Use quarantine_host."
                    else:
                        task_text = action or "Perform the assigned remediation."
                    r = await impl.run_tool_agent(
                        "remediation", agents.REMEDIATION_PROMPT, task_text, emit)
                    results.append({"agent": agent, "result": r})

                elif agent == "comms":
                    skill = task.get("skill") or "notify-internal"
                    # Triage dispatches the A2A call, so the caller identity is agent-triage.
                    r = await impl.run_comms(skill, payload, caller="agent-triage", emit=emit)
                    results.append({"agent": agent, "skill": skill, "result": r})

                else:
                    await emit("note", {"message": f"skipping unknown agent {agent!r}"})

            summary = _summarize(plan, results)
            await emit("run_finished", {"trace_id": trace_id, "status": "ok", "summary": summary})
            return {"trace_id": trace_id, "plan": plan, "results": results, "summary": summary}

        except agents.GuardrailBlocked as exc:
            await emit("run_finished", {"trace_id": trace_id, "status": "blocked",
                                        "summary": f"Run halted: {exc.agent} was blocked by F5 AI Guardrails."})
            return {"trace_id": trace_id, "status": "blocked", "agent": exc.agent, "detail": exc.detail}

        except Exception as exc:  # noqa: BLE001 - surface connectivity/auth errors to the UI
            await emit("error", {"message": f"{type(exc).__name__}: {exc}"})
            await emit("run_finished", {"trace_id": trace_id, "status": "error",
                                        "summary": f"Run failed: {exc}"})
            return {"trace_id": trace_id, "status": "error", "detail": str(exc)}


def _summarize(plan: dict, results: list[dict]) -> dict:
    denials = []
    for r in results:
        res = r.get("result") or {}
        if isinstance(res, dict):
            if res.get("denied"):
                denials.append(f"{r['agent']}:{res.get('reason', 'denied')}")
            if res.get("outcome") == "failed":
                denials.append(f"{r['agent']}:{res.get('summary', 'failed')}")
    return {
        "severity": plan.get("severity") if isinstance(plan, dict) else None,
        "agents_run": [r.get("agent") for r in results],
        "blocked_actions": denials,
    }
