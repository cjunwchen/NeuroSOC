# SOC IR Multi-Agent Demo

A single-page FastAPI demo that links the **agent-security-lab** SOC incident-response
agents together in a live "system flow" UI, styled after the **f5-ai-sec-multi-agent-system-app**.

Triage reads an alert and plans → the plan's tasks are routed to **Threat-Intel**,
**Remediation**, and **Comms** → every LLM call, tool call, scope check, and A2A
decision streams into the UI in real time.

## The flow view

The right panel is a live topology graph (modeled on the MAS app): nodes for the
alert, Triage, the three specialist agents, the F5 AI Guardrails proxy + model, the
SOC tools, and a case-summary sink — linked by labeled connectors. When you run:

- the **progress strip** advances Alert → Triage → Agent Execution → Tool Calls → Response;
- the **active agent pulses** and traffic animates along its connectors (packets flow
  from Triage into the working agent and up through the guardrail path to the model);
- **denied tools and agents turn red** (`execute_db_query`, `notify-external` in the
  poisoned run);
- **click any node** to inspect its output — the alert text, Triage's JSON plan, an
  agent's assessment/report plus the tool calls it made (with allowed/denied verdicts),
  a tool's arguments + result, or the guardrail block detail.

Controls: zoom (−/＋/Reset) and a **Guardrails** toggle to show/hide the proxy path.

## What is preserved from the lab

Each agent keeps its **exact system prompt** and behaviour from `agent-security-lab`:

| Agent | Behaviour | Final output |
|-------|-----------|--------------|
| Triage | planner, no tools | JSON plan `{summary, severity, tasks[]}` |
| Threat-Intel | read-only tool loop | JSON assessment `{risk_score, recommended_action, …}` |
| Remediation | action tool loop (incl. `execute_db_query`) | JSON report `{actions_taken, outcome, …}` |
| Comms | A2A receiver gated by its agent-card | `notify-internal` / `notify-external` result |

The lab's **two authorization layers** and the **A2A card** are reproduced in code, so the
same denials happen:

- **Capability manifest** (identity) — an agent only sees the tools it was granted
  (`mcp_server/capabilities.json`).
- **OAuth scope** (action) — `execute_db_query` resolves scope per SQL verb. Remediation
  holds `mcp:read` + `mcp:write` but **not** `mcp:admin`, so a `DROP TABLE` is denied.
- **A2A agent-card** — Comms `notify-external` only accepts `agent-approver-attested` and
  requires an approval token, so a Triage-dispatched external email is denied.

## Architecture caveat (read this)

The real lab is a **distributed** system: each agent is its own container, plus Keycloak
(OAuth 2.1), Postgres, and an MCP server over SSE. This demo runs all of that agent logic
**in a single FastAPI process** so it behaves like the MAS demo you can open in one browser
tab. The security *rules and outcomes* are identical; the *enforcement mechanism* is
in-process Python instead of live Keycloak/MCP.

- **Faithful and real here:** each agent's prompt and reasoning; the tool-calling loops; the
  BYOA per-agent `x-cai-metadata-session-id` header; the scope / capability / card denials;
  and — in live mode — the **F5 AI Guardrails block at the proxy** (a poisoned prompt is
  refused before the model sees it; the run halts and the failing scanners are shown).
- **Simulated:** the distributed transport (A2A over HTTP, MCP over SSE, Keycloak token
  introspection) and Postgres (an in-memory tickets table stands in).

If you want the full distributed enforcement, keep running the lab's `docker-compose`; this
app can later be pointed at those live services instead of the in-process stand-ins.

## Run it

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Option A — live, against your F5 AI Security proxy:
cp .env.example .env         # fill in CALYPSOAI_OPENAI_API_BASE + CALYPSOAI_TOKEN
#   (.env is auto-loaded)

# Option B — offline demo, no backend:
export MOCK_MODE=1

uvicorn app.main:app --reload --port 8020
# open http://localhost:8020
```

The top-right badge shows **MOCK MODE** or **LIVE · <model>** so you always know which path
you're on.

## Scenarios

- **Benign — SSH brute force**: clean flow. Investigate the Tor IP, quarantine the host,
  notify internal Slack. Everything allowed.
- **Poisoned — injected DROP + external email**: a prompt-injected alert steers Remediation
  to `DROP` the tickets table and Comms to email an outside auditor. Watch OAuth scope block
  the DROP and the A2A card block the egress — layer by layer.

## Layout

```
app/
  config.py      settings + mock-mode detection
  soc_tools.py   the SOC toolkit + scope/capability enforcement (from mcp_server/)
  agents.py      the 4 agents: exact prompts, proxy client, tool loops, mock brain
  workflow.py    orchestration: triage → specialists → comms, emits flow events
  scenarios.py   the two canned alerts
  main.py        FastAPI app + SSE stream
  ui/            single-page UI (index.html + static/app.js + static/styles.css)
```

## Live mode — run the real agent containers (Option C1)

The recommended way to wire this to your stack: your three agents run as real
HTTP services (each keeps its exact `agent.py`, wrapped by a small shim), and
soc-mas is *only an orchestrator* — it fires a task at each agent service and
relays the stream. The UI is unchanged. Enforcement is done by the real
services:

- **Triage** (planner service) returns its JSON plan via the CalypsoAI proxy.
- **Threat-Intel / Remediation** (tool services) fetch a real **Keycloak**
  `client_credentials` token, open a real **MCP** SSE session (real **capability
  manifest** + per-call **OAuth scope**), and `execute_db_query` hits real
  **Postgres**. A `DROP` returns a real `forbidden` (needs `mcp:admin`, which
  Remediation doesn't hold).
- **Comms** is called over real **A2A**; it introspects the `agent-triage` token
  and enforces its agent-card `allowed_callers` — `notify-external` returns a
  real `403`.

So every tool result, scope deny, and card deny you see comes from your
services. `agent.py` is never modified — the shim wraps it.

### Run it

Unzip this `soc-mas/` folder into the `agent-security-lab` repo root, then:

```bash
# 1) layer the shim onto the three agents (agent.py untouched; Dockerfile.orig kept)
./soc-mas/c1/install.sh

# 2) bring up the shimmed agents + orchestrator (paths resolve from the lab root)
docker compose -f docker-compose.yml -f soc-mas/c1/compose.c1.yml up -d --build

# open http://localhost:8020
```

`soc-mas/c1/compose.c1.yml` turns `triage`/`threat-intel`/`remediation` into
services (ports 9201/9202/9203 → 9200) and adds the `soc-mas` orchestrator on
:8020. It reads the lab's `.env`, so your `CALYPSOAI_*` creds and any
`*_OAUTH_CLIENT_SECRET` overrides carry over. To revert the agents to stock
batch form: `./soc-mas/c1/uninstall.sh`.

### For the denials to actually fire, keep the stack enforced

- `mcp-server`: `MCP_SKIP_AUTH` **unset** + capability manifest active (Module 2).
- `comms`: `COMMS_ENFORCE_CARD=1` (Slice B).

If you're on Slice A (auth off), nothing denies — expected. `notify-external`
stays denied unless you also wire the Approver token path (the `approver`
container on :9000); say the word and I'll add it.

`/health` reports `"backend":"agents_http"` so you can confirm the mode.

### Alternative: `BACKEND=distributed` (no agent changes)

If you ever want the same real enforcement *without* turning the agents into
services, `BACKEND=distributed` runs the specialist loops inside the
orchestrator against the same Keycloak/MCP/Comms/Postgres (the three agent
containers sit idle). It's in the code and needs only the endpoint env vars in
`.env.example`.

> Not affiliated with or endorsed by F5. Built for internal demo/enablement.
