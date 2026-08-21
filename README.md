# SOC IR Multi-Agent

A single-page visualization and orchestration layer for the
[**agent-security-lab**](https://github.com/therealnoof/agent-security-lab) SOC
incident-response agents, styled after the
[**f5-ai-sec-multi-agent-system-app**](https://github.com/f5devcentral/f5-ai-sec-multi-agent-system-app).

Fire a security alert and watch it move through **Triage → Threat-Intel →
Remediation → Comms** as a live topology graph: agents light up, traffic
animates along labeled connectors, tools resolve allowed/denied, and clicking
any node shows its output. Depending on the backend you choose, the security
denials on screen are either reproduced in code or **enforced for real by the
live lab stack** (Keycloak, MCP, Postgres, A2A).

> Built for internal demo / enablement.

---

## Contents

- [What it demonstrates](#what-it-demonstrates)
- [Project layout](#project-layout)
- [Quick start](#quick-start)
  - [A. Standalone demo (no backend)](#a-standalone-demo-no-backend)
  - [B. Wire to the real lab stack](#b-wire-to-the-real-lab-stack-option-c1)
- [Operating the stack](#operating-the-stack)
- [Using the UI](#using-the-ui)
- [Scenarios](#scenarios)
- [Configuration reference](#configuration-reference)
- [Ports](#ports)
- [How it works](#how-it-works)
- [Troubleshooting](#troubleshooting)
- [Validation & honest caveats](#validation--honest-caveats)
- [Reverting](#reverting)

---

## What it demonstrates

This lab simulates a multi-agent SOC incident response framework designed to detect and mitigate **prompt injection** attacks targeting agentic attack surfaces.

---

## Project layout

```
NeuroSOC/
├── PRD.md                  ← Full design doc
├── README.md               ← You are here
├── SETUP.md                ← Environment build for self-paced learners and instructors
├── docs/
│   ├── STUDENT_GUIDE.md    ← Module-by-module walkthrough with concept primers
│   └── INSTRUCTOR_GUIDE.md ← Per-module instructor notes (filling in as modules ship)
├── docker-compose.yml      ← Service wiring (Keycloak, Postgres, MCP server, agents)
├── scripts/
│   └── setup-ubuntu-22.sh  ← Idempotent lab-node bootstrap
├── agents/
│   ├── triage/             ← Module 0 vertical slice (planner; no tools)
│   ├── threat_intel/       ← (TBD)
│   ├── remediation/        ← (TBD)
│   ├── comms/              ← (TBD)
│   └── approver/           ← (TBD)
├── mcp_server/             ← Extended SOC + remediation MCP server (TBD)
├── keycloak/               ← Realm export, per-agent clients & scopes (TBD)
├── a2a/                    ← Agent cards, signing keys (TBD)
├── soc-mas/                ← UI orchestrator
├── policies/               ← CalypsoAI session/policy templates per module (TBD)
└── .gitignore

```

---

## Quick start

### A. Standalone demo (no backend)

Great for showing the flow on a laptop with nothing else running.

```bash
cd soc-mas
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

export MOCK_MODE=1                 # deterministic, no proxy needed
uvicorn app.main:app --reload --port 8020
# open http://localhost:8020
```

Drop `MOCK_MODE=1` and set `CALYPSOAI_OPENAI_API_BASE` + `CALYPSOAI_TOKEN` (see
[Configuration](#configuration-reference)) to run the agents' real reasoning
through the proxy while still simulating the security layer. The top-right badge
reads **MOCK MODE** or **LIVE · \<model\>** so you always know which path you're on.

### B. Wire to the real lab stack

the three agents operate as standalone HTTP microservices, while soc-mas serves 
strictly as the orchestrator—dispatching tasks to each service and relaying event 
streams. The agent containers execute backend workloads (Keycloak authentication, 
MCP tool calls, and PostgreSQL transactions), while inter-agent coordination runs 
over native Agent-to-Agent (A2A) protocols.

**Prerequisites:** CalypsoAI proxy creds are in the lab's `.env`.

```bash
# from the NeuroSOC repo root, with this soc-mas/ folder unzipped there:

# 1) layer the shim onto the three agents (backs up each Dockerfile to Dockerfile.orig)
bash soc-mas/c1/install.sh

# 2) build + start the shimmed agents and the orchestrator
docker compose -f docker-compose.yml -f soc-mas/c1/compose.c1.yml up -d --build

# open http://localhost:8020
```

The overlay (`soc-mas/c1/compose.c1.yml`) turns `triage` / `threat-intel` /
`remediation` into services (host ports 9201/9202/9203 → 9200) and adds the
`soc-mas` orchestrator on `:8020`. It reads the lab's `.env`, so your
`CALYPSOAI_*` creds overrides carry over.

---

## Operating the stack

Set them once per terminal to save typing:

```bash
export COMPOSE_FILE=docker-compose.yml:soc-mas/c1/compose.c1.yml
```

Then:

```bash
docker compose stop            # halt all containers (keeps containers + data)
docker compose start           # start them again (no rebuild) — reopen :8020
docker compose restart         # bounce all containers in place

docker compose ps              # status / health
docker compose logs -f soc-mas # tail a service's logs

# rebuild just the orchestrator after editing soc-mas code (agents keep running):
docker compose up -d --build soc-mas

# full teardown (removes containers + network, KEEPS named volumes):
docker compose down
# add -v ONLY to also wipe Keycloak realm state + tickets DB:
docker compose down -v
```

Without `COMPOSE_FILE`, prefix each with
`docker compose -f docker-compose.yml -f soc-mas/c1/compose.c1.yml …`.

- `stop`/`start` is the day-to-day pair — fast, keeps data, no rebuild.
- `stop`/`start` do **not** pick up code or `.env` changes; those need
  `up -d --build`.

---

## Using the UI

![NeuroSOC UI](<images/UI sampple.jpg>)

- **Left panel** — pick a scenario (or paste an alert) and click **Run incident
  response**.
- **Progress strip** — advances Alert → Triage → Agent Execution → Tool Calls →
  Response.
- **Topology graph** — the working agent pulses; traffic packets flow along its
  connectors and up through the guardrail path; **denied tools/agents turn red**.
- **Click any node** — the inspector shows that node's output: the alert text,
  Triage's JSON plan, an agent's assessment/report plus the tool calls it made
  (with allowed/denied verdicts and scope), a tool's args + result, or a
  guardrail block detail.
- **Controls** — zoom (−/＋/Reset); **Show/Hide Guardrail** toggles the F5
  proxy + model path; **Show/Hide Red Team** overlays a Red Team Module that
  probes Triage.

---

## Scenarios

- **Benign — SSH brute force.** Clean flow: investigate the Tor IP, quarantine
  the host, notify internal Slack. Everything allowed.
- **Poisoned — injected DROP + external email.** A prompt-injected alert steers
  Remediation to `DROP` the tickets table and Comms to email an outside auditor.
  OAuth scope blocks the DROP; the A2A card blocks the egress — layer by layer.
  (In live mode with prompt-injection scanners on, Triage may also be blocked at
  the proxy.)

> More to be added.

---

## Configuration reference

Set via environment (or the lab's `.env`, which soc-mas reads). Defaults assume
the compose network.

| Variable | Default | Used by | Purpose |
|---|---|---|---|
| `CALYPSOAI_OPENAI_API_BASE` | — | all (non-mock) | CalypsoAI base URL |
| `CALYPSOAI_TOKEN` | — | all (non-mock) | CalypsoAI project token |
| `CALYPSOAI_MODEL` | `gpt-4o-mini` | all | Model name |
| `MOCK_MODE` | — | `inprocess` | `1` forces the offline mock brain |
| `KEYCLOAK_ISSUER` | `http://keycloak:8080/realms/agent-lab` | distributed, agents_http (Comms) | Token + introspection issuer |
| `MCP_SERVER_URL` | `http://mcp-server:8000/sse` | distributed | MCP SSE endpoint |
| `COMMS_A2A_URL` | `http://comms:9100` | distributed, agents_http | Comms A2A base |
| `TRIAGE_URL` | `http://triage:9200` | agents_http | Triage service |
| `THREAT_INTEL_URL` | `http://threat-intel:9200` | agents_http | Threat-Intel service |
| `REMEDIATION_URL` | `http://remediation:9200` | agents_http | Remediation service |

`GET /health` reports `{"backend": ..., "mock_mode": ..., "model": ...}`.

---

## Ports

| Service | Host → container | Notes |
|---|---|---|
| soc-mas (UI) | `8020` | open this |
| triage | `9201 → 9200` | shim service |
| threat-intel | `9202 → 9200` | shim service |
| remediation | `9203 → 9200` | shim service |
| comms | `9100` | A2A |
| mcp-server | `8000` | SSE + `/health` |
| keycloak | `8080` | IdP |
| postgres | — | internal only |
| approver | `9000` | disabled by default (see Troubleshooting) |

---

## How it works

The UI never talks to agents directly — it consumes one event stream from
`POST /api/run/stream`. Every backend emits the same events
(`run_started`, `agent_started`, `agent_input`, `tool_call`, `agent_message`,
`guardrail_blocked`, `agent_finished`, `run_finished`), so the front end is
identical across all three modes. That SSE contract is the seam that lets the
enforcement move from "simulated in Python" to "real, in your containers"
without touching a line of UI.

Each agent's shim runs `agent.py`'s exact loop — same system prompt,
same Keycloak `client_credentials` token, same MCP SSE session, same tool
calls — and emits structured events instead of printing. The orchestrator POSTs
a task to each agent's `/run` endpoint, relays the events, and calls Comms over
real A2A. Denials are detected from the MCP server's `{"error":"forbidden",
"required_scope": ...}` response and from a Comms `403`.

---

## Troubleshooting

**`unknown shorthand flag: 'f'` on `docker compose -f …`**
Your Docker is invoking Compose v1 (or the plugin isn't wired). Use the
hyphenated `docker-compose -f … -f …`, or check `docker compose version`.

**`unable to prepare context: path ".../agents/approver" not found`**
The stock `docker-compose.yml` declares an `approver` service whose build
context isn't in the repo. The overlay parks it in an inactive `approver`
profile so `up` skips it. If you're on an older overlay, either update it or
name the service to skip approver via the dependency graph:
`docker compose -f docker-compose.yml -f soc-mas/c1/compose.c1.yml up -d --build soc-mas`.

**Agents never become healthy / `soc-mas` waits forever**
You probably didn't run the shim installer, so the agents built in stock
one-shot form (they exit instead of serving on :9200). Run
`bash soc-mas/c1/install.sh`, then `up -d --build` again. Check with
`docker logs asl-triage` — you want uvicorn on :9200, not "python agent.py …
exited".

**No denials appear in the poisoned run**
The stack is on Slice A (auth off). Enable enforcement: `mcp-server` with
`MCP_SKIP_AUTH` unset + capability manifest on, `comms` with
`COMMS_ENFORCE_CARD=1`.

**A run errors on a specific agent**
The UI shows an error line for that agent. Most likely a Keycloak `401` on token
fetch (client-secret mismatch — check the `*_OAUTH_CLIENT_SECRET` values) or an
MCP SSE handshake error (`MCP_SERVER_URL` / mcp-server health). `docker compose
logs -f <service>` has the detail.

**`notify-external` succeeds instead of being denied**
Enforcement is off, or an Approver token path was added. By design it stays
denied (blocked egress) unless the Approver flow is wired.

---

## Validation & honest caveats

- **What's real in C1 / distributed:** the agents' prompts and loops; the
  Keycloak tokens; the MCP capability manifest + per-call scope; Postgres; the
  A2A card; and (in live mode) an actual F5 AI Guardrails block at the proxy.
- **What's simulated in `inprocess`:** the OAuth/MCP/A2A enforcement is
  reproduced in Python, and with no proxy creds a deterministic mock brain
  drives the tools. Good for the visual/narrative, **not** proof the controls
  are correctly enforced — for that, use `agents_http` (C1) or `distributed`
  against the real stack.
- The distributed/agents_http backends were validated with mock harnesses that
  reproduce the real request/response shapes (a `DROP` → `forbidden` needing
  `mcp:admin`; a Comms `403`); end-to-end verification is done against your live
  stack.

---

## Reverting

- **Agents back to stock batch form:** `bash soc-mas/c1/uninstall.sh` (restores
  each `Dockerfile.orig`, removes the shim). After this, `start` will fail for
  the agents — re-run the shim install + `up --build soc-mas` to serve again.
- **Remove just soc-mas:** `docker rm -f asl-soc-mas` and delete its image.
- **Full teardown:** `docker compose … down` (add `-v` to wipe volumes).
