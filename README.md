# Hunter 2

LLM-driven recon + monitoring suite. Successor to Hunter 1.0.

Two design goals:

1. **LLM-driven investigation.** Ask "what's interesting in today's diff?" and get a reasoned answer, not raw data. A local Gemma4 26B (llama.cpp on RunPod) drives a ReAct loop: observe → think → act.
2. **Airtight scope safety.** Out-of-scope hosts never touched. Every tool execution audited. Scope check is code, not prompt — LLM cannot bypass it.

## Quickstart

```bash
git clone https://github.com/Lukaspspsl/Hunter2.git
cd Hunter2
uv venv && uv pip install -r requirements.txt
cp configs/programs.yaml configs/programs.yaml.local   # edit scope
./hunter2 tools                                        # check binaries
./hunter2 scan example_vdp                             # passive scan, no LLM
./hunter2 chat --program example_vdp                   # REPL with LLM
./hunter2 dashboard                                    # read-only UI at :8000
./hunter2 scheduler                                    # cron loop (Railway service)
```

## CLI

| Command | What it does |
|---|---|
| `./hunter2 chat [-p NAME] [--no-llm]` | Interactive REPL. LLM proposes actions; user approves escalation. `--no-llm` keeps slash commands working when RunPod pod is off. |
| `./hunter2 scan PROGRAM` | One-shot passive scan. No LLM. |
| `./hunter2 programs` | List configured programs + scope summary. |
| `./hunter2 tools` | Show tool registry + binary availability. |
| `./hunter2 scheduler` | Run APScheduler cron loop until SIGINT. Drives passive scans per `programs.yaml`. |
| `./hunter2 dashboard --host 0.0.0.0 --port 8000` | FastAPI read-only dashboard. |

### REPL slash commands

```
/help                this help
/program <name>      switch active program
/level               show aggressiveness ceiling
/scan                run passive scan now (no LLM)
/history             last 20 tool executions
/no-llm [on|off]     toggle LLM offline mode
/exit                quit
```

Type free text instead of a slash command to talk to the LLM. The engine emits `<think>`, `<action>`, optional `<escalate>`, then `<final>`. Each `<action>` runs through ToolCaller — scope-checked, ceiling-enforced, audited. Each `<escalate>` pauses the loop for explicit user yes/no.

## Configuration

Three files under `configs/`:

- **`programs.yaml`** — bug bounty programs. Each entry: `platform`, `aggressiveness` (passive/active/aggressive), `in_scope`, `out_of_scope`, `rules`, `notify` toggles, `schedule.cron`.
- **`tools.yaml`** — single source of truth for the tool registry. Each tool: `binary`, `description`, `min_level`, `rate_multiplier`, `timeout`, `args`. Descriptions feed the LLM system prompt.
- **`llm.yaml`** — llama.cpp endpoint, model name, context length, temperature, session TTL.

`${VAR}` substitution from env. Example:

```yaml
# configs/programs.yaml
programs:
  example_vdp:
    platform: hackerone
    aggressiveness: passive
    in_scope:
      - "*.example.com"
      - example.com
    out_of_scope:
      - careers.example.com
      - "*.staging.example.com"
    notify:
      on_new_subdomain: true
      on_critical_vuln: true
      on_scope_violation_attempt: true
    schedule:
      cron: "0 6 * * *"
      enabled: true
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  RAILWAY (always-on)                     │
│                                                          │
│  Cron loop  ──┐   FastAPI dashboard   Terminal REPL      │
│               │       (read-only)     (./hunter2 chat)   │
│               ▼                                          │
│         Orchestrator ◄── ReAct engine ◄── LLMClient ─────┼──► RunPod
│               │                                          │    llama.cpp
│         ┌─────┴─────┬──────────────┐                     │    Gemma4 26B
│         ▼           ▼              ▼                     │    :8090
│   Tool registry  Scope engine   SQLite                   │    on-demand
│   (tools.yaml)   (hard gate)    /app/data                │
└─────────────────────────────────────────────────────────┘
```

Six packages under `src/`:

| Path | Role |
|---|---|
| `core/` | DB models, scope engine, executor, logger, diff. ScopeEngine is the hard gate — every tool calls `assert_in_scope(target)` before subprocess. |
| `modules/` | Per-tool wrappers: httpx_prober, dnsx_resolver, gau_collector, alterx_permuter, tech_detector, notifier, plus Hunter 1.0 ports (subdomain_enum, port_scanner, etc.). |
| `llm/` | LLMClient (OpenAI-compat HTTP to llama.cpp), prompt builder, ToolCaller (action parser + audit), ReActEngine (observe→think→act loop). |
| `orchestrator.py` | Passive pipeline: subfinder+crt.sh → ScopeEngine split → dnsx → httpx → alterx → dnsx. Also `build_tool_caller()` for the REPL. |
| `scheduler.py` | APScheduler cron loop. LLM-free per design invariant #5. |
| `repl.py` + `main.py` | Terminal REPL + typer CLI. |
| `dashboard/` | FastAPI read-only views + JSON API. |

### Data flow per scan

```
subfinder + crt.sh → discovered set
                      │
              ScopeEngine.filter_targets()
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
   in_scope (live-checked)      OOS (stored tagged, never scanned)
        │
      dnsx ──► live hosts
        │
      httpx ──► status/title/tech
        │
      alterx ──► permutations ──► dnsx ──► new live
        │
   diff vs last scan ──► notify Slack
```

Every external call lands in `tool_executions` with started_at, completed_at, duration_ms, exit_code, target, args, triggered_by (`manual`/`cron`/`llm`/`repl`), status (`done`/`failed`/`blocked_oos`), llm_reasoning, result_summary.

### Design invariants (do not violate)

1. Scope gate is code, not LLM. `ScopeEngine.assert_in_scope()` before every subprocess.
2. OOS assets stored, never scanned. `in_scope=False`, `oos_reason` set.
3. LLM cannot self-escalate. `<escalate>` pauses the loop; user types yes/no.
4. Every tool execution logged. ToolExecution row created before subprocess, updated on completion. No silent runs.
5. Cron runs without LLM. If RunPod pod is off, passive monitoring keeps going.
6. Tool registry is single source of truth. `tools.yaml` feeds orchestrator AND LLM system prompt — no duplication.

## Aggressiveness levels

| Tool | passive | active | aggressive |
|---|---|---|---|
| subfinder, crt.sh, dnsx, httpx, gau, waybackurls, alterx, trufflehog, gowitness, wappalyzer, notify | ✅ | ✅ | ✅ |
| nmap_quick, nuclei_focused | ❌ | ✅ | ✅ |
| nmap_full, nuclei_full, ffuf | ❌ | ❌ | ✅ |
| Rate multiplier | 1.0× | 0.6× | 1.5× |

Human sets per-program ceiling in `programs.yaml`. LLM may propose escalation via `<escalate>` block. User approves with the exact action to run; ceiling reverts after that one call.

## Database

SQLite at `data/hunter2.db` (or `/app/data/hunter2.db` in Docker). Tables: `programs`, `scans`, `subdomains`, `ports`, `vulnerabilities`, `technologies`, `secrets`, `screenshots`, `directories`, `tool_executions`, `llm_sessions`.

## Tests / smoke

```bash
.venv/bin/python -c "from src.main import app; print('imports OK')"
./hunter2 scan example_vdp           # end-to-end passive
./hunter2 dashboard                  # browse to http://localhost:8000
```

## Deployment

See [DEPLOY.md](DEPLOY.md) for Railway + RunPod setup.

## Plan

Authoritative design spec: [HUNTER2_PLAN.md](HUNTER2_PLAN.md). Do not deviate from locked decisions without explicit approval.
