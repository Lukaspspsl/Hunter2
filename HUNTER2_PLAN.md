# Hunter 2.0 — Implementation Plan

> Produced from a grill session resolving all design decisions before implementation.
> This document is the authoritative spec for the implementing agent.
> Do not deviate from decisions marked **LOCKED** without explicit user approval.

---

## North Star

Two things Hunter 1.0 fails to deliver that 2.0 must nail:

1. **LLM-driven investigation** — "tell me what's interesting in today's diff" returns a reasoned answer, not raw data.
2. **Airtight scope safety** — never touch OOS hosts, full audit trail proving compliance.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    RAILWAY (always-on)                   │
│                                                         │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  Cron Jobs  │  │  FastAPI     │  │  Terminal     │  │
│  │  (passive   │  │  Dashboard   │  │  REPL chat    │  │
│  │   monitoring│  │  (read-only) │  │  (./hunter2   │  │
│  │   daily)    │  │              │  │   chat)       │  │
│  └──────┬──────┘  └──────┬───────┘  └──────┬────────┘  │
│         │                │                  │           │
│         └────────────────┴──────────────────┘           │
│                          │                              │
│              ┌───────────▼──────────┐                   │
│              │   Orchestrator       │                   │
│              │   (ReAct engine)     │                   │
│              └───────────┬──────────┘                   │
│                          │                              │
│         ┌────────────────┼────────────────┐             │
│         ▼                ▼                ▼             │
│   ┌──────────┐   ┌──────────────┐  ┌──────────────┐    │
│   │  Tool    │   │  Scope       │  │  SQLite DB   │    │
│   │  Registry│   │  Engine      │  │  (persistent │    │
│   │  (tools  │   │  (hard gate) │  │   volume)    │    │
│   │   .yaml) │   │              │  │              │    │
│   └──────────┘   └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────┘
                           │
                    LLM API calls
                           │
┌──────────────────────────▼──────────────────────────────┐
│                  RUNPOD (on-demand)                      │
│                                                         │
│   llama.cpp server — Gemma4 26B Q4_K_M                  │
│   Port 8090, OpenAI-compatible API                      │
│   Start manually before analysis sessions               │
│   Stop when done — pay per hour only                    │
└─────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
hunter2/
├── src/
│   ├── main.py                  # CLI entry + REPL chat loop
│   ├── config_loader.py         # Loads all 3 config files, validates
│   ├── scheduler.py             # APScheduler cron jobs (passive monitoring)
│   ├── tool_checker.py          # Binary validation at startup
│   ├── core/
│   │   ├── database.py          # SQLAlchemy async — extended models
│   │   ├── models.py            # ORM models (extended from Hunter 1.0)
│   │   ├── diff_engine.py       # Keep from Hunter 1.0 unchanged
│   │   ├── executor.py          # Keep + add rate multiplier support
│   │   ├── logger.py            # Keep from Hunter 1.0
│   │   └── scope_engine.py      # NEW — hard gate + OOS tagger
│   ├── llm/
│   │   ├── client.py            # llama.cpp HTTP client (OpenAI-compat)
│   │   ├── react_engine.py      # ReAct loop (observe→think→act)
│   │   ├── tool_caller.py       # Maps LLM tool calls to module methods
│   │   └── prompts.py           # System prompt templates
│   ├── modules/                 # Tool wrappers
│   │   ├── subdomain_enum.py    # Keep + extend
│   │   ├── port_scanner.py      # Keep
│   │   ├── vuln_scanner.py      # Keep + custom template dir
│   │   ├── dir_bruteforce.py    # Keep
│   │   ├── tech_detector.py     # Refactor — add wappalyzer CLI
│   │   ├── secret_scanner.py    # Keep
│   │   ├── screenshotter.py     # Keep
│   │   ├── crtsh.py             # Keep
│   │   ├── httpx_prober.py      # NEW — alive check, status, TLS, titles
│   │   ├── dnsx_resolver.py     # NEW — DNS validation, wildcard detect
│   │   ├── gau_collector.py     # NEW — historical URLs (gau + waybackurls)
│   │   ├── alterx_permuter.py   # NEW — subdomain permutation
│   │   └── notifier.py          # NEW — Slack via notify (ProjectDiscovery)
│   ├── dashboard/
│   │   ├── app.py               # FastAPI app factory
│   │   ├── routes.py            # REST endpoints + timeline API
│   │   └── templates/           # Jinja2 — findings + execution timeline UI
│   └── notifications/
│       └── slack_notifier.py    # Slack webhook (replaces email-only)
├── config/
│   ├── programs.yaml            # Scope definitions per program
│   ├── tools.yaml               # Tool registry — single source of truth
│   └── llm.yaml                 # LLM endpoint + model config
├── docker/
│   ├── Dockerfile               # Extended from Hunter 1.0
│   └── docker-compose.yaml
├── deploy/
│   ├── railway.toml             # Railway deployment config
│   └── runpod_start.sh          # Script to start llama.cpp on RunPod pod
├── tests/
└── documentation/
```

---

## Config Files

### programs.yaml

```yaml
programs:
  bose_vdp:
    platform: hackerone
    aggressiveness: passive          # hard ceiling — LLM cannot exceed
    in_scope:
      - "*.bose.com"
      - "bose.com"
      - "192.168.1.0/24"
    out_of_scope:
      - "careers.bose.com"
      - "*.staging.bose.com"
    rules:
      - "no automated scanning on prod checkout flow"
    notify:
      on_new_subdomain: true
      on_critical_vuln: true
      on_scope_violation_attempt: true   # alert if something tried to scan OOS
    schedule:
      cron: "0 6 * * *"                  # daily 6am passive scan
      enabled: true
```

### tools.yaml

```yaml
tools:
  subfinder:
    binary: subfinder
    description: "Passive subdomain enumeration using multiple sources"
    enabled: true
    min_level: passive
    rate_multiplier: 1.0
    timeout: 300
    args:
      threads: 10
      sources: [certspotter, hackertarget, threatcrowd, virustotal]

  dnsx:
    binary: dnsx
    description: "DNS resolution and validation of discovered subdomains"
    enabled: true
    min_level: passive
    rate_multiplier: 1.0
    timeout: 120
    args:
      threads: 50
      retry: 2

  httpx:
    binary: httpx
    description: "HTTP probing — alive check, status codes, titles, TLS info, redirects"
    enabled: true
    min_level: passive
    rate_multiplier: 1.0
    timeout: 30
    args:
      threads: 50
      follow_redirects: true
      tech_detect: true

  gau:
    binary: gau
    description: "Fetch historical URLs from Wayback Machine and Common Crawl. Zero target traffic."
    enabled: true
    min_level: passive
    rate_multiplier: 1.0
    timeout: 120

  waybackurls:
    binary: waybackurls
    description: "Pull historical URLs from Wayback Machine"
    enabled: true
    min_level: passive
    rate_multiplier: 1.0
    timeout: 60

  alterx:
    binary: alterx
    description: "Subdomain permutation and alteration from discovered subdomains"
    enabled: true
    min_level: passive
    rate_multiplier: 1.0
    timeout: 60

  trufflehog:
    binary: trufflehog
    description: "Secret scanning in git repositories"
    enabled: true
    min_level: passive
    rate_multiplier: 1.0
    timeout: 300

  gowitness:
    binary: gowitness
    description: "Web screenshots for visual recon"
    enabled: true
    min_level: passive
    rate_multiplier: 1.0
    timeout: 120

  nmap_quick:
    binary: nmap
    description: "Quick port scan — top 1000 ports, service detection"
    enabled: true
    min_level: active
    rate_multiplier: 0.6
    timeout: 300
    args:
      flags: "-sV -sC --top-ports 1000"

  nmap_full:
    binary: nmap
    description: "Full port scan — all 65535 ports"
    enabled: true
    min_level: aggressive
    rate_multiplier: 1.5
    timeout: 600
    args:
      flags: "-sV -sC -p-"

  nuclei_focused:
    binary: nuclei
    description: "Vulnerability scan — high and critical severity only"
    enabled: true
    min_level: active
    rate_multiplier: 0.6
    timeout: 600
    args:
      severity: [high, critical]
      tags: [cve, vulnerabilities]
      rate_limit: 100

  nuclei_full:
    binary: nuclei
    description: "Full vulnerability scan — all severities, all template categories"
    enabled: true
    min_level: aggressive
    rate_multiplier: 1.5
    timeout: 900
    args:
      severity: [low, medium, high, critical]
      rate_limit: 150
      custom_templates: "./templates/"

  ffuf:
    binary: ffuf
    description: "Directory and endpoint bruteforce"
    enabled: true
    min_level: aggressive
    rate_multiplier: 1.5
    timeout: 300
    args:
      wordlist: "/usr/share/wordlists/quick.txt"
      threads: 40
      extensions: [php, asp]

  notify:
    binary: notify
    description: "Push notifications to Slack on findings"
    enabled: true
    min_level: passive
    rate_multiplier: 1.0
    timeout: 10

# Rate multipliers per aggressiveness level
rate_multipliers:
  passive: 1.0
  active: 0.6
  aggressive: 1.5
```

### llm.yaml

```yaml
llm:
  provider: local
  base_url: "http://<RUNPOD_POD_IP>:8090/v1"
  model: "gemma4:latest"
  api_key: "not-needed"
  context_length: 65536
  temperature: 0.1              # low temp for tool-use reasoning
  timeout: 120
  fallback:
    enabled: false              # no cloud fallback — privacy concern
  availability_check:
    enabled: true
    on_unavailable: "warn_and_continue_without_llm"  # cron jobs still run
```

---

## Database Schema (Extended)

Keep all Hunter 1.0 models. Add/modify:

```python
class Program(Base):
    """Bug bounty program — top-level scope container"""
    __tablename__ = "programs"
    id: int
    name: str                    # matches programs.yaml key
    platform: str                # hackerone, bugcrowd, etc.
    aggressiveness: str          # passive/active/aggressive ceiling
    created_at: datetime
    updated_at: datetime

class Subdomain(Base):
    """Extended from Hunter 1.0 — add scope and program fields"""
    # existing fields +
    program_id: int              # FK → Program
    in_scope: bool               # False = OOS, stored but never scanned
    oos_reason: str | None       # which OOS rule matched

class ToolExecution(Base):
    """Audit trail for every tool invocation"""
    __tablename__ = "tool_executions"
    id: int
    scan_id: int                 # FK → Scan
    program: str
    target: str
    tool_name: str
    args: dict                   # JSON
    started_at: datetime
    completed_at: datetime | None
    duration_ms: int | None
    exit_code: int | None
    status: str                  # queued/running/done/failed/blocked_oos
    result_summary: str | None
    raw_output_path: str | None  # path to file on persistent volume
    triggered_by: str            # cron/llm/manual
    llm_reasoning: str | None    # LLM's stated reason for calling this tool

class LLMSession(Base):
    """Conversation history for terminal REPL sessions"""
    __tablename__ = "llm_sessions"
    id: int
    started_at: datetime
    ended_at: datetime | None
    program: str | None          # active program context
    messages: list               # JSON array of {role, content, timestamp}
    tool_executions: list        # JSON array of execution IDs triggered this session
```

---

## Scope Engine

**File:** `src/core/scope_engine.py`

```python
class ScopeEngine:
    def __init__(self, program_config: ProgramConfig): ...

    def is_in_scope(self, target: str) -> tuple[bool, str | None]:
        """
        Returns (True, None) if in scope.
        Returns (False, "reason") if OOS.
        Checks: domain pattern match, CIDR for IPs, explicit OOS list.
        Hard gate — called before ANY active tool execution.
        """

    def filter_targets(self, targets: list[str]) -> tuple[list[str], list[OOSTarget]]:
        """
        Split targets into in-scope and OOS.
        OOS targets returned for DB storage, never passed to tools.
        """

    def assert_in_scope(self, target: str) -> None:
        """
        Raises ScopeViolationError if target is OOS.
        Called inside every module's run() before subprocess execution.
        """
```

**OOS storage flow:**
1. subfinder discovers `careers.bose.com`
2. `scope_engine.filter_targets()` flags it OOS (matches OOS pattern)
3. Stored in DB: `Subdomain(domain="careers.bose.com", in_scope=False, oos_reason="matches *.careers.bose.com exclusion")`
4. Never passed to httpx, nmap, nuclei, or any active tool
5. Dashboard shows OOS assets in separate section — useful for scope expansion requests

---

## LLM ReAct Engine

**File:** `src/llm/react_engine.py`

### System Prompt Structure

```
You are Hunter, a security reconnaissance assistant for bug bounty research.

CURRENT PROGRAM: {program_name}
AGGRESSIVENESS CEILING: {level} — you may not suggest tools above this level
IN-SCOPE: {in_scope_patterns}
OUT-OF-SCOPE: {oos_patterns}

AVAILABLE TOOLS:
{tool_registry_descriptions}  <- injected from tools.yaml at runtime

RULES:
- Scope enforcement is handled by code. You do not need to check scope.
- Never suggest escalating aggressiveness without explicitly asking user to confirm.
- When suggesting escalation, state: current level, proposed level, specific reason.
- Always explain your reasoning before calling a tool.
- After tool results, summarize findings in plain language before deciding next action.

CURRENT SCAN CONTEXT:
{accumulated_findings_summary}
```

### ReAct Loop

```
User: "what's interesting in today's diff?"

LLM: <think>
  User wants analysis of new findings. I should query the diff for this program,
  then reason about which new subdomains or changes warrant deeper investigation.
</think>
<action>query_scan_diff(program="bose_vdp", since="24h")</action>

[tool executes, returns diff summary]

LLM: <observe>
  3 new subdomains found: api-v2.bose.com, staging2.bose.com (OOS), beta.bose.com
  api-v2.bose.com returned 200 on httpx with title "Bose API Gateway"
  beta.bose.com returned 403
</observe>
<think>
  api-v2.bose.com is interesting — new API gateway, potentially undocumented endpoints.
  beta.bose.com is 403 but exists. staging2.bose.com is OOS, skip.
  Current level is passive. To probe api-v2 properly I'd want httpx headers + tech detect.
  httpx is passive-level so I can run it without escalation.
</think>
<action>run_httpx(target="api-v2.bose.com")</action>

...and so on until LLM decides task complete.
```

### Escalation Flow

```
LLM: I found api-v2.bose.com running nginx/1.18 with X-Powered-By: Express.
     To check for known CVEs I would need to run nuclei (active level).
     Current ceiling is passive.

     ESCALATION REQUEST
     Propose: passive -> active
     Target: api-v2.bose.com only
     Reason: new API gateway, Express framework, potential CVE exposure

     Type 'yes' to approve or 'no' to skip.

User: yes

[scope engine validates target still in scope]
[orchestrator temporarily sets level=active for this target]
[nuclei_focused runs]
```

---

## Aggressiveness Levels

| Tool | Passive | Active | Aggressive |
|---|---|---|---|
| subfinder | YES | YES | YES |
| crt.sh | YES | YES | YES |
| dnsx | YES | YES | YES |
| httpx | YES | YES | YES |
| gau + waybackurls | YES | YES | YES |
| alterx | YES | YES | YES |
| trufflehog | YES | YES | YES |
| gowitness | YES | YES | YES |
| tech detection | YES | YES | YES |
| notify | YES | YES | YES |
| nmap (quick) | NO | YES | YES |
| nuclei (high/critical) | NO | YES | YES |
| nmap (full range) | NO | NO | YES |
| nuclei (all severities) | NO | NO | YES |
| ffuf | NO | NO | YES |
| **Rate multiplier** | **1.0x** | **0.6x** | **1.5x** |

---

## Observability — Execution Timeline

Dashboard `/timeline` endpoint renders:

```
2026-05-12 06:00:01  [CRON]     passive scan started — bose_vdp
2026-05-12 06:00:02  [TOOL]     subfinder       bose.com          OK 2m 14s   -> 47 subdomains
2026-05-12 06:00:02  [TOOL]     crtsh           bose.com          OK 0m 08s   -> 12 subdomains
2026-05-12 06:02:16  [TOOL]     dnsx            47 hosts          OK 0m 22s   -> 41 live
2026-05-12 06:02:38  [TOOL]     httpx           41 hosts          OK 1m 02s   -> 38 responding
2026-05-12 06:03:40  [TOOL]     alterx          41 subdomains     OK 0m 05s   -> 120 permutations
2026-05-12 06:03:45  [TOOL]     dnsx            120 permutations  OK 0m 31s   -> 3 new live
2026-05-12 06:04:16  [SCOPE]    OOS blocked     careers.bose.com  BLOCKED stored tagged
2026-05-12 06:04:16  [DIFF]     new assets      3 new subdomains detected
2026-05-12 06:04:17  [NOTIFY]   Slack           bose_vdp          OK alert sent
2026-05-12 06:04:18  [CRON]     passive scan complete — bose_vdp  4m 17s
```

Each row = one `ToolExecution` DB record. Dashboard polls `/api/timeline` every 5s during active scans.

---

## Terminal REPL

**Invocation:** `./hunter2 chat [--program bose_vdp]`

```
Hunter 2.0 — security recon assistant
Program: bose_vdp (passive ceiling)
LLM: gemma4 @ runpod connected
DB: 1,247 subdomains, last scan 6h ago

hunter> what's new since yesterday?
...
hunter> run a deep scan on api-v2.bose.com
...
hunter> show me all open ports found this week
...
hunter> exit
```

- No markdown rendering in terminal — plain text + simple tables
- Conversation history stored in `LLMSession` DB record
- `--no-llm` flag for when RunPod pod is off — REPL still works, no AI reasoning

---

## Deployment

### Railway

**`deploy/railway.toml`:**
```toml
[build]
builder = "dockerfile"
dockerfilePath = "docker/Dockerfile"

[deploy]
startCommand = "python -m src.main scheduler"
healthcheckPath = "/health"
healthcheckTimeout = 30
restartPolicyType = "on_failure"

[[volumes]]
mountPath = "/app/data"
```

**Environment variables on Railway:**
```
SLACK_WEBHOOK_URL=
GITHUB_TOKEN=
RUNPOD_POD_IP=          # update when pod starts
LLM_BASE_URL=           # http://${RUNPOD_POD_IP}:8090/v1
```

### RunPod

**`deploy/runpod_start.sh`** — run after SSH into pod:
```bash
#\!/bin/bash
# Start llama.cpp server with Gemma4
./llama-server \
  --model /workspace/models/gemma-4-26B-A4B-it-UD-Q4_K_M.gguf \
  --host 0.0.0.0 \
  --port 8090 \
  --ctx-size 65536 \
  --n-gpu-layers 99 \
  --parallel 4
```

Model already at `~/.Hermes/` on local Mac — upload to RunPod pod volume on first use.

---

## Implementation Phases

### Phase 1 — Foundation
1. New repo `hunter2/` — do not modify Hunter 1.0 in place
2. Copy modules from Hunter 1.0 (keep unchanged: subdomain_enum, port_scanner, vuln_scanner, dir_bruteforce, secret_scanner, screenshotter, crtsh, diff_engine, executor, logger)
3. Implement `ScopeEngine` — hard gate + OOS tagger
4. Implement new DB models — `Program`, `ToolExecution`, `LLMSession`, extend `Subdomain`
5. Implement config loader for 3-file split (`programs.yaml`, `tools.yaml`, `llm.yaml`)
6. Implement tool registry — dynamic loader reads `tools.yaml`, validates binaries exist
7. Verify: scope engine unit tests, config validation tests

### Phase 2 — New Tool Modules
1. `httpx_prober.py` — wrap httpx, return structured `HttpxResult`
2. `dnsx_resolver.py` — wrap dnsx, return live/dead split
3. `gau_collector.py` — wrap gau + waybackurls, deduplicate URLs
4. `alterx_permuter.py` — wrap alterx, feed back into dnsx
5. `notifier.py` — wrap notify binary, Slack webhook
6. Refactor `tech_detector.py` — add wappalyzer CLI properly
7. Verify: each module has unit test with mocked subprocess

### Phase 3 — LLM Integration
1. `llm/client.py` — OpenAI-compatible HTTP client for llama.cpp
2. `llm/prompts.py` — system prompt builder (injects tool registry + scope)
3. `llm/tool_caller.py` — maps LLM action calls to module methods
4. `llm/react_engine.py` — full ReAct loop with escalation approval flow
5. Verify: ReAct loop test with mocked LLM responses, escalation flow test

### Phase 4 — Orchestrator + REPL
1. Rewrite `main.py` — new orchestrator using tool registry + scope engine
2. Terminal REPL (`./hunter2 chat`) — readline loop, LLM integration, `--no-llm` flag
3. Cron scheduler integration — passive scans run without LLM
4. Verify: end-to-end passive scan against lab target, REPL conversation test

### Phase 5 — Dashboard + Observability
1. Extend FastAPI routes — `/timeline`, `/programs`, `/oos-assets`
2. Execution timeline UI — poll `/api/timeline`, render tool execution log
3. OOS assets panel — show tagged assets, scope expansion helper
4. Verify: dashboard renders timeline correctly, OOS panel populated

### Phase 6 — Deployment
1. Update Dockerfile — add httpx, dnsx, gau, waybackurls, alterx, notify binaries
2. `railway.toml` — Railway deployment config
3. `runpod_start.sh` — llama.cpp startup script for RunPod pod
4. End-to-end test on Railway + RunPod pod
5. Verify: cron fires on Railway, LLM reachable from Railway to RunPod

---

## What NOT to Build

- No Postgres migration (SQLite sufficient)
- No role-based auth (HTTP Basic Auth sufficient, single user)
- No katana (JS crawler) — out of scope for v1
- No Shodan/Censys API integration — cost concern
- No cloud enum (S3/Azure/GCP) — v2
- No custom nuclei template UI — file-based templates only
- No mobile notifications — Slack only
- No Hunter 1.0 backwards compatibility — clean break, new repo

---

## Key Design Invariants

Never violate these regardless of implementation convenience:

1. **Scope gate is code, not LLM.** `ScopeEngine.assert_in_scope()` called inside every active module before subprocess. No exceptions.
2. **OOS assets stored, never scanned.** Store with `in_scope=False`, never pass to tool subprocess.
3. **LLM cannot self-escalate.** Aggressiveness level changes require explicit user `yes` in terminal.
4. **Every tool execution logged.** `ToolExecution` record created before subprocess starts, updated on completion. No silent executions.
5. **Cron jobs run without LLM.** If RunPod pod is off, passive monitoring continues unaffected. `on_unavailable: warn_and_continue_without_llm`.
6. **Tool registry is single source of truth.** Tool descriptions in `tools.yaml` feed both orchestrator and LLM system prompt. No duplication.

---

## Open Questions for Implementing Agent

Make a reasonable call on these, document the decision:

1. **alterx feedback loop:** validate permutations via dnsx before storing, or store all lazily? Recommend: validate before storing.
2. **gau deduplication:** module-level dedup or DB unique constraint? Recommend: both — module dedup + DB unique constraint as backstop.
3. **LLM session TTL:** how long to keep conversation history? Recommend: 30-day TTL, configurable in `llm.yaml`.
4. **RunPod IP update flow:** when pod restarts IP changes. Recommend: `RUNPOD_POD_IP` env var on Railway, user updates via Railway CLI. Document in README.
5. **REPL history:** readline up-arrow history? Recommend: yes, Python `readline` module, persist to `~/.hunter2_history`.

---

## Decision Log

All decisions locked in grill session 2026-05-12:

| Decision | Choice |
|---|---|
| LLM availability | Always-on llama.cpp, Gemma4 26B, RunPod GPU on-demand |
| Interface | Terminal REPL (chat) + web dashboard (read-only) |
| LLM pattern | ReAct loop (observe->think->act) |
| Scope format | Full program block — in/OOS, CIDR, rules, aggressiveness ceiling |
| Scope enforcement | Hard code gate (pre-exec) + tagged OOS storage (post-discovery) |
| LLM scope awareness | Code-only — no scope in LLM prompt |
| OOS handling | Store tagged in_scope=false, never active-scan |
| Deployment | Railway (app+cron+dashboard) + RunPod on-demand (LLM) |
| Storage | SQLite on Railway persistent volume |
| Observability | DB audit trail + live dashboard timeline + LLM reasoning stored |
| Aggressiveness | 3 levels: passive/active/aggressive |
| Level assignment | Human sets ceiling, LLM suggests escalation, human approves |
| Rate limiting | Per-tool baseline x level multiplier |
| Config | programs.yaml / tools.yaml / llm.yaml |
| Tool registry | Registry-driven single source of truth |
| Modules kept | subdomain_enum, port_scanner, vuln_scanner, dir_bruteforce, secret_scanner, screenshotter, crtsh, diff_engine, executor, logger |
| Modules rewritten | main.py, database.py, dashboard/ |
| Modules new | httpx_prober, dnsx_resolver, gau_collector, alterx_permuter, notifier, scope_engine, llm/ package |
| Tools added | httpx, dnsx, gau, waybackurls, alterx, notify |
| Notifications | Slack only via notify (ProjectDiscovery) |
| North star | LLM-driven investigation + airtight scope safety |

*Plan produced: 2026-05-12. Do not deviate from locked decisions without explicit user approval.*
