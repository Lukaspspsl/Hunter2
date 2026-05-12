# Hunter 2 — deployment

Two-host layout:

- **Railway** runs the always-on Python app: scheduler + dashboard. Persistent SQLite volume. No GPU.
- **RunPod** hosts llama.cpp + Gemma4 26B Q4_K_M on a community GPU pod. On-demand — spin up for analysis sessions, tear down after.

Railway reaches RunPod over HTTP (OpenAI-compatible API on port 8090). If RunPod is off, passive monitoring keeps going — invariant #5.

```
Railway services                            RunPod pod
┌──────────────────────┐                    ┌────────────────────┐
│ scheduler  (cron)    │                    │ llama-server :8090 │
│ dashboard  :8000     │ ── LLM_BASE_URL ──►│ Gemma4 26B Q4_K_M  │
│ shared SQLite volume │                    │ ctx 65536          │
└──────────────────────┘                    └────────────────────┘
```

---

## Part 1 — Railway

### 1. Connect repo

1. Sign in to https://railway.app.
2. New Project → Deploy from GitHub repo → pick `Lukaspspsl/Hunter2`.
3. Railway picks up `deploy/railway.toml`. Builder: docker. Dockerfile: `docker/Dockerfile`.

### 2. Create two services from same image

Railway can run multiple services off one repo with different start commands.

**Service A — scheduler** (default start command):

```
python -m src.main scheduler
```

No public port. Just keeps the cron loop alive.

**Service B — dashboard** (override start command in Railway UI → Settings → Deploy):

```
python -m src.main dashboard --host 0.0.0.0 --port 8000
```

Expose port 8000. Railway issues a TLS hostname automatically.

### 3. Persistent volume

Both services need the same SQLite DB at `/app/data`.

1. Add a volume in Railway: mount path `/app/data`, size 1 GB to start.
2. Attach to both services.

(Without this, every redeploy wipes the DB.)

### 4. Environment variables

Set on both services:

| Var | Example | Notes |
|---|---|---|
| `SLACK_WEBHOOK_URL` | `https://hooks.slack.com/services/...` | Optional. Notifier falls back to webhook if `notify` binary fails. |
| `GITHUB_TOKEN` | `ghp_...` | Used by `gau` for higher GitHub rate limits. |
| `RUNPOD_POD_IP` | `123.45.67.89` | Pod's public IP. Updated whenever pod restarts (RunPod re-assigns IP). |
| `LLM_BASE_URL` | `http://${RUNPOD_POD_IP}:8090/v1` | Hunter resolves `${VAR}` at config-load time. |

Scheduler does not need `LLM_BASE_URL` strictly (cron path is LLM-free), but harmless to set.

### 5. Update IP after pod restart

RunPod re-issues IPs on every pod start. To avoid redeploying Railway:

```bash
railway variables set RUNPOD_POD_IP=<new-ip> --service scheduler
railway variables set RUNPOD_POD_IP=<new-ip> --service dashboard
```

Or use the Railway dashboard → service → Variables → edit. Railway restarts the service with the new value. Takes ~30 s.

### 6. Initial smoke

After first deploy:

```bash
curl https://<dashboard-railway-url>/health
# {"status":"ok"}

curl https://<dashboard-railway-url>/api/programs
```

Cron jobs fire at the times set in `configs/programs.yaml`. Tail logs:

```bash
railway logs --service scheduler
```

### 7. Editing scope

`configs/programs.yaml` ships in the image. To add a program, edit the file in the repo, push, Railway redeploys both services. SQLite data persists.

---

## Part 2 — RunPod

### 1. Pick a pod

- Template: any with CUDA 12.x and Ubuntu 22.04 (the "RunPod PyTorch 2.1" template works).
- GPU: A100 40 GB minimum for Gemma4 26B Q4_K_M at ctx 65536. H100 if you want headroom.
- Volume: persistent volume at `/workspace`, ≥ 30 GB (model is ~15 GB).
- Expose TCP port 8090 in the pod template (RunPod → pod → Edit Pod → expose ports).

### 2. Build / install llama.cpp

SSH into the pod:

```bash
ssh root@<pod-ip> -p <pod-port>

apt-get update && apt-get install -y build-essential cmake git
cd /workspace
git clone https://github.com/ggerganov/llama.cpp
cd llama.cpp
cmake -B build -DGGML_CUDA=ON
cmake --build build --config Release -j
cp build/bin/llama-server /workspace/llama-server
```

### 3. Upload the model

From the Mac:

```bash
# Model lives at ~/.Hermes/ locally (per HUNTER2_PLAN.md)
scp -P <pod-port> ~/.Hermes/gemma-4-26B-A4B-it-UD-Q4_K_M.gguf \
    root@<pod-ip>:/workspace/models/
```

Or `runpodctl send` if you prefer the RunPod CLI. ~15 GB transfer.

### 4. Start the server

`deploy/runpod_start.sh` lives in the repo. Copy it onto the pod once:

```bash
scp -P <pod-port> deploy/runpod_start.sh root@<pod-ip>:/workspace/
ssh root@<pod-ip> -p <pod-port> "chmod +x /workspace/runpod_start.sh"
```

Then on the pod:

```bash
cd /workspace
./runpod_start.sh
```

Defaults: port 8090, ctx 65536, all layers on GPU, parallel 4. Override with env vars:

```bash
PORT=8091 CTX_SIZE=32768 PARALLEL=2 ./runpod_start.sh
```

Liveness probe:

```bash
curl http://<pod-ip>:8090/v1/models
# {"object":"list","data":[{"id":"gemma4:latest", ...}]}
```

### 5. Wire to Railway

Copy the pod's public IP, set `RUNPOD_POD_IP` on Railway (see Part 1 step 5). Hunter's `LLMClient.is_available()` probes `/v1/models` — visible in `./hunter2 chat` header.

### 6. Tear down

Stop the pod when done. Railway scheduler keeps running. `--no-llm` flag on the REPL skips the availability probe entirely.

---

## Part 3 — Local dev (no Railway, no RunPod)

```bash
git clone https://github.com/Lukaspspsl/Hunter2.git
cd Hunter2
uv venv && uv pip install -r requirements.txt

# install go-based tools (macOS via brew or go install)
brew install httpx dnsx subfinder alterx nuclei ffuf nmap gowitness
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

./hunter2 tools                       # confirm binaries on PATH
./hunter2 scan example_vdp            # passive scan, no LLM
./hunter2 chat --program example_vdp --no-llm    # REPL slash commands only
./hunter2 dashboard                   # browse http://localhost:8000
```

For full LLM dev, point `LLM_BASE_URL` at a local llama.cpp:

```bash
export LLM_BASE_URL=http://127.0.0.1:8090/v1
./hunter2 chat --program example_vdp
```

---

## Troubleshooting

**Dashboard returns 500 on `/timeline`.** Check Railway logs — usually a missing tool binary or stale Python image. Trigger a redeploy.

**Cron doesn't fire.** Check `programs.yaml`: `schedule.enabled: true` and a valid 5-field cron expression. `./hunter2 programs` shows what the scheduler will register.

**LLM reachable from local Mac but not from Railway.** RunPod pod port not exposed. Edit Pod → expose TCP 8090.

**Scope violation showing up in logs.** Inspect `tool_executions` rows with `status='blocked_oos'`. Means an LLM or REPL action targeted an OOS host — the gate fired correctly. Investigate which path proposed it.

**Volume full.** SQLite + raw tool outputs in `/app/data`. Either expand the volume in Railway, or periodically prune `data/raw_results/`.

---

## Cost

- Railway: hobby tier ~$5/mo for two services + 1 GB volume.
- RunPod A100 community pod: ~$1.10/hr while running. Pay-per-hour; only start for analysis sessions.

Expected pattern: scheduler always on, pod up 1–2 hr/day for interactive chat.
