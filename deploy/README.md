# Hunter 2 — deployment

Two-host layout: Railway runs the always-on Python app + cron + dashboard;
RunPod hosts the GPU + llama.cpp server. The Python app reaches the LLM over
HTTP.

## Railway

1. Connect this repo to Railway. Railway picks up `deploy/railway.toml`.
2. Create two services from the same image:
   - **scheduler** — default start command (`python -m src.main scheduler`).
   - **dashboard** — override start command:
     ```
     python -m src.main dashboard --host 0.0.0.0 --port 8000
     ```
3. Attach a persistent volume at `/app/data` to both services.
4. Set env vars on each:
   - `SLACK_WEBHOOK_URL`
   - `GITHUB_TOKEN` (gau)
   - `RUNPOD_POD_IP` (update when the pod restarts)
   - `LLM_BASE_URL` = `http://${RUNPOD_POD_IP}:8090/v1`

The dashboard exposes `:8000`. Use Railway's built-in TLS routing.

## RunPod

1. Spin up an A100/H100 community pod with llama.cpp pre-built.
2. Upload the Gemma4 26B Q4_K_M GGUF once to `/workspace/models/`.
3. Drop `deploy/runpod_start.sh` at `/workspace/runpod_start.sh`, chmod, run.
4. Copy the pod's public IP into the Railway `RUNPOD_POD_IP` env var.

The pod can be torn down between sessions — Hunter still does passive
monitoring without it (invariant #5).
