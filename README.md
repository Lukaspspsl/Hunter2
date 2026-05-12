# Hunter 2

LLM-driven recon and pentest suite for ongoing monitoring and discovery. Successor to Hunter 1.0.

## North Star

1. **LLM-driven investigation** — "tell me what's interesting in today's diff" returns a reasoned answer.
2. **Airtight scope safety** — never touch out-of-scope hosts, full audit trail.

See `HUNTER2_PLAN.md` for the full design spec.

## Layout

```
src/         application code
configs/     programs.yaml + tools.yaml + llm.yaml
docker/      container build
deploy/      Railway + RunPod deployment scripts
tests/       unit + integration tests
```

## Status

Implementation in progress — phased rollout per plan.
