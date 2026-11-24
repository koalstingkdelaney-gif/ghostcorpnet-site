# Jarvis Local Model Fleet

Status: **scaffold committed; runtime connection not yet verified**.

## Goal

Run multiple open-weight models through an authorized local inference host and give Jarvis one provider-neutral interface. The default path uses Ollama's local HTTP API and requires no AI API key, prepaid balance, or paid fallback.

## Important GitHub boundary

GitHub stores this configuration, source code, tests, and workflow history. GitHub Actions can temporarily download and smoke-test small models on its hosted runners, but those runners are short-lived CI machines—not a persistent inference server. A model started in an Action stops when the job ends. The durable Jarvis runtime must live on an authorized always-on host; the VR headset is only a client.

GitHub documents standard public-repository Linux runners as 4 CPU / 16 GB RAM / 14 GB SSD. This is enough to smoke-test several small quantized models one at a time, not to host a permanent fleet or large models. The workflow in `.github/workflows/local-model-smoke.yml` tests candidates sequentially and records pass/fail in Actions.

## Initial model candidates

See `catalog.json`. The first CI pass focuses on:
- `qwen3:0.6b` — lightweight classification/routing
- `qwen3:1.7b` — general small-model tasks
- `qwen3:4b` — stronger general/reasoning candidate
- `deepseek-r1:1.5b` — reasoning comparison
- `qwen2.5-coder:1.5b` — code-focused comparison
- `phi3.5:latest` — long-context comparison candidate

These are candidates, not a claim that they are installed or suitable for production. Actual quality, speed, memory use, tool calling, and license terms must be evaluated. Do not assume that a model's advertised context window is practical on the available host.

## Connect Jarvis to local Ollama

1. Install Ollama on an authorized host and keep its API bound to loopback.
2. Pull the chosen models, for example:
   `ollama pull qwen3:0.6b`
   `ollama pull qwen3:1.7b`
   `ollama pull qwen3:4b`
   `ollama pull deepseek-r1:1.5b`
   `ollama pull qwen2.5-coder:1.5b`
   `ollama pull phi3.5`
3. Start the Jarvis adapter with `python jarvis/model-fleet/router.py health`.
4. Run `python jarvis/model-fleet/router.py list` to discover models actually present.
5. Run a smoke prompt with `python jarvis/model-fleet/router.py chat general "Reply with the word READY."`.

The adapter defaults to `http://127.0.0.1:11434`. It refuses a remote plain-HTTP endpoint. A remote endpoint must use HTTPS and a bearer token supplied through the runtime environment; put an authenticated private gateway in front of Ollama. Never expose Ollama's unauthenticated port directly to the public internet.

## Routing

The initial task map is deliberately simple and overrideable with environment variables:
- `JARVIS_MODEL_CLASSIFY`
- `JARVIS_MODEL_GENERAL`
- `JARVIS_MODEL_REASONING`
- `JARVIS_MODEL_CODE`
- `JARVIS_MODEL_LONG_CONTEXT`

Jarvis should choose based on task class, then measure output quality and latency. It should not blindly run every model on every prompt: that wastes compute and can make answers worse. Use parallel model voting only for selected high-value tasks, then have a separate evaluator compare evidence and disagreements.

## Zero-credit and safety rules

- Local inference is the default; no hosted inference or paid API fallback is implemented here.
- Missing models cause a clear error; the adapter never downloads models automatically or incurs a charge.
- Do not send private customer, payment, or owner data to an external inference endpoint without explicit authorization.
- Only run models on hardware GhostCorp is authorized to use.
- Keep model weights out of Git; download them into the host's model cache.
- CI test results prove only that a temporary GitHub runner completed a smoke test. They do not prove Jarvis is connected to a persistent host.

## Current status

- [x] Model fleet design and candidate registry committed.
- [x] Local Ollama adapter scaffold committed.
- [x] Manual/push-triggered sequential CI smoke-test workflow committed.
- [ ] CI workflow run and model-by-model results verified.
- [ ] Persistent authorized inference host provisioned.
- [ ] Models downloaded on that host.
- [ ] Jarvis orchestrator connected to the adapter.
- [ ] Restart, fallback, privacy, and no-billing tests passed.


## Provider-output handoff into local models

All provider-produced work must be treated as portable project artifacts, not as the only copy of Jarvis's progress. Use `jarvis/handoff.py` to persist a mission, checkpoint, next action, provider/model attribution, quota usage, and generated artifacts in a local SQLite state database. Export a mission handoff JSON bundle for the local model to continue from. The bundle includes a verification instruction and explicitly tells the receiving model not to repeat completed work.

Example:
- `python -m jarvis.handoff add M-001 "Build feature" "Implement the feature and tests"`
- `python -m jarvis.handoff checkpoint M-001 "Design complete" "Local model: implement tests" --provider groq --model model-id --artifact design.md --artifact-file /path/to/design.md`
- `python -m jarvis.handoff export M-001 --output state/handoffs/M-001.json`

Runtime SQLite databases and handoff bundles belong in local/private state, never in public Git. Do not put secrets, customer PII, payment records, or confidential business data into provider prompts or handoff artifacts unless approved and protected. Provider output is untrusted until checked by tests, source verification, or another model.
