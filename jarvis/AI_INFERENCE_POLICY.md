# Jarvis AI Inference: Zero-Credit Core Policy

Status: architecture and operating requirement. This document does not mean local models, hardware, or inference backends are already deployed.

## Objective

Jarvis must not require the owner to buy AI credits, maintain a prepaid API balance, or pay per-token API charges for its core operation. No paid inference may occur by default.

"Zero-credit" means no mandatory AI API credit purchases. It does not mean compute has zero resource cost: local inference consumes hardware, electricity, memory, storage, and cooling; hosted free tiers have quotas and can change or disappear.

## Required architecture

1. **Provider-neutral model interface.** Define a common adapter for chat/completions, embeddings, tool calls, structured output, streaming, context limits, health, and capability reporting. Do not couple Jarvis's memory, task queue, or world state to one model vendor.
2. **Local-first inference.** Prefer open-weight models running on hardware GhostCorp is authorized to use. Detect available RAM, VRAM, CPU/GPU acceleration, storage, and thermal constraints before selecting a model. Use smaller quantized models when appropriate.
3. **Free-tier backends are optional.** Use a hosted free inference tier only when its current terms, quota, data handling, and availability are checked. Never treat a trial as free if it converts to paid service.
4. **Capability-based routing.** Select models by task requirements: lightweight classification/routing, coding, long-context research, multimodal input, structured extraction, or high-quality reasoning. Keep benchmarks for correctness, latency, reliability, context, and resource use.
5. **No silent paid fallback.** Paid endpoints, paid credits, subscriptions, usage-based billing, and paid upgrades are disabled unless the owner explicitly authorizes a defined GhostCorp operating budget funded from verified business revenue. The default permitted paid inference budget is $0.
6. **Graceful degradation.** When a model is unavailable or a quota is exhausted, try another authorized zero-credit backend, reduce task scope, queue the task, or ask for a decision. Never incur a charge to keep a workflow moving.
7. **Non-AI core services.** Durable memory, mission scheduling, state transitions, audit logging, deterministic business rules, health checks, retries, and world persistence must operate without calling a paid LLM. Use deterministic code for predictable tasks.
8. **Privacy and secrets.** Do not send private customer, payment, owner, or business data to a hosted inference provider unless the data flow is explicitly authorized and appropriately protected. Keep provider keys server-side; never place them in VR or browser clients.
9. **No unauthorized resource use.** Do not use another person's hardware, account, subscription, API key, or compute without their explicit permission. Local models must run only on hardware GhostCorp is authorized to use.
10. **Transparent capacity reporting.** Report active backend, model, local/hosted status, quota/limits if known, last successful inference, fallback state, and any tasks waiting for capacity. Do not claim a model is installed, available, or running without a test.

## Model selection strategy

- **Tier A — deterministic operations:** ordinary queue management, validation, scheduling, permissions, retries, audit records, and state updates should use code rather than an LLM.
- **Tier B — local small models:** routine summaries, classification, extraction, simple drafting, and routing where local hardware can handle them.
- **Tier C — local specialist models:** coding, reasoning, or multimodal work where the available hardware and model licenses permit.
- **Tier D — authorized free hosted inference:** only when genuinely free, quota-aware, privacy-reviewed, and not dependent on a paid conversion.
- **Tier E — paid inference:** disabled unless an explicit owner-approved operating budget exists and the spending source is verified GhostCorp revenue. Never draw from personal funds or exceed the approved cap.

## Acceptance tests

- Complete a representative set of core Jarvis tasks with paid API credentials absent.
- Confirm no code path silently calls a billable endpoint.
- Exhaust or disable one backend and verify safe fallback/queue behavior without charges.
- Restart the orchestrator and verify memory, mission state, and policy enforcement work without an LLM.
- Benchmark local models on actual authorized hardware and record latency, memory, quality, and thermal limits.
- Verify hosted-free provider quotas and privacy terms before enabling each provider.
- Audit logs and network egress to ensure no hidden paid inference calls occur.

## Current truth

This policy is a committed requirement, not proof of implementation. A local inference runtime, selected model weights, model router, hardware benchmark, and zero-billing network test still need to be built and verified. Do not claim Jarvis is already running locally or has unlimited free inference.
