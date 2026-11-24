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


## Free provider quota pool

Use every legitimate no-cost inference allocation the owner is already authorized to access, while obeying each provider's rate limits, terms, privacy rules, and account eligibility. The provider inventory is maintained in `jarvis/model-fleet/free-provider-registry.json`.

Initial documented candidates (not yet connected to Jarvis):
- Google AI Studio / Gemini Developer API free tier — per-model/project quotas; free-tier prompts may be used to improve Google's products, so sensitive GhostCorp/customer data is excluded.
- GroqCloud free tier — published per-model request/token limits; read live account limits and response headers.
- Cloudflare Workers AI — 10,000 Neurons/day free allocation; exceeding it requires paid plan, so stop at quota.
- Cohere trial key — documented 1,000 API calls/month; treat as a limited trial allocation, not a permanent guarantee.
- OpenRouter explicitly free model variants — free variants have low daily/minute caps; use only variants confirmed as genuinely no-balance-required and never purchase credits.
- Local Ollama — no API credits, limited by authorized hardware and model licenses.

Explicit exclusions:
- Hugging Face Inference Providers: current official free-account pricing page says Free users have no included inference credits; older pages may be stale.
- Mistral API: Free mode does not include API access; API requires billing activation.
- GitHub Models: don't rely on it unless current official availability is re-established.

## Quota-aware routing requirements

1. Store provider/model eligibility, quota type, remaining quota estimate, reset time, rate-limit headers, last verification time, and privacy classification.
2. Prefer local models for offline work and sensitive tasks.
3. Route eligible low-sensitivity requests to a provider with available free quota; choose by task capability, measured quality, latency, and remaining quota—not by provider count alone.
4. On 429/quota exhaustion, record reset time and queue or switch to another authorized free provider. Never retry in a tight loop.
5. Hard-disable paid model IDs, billing upgrades, auto-recharge, credit purchases, trial conversion, and paid fallback.
6. Do not create multiple accounts to evade quotas or identity/rate limits.
7. Revalidate provider offers at least every 30 days and before any new provider is activated.
8. Provider free tiers may inspect or retain prompts. Sensitive business, payment, credential, customer, and owner data must stay local unless the provider's terms and explicit owner authorization permit otherwise.
9. When all free quotas are exhausted, continue local inference, deterministic operations, cached knowledge, and checkpointed queues; wait for provider resets rather than spending.

The registry describes public offers only. It does not prove the owner's accounts are enrolled, API keys exist, or any provider is connected.


### Owner-directed quota consumption order

For non-sensitive tasks, use available authorized free hosted inference quotas before spending local compute. Immediately persist each provider's useful output, source/model attribution, quota usage, and exact next action through `jarvis/handoff.py`. Local models then verify and continue the work. Local inference remains first for sensitive/private data, offline operation, provider outages, and after quotas are exhausted. When all hosted free quotas are depleted, continue locally or queue until reset. Never pay.
