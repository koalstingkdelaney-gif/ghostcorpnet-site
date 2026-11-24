# GhostCorp AI Academy

GhostCorp's public education program turns internal, approved research into understandable and reproducible learning material. The Academy is a public-facing knowledge product, separate from private business operations.

## Learning tracks

### Track 1 — AI foundations
- What language models do and do not do.
- Tokens, context windows, embeddings, retrieval, and inference.
- Training versus inference; open weights versus hosted APIs.
- Hallucinations, uncertainty, and verification.

### Track 2 — Building a multi-model system
- Model adapters and provider-neutral interfaces.
- Capability-based routing and specialist models.
- Rate limits, free quotas, privacy tradeoffs, and graceful fallback.
- Evaluating model quality rather than trusting brand names.

### Track 3 — Persistent agents
- Missions, queues, checkpoints, event logs, and resumable tasks.
- Memory architecture, retrieval, provenance, and retention.
- Tool permissions, approval boundaries, and audit trails.
- Human oversight and secure delegation.

### Track 4 — Local and offline AI
- Hardware sizing and model quantization.
- Local inference servers and model selection.
- Offline operation, caching, and deterministic fallbacks.
- Backups, restore drills, and continuity testing.

### Track 5 — AI research and invention
- Turning ideas into falsifiable hypotheses.
- Designing fair benchmarks and baselines.
- Reproducibility, ablation studies, and prior-art review.
- Reporting failures and avoiding exaggerated claims.

### Track 6 — Simulation, VR, and embodied AI
- World state, agents, sensors, and simulation.
- Spatial planning and multi-agent coordination.
- Sim-to-real gaps and safety boundaries.
- Building interactive educational experiments.

### Track 7 — Responsible AI engineering
- Privacy and data minimization.
- Secure tool use and prompt-injection defense.
- Model/data/software licensing.
- Bias, accessibility, transparency, and release safety.

## Public learning artifacts

Each approved research project can produce:
1. A plain-language explanation.
2. A technical deep dive.
3. A runnable, sandboxed demonstration.
4. A reproducible code repository or notebook where appropriate.
5. A benchmark card with methodology and limitations.
6. A short lesson, exercise, or quiz.
7. A changelog and citations to primary sources.

## Publication rules

- Only publish material explicitly classified as public.
- Never expose credentials, customer records, private mission logs, internal URLs, or owner-only controls.
- Separate verified facts, hypotheses, and speculation.
- Cite primary sources and respect copyright and licenses.
- Avoid claiming that a prototype is production-ready.
- Make demos safe, rate-limited, and isolated from business infrastructure.
- Provide accessible text alternatives and explain prerequisites.

## Suggested first public course

**"How to Build an AI That Doesn't Forget Its Work"**
1. A simple task queue.
2. Checkpoints and resumable work.
3. Saving artifacts and source provenance.
4. Switching from a hosted model to a local model.
5. Testing recovery after a simulated outage.
6. Comparing reliability with a no-checkpoint baseline.

The course should use synthetic data and a local sandbox, and publish the exact test procedure and results.
