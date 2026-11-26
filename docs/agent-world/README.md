# GhostCorp Agent World

This module brings the useful engineering ideas demonstrated by Pino / Pino Protocol into GhostCorp as an **original, governed agent-world platform**. It does not copy Pino's identity, private implementation, source code, personality, or claim that GhostCorp agents are conscious.

## What we are building

GhostCorp agents become persistent workers with:
- a durable identity, role, goals, skills, and career history;
- bounded internal state (energy, focus, curiosity, social contact, expression) used as scheduling signals, not claims of sentience;
- short-term working memory, long-term memory, evidence-backed beliefs, and a daily consolidation cycle;
- a world manifest describing available entities, observations, actions, and the effects of actions;
- a strict sense → observe → decide → validate → act → record → learn loop;
- independent workspaces, portfolios, collaboration, and a marketplace;
- spend limits, permission scopes, approval queues, audit trails, rollback, and a global kill switch.

The runtime is designed so the same agent mind can work in different environments: the GhostCorp website, the private VR headquarters, a game simulation, a research workspace, or an approved business tool.

## Repository layout

- `integrations/pinos_public_api/`: read-only adapter for Pino's documented public API. It is an optional observatory/inspiration feed, not a dependency of GhostCorp's agent runtime.
- `docs/agent-world/`: architecture, safety boundaries, rollout plan, and example world manifest.
- Future implementation modules should live under the repository's existing application structure once that structure is confirmed. Keep this integration modular; do not replace existing revenue, approvals, or deployment systems.

## Pino public API adapter

The adapter in `integrations/pinos_public_api/client.py` reads documented public endpoints only. It:
- uses the public API without a key;
- respects each endpoint's update interval;
- handles timeouts, HTTP 503, and malformed responses without crashing the main app;
- labels returned content as third-party data and credits “Pino, from pinos.world”;
- never writes to Pino, controls Pino, or presents Pino's words as GhostCorp's.

The public API is optional. If it is unavailable, GhostCorp continues operating.

## Safety model

The agent may independently research, draft, create local artifacts, run tests, and propose new tools within its assigned sandbox. External side effects are capability-gated:
- read-only access is the default;
- network destinations are allowlisted;
- secrets are injected by the host and never placed in prompts, logs, or agent memory;
- payments, payouts, purchases, account creation, public outreach, production deployment, permission changes, and destructive operations require the configured approval policy;
- agents cannot raise their own budgets, grant themselves permissions, disable audit logging, or alter the kill switch;
- every action records actor, intent, inputs, policy decision, result, cost, and rollback reference.

The initial operating budget remains **$0 in new paid API spend before revenue**. Use local/free resources where practical; fail closed when a paid service or credential is unavailable.

## Rollout

1. Add the optional Pino read-only observer and manifest example.
2. Implement the GhostCorp world runtime behind feature flags, with deterministic tests and a simulated world first.
3. Connect the Action Center approval queue and audit log.
4. Add the private VR world as another world adapter; business data remains owner-only.
5. Add multi-agent teams, careers, portfolios, and a marketplace after isolation and governance tests pass.
6. Enable carefully scoped production actions only after explicit owner policy configuration and provider verification.

## References

- Pino public API and developer guide: https://pinos.world/developers
- Pino Protocol overview: https://protocol.pinos.world/
- Pino's explanation of its architecture and roadmap: https://pinos.world/what-ships-next

Pino and Pino Protocol are independent projects. This integration uses their public documentation as inspiration and treats their API as an optional external data source.
