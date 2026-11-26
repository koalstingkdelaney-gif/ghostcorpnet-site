"""Versioned world-manifest validation and deterministic dry-run simulation."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


class ManifestError(ValueError):
    """Raised when a world manifest violates the GhostCorp contract."""


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{label} must be a non-empty string")
    return value


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Validate a manifest and return a defensive JSON-compatible copy."""
    if not isinstance(manifest, dict):
        raise ManifestError("Manifest must be an object")
    if manifest.get("protocol") != "ghostcorp-world/1":
        raise ManifestError("Unsupported or missing world protocol")
    _string(manifest.get("name"), "name")
    if manifest.get("visibility") not in {"private", "public"}:
        raise ManifestError("visibility must be private or public")

    clock = manifest.get("clock")
    if not isinstance(clock, dict):
        raise ManifestError("clock must be an object")
    tick = clock.get("tick_seconds")
    if not isinstance(tick, int) or isinstance(tick, bool) or not 1 <= tick <= 3600:
        raise ManifestError("clock.tick_seconds must be an integer from 1 to 3600")

    state = manifest.get("state")
    signals = state.get("signals") if isinstance(state, dict) else None
    if not isinstance(signals, list):
        raise ManifestError("state.signals must be a list")
    signal_ids: set[str] = set()
    for signal in signals:
        if not isinstance(signal, dict):
            raise ManifestError("Each state signal must be an object")
        signal_id = _string(signal.get("id"), "state signal id")
        if signal_id in signal_ids:
            raise ManifestError(f"Duplicate state signal: {signal_id}")
        signal_ids.add(signal_id)
        bounds = signal.get("range")
        if (
            not isinstance(bounds, list) or len(bounds) != 2
            or bounds != [0, 1]
        ):
            raise ManifestError(f"State signal {signal_id} must use the normalized [0, 1] range")

    observations = manifest.get("observations")
    if not isinstance(observations, list):
        raise ManifestError("observations must be a list")
    observation_ids: set[str] = set()
    for observation in observations:
        if not isinstance(observation, dict):
            raise ManifestError("Each observation must be an object")
        observation_id = _string(observation.get("id"), "observation id")
        if observation_id in observation_ids:
            raise ManifestError(f"Duplicate observation: {observation_id}")
        observation_ids.add(observation_id)
        _string(observation.get("source"), f"observation {observation_id} source")
        if observation.get("sensitivity") not in {"public", "internal", "restricted"}:
            raise ManifestError(f"Invalid sensitivity for observation {observation_id}")

    actions = manifest.get("actions")
    if not isinstance(actions, list):
        raise ManifestError("actions must be a list")
    action_names: set[str] = set()
    for action in actions:
        if not isinstance(action, dict):
            raise ManifestError("Each action must be an object")
        name = _string(action.get("name"), "action name")
        if name in action_names:
            raise ManifestError(f"Duplicate action: {name}")
        action_names.add(name)
        _string(action.get("description"), f"action {name} description")
        risk = action.get("risk")
        if risk not in {"low", "medium", "high", "critical"}:
            raise ManifestError(f"Invalid risk for action {name}")
        approval = action.get("requires_approval")
        if not isinstance(approval, bool):
            raise ManifestError(f"Action {name} requires_approval must be boolean")
        if risk in {"high", "critical"} and not approval:
            raise ManifestError(f"High/critical action {name} must require approval")
        permissions = action.get("permissions")
        if (
            not isinstance(permissions, list) or not permissions
            or any(not isinstance(p, str) or not p.strip() for p in permissions)
        ):
            raise ManifestError(f"Action {name} must declare permissions")

    limits = manifest.get("limits")
    if not isinstance(limits, dict):
        raise ManifestError("limits must be an object")
    if limits.get("paid_api_spend_before_revenue_usd") != 0:
        raise ManifestError("Pre-revenue paid API spend must remain exactly $0")
    for guard in (
        "agent_can_expand_own_permissions",
        "agent_can_raise_own_budget",
        "agent_can_disable_audit",
        "agent_can_disable_kill_switch",
    ):
        if limits.get(guard) is not False:
            raise ManifestError(f"Safety limit {guard} must be false")

    events = manifest.get("events")
    if not isinstance(events, list) or any(not isinstance(e, str) or not e.strip() for e in events):
        raise ManifestError("events must be a list of non-empty strings")
    if len(events) != len(set(events)):
        raise ManifestError("events must not contain duplicates")

    # JSON round-trip rejects non-serializable values and returns a detached copy.
    import json
    try:
        return json.loads(json.dumps(manifest))
    except (TypeError, ValueError) as exc:
        raise ManifestError("Manifest must contain JSON-compatible values") from exc


@dataclass(frozen=True)
class SimulationResult:
    action: str
    outcome: str
    reason: str


class SimulationRunner:
    """Deterministic dry-run only; it never invokes external tools or providers."""

    def __init__(self, manifest: dict[str, Any]):
        self.manifest = validate_manifest(manifest)
        self._actions = {item["name"]: item for item in self.manifest["actions"]}

    def run(self, requests: Iterable[dict[str, Any]]) -> list[SimulationResult]:
        results: list[SimulationResult] = []
        for request in requests:
            if not isinstance(request, dict):
                results.append(SimulationResult("", "denied", "request must be an object"))
                continue
            action_name = request.get("action")
            action = self._actions.get(action_name)
            if action is None:
                results.append(SimulationResult(str(action_name or ""), "denied", "action is not in the manifest"))
                continue
            requested = request.get("permissions", [])
            if not isinstance(requested, list) or any(not isinstance(p, str) for p in requested):
                results.append(SimulationResult(action_name, "denied", "permissions must be a list of strings"))
                continue
            if not set(requested).issubset(set(action["permissions"])):
                results.append(SimulationResult(action_name, "denied", "permission is not declared for this action"))
                continue
            spend = request.get("estimated_spend_usd", 0)
            if not isinstance(spend, (int, float)) or isinstance(spend, bool) or spend < 0:
                results.append(SimulationResult(action_name, "denied", "invalid spend estimate"))
                continue
            if spend > 0:
                results.append(SimulationResult(action_name, "denied", "pre-revenue paid API spend cap is $0"))
                continue
            if action["requires_approval"] or action["risk"] != "low":
                results.append(SimulationResult(action_name, "approval_required", "manifest requires an owner approval"))
                continue
            results.append(SimulationResult(action_name, "simulated", "dry-run completed; no external side effect occurred"))
        return results


__all__ = ["ManifestError", "SimulationResult", "SimulationRunner", "validate_manifest"]
