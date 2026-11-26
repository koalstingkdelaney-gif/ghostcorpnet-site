import json
import unittest
from pathlib import Path

from world import ManifestError, SimulationRunner, validate_manifest


MANIFEST_PATH = Path(__file__).resolve().parents[2] / "docs" / "agent-world" / "world-manifest.example.json"


class WorldManifestTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_repository_manifest_is_valid(self):
        result = validate_manifest(self.manifest)
        self.assertEqual(result["protocol"], "ghostcorp-world/1")

    def test_high_risk_action_cannot_skip_approval(self):
        self.manifest["actions"][3]["requires_approval"] = False
        with self.assertRaises(ManifestError):
            validate_manifest(self.manifest)

    def test_pre_revenue_spend_cap_cannot_be_raised(self):
        self.manifest["limits"]["paid_api_spend_before_revenue_usd"] = 1
        with self.assertRaises(ManifestError):
            validate_manifest(self.manifest)

    def test_duplicate_action_names_are_rejected(self):
        self.manifest["actions"].append(dict(self.manifest["actions"][0]))
        with self.assertRaises(ManifestError):
            validate_manifest(self.manifest)

    def test_simulation_allows_only_declared_low_risk_zero_spend(self):
        runner = SimulationRunner(self.manifest)
        results = runner.run([
            {"action": "research", "permissions": ["web.read"], "estimated_spend_usd": 0},
            {"action": "publish_or_contact", "permissions": ["external.publish"]},
            {"action": "spend_or_transfer", "permissions": ["treasury.transact"]},
            {"action": "unknown_action"},
            {"action": "research", "permissions": ["admin.root"]},
            {"action": "research", "permissions": ["web.read"], "estimated_spend_usd": 0.01},
        ])
        self.assertEqual([r.outcome for r in results], [
            "simulated", "approval_required", "approval_required",
            "denied", "denied", "denied",
        ])
        self.assertIn("no external side effect", results[0].reason)

    def test_simulation_does_not_trust_caller_approval_boolean(self):
        runner = SimulationRunner(self.manifest)
        result = runner.run([{
            "action": "publish_or_contact",
            "permissions": ["external.publish"],
            "approval_granted": True,
        }])[0]
        self.assertEqual(result.outcome, "approval_required")


if __name__ == "__main__":
    unittest.main()
