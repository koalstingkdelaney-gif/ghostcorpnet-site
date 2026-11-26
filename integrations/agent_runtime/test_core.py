import unittest

from core import ActionRequest, JournalLine, RuntimeStore


class RuntimeStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = RuntimeStore()

    def tearDown(self):
        self.store.close()

    def test_agent_autonomous_low_risk_action(self):
        self.store.create_agent("researcher-1", "researcher", ["web.read", "workspace.write"])
        result = self.store.evaluate(ActionRequest(
            actor_id="researcher-1", action="research",
            requested_permissions=("web.read",), risk="low",
        ))
        self.assertTrue(result.allowed)
        self.assertFalse(result.requires_approval)

    def test_ungranted_permission_fails_closed(self):
        self.store.create_agent("agent-1", "worker", ["workspace.write"])
        result = self.store.evaluate(ActionRequest(
            actor_id="agent-1", action="research",
            requested_permissions=("web.read",),
        ))
        self.assertFalse(result.allowed)

    def test_external_action_requires_approval(self):
        self.store.create_agent("agent-1", "worker", ["external.publish"])
        denied = self.store.evaluate(ActionRequest(
            actor_id="agent-1", action="publish_or_contact",
            requested_permissions=("external.publish",),
        ))
        self.assertFalse(denied.allowed)
        self.assertTrue(denied.requires_approval)
        approved = self.store.evaluate(ActionRequest(
            actor_id="agent-1", action="publish_or_contact",
            requested_permissions=("external.publish",), approval_granted=True,
        ))
        self.assertTrue(approved.allowed)

    def test_pre_revenue_spend_is_blocked(self):
        self.store.create_agent("agent-1", "worker", ["workspace.write"])
        result = self.store.evaluate(ActionRequest(
            actor_id="agent-1", action="create_artifact",
            requested_permissions=("workspace.write",),
            estimated_spend_minor=1, revenue_recorded=False,
        ))
        self.assertFalse(result.allowed)

    def test_kill_switch_blocks_even_low_risk_action(self):
        self.store.create_agent("agent-1", "worker", ["workspace.write"])
        self.store.kill_switch_enabled = True
        result = self.store.evaluate(ActionRequest(
            actor_id="agent-1", action="create_artifact",
            requested_permissions=("workspace.write",),
        ))
        self.assertFalse(result.allowed)

    def test_journal_must_balance_and_is_idempotent(self):
        lines = [
            JournalLine("cash", debit_minor=1250),
            JournalLine("sales", credit_minor=1250),
        ]
        self.assertTrue(self.store.post_journal("payment-1", "Customer payment", lines))
        self.assertFalse(self.store.post_journal("payment-1", "Duplicate webhook", lines))
        self.assertEqual(self.store.account_balance_minor("cash"), 1250)
        self.assertEqual(self.store.account_balance_minor("sales"), -1250)
        with self.assertRaises(ValueError):
            self.store.post_journal("bad", "Unbalanced", [
                JournalLine("cash", debit_minor=100),
                JournalLine("sales", credit_minor=99),
            ])

    def test_policy_decisions_are_audited(self):
        self.store.create_agent("agent-1", "worker", ["workspace.write"])
        self.store.evaluate(ActionRequest(
            actor_id="agent-1", action="create_artifact",
            requested_permissions=("workspace.write",),
        ))
        self.assertTrue(any(event["event_type"] == "policy_decision" for event in self.store.events()))


if __name__ == "__main__":
    unittest.main()
