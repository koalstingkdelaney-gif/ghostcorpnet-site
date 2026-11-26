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

    def test_external_action_requires_scoped_one_time_approval(self):
        self.store.create_agent("agent-1", "worker", ["external.publish"])
        request = ActionRequest(
            actor_id="agent-1", action="publish_or_contact",
            requested_permissions=("external.publish",),
        )
        denied = self.store.evaluate(request)
        self.assertFalse(denied.allowed)
        self.assertTrue(denied.requires_approval)

        approval_id = self.store.request_approval(
            "agent-1", "publish_or_contact", ["external.publish"]
        )
        self.store.grant_approval(approval_id, approved_by="authenticated-owner")
        approved = self.store.evaluate(ActionRequest(
            actor_id="agent-1", action="publish_or_contact",
            requested_permissions=("external.publish",), approval_id=approval_id,
        ))
        self.assertTrue(approved.allowed)
        replay = self.store.evaluate(ActionRequest(
            actor_id="agent-1", action="publish_or_contact",
            requested_permissions=("external.publish",), approval_id=approval_id,
        ))
        self.assertFalse(replay.allowed)

    def test_legacy_approval_boolean_is_not_trusted(self):
        self.store.create_agent("agent-1", "worker", ["external.publish"])
        result = self.store.evaluate(ActionRequest(
            actor_id="agent-1", action="publish_or_contact",
            requested_permissions=("external.publish",), approval_granted=True,
        ))
        self.assertFalse(result.allowed)

    def test_approval_is_bound_to_actor_action_and_permissions(self):
        self.store.create_agent("agent-1", "worker", ["external.publish"])
        self.store.create_agent("agent-2", "worker", ["external.publish"])
        approval_id = self.store.request_approval(
            "agent-1", "publish_or_contact", ["external.publish"]
        )
        self.store.grant_approval(approval_id, approved_by="authenticated-owner")
        wrong_actor = self.store.evaluate(ActionRequest(
            actor_id="agent-2", action="publish_or_contact",
            requested_permissions=("external.publish",), approval_id=approval_id,
        ))
        self.assertFalse(wrong_actor.allowed)
        right_actor = self.store.evaluate(ActionRequest(
            actor_id="agent-1", action="publish_or_contact",
            requested_permissions=("external.publish",), approval_id=approval_id,
        ))
        self.assertTrue(right_actor.allowed)

    def test_pre_revenue_spend_is_blocked(self):
        self.store.create_agent("agent-1", "worker", ["workspace.write"])
        result = self.store.evaluate(ActionRequest(
            actor_id="agent-1", action="create_artifact",
            requested_permissions=("workspace.write",),
            estimated_spend_minor=1, revenue_recorded=False,
        ))
        self.assertFalse(result.allowed)


    def test_spend_above_configured_cap_is_blocked_even_after_revenue(self):
        self.store.paid_api_spend_cap_minor = 500
        self.store.create_agent("agent-1", "worker", ["workspace.write"])
        result = self.store.evaluate(ActionRequest(
            actor_id="agent-1", action="create_artifact",
            requested_permissions=("workspace.write",),
            estimated_spend_minor=501, revenue_recorded=True,
        ))
        self.assertFalse(result.allowed)
        self.assertIn("cap", result.reason)

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
