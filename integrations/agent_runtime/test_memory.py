import tempfile
import time
import unittest
from pathlib import Path

from memory import Memory, MemoryStore


class MemoryStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "state.sqlite3")
        self.store = MemoryStore(self.path)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_memory_persists_with_provenance_and_confidence(self):
        self.store.remember(Memory("project_goal", {"name": "GhostCorp"}, "owner instruction", 0.99))
        self.store.close()
        self.store = MemoryStore(self.path)
        result = self.store.recall("project_goal")
        self.assertEqual(result["value"]["name"], "GhostCorp")
        self.assertEqual(result["source"], "owner instruction")
        self.assertEqual(result["confidence"], 0.99)

    def test_correction_increments_version(self):
        self.assertEqual(self.store.remember(Memory("timezone", "UTC", "config", 1.0)), 1)
        self.assertEqual(self.store.remember(Memory("timezone", "America/Indiana/Indianapolis", "owner correction", 1.0)), 2)

    def test_expired_memory_is_not_recalled_and_can_be_pruned(self):
        self.store.remember(Memory("temporary", "value", "test", 0.8, expires_at=time.time() + 10))
        self.assertIsNone(self.store.recall("temporary", now=time.time() + 20))
        self.assertEqual(self.store.prune_expired(now=time.time() + 20), 1)

    def test_credential_like_material_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.remember(Memory("api_key", "not-a-real-key", "test", 1.0))
        with self.assertRaises(ValueError):
            self.store.remember(Memory("notes", "-----BEGIN PRIVATE KEY-----", "test", 1.0))

    def test_memory_limits_and_confidence_are_validated(self):
        with self.assertRaises(ValueError):
            self.store.remember(Memory("fact", "x" * 17000, "test", 1.0))
        with self.assertRaises(ValueError):
            self.store.remember(Memory("fact", "x", "test", 1.2))

    def test_forget_removes_a_memory(self):
        self.store.remember(Memory("temporary", "value", "test", 1.0))
        self.assertTrue(self.store.forget("temporary"))
        self.assertIsNone(self.store.recall("temporary"))

    def test_goal_lifecycle_and_blockers(self):
        goal_id = self.store.create_goal("Connect Action Center", priority=90, blockers=["need authenticated approval bridge"])
        self.assertEqual(self.store.goals(status="active")[0]["goal_id"], goal_id)
        self.store.update_goal(goal_id, status="blocked")
        self.assertEqual(self.store.goals(status="blocked")[0]["blockers"], ["need authenticated approval bridge"])
        self.store.update_goal(goal_id, status="completed", completion_reason="Integration tests passed")
        self.assertEqual(self.store.goals(status="completed")[0]["completion_reason"], "Integration tests passed")

    def test_terminal_goal_requires_reason(self):
        goal_id = self.store.create_goal("Example")
        with self.assertRaises(ValueError):
            self.store.update_goal(goal_id, status="completed")


if __name__ == "__main__":
    unittest.main()
