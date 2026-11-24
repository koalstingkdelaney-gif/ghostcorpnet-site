import json
import sqlite3
from pathlib import Path

from jarvis.handoff import add_mission, checkpoint, connect, export_handoff, log_usage


def test_provider_to_local_handoff_round_trip(tmp_path: Path):
    db=connect(tmp_path/"state.sqlite3")
    add_mission(db,"M-1","Build feature","Implement feature and tests",10)
    checkpoint(db,"M-1","API model completed design and wrote draft","Local model: implement tests and verify behavior","provider-a","model-x","design.md","Design artifact")
    log_usage(db,"provider-a","model-x","success",100,200,"2026-11-25T00:00:00Z")
    db.commit()
    output=export_handoff(db,"M-1",tmp_path/"handoff.json")
    data=json.loads(output.read_text())
    assert data["mission"]["status"]=="paused"
    assert data["mission"]["next_action"].startswith("Local model")
    assert data["artifacts"][0]["content"]=="Design artifact"
    assert data["local_model_instructions"]["never_assume_provider_outputs_are_correct"] is True
    db.close()


def test_unknown_mission_cannot_be_checkpointed(tmp_path: Path):
    db=connect(tmp_path/"state.sqlite3")
    try:
        checkpoint(db,"missing","checkpoint","continue","provider","model")
        assert False, "expected KeyError"
    except KeyError:
        pass
    db.close()
