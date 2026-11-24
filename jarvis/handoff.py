#!/usr/bin/env python3
"""Durable provider-to-local handoff queue for Jarvis.

Stores task state and model-produced artifacts locally so another model can resume.
Do not place credentials, payment data, customer PII, or raw secrets in task payloads.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS missions (
  mission_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  objective TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  priority INTEGER NOT NULL DEFAULT 50,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  current_checkpoint TEXT NOT NULL DEFAULT '',
  next_action TEXT NOT NULL DEFAULT '',
  assigned_model TEXT NOT NULL DEFAULT '',
  source_provider TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  mission_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  summary TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY(mission_id) REFERENCES missions(mission_id)
);
CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
  mission_id TEXT NOT NULL,
  name TEXT NOT NULL,
  media_type TEXT NOT NULL DEFAULT 'text/plain',
  content TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  FOREIGN KEY(mission_id) REFERENCES missions(mission_id)
);
CREATE TABLE IF NOT EXISTS provider_usage (
  usage_id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  request_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  quota_reset_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_missions_status_priority ON missions(status, priority, created_at);
CREATE INDEX IF NOT EXISTS idx_events_mission ON events(mission_id, event_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_mission ON artifacts(mission_id, artifact_id);
"""

def now() -> str:
    return datetime.now(timezone.utc).isoformat()

def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    return db

def record_event(db: sqlite3.Connection, mission_id: str, event_type: str,
                 summary: str, provider: str = "", model: str = "",
                 payload: dict[str, Any] | None = None) -> None:
    db.execute(
        "INSERT INTO events(mission_id,event_type,provider,model,created_at,summary,payload_json) VALUES(?,?,?,?,?,?,?)",
        (mission_id,event_type,provider,model,now(),summary,json.dumps(payload or {}, sort_keys=True))
    )

def add_mission(db: sqlite3.Connection, mission_id: str, title: str, objective: str,
                priority: int = 50) -> None:
    stamp=now()
    db.execute(
        "INSERT INTO missions(mission_id,title,objective,status,priority,created_at,updated_at) VALUES(?,?,?,'queued',?,?,?)",
        (mission_id,title,objective,priority,stamp,stamp)
    )
    record_event(db,mission_id,"created","Mission queued.")

def checkpoint(db: sqlite3.Connection, mission_id: str, summary: str,
               next_action: str, provider: str, model: str,
               artifact_name: str = "", artifact_content: str = "") -> None:
    stamp=now()
    cur=db.execute("UPDATE missions SET status='paused',current_checkpoint=?,next_action=?,assigned_model=?,source_provider=?,updated_at=? WHERE mission_id=?",
                   (summary,next_action,model,provider,stamp,mission_id))
    if cur.rowcount != 1:
        raise KeyError(f"Unknown mission: {mission_id}")
    record_event(db,mission_id,"checkpoint",summary,provider,model,{"next_action":next_action})
    if artifact_name:
        digest=hashlib.sha256(artifact_content.encode("utf-8")).hexdigest()
        db.execute("INSERT INTO artifacts(mission_id,name,content,sha256,created_at,provider,model) VALUES(?,?,?,?,?,?,?)",
                   (mission_id,artifact_name,artifact_content,digest,stamp,provider,model))

def log_usage(db: sqlite3.Connection, provider: str, model: str, status: str,
              input_tokens: int=0, output_tokens: int=0, quota_reset_at: str="",
              request_id: str="", error: str="") -> None:
    db.execute("INSERT INTO provider_usage(provider,model,request_id,status,input_tokens,output_tokens,quota_reset_at,created_at,error) VALUES(?,?,?,?,?,?,?,?,?)",
               (provider,model,request_id,status,input_tokens,output_tokens,quota_reset_at,now(),error))

def export_handoff(db: sqlite3.Connection, mission_id: str, output: Path) -> Path:
    mission=db.execute("SELECT * FROM missions WHERE mission_id=?",(mission_id,)).fetchone()
    if mission is None:
        raise KeyError(f"Unknown mission: {mission_id}")
    events=db.execute("SELECT event_type,provider,model,created_at,summary,payload_json FROM events WHERE mission_id=? ORDER BY event_id",(mission_id,)).fetchall()
    artifacts=db.execute("SELECT name,media_type,content,sha256,created_at,provider,model FROM artifacts WHERE mission_id=? ORDER BY artifact_id",(mission_id,)).fetchall()
    usage=db.execute("SELECT provider,model,status,input_tokens,output_tokens,quota_reset_at,created_at,error FROM provider_usage WHERE created_at >= ? ORDER BY usage_id",(mission["created_at"],)).fetchall()
    bundle={
      "schema_version":1,
      "exported_at":now(),
      "mission":dict(mission),
      "events":[{**dict(e),"payload":json.loads(e["payload_json"])} for e in events],
      "artifacts":[{k:a[k] for k in a.keys()} for a in artifacts],
      "provider_usage":[dict(u) for u in usage],
      "local_model_instructions":{
        "task":"Resume the mission from its latest checkpoint. Do not repeat completed work.",
        "verify_artifact_hashes":True,
        "preserve_owner_policy":True,
        "never_assume_provider_outputs_are_correct":True,
        "first_action":mission["next_action"] or "Inspect the checkpoint and determine the smallest next step."
      }
    }
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(bundle,indent=2,ensure_ascii=False)+"\n")
    return output

def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--db",default="state/jarvis-handoff.sqlite3")
    sub=p.add_subparsers(dest="command",required=True)
    a=sub.add_parser("add"); a.add_argument("mission_id"); a.add_argument("title"); a.add_argument("objective"); a.add_argument("--priority",type=int,default=50)
    c=sub.add_parser("checkpoint"); c.add_argument("mission_id"); c.add_argument("summary"); c.add_argument("next_action"); c.add_argument("--provider",default=""); c.add_argument("--model",default=""); c.add_argument("--artifact"); c.add_argument("--artifact-file")
    e=sub.add_parser("export"); e.add_argument("mission_id"); e.add_argument("--output",required=True)
    n=sub.add_parser("next")
    u=sub.add_parser("usage"); u.add_argument("provider"); u.add_argument("model"); u.add_argument("status"); u.add_argument("--input-tokens",type=int,default=0); u.add_argument("--output-tokens",type=int,default=0); u.add_argument("--reset-at",default=""); u.add_argument("--request-id",default=""); u.add_argument("--error",default="")
    args=p.parse_args()
    db=connect(Path(args.db))
    try:
        if args.command=="add":
            add_mission(db,args.mission_id,args.title,args.objective,args.priority)
        elif args.command=="checkpoint":
            content=Path(args.artifact_file).read_text() if args.artifact_file else ""
            checkpoint(db,args.mission_id,args.summary,args.next_action,args.provider,args.model,args.artifact or "",content)
        elif args.command=="usage":
            log_usage(db,args.provider,args.model,args.status,args.input_tokens,args.output_tokens,args.reset_at,args.request_id,args.error)
        elif args.command=="export":
            out=export_handoff(db,args.mission_id,Path(args.output)); print(out)
        elif args.command=="next":
            row=db.execute("SELECT mission_id,title,status,priority,current_checkpoint,next_action,assigned_model,source_provider FROM missions WHERE status IN ('queued','paused') ORDER BY priority ASC,created_at ASC LIMIT 1").fetchone()
            print(json.dumps(dict(row) if row else None,indent=2))
        db.commit()
        return 0
    except Exception as exc:
        db.rollback()
        print(f"handoff error: {exc}",file=sys.stderr)
        return 1
    finally:
        db.close()

if __name__=="__main__":
    raise SystemExit(main())
