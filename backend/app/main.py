import json
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

DB_PATH = Path(os.getenv("GHOSTCORP_DB_PATH", "data/ghostcorp.db"))
API_TOKEN = os.getenv("GHOSTCORP_API_TOKEN", "")

app = FastAPI(title="GhostCorp Shared Core", version="0.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json")


@contextmanager
def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS tasks (
          id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL,
          payload TEXT NOT NULL, checkpoint TEXT, created_at REAL NOT NULL,
          updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS world_state (
          entity_id TEXT PRIMARY KEY, entity_type TEXT NOT NULL,
          data TEXT NOT NULL, revision INTEGER NOT NULL, updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS agent_state (
          agent_id TEXT PRIMARY KEY, status TEXT NOT NULL,
          data TEXT NOT NULL, updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS events (
          seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,
          event_type TEXT NOT NULL, actor TEXT NOT NULL,
          correlation_id TEXT NOT NULL, schema_version INTEGER NOT NULL,
          payload TEXT NOT NULL, created_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
        CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
        """)
        conn.execute("INSERT OR IGNORE INTO world_state(entity_id,entity_type,data,revision,updated_at) VALUES(?,?,?,?,?)",
                     ("world:root", "world", json.dumps({"name":"GhostCorp","schema_version":1,"scenes":{}}), 1, time.time()))


@app.on_event("startup")
def startup():
    init_db()


def require_token(authorization: str | None = Header(default=None)):
    # No default credential is shipped. Configure a long random token in server secrets.
    if not API_TOKEN:
        raise HTTPException(status_code=503, detail="Backend is not configured: set GHOSTCORP_API_TOKEN in server secrets")
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(supplied, API_TOKEN):
        raise HTTPException(status_code=401, detail="Valid owner/service bearer token required")


def emit(conn, event_type: str, payload: dict[str, Any], actor: str = "jarvis", correlation_id: str | None = None):
    conn.execute(
        "INSERT INTO events(event_id,event_type,actor,correlation_id,schema_version,payload,created_at) VALUES(?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), event_type, actor, correlation_id or str(uuid.uuid4()), 1,
         json.dumps(payload, separators=(",", ":")), time.time())
    )


class TaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    payload: dict[str, Any] = Field(default_factory=dict)


class Checkpoint(BaseModel):
    checkpoint: dict[str, Any]
    status: str = Field(default="running", pattern="^(queued|running|blocked|completed|failed)$")


class WorldUpsert(BaseModel):
    entity_type: str = Field(min_length=1, max_length=80)
    data: dict[str, Any]


class AgentUpsert(BaseModel):
    status: str = Field(min_length=1, max_length=40)
    data: dict[str, Any] = Field(default_factory=dict)


@app.get("/health")
def health():
    try:
        with db() as conn:
            conn.execute("SELECT 1").fetchone()
        return {"status": "ok", "service": "ghostcorp-shared-core", "database": "reachable", "api_version": "v1"}
    except sqlite3.Error:
        raise HTTPException(status_code=503, detail="Database unavailable")


@app.get("/api/v1/status", dependencies=[Depends(require_token)])
def status():
    with db() as conn:
        counts = {row["status"]: row["n"] for row in conn.execute("SELECT status,COUNT(*) n FROM tasks GROUP BY status")}
        world = conn.execute("SELECT revision,updated_at FROM world_state WHERE entity_id='world:root'").fetchone()
        agents = conn.execute("SELECT COUNT(*) n FROM agent_state").fetchone()["n"]
        latest = conn.execute("SELECT seq,event_type,created_at FROM events ORDER BY seq DESC LIMIT 1").fetchone()
    return {"service":"ghostcorp-shared-core","tasks":counts,"agent_count":agents,
            "world_revision":world["revision"] if world else 0,
            "last_event":dict(latest) if latest else None}


@app.post("/api/v1/tasks", status_code=201, dependencies=[Depends(require_token)])
def create_task(body: TaskCreate):
    now, task_id = time.time(), str(uuid.uuid4())
    with db() as conn:
        conn.execute("INSERT INTO tasks(id,title,status,payload,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                     (task_id, body.title, "queued", json.dumps(body.payload), now, now))
        emit(conn, "TaskCreated", {"task_id":task_id,"title":body.title})
    return {"id":task_id,"title":body.title,"status":"queued","created_at":now}


@app.get("/api/v1/tasks", dependencies=[Depends(require_token)])
def list_tasks(status: str | None = None, limit: int = 100):
    limit = max(1, min(limit, 500))
    with db() as conn:
        if status:
            rows = conn.execute("SELECT * FROM tasks WHERE status=? ORDER BY created_at DESC LIMIT ?", (status,limit)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return {"items":[{**dict(r),"payload":json.loads(r["payload"]),"checkpoint":json.loads(r["checkpoint"]) if r["checkpoint"] else None} for r in rows]}


@app.put("/api/v1/tasks/{task_id}/checkpoint", dependencies=[Depends(require_token)])
def checkpoint_task(task_id: str, body: Checkpoint):
    now = time.time()
    with db() as conn:
        cur = conn.execute("UPDATE tasks SET checkpoint=?,status=?,updated_at=? WHERE id=?",
                           (json.dumps(body.checkpoint),body.status,now,task_id))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Task not found")
        emit(conn, "TaskCheckpointed", {"task_id":task_id,"status":body.status})
    return {"id":task_id,"status":body.status,"updated_at":now}


@app.get("/api/v1/world/{entity_id}", dependencies=[Depends(require_token)])
def get_world_entity(entity_id: str):
    with db() as conn:
        row = conn.execute("SELECT * FROM world_state WHERE entity_id=?", (entity_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="World entity not found")
    return {"entity_id":row["entity_id"],"entity_type":row["entity_type"],"data":json.loads(row["data"]),
            "revision":row["revision"],"updated_at":row["updated_at"]}


@app.put("/api/v1/world/{entity_id}", dependencies=[Depends(require_token)])
def put_world_entity(entity_id: str, body: WorldUpsert):
    now = time.time()
    with db() as conn:
        row = conn.execute("SELECT revision FROM world_state WHERE entity_id=?", (entity_id,)).fetchone()
        revision = (row["revision"] + 1) if row else 1
        conn.execute("""INSERT INTO world_state(entity_id,entity_type,data,revision,updated_at) VALUES(?,?,?,?,?)
          ON CONFLICT(entity_id) DO UPDATE SET entity_type=excluded.entity_type,data=excluded.data,
          revision=excluded.revision,updated_at=excluded.updated_at""",
          (entity_id,body.entity_type,json.dumps(body.data),revision,now))
        emit(conn, "WorldRevisionCreated", {"entity_id":entity_id,"entity_type":body.entity_type,"revision":revision})
    return {"entity_id":entity_id,"revision":revision,"updated_at":now}


@app.put("/api/v1/agents/{agent_id}", dependencies=[Depends(require_token)])
def put_agent_state(agent_id: str, body: AgentUpsert):
    now = time.time()
    with db() as conn:
        conn.execute("""INSERT INTO agent_state(agent_id,status,data,updated_at) VALUES(?,?,?,?)
          ON CONFLICT(agent_id) DO UPDATE SET status=excluded.status,data=excluded.data,updated_at=excluded.updated_at""",
          (agent_id,body.status,json.dumps(body.data),now))
        emit(conn, "AgentStatusChanged", {"agent_id":agent_id,"status":body.status})
    return {"agent_id":agent_id,"status":body.status,"updated_at":now}


@app.get("/api/v1/events", dependencies=[Depends(require_token)])
def list_events(after: int = 0, limit: int = 100):
    limit = max(1, min(limit, 500))
    with db() as conn:
        rows = conn.execute("SELECT * FROM events WHERE seq>? ORDER BY seq LIMIT ?", (max(0,after),limit)).fetchall()
    return {"items":[{**dict(r),"payload":json.loads(r["payload"])} for r in rows]}
