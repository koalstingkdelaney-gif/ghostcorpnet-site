import importlib
import os


def load_app(monkeypatch, tmp_path):
    monkeypatch.setenv("GHOSTCORP_API_TOKEN", "test-secret-token")
    monkeypatch.setenv("GHOSTCORP_DB_PATH", str(tmp_path / "test.db"))
    import app.main as main
    importlib.reload(main)
    main.init_db()
    from fastapi.testclient import TestClient
    return TestClient(main.app), main


def headers():
    return {"Authorization":"Bearer test-secret-token"}


def test_health_and_auth(monkeypatch, tmp_path):
    client, _ = load_app(monkeypatch, tmp_path)
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/api/v1/status").status_code == 401
    assert client.get("/api/v1/status", headers=headers()).status_code == 200


def test_task_checkpoint_persists_and_emits_event(monkeypatch, tmp_path):
    client, _ = load_app(monkeypatch, tmp_path)
    created = client.post("/api/v1/tasks", headers=headers(), json={"title":"Build world scene","payload":{"scene":"atrium"}})
    assert created.status_code == 201
    task_id = created.json()["id"]
    saved = client.put(f"/api/v1/tasks/{task_id}/checkpoint", headers=headers(),
                       json={"checkpoint":{"step":"geometry","done":3},"status":"running"})
    assert saved.status_code == 200
    item = client.get("/api/v1/tasks", headers=headers()).json()["items"][0]
    assert item["checkpoint"]["step"] == "geometry"
    events = client.get("/api/v1/events", headers=headers()).json()["items"]
    assert [e["event_type"] for e in events] == ["TaskCreated","TaskCheckpointed"]


def test_world_revision_and_agent_state(monkeypatch, tmp_path):
    client, _ = load_app(monkeypatch, tmp_path)
    first = client.put("/api/v1/world/scene:atrium", headers=headers(),
                       json={"entity_type":"scene","data":{"objects":[]}})
    second = client.put("/api/v1/world/scene:atrium", headers=headers(),
                        json={"entity_type":"scene","data":{"objects":[{"id":"core"}]}})
    assert first.json()["revision"] == 1
    assert second.json()["revision"] == 2
    assert client.get("/api/v1/world/scene:atrium", headers=headers()).json()["data"]["objects"][0]["id"] == "core"
    assert client.put("/api/v1/agents/jarvis", headers=headers(),
                      json={"status":"idle","data":{"mode":"local-first"}}).status_code == 200
