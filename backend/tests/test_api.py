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
    first = client.put("/api/v1/world/entities/scene:atrium", headers=headers(),
                       json={"entity_type":"scene","data":{"objects":[]}})
    second = client.put("/api/v1/world/entities/scene:atrium", headers=headers(),
                        json={"entity_type":"scene","data":{"objects":[{"id":"core"}]}})
    assert first.json()["revision"] == 1
    assert second.json()["revision"] == 2
    assert client.get("/api/v1/world/entities/scene:atrium", headers=headers()).json()["data"]["objects"][0]["id"] == "core"
    assert client.put("/api/v1/agents/jarvis", headers=headers(),
                      json={"status":"idle","data":{"mode":"local-first"}}).status_code == 200


def test_world_scene_objects_revisions_and_conflict(monkeypatch, tmp_path):
    client, _ = load_app(monkeypatch, tmp_path)
    created = client.post("/api/v1/world/scenes", headers=headers(),
                          json={"name":"Central Atrium","description":"Main headquarters"})
    assert created.status_code == 201
    scene_id = created.json()["scene_id"]
    assert created.json()["revision"] == 1

    obj = {"object_id":"central-core","asset":"assets/core.glb",
           "position":[0,1,0],"rotation":[0,0,0],"scale":[1,1,1],
           "properties":{"interactive":True}}
    placed = client.put(f"/api/v1/world/scenes/{scene_id}/objects/central-core",
                        headers=headers(), json={"object":obj,"expected_revision":1})
    assert placed.status_code == 200
    assert placed.json()["revision"] == 2

    stale = client.put(f"/api/v1/world/scenes/{scene_id}/objects/central-core",
                       headers=headers(), json={"object":obj,"expected_revision":1})
    assert stale.status_code == 409

    scene = client.get(f"/api/v1/world/scenes/{scene_id}", headers=headers()).json()
    assert scene["revision"] == 2
    assert scene["data"]["objects"][0]["object_id"] == "central-core"

    deleted = client.delete(f"/api/v1/world/scenes/{scene_id}/objects/central-core",
                            headers=headers(), params={"expected_revision":2})
    assert deleted.status_code == 200
    assert deleted.json()["revision"] == 3

    snapshot = client.get("/api/v1/world/snapshot", headers=headers()).json()
    assert snapshot["schema_version"] == 1
    assert any(item["entity_id"] == f"scene:{scene_id}" for item in snapshot["entities"])


def test_quest_gateway_is_private_by_default(monkeypatch, tmp_path):
    client, _ = load_app(monkeypatch, tmp_path)
    assert client.get("/auth/me").json()["authenticated"] is False
    assert client.get("/api/vr/session").status_code == 401
    assert client.get("/api/vr/world/snapshot").status_code == 401
    assert client.get("/api/vr/events").status_code == 401


def test_quest_gateway_does_not_claim_oauth_is_configured_without_secrets(monkeypatch, tmp_path):
    for key in ("GITHUB_OAUTH_CLIENT_ID", "GITHUB_OAUTH_CLIENT_SECRET",
                "GHOSTCORP_OWNER_GITHUB_LOGIN", "GHOSTCORP_SESSION_SECRET",
                "GHOSTCORP_PUBLIC_ORIGIN"):
        monkeypatch.delenv(key, raising=False)
    client, _ = load_app(monkeypatch, tmp_path)
    assert client.get("/auth/status").json()["configured"] is False
    assert client.get("/auth/github/start").status_code == 503
