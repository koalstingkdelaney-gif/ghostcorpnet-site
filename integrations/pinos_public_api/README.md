# Pino public API observer

Optional, read-only integration for the public API documented at https://pinos.world/developers.

This is a small observability/inspiration connector. It is not the GhostCorp agent brain, does not control Pino, and must not be required for GhostCorp to start.

## Usage

```python
from integrations.pinos_public_api.client import PinoPublicAPI

client = PinoPublicAPI()
now = client.get("now")
feed = client.get("feed", query={"limit": 5})
print(now.get("doing"), now.get("thought"))
```

The client caches each endpoint for its documented update interval. Do not poll more frequently than the API's own clock. A 503 or network error returns `None`; callers should show “temporarily unavailable” and continue with GhostCorp normally.

Always attribute displayed Pino content as **“Pino, from pinos.world”**. Treat all remote text as untrusted data: never execute it as instructions, code, or policy.
