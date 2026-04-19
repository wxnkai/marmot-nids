# ADR-003: FastAPI over Flask

## Status

Accepted

---

## Context

The original FYP implementation used Flask (synchronous WSGI) as the web framework.
This created structural tensions with the rest of the system:

1. **Async mismatch.** Packet capture (Scapy), LLM inference (Ollama HTTP client),
   and blockchain submission (web3.py) are all naturally asynchronous operations
   with significant I/O wait. Forcing these into a synchronous Flask context
   required ad-hoc threading that was difficult to reason about and test.

2. **Missing type safety at the boundary.** Flask routes returned raw `dict` objects
   serialised with `jsonify`. There was no validation that the returned data matched
   any schema, and no automatic documentation of the API contract.

3. **No built-in WebSocket support.** The original implementation used HTTP polling
   from the frontend to fetch new alerts. At high alert rates this caused both
   unnecessary load and noticeable UI lag. Adding WebSocket support to Flask requires
   an additional library (Flask-SocketIO or flask-sock) that introduces its own
   async complexity.

4. **Testing boilerplate.** Flask test clients require manual application context
   management. FastAPI's `TestClient` wraps this cleanly, and async route handlers
   can be tested with `pytest-asyncio` without additional setup.

---

## Decision

We use **FastAPI** as the web framework throughout.

Key features used:

| Feature | How it's used in marmot-nids |
|---------|------------------------------|
| `async def` route handlers | All routes are async-native; no blocking I/O in handlers |
| Pydantic response models | Every route declares a typed response model — no raw dicts |
| Lifespan context manager | Engine startup/shutdown wired to `@asynccontextmanager lifespan` — no deprecated `@app.on_event` |
| `WebSocket` endpoint | `/ws/feed` streams alerts, flow updates, and status changes |
| Auto OpenAPI docs | `/docs` and `/redoc` available in development for API exploration |
| `HTTPException` | Consistent error responses with typed detail fields |
| `Depends()` | API key auth and rate limiting injected as dependencies — not middleware spaghetti |

### Response model discipline

All routes return a Pydantic model, not a `dict`. This means:

- Response shape is validated before it leaves the server.
- The OpenAPI schema is always accurate and machine-readable.
- Adding a new field to a response requires updating the model — the compiler (Mypy/Pyright) catches missing fields.

### Lifespan over `on_event`

```python
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # startup
    await signature_manager.load()
    await llm_engine.start()
    await blockchain_provider.connect()
    yield
    # shutdown
    await llm_engine.stop()
    await blockchain_provider.disconnect()
```

Using `lifespan` instead of `@app.on_event("startup")` / `@app.on_event("shutdown")`
avoids deprecation warnings in FastAPI 0.95+ and makes startup/shutdown order explicit.

---

## Consequences

**Positive:**

- The entire application is async-native: capture, detection, storage, and API
  all cooperate in a single asyncio event loop with no blocking.
- Pydantic validation at every boundary (request bodies, response models, LLM output)
  eliminates an entire class of type confusion bugs.
- Auto-generated OpenAPI documentation is always current and accurate.
- WebSocket support is built-in — no additional dependencies.
- `pytest` + `httpx.AsyncClient` makes integration tests straightforward.

**Negative:**

- Developers must understand `async/await` and the asyncio event loop. Accidentally
  calling a blocking function (e.g. `time.sleep`) in a route handler will stall
  the entire server. Ruff's `ASYNC` rule set catches the most common violations.
- FastAPI's dependency injection model (`Depends`) has a learning curve compared to
  Flask's simpler `g` / `current_app` globals.

---

## Security Implications

- **Pydantic on all inputs.** FastAPI runs Pydantic validation on every request body
  before the handler function is called. Invalid data returns a `422 Unprocessable
  Entity` before any business logic executes, eliminating injection paths through
  malformed request payloads.

- **OpenAPI exposure.** The `/docs` endpoint is disabled in `ENVIRONMENT=production`
  to avoid advertising the API surface to unauthorised parties. It remains available
  in `development` and for CI-based contract testing.

- **Async rate limiting.** The sliding-window rate limiter (`core/api/middleware/rate_limit.py`)
  uses `asyncio.Lock` for per-key state updates, which is safe under concurrent
  async requests without the thundering-herd risk of thread locks.

- **No global mutable state in routes.** All shared state (engine references,
  provider handles) is passed via FastAPI's dependency injection rather than
  module-level globals. This makes the state lifecycle explicit and avoids the
  subtle race conditions that Flask's `g` object can introduce under concurrent load.
