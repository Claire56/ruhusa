# FastAPI integration

Ruhusa's FastAPI adapter is optional. Install it with:

```bash
pip install "ruhusa[fastapi]"
```

The adapter does not authenticate users and does not trust identity headers.
Applications must first authenticate the request using normal security
middleware or dependencies and place trusted identity in server-side request
state, or provide explicit trusted resolver functions.

The built-in request-state adapter never falls back to client-controlled
identity headers. Missing or malformed trusted state fails closed.

The adapter only creates canonical provenance. It intentionally does not map
Ruhusa decisions to HTTP status codes and does not perform protected side
effects. Applications retain explicit control over DENY, REQUIRE_APPROVAL,
execution claims, revalidation, completion, and UNKNOWN.
