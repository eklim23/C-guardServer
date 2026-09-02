# C-GuardServer

This is the C-Guard admin-only deployment bundle.

## Included Services

- `postgres`: C-Guard state storage
- `cguard-server`: C-Guard client API and admin API
- `cguard-frontend`: C-Guard admin UI
- `nginx`: public HTTPS gateway

## Public Routes

- `/cguard-admin`: administrator UI
- `/cguard-api/*`: admin UI API proxy
- `/health`: C-Guard server health check
- `/v1/auth/login`: C-Guard client login
- `/v1/client/*`: C-Guard client heartbeat/proof APIs
- `/v1/events`: C-Guard client telemetry upload
- `/v1/verify`: C-Guard verification API

Other C-Strike operations portal pages and services are removed from this bundle.

## Run

```bash
cd C-GuardServer/infra
docker compose --env-file ../.env up -d --build
```
