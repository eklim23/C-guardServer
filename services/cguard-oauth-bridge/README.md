# C-Guard OAuth Bridge

Public Discord OAuth bridge for C-Guard identity linking.

## Role

This service is an identity handoff only:

- Receives Discord OAuth callback on a public HTTPS URL.
- Fetches Discord user identity with the `identify` scope.
- Calls C-Guard `/v1/integration/discord/identity/link`.
- Shows a simple success or failure page.

It does not make C-Guard policy decisions, read participant telemetry, or expose ops
portal admin functions.

## Required Environment

```text
PUBLIC_BASE_URL=https://cguard-auth.example.com
DISCORD_CLIENT_ID=...
DISCORD_CLIENT_SECRET=...
DISCORD_REDIRECT_URI=https://cguard-auth.example.com/discord/callback
CGUARD_SERVER_BASE_URL=http://cguard-server:8500
CGUARD_INTEGRATION_TOKEN=...
OAUTH_STATE_SIGNING_SECRET=...
```

When this bridge is hosted outside the compose network, set
`CGUARD_SERVER_BASE_URL` to the participant C-Guard API, for example
`https://10.3.0.10:9443`.

For staging with a self-signed C-Guard certificate only:

```text
CGUARD_ALLOW_SELF_SIGNED_TLS=true
```

Do not enable that in production.

## Routes

```text
GET /health
GET /discord/start?user_id=...&session_id=...&reason_code=...
GET /discord/callback?code=...&state=...
```

## C-Guard Server Wiring

Set C-Guard server:

```text
INTEGRATION_DISCORD_IDENTITY_AUTH_URL_TEMPLATE=https://cguard-auth.example.com/discord/start?user_id={user_id}&session_id={session_id}&reason_code={reason_code}&server_base_url={server_base_url}
```

## Tests

```bash
npm test
```
