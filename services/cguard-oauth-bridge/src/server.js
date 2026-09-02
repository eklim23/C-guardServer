"use strict";

const http = require("http");
const { URL, URLSearchParams } = require("url");
const {
  createMemoryNonceStore,
  createSignedState,
  verifySignedState
} = require("./state");

const DISCORD_AUTHORIZE_URL = "https://discord.com/oauth2/authorize";
const DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token";
const DISCORD_ME_URL = "https://discord.com/api/users/@me";
const BRIDGE_CLIENT_VERSION = "cguard-oauth-bridge@0.1.0";

function normalizeString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : "";
}

function normalizeBaseUrl(value) {
  return normalizeString(value).replace(/\/+$/, "");
}

function parsePositiveInt(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.floor(parsed);
}

function parseBoolean(value, fallback = false) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) return fallback;
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
}

function loadConfig(env = process.env) {
  const publicBaseUrl = normalizeBaseUrl(env.PUBLIC_BASE_URL);
  const redirectUri =
    normalizeString(env.DISCORD_REDIRECT_URI) ||
    (publicBaseUrl ? `${publicBaseUrl}/discord/callback` : "");
  return {
    port: parsePositiveInt(env.PORT, 8600),
    publicBaseUrl,
    discordClientId: normalizeString(env.DISCORD_CLIENT_ID),
    discordClientSecret: normalizeString(env.DISCORD_CLIENT_SECRET),
    discordRedirectUri: redirectUri,
    cguardServerBaseUrl: normalizeBaseUrl(env.CGUARD_SERVER_BASE_URL),
    cguardIntegrationToken: normalizeString(env.CGUARD_INTEGRATION_TOKEN),
    stateSigningSecret: normalizeString(env.OAUTH_STATE_SIGNING_SECRET),
    stateTtlMs: parsePositiveInt(env.OAUTH_STATE_TTL_SEC, 600) * 1000,
    allowSelfSignedTls: parseBoolean(env.CGUARD_ALLOW_SELF_SIGNED_TLS, false)
  };
}

function bridgeReady(config) {
  return Boolean(
    config.publicBaseUrl &&
      config.discordClientId &&
      config.discordClientSecret &&
      config.discordRedirectUri &&
      config.cguardServerBaseUrl &&
      config.cguardIntegrationToken &&
      config.stateSigningSecret
  );
}

function log(severity, eventType, detail = {}) {
  const safeDetail = { ...detail };
  delete safeDetail.code;
  delete safeDetail.access_token;
  delete safeDetail.refresh_token;
  delete safeDetail.client_secret;
  const userId = normalizeString(safeDetail.user_id) || null;
  const sessionId = normalizeString(safeDetail.session_id) || null;
  const evidence =
    safeDetail.evidence && typeof safeDetail.evidence === "object" ? safeDetail.evidence : {};
  delete safeDetail.user_id;
  delete safeDetail.session_id;
  delete safeDetail.evidence;
  console.log(
    JSON.stringify({
      timestamp: new Date().toISOString(),
      event_type: eventType,
      severity,
      session_id: sessionId,
      user_id: userId,
      client_version: BRIDGE_CLIENT_VERSION,
      evidence,
      ...safeDetail
    })
  );
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store"
  });
  res.end(body);
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function sendHtml(res, statusCode, title, message) {
  const safeTitle = String(title || "");
  const safeMessage = String(message || "");
  res.writeHead(statusCode, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store"
  });
  res.end(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(safeTitle)}</title>
  <style>
    body { font-family: system-ui, sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f8fafc; color: #0f172a; }
    main { max-width: 520px; padding: 32px; border: 1px solid #dbe3ef; border-radius: 20px; background: white; box-shadow: 0 20px 50px rgba(15, 23, 42, 0.08); }
    h1 { margin: 0 0 12px; font-size: 24px; }
    p { margin: 0; line-height: 1.6; color: #475569; }
  </style>
</head>
<body>
  <main>
    <h1>${escapeHtml(safeTitle)}</h1>
    <p>${escapeHtml(safeMessage)}</p>
  </main>
</body>
</html>`);
}

function redirect(res, location) {
  res.writeHead(302, {
    location,
    "cache-control": "no-store"
  });
  res.end();
}

function buildDiscordAuthorizeUrl(config, state) {
  const url = new URL(DISCORD_AUTHORIZE_URL);
  url.searchParams.set("client_id", config.discordClientId);
  url.searchParams.set("redirect_uri", config.discordRedirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "identify");
  url.searchParams.set("state", state);
  return url.toString();
}

async function exchangeDiscordCode(config, code) {
  const body = new URLSearchParams({
    client_id: config.discordClientId,
    client_secret: config.discordClientSecret,
    grant_type: "authorization_code",
    code,
    redirect_uri: config.discordRedirectUri
  });
  const response = await fetch(DISCORD_TOKEN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json"
    },
    body
  });
  if (!response.ok) {
    throw new Error(`discord token exchange failed: HTTP ${response.status}`);
  }
  const payload = await response.json();
  if (!payload || typeof payload.access_token !== "string" || !payload.access_token.trim()) {
    throw new Error("discord token exchange response missing access_token");
  }
  return payload.access_token;
}

async function fetchDiscordUser(accessToken) {
  const response = await fetch(DISCORD_ME_URL, {
    headers: {
      authorization: `Bearer ${accessToken}`,
      accept: "application/json"
    }
  });
  if (!response.ok) {
    throw new Error(`discord user fetch failed: HTTP ${response.status}`);
  }
  const user = await response.json();
  if (!user || typeof user.id !== "string" || !user.id.trim()) {
    throw new Error("discord user response missing id");
  }
  return user;
}

function resolveDiscordDisplayName(user) {
  return (
    normalizeString(user.global_name) ||
    normalizeString(user.display_name) ||
    normalizeString(user.username) ||
    normalizeString(user.id)
  );
}

async function linkCguardIdentity(config, statePayload, discordUser) {
  const payload = {
    user_id: statePayload.user_id,
    discord_user_id: discordUser.id,
    discord_display_name: resolveDiscordDisplayName(discordUser),
    discord_username: normalizeString(discordUser.username) || null,
    identity_source: "oauth",
    verification_method: "discord_oauth2_bridge",
    verified_at: new Date().toISOString(),
    metadata: {
      session_id: statePayload.session_id,
      reason_code: statePayload.reason_code,
      bridge: "cguard-oauth-bridge"
    }
  };
  const response = await fetch(
    `${config.cguardServerBaseUrl}/v1/integration/discord/identity/link`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${config.cguardIntegrationToken}`,
        "x-integration-client": "cguard-oauth-bridge",
        "content-type": "application/json",
        accept: "application/json"
      },
      body: JSON.stringify(payload)
    }
  );
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    const detail = text ? `: ${text.slice(0, 200)}` : "";
    throw new Error(`cguard identity link failed: HTTP ${response.status}${detail}`);
  }
  return response.json().catch(() => ({}));
}

function createServer(config = loadConfig(), deps = {}) {
  const nonceStore = deps.nonceStore || createMemoryNonceStore();

  if (config.allowSelfSignedTls) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    log("warn", "CGUARD_SELF_SIGNED_TLS_ENABLED", {
      message: "TLS verification is disabled for C-Guard link requests"
    });
  }

  return http.createServer(async (req, res) => {
    const requestUrl = new URL(req.url || "/", "http://localhost");
    try {
      if (req.method === "GET" && requestUrl.pathname === "/health") {
        return sendJson(res, 200, {
          status: "ok",
          configured: bridgeReady(config),
          discord_client_configured: Boolean(config.discordClientId && config.discordClientSecret),
          redirect_uri_configured: Boolean(config.discordRedirectUri),
          cguard_configured: Boolean(config.cguardServerBaseUrl && config.cguardIntegrationToken)
        });
      }

      if (req.method === "GET" && requestUrl.pathname === "/discord/start") {
        if (!bridgeReady(config)) {
          log("error", "BRIDGE_MISCONFIGURED");
          return sendHtml(
            res,
            500,
            "C-Guard identity setup error",
            "The Discord identity bridge is not fully configured."
          );
        }
        const userId = normalizeString(requestUrl.searchParams.get("user_id"));
        const sessionId = normalizeString(requestUrl.searchParams.get("session_id"));
        if (!userId || !sessionId) {
          return sendHtml(
            res,
            400,
            "C-Guard identity request error",
            "user_id or session_id is missing."
          );
        }
        const reasonCode =
          normalizeString(requestUrl.searchParams.get("reason_code")) ||
          "DISCORD_IDENTITY_REQUIRED";
        const serverBaseUrl = normalizeString(requestUrl.searchParams.get("server_base_url"));
        const signed = createSignedState(
          { userId, sessionId, reasonCode, serverBaseUrl },
          {
            secret: config.stateSigningSecret,
            ttlMs: config.stateTtlMs,
            nonceStore
          }
        );
        log("info", "DISCORD_OAUTH_START", {
          user_id: userId,
          session_id: sessionId,
          reason_code: reasonCode
        });
        return redirect(res, buildDiscordAuthorizeUrl(config, signed.state));
      }

      if (req.method === "GET" && requestUrl.pathname === "/discord/callback") {
        if (requestUrl.searchParams.get("error")) {
          log("warn", "DISCORD_OAUTH_DENIED", {
            error_name: requestUrl.searchParams.get("error")
          });
          return sendHtml(
            res,
            400,
            "Discord identity cancelled",
            "Discord authorization was cancelled or denied."
          );
        }
        const code = normalizeString(requestUrl.searchParams.get("code"));
        const rawState = normalizeString(requestUrl.searchParams.get("state"));
        if (!code || !rawState) {
          return sendHtml(
            res,
            400,
            "Discord identity error",
            "code or state is missing."
          );
        }
        const verified = verifySignedState(rawState, {
          secret: config.stateSigningSecret,
          nonceStore
        });
        if (!verified.ok) {
          log("warn", "DISCORD_OAUTH_STATE_REJECTED", { code_name: verified.code });
          return sendHtml(res, 400, "Discord identity error", verified.message);
        }

        const accessToken = await exchangeDiscordCode(config, code);
        const discordUser = await fetchDiscordUser(accessToken);
        await linkCguardIdentity(config, verified.payload, discordUser);

        log("info", "DISCORD_OAUTH_LINKED", {
          user_id: verified.payload.user_id,
          session_id: verified.payload.session_id,
          discord_user_id: discordUser.id
        });
        return sendHtml(
          res,
          200,
          "C-Guard Discord identity linked",
          "Your Discord account has been linked to this C-Guard session. You can close this window."
        );
      }

      return sendJson(res, 404, { code: "NOT_FOUND", message: "not found" });
    } catch (error) {
      log("error", "BRIDGE_REQUEST_FAILED", {
        pathname: requestUrl.pathname,
        message: error && error.message ? error.message : String(error)
      });
      return sendHtml(
        res,
        500,
        "C-Guard identity failed",
        "An error occurred while processing Discord identity."
      );
    }
  });
}

if (require.main === module) {
  const config = loadConfig();
  const server = createServer(config);
  server.listen(config.port, () => {
    log("info", "BRIDGE_STARTED", {
      port: config.port,
      configured: bridgeReady(config)
    });
  });
}

module.exports = {
  createServer,
  loadConfig,
  bridgeReady
};
