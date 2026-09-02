const { createApp } = require("./httpServer");

const port = Number(process.env.PORT || 8080);

function normalizePositiveInteger(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.floor(parsed);
}

function normalizePositiveNumber(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return parsed;
}

function normalizeBoolean(value, fallback) {
  if (value === undefined || value === null || String(value).trim() === "") return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
}

function buildAdminUsersFromEnv() {
  const username = String(process.env.CGUARD_ADMIN_USERNAME || "").trim();
  const password = String(process.env.CGUARD_ADMIN_PASSWORD || "");
  const role = String(process.env.CGUARD_ADMIN_ROLE || "enforcer").trim() || "enforcer";
  if (!username || !password) return undefined;
  return [{ username, password, role }];
}

const app = createApp({
  stateMode: process.env.STATE_MODE || "memory",
  postgresConnectionString:
    process.env.STATE_PG_CONNECTION_STRING || process.env.DATABASE_URL || "",
  postgresSchema: process.env.STATE_PG_SCHEMA || "cstrike",
  postgresPsqlBin: process.env.STATE_PG_PSQL_BIN || "psql",
  postgresDdlPath: process.env.STATE_PG_DDL_PATH || "",
  postgresStatementTimeoutMs: Number(process.env.STATE_PG_STATEMENT_TIMEOUT_MS || 5000),
  adminApiKey: process.env.ADMIN_API_KEY || null,
  adminSigningSecret: process.env.ADMIN_SIGNING_SECRET || "dev-admin-signing-secret",
  adminTokenTtlSec: Number(process.env.ADMIN_TOKEN_TTL_SEC || 60 * 60 * 4),
  adminUsers: buildAdminUsersFromEnv(),
  archiveDirectory: process.env.CGUARD_ARCHIVE_DIR || "",
  archiveSessionGroupSize: normalizePositiveInteger(
    process.env.CGUARD_ARCHIVE_SESSION_GROUP_SIZE,
    7
  ),
  archiveMemoryEventLimit: normalizePositiveInteger(
    process.env.CGUARD_ARCHIVE_MEMORY_EVENT_LIMIT,
    50000
  ),
  competitionName: process.env.CGUARD_COMPETITION_NAME || "",
  competitionStartsAt: process.env.CGUARD_COMPETITION_STARTS_AT || "",
  competitionEndsAt: process.env.CGUARD_COMPETITION_ENDS_AT || "",
  integrationPublicBaseUrl: process.env.INTEGRATION_PUBLIC_BASE_URL || "",
  integrationApiEnabled: normalizeBoolean(
    process.env.INTEGRATION_API_ENABLED || process.env.ANTILLM_INTEGRATION_API_ENABLED,
    false
  ),
  integrationApiToken:
    process.env.CGUARD_INTEGRATION_TOKEN ||
    process.env.INTEGRATION_API_TOKEN ||
    process.env.ANTILLM_INTEGRATION_API_TOKEN ||
    undefined,
  integrationApiKey:
    process.env.CGUARD_INTEGRATION_API_KEY ||
    process.env.INTEGRATION_API_KEY ||
    process.env.ANTILLM_INTEGRATION_API_KEY ||
    undefined,
  integrationDiscordIdentityAuthorizationUrlTemplate:
    process.env.INTEGRATION_DISCORD_IDENTITY_AUTH_URL_TEMPLATE || "",
  integrationDiscordRequireLinked: normalizeBoolean(
    process.env.INTEGRATION_DISCORD_REQUIRE_LINKED,
    false
  ),
  integrationDiscordRequireLinkedAction:
    process.env.INTEGRATION_DISCORD_REQUIRE_LINKED_ACTION || "restricted",
  integrationDiscordRequireLinkedGraceSec: normalizePositiveInteger(
    process.env.INTEGRATION_DISCORD_REQUIRE_LINKED_GRACE_SEC,
    0
  ),
  integrationDiscordIdentityAllowRelink: normalizeBoolean(
    process.env.INTEGRATION_DISCORD_IDENTITY_ALLOW_RELINK,
    true
  ),
  kernelIntegrity: {
    maxKernelSignalsPerBatch: normalizePositiveInteger(
      process.env.ANTILLM_MAX_KERNEL_SIGNALS_PER_BATCH,
      5
    ),
    maxBridgeEmitDeltaMs: normalizePositiveInteger(
      process.env.ANTILLM_MAX_BRIDGE_EMIT_DELTA_MS,
      60 * 1000
    ),
    warnAction: process.env.ANTILLM_KERNEL_WARN_ACTION || "monitor",
    requireSignals: normalizeBoolean(process.env.ANTILLM_KERNEL_REQUIRE_SIGNALS, false),
    minKernelSignalsPerBatch: normalizePositiveInteger(
      process.env.ANTILLM_MIN_KERNEL_SIGNALS_PER_BATCH,
      1
    ),
    minKernelSignalsPerMinute: normalizePositiveNumber(
      process.env.ANTILLM_MIN_KERNEL_SIGNALS_PER_MINUTE,
      0
    )
  },
  participantGate: {
    requireClientAgentRunning: normalizeBoolean(
      process.env.ANTILLM_PARTICIPANT_REQUIRE_CLIENT_AGENT_RUNNING,
      true
    ),
    requireKernelConnected: normalizeBoolean(
      process.env.ANTILLM_PARTICIPANT_REQUIRE_KERNEL_CONNECTED,
      false
    ),
    autoBanClientAgentStopped: normalizeBoolean(
      process.env.ANTILLM_PARTICIPANT_AUTO_BAN_CLIENT_AGENT_STOPPED,
      true
    )
  },
  integrationHeartbeatStaleSec: normalizePositiveInteger(
    process.env.ANTILLM_INTEGRATION_HEARTBEAT_STALE_SEC,
    30
  ),
  integrationAutoBanOfflineSession: normalizeBoolean(
    process.env.ANTILLM_INTEGRATION_AUTO_BAN_OFFLINE_SESSION,
    false
  ),
  llmMonitor: {
    cliDetectionAction:
      process.env.CGUARD_CLI_DETECTION_ACTION ||
      process.env.ANTILLM_CLI_DETECTION_ACTION ||
      "blocked",
    cliConfidenceThreshold: Number(
      process.env.CGUARD_CLI_CONFIDENCE_THRESHOLD ||
        process.env.ANTILLM_CLI_CONFIDENCE_THRESHOLD ||
        85
    )
  }
});

app.server.listen(port, () => {
  // Keep startup output minimal and machine-friendly.
  process.stdout.write(`antiLLM server listening on :${port}\n`);
});
