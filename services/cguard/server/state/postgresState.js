const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const { RuntimeState } = require("../runtimeState");

const MUTATION_METHODS = new Set([
  "ensureUser",
  "ensureTeam",
  "registerClient",
  "createSession",
  "issueRefreshToken",
  "updateHeartbeat",
  "linkDiscordIdentity",
  "setUserBan",
  "setTeamBan",
  "setSessionBan",
  "createBan",
  "revokeBan",
  "setActiveJti",
  "revokeJti",
  "revokeActiveJtiForUser",
  "resetParticipantForReconnect",
  "appendEvents",
  "setSessionDecision",
  "addReviewNote",
  "addReviewAction",
  "createDiscordAction",
  "applyDiscordActionCallback",
  "addEventRejections",
  "consumeSubmissionProofReplayEntry",
  "addAuditLog"
]);

const SESSION_COLUMNS = new Set([
  "session_id",
  "user_id",
  "team_id",
  "client_instance_id",
  "status",
  "policy_version",
  "last_heartbeat_at",
  "health_firewall_state",
  "health_observer_state",
  "health_client_agent_state",
  "health_kernel_bridge_state",
  "health_kernel_driver_loaded",
  "discord_user_id",
  "discord_display_name",
  "discord_username",
  "discord_link_state",
  "identity_source",
  "session_binding_device_id",
  "last_ip",
  "last_user_agent",
  "decision_status",
  "decision_reason_code",
  "decision_reason",
  "risk_score",
  "created_at",
  "updated_at",
  "ended_at"
]);

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sanitizeIdentifier(rawValue, fallback) {
  const value = String(rawValue || "").trim();
  if (!value) return fallback;
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(value)) {
    throw new Error(`invalid SQL identifier: ${rawValue}`);
  }
  return value;
}

function sqlText(value) {
  if (value === undefined || value === null) return "NULL";
  return `'${String(value).replace(/'/g, "''")}'`;
}

function sqlTextNotNull(value, fallback = "") {
  const normalized = value === undefined || value === null ? fallback : value;
  return sqlText(normalized);
}

function sqlNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? String(parsed) : "NULL";
}

function sqlBoolean(value) {
  return value === true ? "true" : "false";
}

function sqlTimestamp(value) {
  if (!value) return "NULL";
  const parsed = Date.parse(String(value));
  if (Number.isNaN(parsed)) return "NULL";
  return `${sqlText(new Date(parsed).toISOString())}::timestamptz`;
}

function sqlJson(value) {
  const json = JSON.stringify(value === undefined ? null : value);
  return `${sqlText(json)}::jsonb`;
}

function hashToken(token) {
  return crypto.createHash("sha256").update(String(token || "")).digest("hex");
}

function epochToIso(epochSec) {
  const parsed = Number(epochSec);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return new Date(Math.floor(parsed) * 1000).toISOString();
}

function sessionMeta(session) {
  const meta = {};
  for (const [key, value] of Object.entries(session || {})) {
    if (!SESSION_COLUMNS.has(key)) {
      meta[key] = value;
    }
  }
  return meta;
}

function decisionStatusForSession(status) {
  const normalized = String(status || "").trim().toLowerCase();
  if (!normalized) return null;
  return normalized;
}

function decisionRiskScore(decision) {
  if (!isPlainObject(decision)) return null;
  const value = decision.risk_score ?? decision.score;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function eventMeta(event) {
  return {
    source_event_id: event && event.event_id ? String(event.event_id) : null,
    team_id: event && event.team_id ? String(event.team_id) : null,
    policy_version: event && event.policy_version ? String(event.policy_version) : null,
    received_by: "cguard-server"
  };
}

function rejectionMeta(rejection) {
  return {
    index: Number.isFinite(Number(rejection && rejection.index))
      ? Math.floor(Number(rejection.index))
      : null,
    error: rejection && typeof rejection.error === "string" ? rejection.error : null
  };
}

function banFromRuntime(scope, targetId, durationSec, reasonCode, reason) {
  const now = new Date();
  const duration = Number(durationSec);
  return {
    ban_id: crypto.randomUUID(),
    scope,
    target_id: String(targetId || ""),
    reason: reason || null,
    reason_code: reasonCode || null,
    created_by: "server",
    created_at: now.toISOString(),
    expires_at: Number.isFinite(duration) && duration > 0
      ? new Date(now.getTime() + duration * 1000).toISOString()
      : null,
    revoked_at: null,
    revoked_by: null,
    status: "ACTIVE"
  };
}

function captureBefore(inner, methodName, args) {
  return {
    auditLogCount: Array.isArray(inner.auditLogs) ? inner.auditLogs.length : 0,
    activeJti:
      methodName === "revokeActiveJtiForUser" && inner.activeJtiByUser
        ? inner.activeJtiByUser.get(args[0])
        : null
  };
}

function collectNewAuditLogOps(inner, before) {
  if (!Array.isArray(inner.auditLogs)) return [];
  return inner.auditLogs
    .slice(before.auditLogCount)
    .map((record) => ({ type: "audit_log", record }));
}

function buildMutationOperations(methodName, args, result, inner, before) {
  const operations = [];
  switch (methodName) {
    case "ensureUser":
      if (result) operations.push({ type: "user", record: result });
      break;
    case "ensureTeam":
      if (result) operations.push({ type: "team", record: result });
      break;
    case "registerClient":
      if (result) operations.push({ type: "client", record: result });
      break;
    case "createSession": {
      const userId = args[0] && args[0].userId;
      const sessions = userId && typeof inner.listSessions === "function"
        ? inner.listSessions({ user_id: userId, limit: 1000, offset: 0 }).items
        : [result];
      for (const session of sessions || []) {
        if (session) operations.push({ type: "session", record: session });
      }
      break;
    }
    case "issueRefreshToken": {
      const session = args[0];
      if (session && result && result.refresh_token) {
        operations.push({
          type: "refresh_token",
          record: {
            token_hash: hashToken(result.refresh_token),
            user_id: session.user_id,
            team_id: session.team_id,
            session_id: session.session_id,
            client_instance_id: session.client_instance_id,
            exp_epoch_sec: Math.floor(Date.parse(result.refresh_expires_at) / 1000)
          }
        });
      }
      break;
    }
    case "updateHeartbeat": {
      const clientId = args[0];
      const ts = inner.heartbeatByClient ? inner.heartbeatByClient.get(clientId) : null;
      if (clientId && ts) {
        operations.push({
          type: "heartbeat",
          record: {
            client_instance_id: clientId,
            heartbeat_epoch_sec: ts,
            updated_at: epochToIso(ts)
          }
        });
      }
      const sessionId = inner.sessionByClient ? inner.sessionByClient.get(clientId) : null;
      const session = sessionId && typeof inner.getSession === "function" ? inner.getSession(sessionId) : null;
      if (session) operations.push({ type: "session", record: session });
      break;
    }
    case "linkDiscordIdentity":
      if (result && result.record) {
        operations.push({ type: "discord_identity_link", record: result.record });
        const session = typeof inner.getActiveSessionByUser === "function"
          ? inner.getActiveSessionByUser(result.record.user_id)
          : null;
        if (session) operations.push({ type: "session", record: session });
      }
      break;
    case "setUserBan":
      operations.push({ type: "ban", record: banFromRuntime("user", args[0], args[1], args[2], args[3]) });
      break;
    case "setTeamBan":
      operations.push({ type: "ban", record: banFromRuntime("team", args[0], args[1], args[2], args[3]) });
      break;
    case "setSessionBan":
      operations.push({ type: "ban", record: banFromRuntime("session", args[0], args[1], args[2], args[3]) });
      break;
    case "createBan":
    case "revokeBan":
      if (result) operations.push({ type: "ban", record: result });
      break;
    case "setActiveJti":
      operations.push({
        type: "active_jti",
        record: {
          user_id: args[0],
          jti: args[1],
          exp_epoch_sec: args[2]
        }
      });
      break;
    case "revokeJti":
      operations.push({
        type: "revoked_jti",
        record: {
          jti: args[0],
          exp_epoch_sec: args[1] || Math.floor(Date.now() / 1000) + 120
        }
      });
      break;
    case "revokeActiveJtiForUser":
      if (result === true && before.activeJti) {
        operations.push({
          type: "revoked_jti",
          record: {
            jti: before.activeJti.jti,
            exp_epoch_sec: before.activeJti.exp
          }
        });
      }
      break;
    case "resetParticipantForReconnect":
      if (result && Array.isArray(result.reset_session_ids)) {
        for (const sessionId of result.reset_session_ids) {
          const session =
            typeof inner.getSession === "function" ? inner.getSession(sessionId) : null;
          if (session) operations.push({ type: "session", record: session });
        }
      }
      if (result && Array.isArray(result.revoked_bans)) {
        for (const record of result.revoked_bans) {
          if (record) operations.push({ type: "ban", record });
        }
      }
      if (result && Array.isArray(result.revoked_jti)) {
        for (const record of result.revoked_jti) {
          if (record && record.jti) operations.push({ type: "revoked_jti", record });
        }
      }
      break;
    case "appendEvents":
      for (const record of args[0] || []) {
        operations.push({ type: "event", record });
      }
      break;
    case "setSessionDecision": {
      const sessionId = args[0];
      const decision = typeof inner.getSessionDecision === "function"
        ? inner.getSessionDecision(sessionId)
        : null;
      if (decision) {
        operations.push({ type: "session_decision", session_id: sessionId, record: decision });
      }
      break;
    }
    case "addReviewNote":
      if (result) operations.push({ type: "review_note", record: result });
      break;
    case "addReviewAction":
      if (result) operations.push({ type: "review_action", record: result });
      break;
    case "createDiscordAction":
      if (result && result.record) operations.push({ type: "discord_action", record: result.record });
      break;
    case "applyDiscordActionCallback":
      if (result && result.updated === true && result.record) {
        operations.push({ type: "discord_action", record: result.record });
      }
      if (result && result.updated === true && result.receipt) {
        operations.push({
          type: "discord_action_callback",
          action_id: args[0] && args[0].action_id,
          record: result.receipt
        });
      }
      break;
    case "addEventRejections":
      for (const rejection of args[0] || []) {
        operations.push({ type: "event_rejection", record: rejection });
      }
      break;
    case "consumeSubmissionProofReplayEntry": {
      const input = args[0] || {};
      if (result && result.accepted === true && input.session_id && input.user_id && input.client_instance_id) {
        operations.push({
          type: "submission_proof_consumption",
          record: {
            proof_jti: input.jti,
            proof_nonce: input.nonce,
            session_id: input.session_id,
            user_id: input.user_id,
            client_instance_id: input.client_instance_id,
            device_id: input.device_id || null,
            purpose: input.purpose || "submit",
            source_ip: input.source_ip || null,
            consume_meta: {
              expires_at_epoch_sec: result.expires_at_epoch_sec || null
            }
          }
        });
      }
      break;
    }
    case "addAuditLog":
      if (result) operations.push({ type: "audit_log", record: result });
      break;
    default:
      break;
  }

  if (methodName !== "addAuditLog") {
    operations.push(...collectNewAuditLogOps(inner, before));
  }
  return operations.filter((operation) => operation && operation.record);
}

class PsqlCguardRepository {
  constructor(options = {}) {
    this.connectionString =
      typeof options.connectionString === "string" ? options.connectionString.trim() : "";
    this.psqlBin =
      typeof options.psqlBin === "string" && options.psqlBin.trim()
        ? options.psqlBin.trim()
        : "psql";
    this.schema = sanitizeIdentifier(options.schema, "cstrike");
    this.statementTimeoutMs = Number.isFinite(Number(options.statementTimeoutMs))
      ? Math.max(1000, Math.floor(Number(options.statementTimeoutMs)))
      : 5000;
    this.ddlPath = options.ddlPath
      ? path.resolve(options.ddlPath)
      : path.resolve(__dirname, "..", "..", "db", "ddl", "cguard_alignment_v1.sql");
  }

  isConfigured() {
    return this.connectionString.length > 0;
  }

  runSql(sql) {
    const args = [
      this.connectionString,
      "--no-psqlrc",
      "--set",
      "ON_ERROR_STOP=1",
      "--quiet",
      "--tuples-only",
      "--no-align",
      "--command",
      `SET statement_timeout=${this.statementTimeoutMs}; ${sql}`
    ];
    execFileSync(this.psqlBin, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });
  }

  ensureSchema() {
    const ddl = fs.readFileSync(this.ddlPath, "utf8");
    this.runSql(ddl);
  }

  writeBatch(operations) {
    const statements = (operations || [])
      .map((operation) => this.operationToSql(operation))
      .filter(Boolean);
    if (statements.length === 0) return;
    this.runSql(["BEGIN;", ...statements, "COMMIT;"].join("\n"));
  }

  operationToSql(operation) {
    const record = operation.record || {};
    switch (operation.type) {
      case "user":
        return `
INSERT INTO ${this.schema}.cguard_users (user_id, username, created_at)
VALUES (${sqlText(record.user_id)}, ${sqlTextNotNull(record.username)}, ${sqlTimestamp(record.created_at)})
ON CONFLICT (user_id) DO UPDATE SET username=excluded.username;`;
      case "team":
        return `
INSERT INTO ${this.schema}.cguard_teams (team_id, name, created_at)
VALUES (${sqlText(record.team_id)}, ${sqlTextNotNull(record.name)}, ${sqlTimestamp(record.created_at)})
ON CONFLICT (team_id) DO UPDATE SET name=excluded.name;`;
      case "client":
        return `
INSERT INTO ${this.schema}.cguard_clients (
  client_instance_id, user_id, team_id, device_id, os, os_version, app_version, last_seen_at, created_at, updated_at
)
VALUES (
  ${sqlText(record.client_instance_id)}, ${sqlText(record.user_id)}, ${sqlText(record.team_id)},
  ${sqlTextNotNull(record.device_id)}, ${sqlText(record.os)}, ${sqlText(record.os_version)},
  ${sqlText(record.app_version)}, ${sqlTimestamp(record.last_seen_at)},
  COALESCE(${sqlTimestamp(record.created_at)}, now()), COALESCE(${sqlTimestamp(record.updated_at)}, now())
)
ON CONFLICT (client_instance_id) DO UPDATE SET
  team_id=excluded.team_id,
  device_id=excluded.device_id,
  os=excluded.os,
  os_version=excluded.os_version,
  app_version=excluded.app_version,
  last_seen_at=excluded.last_seen_at,
  updated_at=now();`;
      case "session":
        return `
INSERT INTO ${this.schema}.cguard_sessions (
  session_id, user_id, team_id, client_instance_id, status, policy_version,
  last_heartbeat_at, health_firewall_state, health_observer_state,
  health_client_agent_state, health_kernel_bridge_state, health_kernel_driver_loaded,
  discord_user_id, discord_display_name, discord_username, discord_link_state, identity_source, session_binding_device_id,
  last_ip, last_user_agent, decision_status, decision_reason_code, decision_reason,
  risk_score, session_meta, created_at, updated_at, ended_at
)
VALUES (
  ${sqlText(record.session_id)}, ${sqlText(record.user_id)}, ${sqlText(record.team_id)},
  ${sqlText(record.client_instance_id)}, ${sqlTextNotNull(record.status, "ACTIVE")},
  ${sqlTextNotNull(record.policy_version, "policy-v1")},
  ${sqlTimestamp(record.last_heartbeat_at)}, ${sqlText(record.health_firewall_state)},
  ${sqlText(record.health_observer_state)}, ${sqlText(record.health_client_agent_state)},
  ${sqlText(record.health_kernel_bridge_state)}, ${sqlBoolean(record.health_kernel_driver_loaded)},
  ${sqlText(record.discord_user_id)}, ${sqlText(record.discord_display_name)}, ${sqlText(record.discord_username)},
  ${sqlText(record.discord_link_state)},
  ${sqlText(record.identity_source)}, ${sqlText(record.session_binding_device_id)},
  ${sqlText(record.last_ip)}, ${sqlText(record.last_user_agent)},
  ${sqlText(record.decision_status)}, ${sqlText(record.decision_reason_code)},
  ${sqlText(record.decision_reason)}, ${sqlNumber(record.risk_score)},
  ${sqlJson(sessionMeta(record))}, COALESCE(${sqlTimestamp(record.created_at)}, now()),
  COALESCE(${sqlTimestamp(record.updated_at)}, now()), ${sqlTimestamp(record.ended_at)}
)
ON CONFLICT (session_id) DO UPDATE SET
  status=excluded.status,
  policy_version=excluded.policy_version,
  last_heartbeat_at=excluded.last_heartbeat_at,
  health_firewall_state=excluded.health_firewall_state,
  health_observer_state=excluded.health_observer_state,
  health_client_agent_state=excluded.health_client_agent_state,
  health_kernel_bridge_state=excluded.health_kernel_bridge_state,
  health_kernel_driver_loaded=excluded.health_kernel_driver_loaded,
  discord_user_id=excluded.discord_user_id,
  discord_display_name=excluded.discord_display_name,
  discord_username=excluded.discord_username,
  discord_link_state=excluded.discord_link_state,
  identity_source=excluded.identity_source,
  session_binding_device_id=excluded.session_binding_device_id,
  last_ip=excluded.last_ip,
  last_user_agent=excluded.last_user_agent,
  decision_status=excluded.decision_status,
  decision_reason_code=excluded.decision_reason_code,
  decision_reason=excluded.decision_reason,
  risk_score=excluded.risk_score,
  session_meta=excluded.session_meta,
  updated_at=excluded.updated_at,
  ended_at=excluded.ended_at;`;
      case "heartbeat":
        return `
INSERT INTO ${this.schema}.cguard_client_heartbeats (client_instance_id, heartbeat_epoch_sec, updated_at)
VALUES (${sqlText(record.client_instance_id)}, ${sqlNumber(record.heartbeat_epoch_sec)}, COALESCE(${sqlTimestamp(record.updated_at)}, now()))
ON CONFLICT (client_instance_id) DO UPDATE SET
  heartbeat_epoch_sec=excluded.heartbeat_epoch_sec,
  updated_at=excluded.updated_at;`;
      case "event":
        return `
INSERT INTO ${this.schema}.cguard_events (
  timestamp, received_at, event_type, severity, session_id, user_id, client_version, evidence, event_meta
)
VALUES (
  COALESCE(${sqlTimestamp(record.timestamp)}, now()), COALESCE(${sqlTimestamp(record.received_at)}, now()),
  ${sqlTextNotNull(record.event_type)}, ${sqlTextNotNull(record.severity, "low")},
  ${sqlText(record.session_id)}, ${sqlText(record.user_id)}, ${sqlTextNotNull(record.client_version)},
  ${sqlJson(record.evidence || {})}, ${sqlJson(eventMeta(record))}
);`;
      case "event_rejection": {
        const rawEvent = isPlainObject(record.event) ? record.event : null;
        return `
INSERT INTO ${this.schema}.cguard_event_rejections (
  received_at, session_id, user_id, event_type, reject_code, reject_message, raw_event, rejection_meta
)
VALUES (
  COALESCE(${sqlTimestamp(record.received_at)}, now()),
  ${sqlText(rawEvent && rawEvent.session_id)}, ${sqlText(rawEvent && rawEvent.user_id)},
  ${sqlText(record.event_type || (rawEvent && rawEvent.event_type))},
  ${sqlTextNotNull(record.reject_code || "SCHEMA_VALIDATION_REJECTED")},
  ${sqlTextNotNull(record.reject_message || record.error || "event rejected")},
  ${rawEvent ? sqlJson(rawEvent) : "NULL"}, ${sqlJson(rejectionMeta(record))}
);`;
      }
      case "session_decision": {
        const status = decisionStatusForSession(record.status);
        const reasonCode = record.reason_code || null;
        const reason = record.reason || record.message || null;
        const score = decisionRiskScore(record);
        return `
INSERT INTO ${this.schema}.cguard_session_decisions (
  session_id, status, reason_code, reason, risk_score, decided_at, decision_meta
)
VALUES (
  ${sqlText(operation.session_id)}, ${sqlTextNotNull(status, "ok")}, ${sqlText(reasonCode)},
  ${sqlText(reason)}, ${sqlNumber(score)}, COALESCE(${sqlTimestamp(record.decided_at)}, now()),
  ${sqlJson(record)}
);
UPDATE ${this.schema}.cguard_sessions SET
  decision_status=${sqlText(status)},
  decision_reason_code=${sqlText(reasonCode)},
  decision_reason=${sqlText(reason)},
  risk_score=${sqlNumber(score)},
  updated_at=now()
WHERE session_id=${sqlText(operation.session_id)};`;
      }
      case "review_note":
        return `
INSERT INTO ${this.schema}.cguard_review_notes (note_id, session_id, operator_id, note, created_at, note_meta)
VALUES (
  ${sqlText(record.note_id)}, ${sqlText(record.session_id)}, NULL, ${sqlTextNotNull(record.note)},
  COALESCE(${sqlTimestamp(record.created_at)}, now()), ${sqlJson({ author: record.author, metadata: record.metadata || {} })}
)
ON CONFLICT (note_id) DO NOTHING;`;
      case "review_action":
        return `
INSERT INTO ${this.schema}.cguard_review_actions (
  action_row_id, session_id, operator_id, action_type, reason_code, reason, metadata, created_at
)
VALUES (
  ${sqlText(record.action_id)}, ${sqlText(record.session_id)}, NULL,
  ${sqlTextNotNull(record.action)}, ${sqlText(record.reason_code)}, ${sqlText(record.reason)},
  ${sqlJson({ actor: record.actor, metadata: record.metadata || {} })},
  COALESCE(${sqlTimestamp(record.created_at)}, now())
)
ON CONFLICT (action_row_id) DO NOTHING;`;
      case "discord_identity_link":
        return `
INSERT INTO ${this.schema}.cguard_discord_identity_links (
  user_id, discord_user_id, discord_display_name, discord_username, discord_link_state, identity_source, verification_method,
  linked_by, linked_at, verified_at, updated_at, metadata
)
VALUES (
  ${sqlText(record.user_id)}, ${sqlTextNotNull(record.discord_user_id)},
  ${sqlText(record.discord_display_name)}, ${sqlText(record.discord_username)},
  ${sqlTextNotNull(record.discord_link_state, "linked")}, ${sqlTextNotNull(record.identity_source, "oauth")},
  ${sqlTextNotNull(record.verification_method, "oauth_pkce")}, ${sqlTextNotNull(record.linked_by, "integration-client")},
  COALESCE(${sqlTimestamp(record.linked_at)}, now()), COALESCE(${sqlTimestamp(record.verified_at)}, now()),
  COALESCE(${sqlTimestamp(record.updated_at)}, now()), ${sqlJson(record.metadata || {})}
)
ON CONFLICT (user_id) DO UPDATE SET
  discord_user_id=excluded.discord_user_id,
  discord_display_name=excluded.discord_display_name,
  discord_username=excluded.discord_username,
  discord_link_state=excluded.discord_link_state,
  identity_source=excluded.identity_source,
  verification_method=excluded.verification_method,
  linked_by=excluded.linked_by,
  linked_at=excluded.linked_at,
  verified_at=excluded.verified_at,
  updated_at=excluded.updated_at,
  metadata=excluded.metadata;`;
      case "discord_action":
        return `
INSERT INTO ${this.schema}.cguard_discord_actions (
  action_id, action_type, status, discord_user_id, guild_id, role_id, reason_code,
  reason_text, metadata, created_by, created_at, updated_at, expires_at,
  callback_status, callback_at, applied_at, failed_at, retry_after_at, attempt_count,
  last_error, idempotency_fingerprint
)
VALUES (
  ${sqlText(record.action_id)}, ${sqlTextNotNull(record.action_type)}, ${sqlTextNotNull(record.status, "pending")},
  ${sqlTextNotNull(record.discord_user_id)}, ${sqlText(record.guild_id)}, ${sqlText(record.role_id)},
  ${sqlText(record.reason_code)}, ${sqlText(record.reason_text)}, ${sqlJson(record.metadata || {})},
  ${sqlTextNotNull(record.created_by, "integration-client")}, COALESCE(${sqlTimestamp(record.created_at)}, now()),
  COALESCE(${sqlTimestamp(record.updated_at)}, now()), ${sqlTimestamp(record.expires_at)},
  ${sqlText(record.callback_status)}, ${sqlTimestamp(record.callback_at)}, ${sqlTimestamp(record.applied_at)},
  ${sqlTimestamp(record.failed_at)}, ${sqlTimestamp(record.retry_after_at)}, ${sqlNumber(record.attempt_count || 0)},
  ${record.last_error ? sqlJson(record.last_error) : "NULL"}, ${sqlTextNotNull(record.idempotency_fingerprint)}
)
ON CONFLICT (action_id) DO UPDATE SET
  status=excluded.status,
  metadata=excluded.metadata,
  updated_at=excluded.updated_at,
  callback_status=excluded.callback_status,
  callback_at=excluded.callback_at,
  applied_at=excluded.applied_at,
  failed_at=excluded.failed_at,
  retry_after_at=excluded.retry_after_at,
  attempt_count=excluded.attempt_count,
  last_error=excluded.last_error;`;
      case "discord_action_callback":
        return `
INSERT INTO ${this.schema}.cguard_discord_action_callbacks (
  callback_id, action_id, status, callback_at, retry_after_at, error_code,
  error_message, metadata, processed_by, processed_at, idempotency_fingerprint
)
VALUES (
  ${sqlText(record.callback_id)}, ${sqlText(operation.action_id)}, ${sqlTextNotNull(record.status)},
  COALESCE(${sqlTimestamp(record.callback_at)}, now()), ${sqlTimestamp(record.retry_after_at)},
  ${sqlText(record.error_code)}, ${sqlText(record.error_message)}, ${sqlJson(record.metadata || {})},
  ${sqlTextNotNull(record.processed_by, "integration-client")}, COALESCE(${sqlTimestamp(record.processed_at)}, now()),
  ${sqlTextNotNull(record.idempotency_fingerprint)}
)
ON CONFLICT (callback_id) DO NOTHING;`;
      case "ban":
        return `
INSERT INTO ${this.schema}.cguard_bans (
  ban_id, scope, target_id, reason, reason_code, created_by, created_at, expires_at,
  revoked_at, revoked_by, status
)
VALUES (
  ${sqlText(record.ban_id)}, ${sqlTextNotNull(record.scope)}, ${sqlTextNotNull(record.target_id)},
  ${sqlText(record.reason)}, ${sqlText(record.reason_code)}, ${sqlTextNotNull(record.created_by, "server")},
  COALESCE(${sqlTimestamp(record.created_at)}, now()), ${sqlTimestamp(record.expires_at)},
  ${sqlTimestamp(record.revoked_at)}, ${sqlText(record.revoked_by)}, ${sqlTextNotNull(record.status, "ACTIVE")}
)
ON CONFLICT (ban_id) DO UPDATE SET
  revoked_at=excluded.revoked_at,
  revoked_by=excluded.revoked_by,
  status=excluded.status;`;
      case "audit_log":
        return `
INSERT INTO ${this.schema}.cguard_audit_logs (audit_id, at, actor, action, object_type, object_id, detail)
VALUES (
  ${sqlText(record.audit_id)}, COALESCE(${sqlTimestamp(record.at)}, now()),
  ${sqlTextNotNull(record.actor, "system")}, ${sqlTextNotNull(record.action)},
  ${sqlText(record.object_type)}, ${sqlText(record.object_id)}, ${sqlJson(record.detail || {})}
)
ON CONFLICT (audit_id) DO NOTHING;`;
      case "submission_proof_consumption":
        return `
INSERT INTO ${this.schema}.cguard_submission_proof_consumptions (
  proof_jti, proof_nonce, session_id, user_id, client_instance_id, device_id,
  purpose, consumed_at, source_ip, consume_meta
)
VALUES (
  ${sqlTextNotNull(record.proof_jti)}, ${sqlTextNotNull(record.proof_nonce)},
  ${sqlText(record.session_id)}, ${sqlText(record.user_id)}, ${sqlText(record.client_instance_id)},
  ${sqlText(record.device_id)}, ${sqlTextNotNull(record.purpose, "submit")}, now(),
  ${sqlText(record.source_ip)}, ${sqlJson(record.consume_meta || {})}
)
ON CONFLICT (proof_jti) DO NOTHING;`;
      case "refresh_token":
        return `
INSERT INTO ${this.schema}.cguard_refresh_tokens (
  token_hash, user_id, team_id, session_id, client_instance_id, exp_epoch_sec, created_at
)
VALUES (
  ${sqlTextNotNull(record.token_hash)}, ${sqlText(record.user_id)}, ${sqlText(record.team_id)},
  ${sqlText(record.session_id)}, ${sqlText(record.client_instance_id)}, ${sqlNumber(record.exp_epoch_sec)}, now()
)
ON CONFLICT (token_hash) DO NOTHING;`;
      case "revoked_jti":
        return `
INSERT INTO ${this.schema}.cguard_revoked_jti (jti, exp_epoch_sec, revoked_at)
VALUES (${sqlTextNotNull(record.jti)}, ${sqlNumber(record.exp_epoch_sec)}, now())
ON CONFLICT (jti) DO UPDATE SET exp_epoch_sec=excluded.exp_epoch_sec, revoked_at=excluded.revoked_at;`;
      case "active_jti":
        return `
INSERT INTO ${this.schema}.cguard_active_jti_by_user (user_id, jti, exp_epoch_sec, updated_at)
VALUES (${sqlText(record.user_id)}, ${sqlTextNotNull(record.jti)}, ${sqlNumber(record.exp_epoch_sec)}, now())
ON CONFLICT (user_id) DO UPDATE SET jti=excluded.jti, exp_epoch_sec=excluded.exp_epoch_sec, updated_at=excluded.updated_at;`;
      default:
        return null;
    }
  }
}

class PostgresState {
  constructor(inner, options = {}) {
    this.inner = inner;
    this.repository = options.repository;
    this._transactionDepth = 0;
    this._queuedOperations = [];
  }

  static create({ config = {} } = {}) {
    const repository =
      config.cguardRepository ||
      config.postgresRepository ||
      config.postgresProvider ||
      new PsqlCguardRepository({
        connectionString:
          config.postgresConnectionString ||
          config.statePostgresConnectionString ||
          process.env.STATE_PG_CONNECTION_STRING ||
          process.env.DATABASE_URL ||
          "",
        schema: config.postgresSchema || process.env.STATE_PG_SCHEMA || "cstrike",
        psqlBin: config.postgresPsqlBin || process.env.STATE_PG_PSQL_BIN || "psql",
        statementTimeoutMs:
          config.postgresStatementTimeoutMs ||
          process.env.STATE_PG_STATEMENT_TIMEOUT_MS ||
          5000,
        ddlPath: config.postgresDdlPath || process.env.STATE_PG_DDL_PATH
      });

    const canUseRepository =
      repository &&
      typeof repository.ensureSchema === "function" &&
      typeof repository.writeBatch === "function" &&
      (typeof repository.isConfigured !== "function" || repository.isConfigured() === true);

    if (!canUseRepository) {
      throw new Error(
        "STATE_MODE=postgres requires a configured cguard repository; legacy fallback is disabled"
      );
    }

    repository.ensureSchema();
    return new PostgresState(new RuntimeState(config), { repository });
  }

  writeOperations(operations) {
    if (!operations || operations.length === 0) return;
    if (this._transactionDepth > 0) {
      this._queuedOperations.push(...operations);
      return;
    }
    this.repository.writeBatch(operations);
  }

  transact(executor) {
    if (typeof executor !== "function") {
      throw new Error("executor must be a function");
    }

    if (this._transactionDepth > 0) {
      this._transactionDepth += 1;
      try {
        return executor();
      } finally {
        this._transactionDepth -= 1;
      }
    }

    const runtimeBefore = this.inner.toJSON();
    const queuedBefore = this._queuedOperations;
    this._queuedOperations = [];
    this._transactionDepth = 1;
    try {
      const result = executor();
      if (result && typeof result.then === "function") {
        throw new Error("state.transact does not support async callbacks");
      }
      this._transactionDepth = 0;
      this.repository.writeBatch(this._queuedOperations);
      this._queuedOperations = queuedBefore;
      return result;
    } catch (error) {
      this._transactionDepth = 0;
      this._queuedOperations = queuedBefore;
      this.inner = RuntimeState.fromJSON(runtimeBefore, this.inner.config || {});
      throw error;
    }
  }
}

for (const methodName of Object.getOwnPropertyNames(RuntimeState.prototype)) {
  if (methodName === "constructor" || methodName === "transact") continue;
  PostgresState.prototype[methodName] = function wrappedMethod(...args) {
    const before = captureBefore(this.inner, methodName, args);
    const runtimeBefore = MUTATION_METHODS.has(methodName) ? this.inner.toJSON() : null;
    const result = this.inner[methodName](...args);
    if (MUTATION_METHODS.has(methodName)) {
      const operations = buildMutationOperations(methodName, args, result, this.inner, before);
      try {
        this.writeOperations(operations);
      } catch (error) {
        this.inner = RuntimeState.fromJSON(runtimeBefore, this.inner.config || {});
        throw error;
      }
    }
    return result;
  };
}

module.exports = {
  PostgresState,
  PsqlCguardRepository,
  buildMutationOperations
};
