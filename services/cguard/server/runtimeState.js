const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

function nowIso() {
  return new Date().toISOString();
}

function nowEpochSec() {
  return Math.floor(Date.now() / 1000);
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeStringArray(value) {
  if (Array.isArray(value)) {
    return value
      .filter((item) => typeof item === "string")
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
  }
  if (typeof value === "string") {
    return value
      .split(",")
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
  }
  return [];
}

const ALLOWED_SEVERITIES = new Set(["low", "medium", "high", "critical"]);
const POSITIVE_DECISION_STATUSES = new Set(["warn", "blocked"]);
const POSITIVE_REVIEW_ACTIONS = new Set(["mark_as_suspicious", "escalate"]);
const NEGATIVE_REVIEW_ACTIONS = new Set(["clear_with_reason"]);
const GATE_FAILURE_ACTIONS = new Set(["CLIENT_AGENT_REQUIRED", "KERNEL_CONNECTION_REQUIRED"]);
const DISCORD_ACTION_TYPES = new Set(["assign_role", "remove_role", "announce"]);
const DISCORD_ACTION_STATUSES = new Set([
  "pending",
  "applied",
  "failed",
  "retrying",
  "expired"
]);
const DISCORD_IDENTITY_SOURCES = new Set(["oauth", "sdk_hint", "unknown"]);
const DISCORD_LINK_STATES = new Set(["linked", "unlinked", "unknown", "error"]);
const DEVICE_BINDING_MODES = new Set(["static", "dpapi", "unknown"]);
const DEVICE_BINDING_STATES = new Set(["ready", "fallback", "error", "unknown"]);
const MAX_DISCORD_CALLBACK_RECEIPTS = 500;
const MAX_EVENT_REJECTION_RECORDS = 5000;
const MAX_SUBMISSION_PROOF_REPLAY_ENTRIES = 20000;
const DAY_MS = 24 * 60 * 60 * 1000;
const DEFAULT_ARCHIVE_SESSION_GROUP_SIZE = 7;
const DEFAULT_ARCHIVE_MEMORY_EVENT_LIMIT = 50000;

function safeRatio(numerator, denominator) {
  if (!Number.isFinite(numerator) || !Number.isFinite(denominator) || denominator <= 0) {
    return null;
  }
  return numerator / denominator;
}

function normalizeTimestampOrNull(value) {
  if (typeof value !== "string" || value.trim() === "") return null;
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return null;
  return new Date(parsed).toISOString();
}

function normalizeOptionalString(value) {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

function safeArchiveJsonLine(rootDir, relativePath, record) {
  if (!rootDir) return false;
  const targetPath = path.join(rootDir, relativePath);
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.appendFileSync(targetPath, `${JSON.stringify(record)}\n`, "utf8");
  return true;
}

function archiveGroupName(index) {
  const safeIndex = Number.isFinite(Number(index)) && Number(index) > 0 ? Math.floor(Number(index)) : 0;
  return safeIndex > 0 ? `group-${String(safeIndex).padStart(3, "0")}` : "ungrouped";
}

function resolveDiscordDisplayName({ displayName, username, metadata } = {}) {
  return (
    normalizeOptionalString(displayName) ||
    (isPlainObject(metadata)
      ? normalizeOptionalString(metadata.display_name) ||
        normalizeOptionalString(metadata.global_name) ||
        normalizeOptionalString(metadata.discord_display_name)
      : null) ||
    normalizeOptionalString(username) ||
    (isPlainObject(metadata)
      ? normalizeOptionalString(metadata.username) ||
        normalizeOptionalString(metadata.discord_username)
      : null)
  );
}

function normalizeTimestampOrThrow(value, fieldName) {
  if (value === undefined || value === null || String(value).trim() === "") return null;
  const parsed = Date.parse(String(value));
  if (Number.isNaN(parsed)) {
    throw new Error(`${fieldName} must be an ISO timestamp`);
  }
  return new Date(parsed).toISOString();
}

function resolveEventTimeMs(event) {
  if (!isPlainObject(event)) return null;
  const receivedAt =
    typeof event.received_at === "string" && event.received_at.trim()
      ? Date.parse(event.received_at)
      : NaN;
  if (!Number.isNaN(receivedAt)) return receivedAt;
  const timestamp =
    typeof event.timestamp === "string" && event.timestamp.trim()
      ? Date.parse(event.timestamp)
      : NaN;
  if (!Number.isNaN(timestamp)) return timestamp;
  return null;
}

function toSafeLowerTrimmed(value) {
  if (typeof value !== "string") return "";
  return value.trim().toLowerCase();
}

function clampPositiveInteger(value, fallback, maxValue) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  const normalized = Math.floor(parsed);
  return typeof maxValue === "number" ? Math.min(normalized, maxValue) : normalized;
}

function startOfUtcDayMs(timestampMs) {
  const date = new Date(timestampMs);
  date.setUTCHours(0, 0, 0, 0);
  return date.getTime();
}

function summarizeGateFailures(records, resolveUserIdFromSessionId) {
  const byReason = {};
  const sessions = new Set();
  const users = new Set();
  let total = 0;

  for (const record of records) {
    if (!isPlainObject(record)) continue;
    const action = typeof record.action === "string" ? record.action : "";
    if (!GATE_FAILURE_ACTIONS.has(action)) continue;
    total += 1;
    byReason[action] = (byReason[action] || 0) + 1;

    const sessionId = typeof record.object_id === "string" ? record.object_id.trim() : "";
    if (sessionId) {
      sessions.add(sessionId);
      if (typeof resolveUserIdFromSessionId === "function") {
        const userId = resolveUserIdFromSessionId(sessionId);
        if (userId) users.add(userId);
      }
    }
  }

  return {
    total,
    unique_sessions: sessions.size,
    unique_users: users.size,
    by_reason: byReason
  };
}

function buildKernelSignalTrustMetrics(events, { sessionIdSet, hasFrom, fromTs, hasTo, toTs, sampleLimit }) {
  const failedRuleCounts = new Map();
  const warnSamples = [];
  let totalKernelEvents = 0;
  let validationPassEvents = 0;
  let validationWarnEvents = 0;
  let validationMissingEvents = 0;
  let sourceKernelBridgeEvents = 0;
  let sourceMismatchEvents = 0;
  let sourceMissingEvents = 0;

  for (const event of events) {
    if (!isPlainObject(event)) continue;
    if (typeof event.event_type !== "string" || !event.event_type.startsWith("KERNEL_")) continue;
    if (sessionIdSet.size > 0 && !sessionIdSet.has(event.session_id)) continue;

    const eventTime = resolveEventTimeMs(event);
    if (hasFrom && Number.isFinite(eventTime) && eventTime < fromTs) continue;
    if (hasTo && Number.isFinite(eventTime) && eventTime > toTs) continue;

    totalKernelEvents += 1;
    const evidence = isPlainObject(event.evidence) ? event.evidence : {};

    const detectionSource = toSafeLowerTrimmed(evidence.detection_source);
    if (!detectionSource) sourceMissingEvents += 1;
    else if (detectionSource === "kernel_bridge") sourceKernelBridgeEvents += 1;
    else sourceMismatchEvents += 1;

    const kernelValidation = isPlainObject(evidence.kernel_validation) ? evidence.kernel_validation : null;
    const validationStatus = kernelValidation ? toSafeLowerTrimmed(kernelValidation.status) : "";
    if (validationStatus === "pass") {
      validationPassEvents += 1;
    } else if (validationStatus === "warn") {
      validationWarnEvents += 1;
      const failedRules = Array.isArray(kernelValidation.failed_rules)
        ? kernelValidation.failed_rules.filter((rule) => typeof rule === "string" && rule.trim())
        : [];
      for (const rule of failedRules) {
        const key = rule.trim();
        failedRuleCounts.set(key, (failedRuleCounts.get(key) || 0) + 1);
      }
      if (warnSamples.length < sampleLimit) {
        warnSamples.push({
          session_id: event.session_id || null,
          event_type: event.event_type,
          timestamp: normalizeTimestampOrNull(event.timestamp),
          failed_rules: failedRules
        });
      }
    } else {
      validationMissingEvents += 1;
    }
  }

  const topFailedRules = Array.from(failedRuleCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([rule, count]) => ({ rule, count }));

  return {
    counters: {
      total_kernel_events: totalKernelEvents,
      validation_pass_events: validationPassEvents,
      validation_warn_events: validationWarnEvents,
      validation_missing_events: validationMissingEvents,
      source_kernel_bridge_events: sourceKernelBridgeEvents,
      source_mismatch_events: sourceMismatchEvents,
      source_missing_events: sourceMissingEvents
    },
    rates: {
      validation_pass_rate: safeRatio(validationPassEvents, totalKernelEvents),
      validation_warn_rate: safeRatio(validationWarnEvents, totalKernelEvents),
      validation_missing_rate: safeRatio(validationMissingEvents, totalKernelEvents),
      source_kernel_bridge_rate: safeRatio(sourceKernelBridgeEvents, totalKernelEvents)
    },
    top_failed_rules: topFailedRules,
    warn_samples: warnSamples
  };
}

function validateReviewMetadata(metadata) {
  if (!isPlainObject(metadata)) {
    throw new Error("metadata must be an object");
  }
  if (
    metadata.related_event_type !== undefined &&
    typeof metadata.related_event_type !== "string"
  ) {
    throw new Error("metadata.related_event_type must be a string");
  }
  if (
    metadata.related_severity !== undefined &&
    (!ALLOWED_SEVERITIES.has(metadata.related_severity) ||
      typeof metadata.related_severity !== "string")
  ) {
    throw new Error("metadata.related_severity must be one of low|medium|high|critical");
  }
}

function paginate(records, defaultLimit, limit, offset) {
  const safeLimit = Number.isFinite(limit) ? Math.max(1, Math.floor(limit)) : defaultLimit;
  const safeOffset = Number.isFinite(offset) ? Math.max(0, Math.floor(offset)) : 0;
  const total = records.length;
  const items = records.slice(safeOffset, safeOffset + safeLimit);
  return {
    items,
    page: {
      total,
      offset: safeOffset,
      limit: safeLimit,
      has_more: safeOffset + safeLimit < total,
      next_offset: safeOffset + safeLimit < total ? safeOffset + safeLimit : null
    }
  };
}

function asFiniteNumberOrNull(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

class RuntimeState {
  constructor(config = {}) {
    this.config = {
      refreshTokenTtlSec: config.refreshTokenTtlSec || 60 * 60 * 12,
      heartbeatTtlSec: config.heartbeatTtlSec || 60
    };

    this.usersByCredential = new Map();
    this.usersById = new Map();
    this.teamsById = new Map();

    this.clientByUserDevice = new Map();
    this.clientsById = new Map();

    this.sessionsById = new Map();
    this.activeSessionByUser = new Map();
    this.sessionByClient = new Map();

    this.refreshTokens = new Map();
    this.banUsers = new Map();
    this.banTeams = new Map();
    this.banSessions = new Map();
    this.banRecords = [];
    this.revokedJti = new Map();
    this.activeJtiByUser = new Map();
    this.heartbeatByClient = new Map();
    this.latestUploadStatusBySession = new Map();
    this.archiveDirectory = normalizeOptionalString(config.archiveDirectory);
    this.archiveSessionGroupSize = clampPositiveInteger(
      config.archiveSessionGroupSize,
      DEFAULT_ARCHIVE_SESSION_GROUP_SIZE,
      1000
    );
    this.archiveMemoryEventLimit = this.archiveDirectory
      ? clampPositiveInteger(
          config.archiveMemoryEventLimit,
          DEFAULT_ARCHIVE_MEMORY_EVENT_LIMIT,
          1000000
        )
      : 0;
    this.sessionArchiveGroupById = new Map();
    this.archiveWriteFailures = [];
    this.events = [];
    this.sessionDecisions = new Map();
    this.reviewNotes = [];
    this.reviewActions = [];
    this.discordActions = [];
    this.discordActionsById = new Map();
    this.discordIdentityByUserId = new Map();
    this.userIdByDiscordUserId = new Map();
    this.eventRejections = [];
    this.submissionProofNonceCache = new Map();
    this.submissionProofJtiCache = new Map();
    this.auditLogs = [];
  }

  ensureUser(credential) {
    const key = String(credential).trim();
    let userId = this.usersByCredential.get(key);
    if (!userId) {
      userId = crypto.randomUUID();
      const user = {
        user_id: userId,
        username: key,
        created_at: nowIso()
      };
      this.usersByCredential.set(key, userId);
      this.usersById.set(userId, user);
    }
    return this.usersById.get(userId);
  }

  ensureTeam(teamIdMaybe) {
    const teamId = teamIdMaybe && String(teamIdMaybe).trim() ? String(teamIdMaybe).trim() : crypto.randomUUID();
    if (!this.teamsById.has(teamId)) {
      this.teamsById.set(teamId, {
        team_id: teamId,
        name: `team-${teamId.slice(0, 8)}`,
        created_at: nowIso()
      });
    }
    return this.teamsById.get(teamId);
  }

  registerClient(userId, teamId, clientInfo) {
    const key = `${userId}:${clientInfo.device_id}`;
    let clientId = this.clientByUserDevice.get(key);
    if (!clientId) {
      clientId = crypto.randomUUID();
      this.clientByUserDevice.set(key, clientId);
    }

    const client = {
      client_instance_id: clientId,
      user_id: userId,
      team_id: teamId,
      device_id: clientInfo.device_id,
      os: clientInfo.os,
      os_version: clientInfo.os_version,
      app_version: clientInfo.app_version,
      last_seen_at: nowIso()
    };
    this.clientsById.set(clientId, client);
    return client;
  }

  createSession({ userId, teamId, clientId, policyVersion, ip, userAgent }) {
    const activeSessionId = this.activeSessionByUser.get(userId);
    if (activeSessionId) {
      const prev = this.sessionsById.get(activeSessionId);
      if (prev) {
        prev.status = "OFFLINE";
        prev.ended_at = nowIso();
        prev.updated_at = nowIso();
      }
    }

    const linkedIdentity = this.getDiscordIdentityByUserId(userId);
    const client = this.getClient(clientId);
    const initialBoundDiscordUserId =
      linkedIdentity &&
      typeof linkedIdentity.discord_user_id === "string" &&
      linkedIdentity.discord_user_id.trim().length > 0
        ? linkedIdentity.discord_user_id.trim()
        : null;
    const sessionId = crypto.randomUUID();
    const archiveGroupIndex = Math.ceil(
      (this.sessionsById.size + 1) / this.archiveSessionGroupSize
    );
    const now = nowIso();
    const session = {
      session_id: sessionId,
      user_id: userId,
      team_id: teamId,
      client_instance_id: clientId,
      status: "ACTIVE",
      policy_version: policyVersion || "policy-v1",
      last_heartbeat_at: now,
      health_firewall_state: "unknown",
      health_observer_state: "unknown",
      health_client_agent_state: "unknown",
      health_kernel_bridge_state: "unknown",
      health_kernel_driver_loaded: false,
      discord_user_id: linkedIdentity ? linkedIdentity.discord_user_id : null,
      discord_display_name: linkedIdentity ? linkedIdentity.discord_display_name || null : null,
      discord_username: linkedIdentity ? linkedIdentity.discord_username || null : null,
      discord_link_state: linkedIdentity ? "linked" : "unlinked",
      discord_require_linked_policy: "none",
      discord_require_linked_reason_code: null,
      discord_require_linked_since: null,
      discord_require_linked_grace_expires_at: null,
      discord_require_linked_enforcement_state: "none",
      identity_source: linkedIdentity ? linkedIdentity.identity_source : "unknown",
      identity_hint_source: "unknown",
      identity_hint_link_state: "unknown",
      identity_hint_discord_user_id: null,
      identity_hint_discord_display_name: null,
      identity_hint_discord_username: null,
      identity_hint_device_binding_mode: "unknown",
      identity_hint_device_binding_state: "unknown",
      identity_hint_device_binding_id: null,
      identity_hint_device_binding_error_code: null,
      session_binding_device_id:
        client &&
        typeof client.device_id === "string" &&
        client.device_id.trim().length > 0
          ? client.device_id.trim()
          : null,
      session_binding_discord_user_id: initialBoundDiscordUserId,
      session_binding_bound_at: now,
      session_binding_last_relink_at: null,
      session_binding_policy: "none",
      session_binding_reason_code: null,
      session_binding_risk_type: null,
      session_binding_conflicting_session_ids: [],
      session_binding_enforcement_state: "none",
      session_binding_checked_at: null,
      discord_identity_policy: "none",
      discord_identity_policy_reason_code: null,
      discord_identity_loss_since: null,
      discord_identity_grace_expires_at: null,
      discord_identity_enforcement_state: "none",
      discord_identity_revoke_state: "none",
      discord_identity_revoke_action_id: null,
      discord_identity_revoke_requested_at: null,
      discord_identity_revoke_skip_reason: null,
      discord_gate_role_state: "none",
      discord_gate_role_last_action_id: null,
      discord_gate_role_last_requested_at: null,
      discord_gate_role_skip_reason: null,
      last_ip: ip || null,
      last_user_agent: userAgent || null,
      archive_group_index: archiveGroupIndex,
      created_at: now,
      updated_at: now,
      ended_at: null
    };

    this.sessionsById.set(sessionId, session);
    this.sessionArchiveGroupById.set(sessionId, archiveGroupIndex);
    this.archiveRecord("session", session);
    this.activeSessionByUser.set(userId, sessionId);
    this.sessionByClient.set(clientId, sessionId);
    return session;
  }

  issueRefreshToken(session) {
    const token = crypto.randomBytes(24).toString("base64url");
    const expiresAt = nowEpochSec() + this.config.refreshTokenTtlSec;
    this.refreshTokens.set(token, {
      user_id: session.user_id,
      team_id: session.team_id,
      session_id: session.session_id,
      client_instance_id: session.client_instance_id,
      exp: expiresAt
    });
    return {
      refresh_token: token,
      refresh_expires_at: new Date(expiresAt * 1000).toISOString()
    };
  }

  validateRefreshToken(token) {
    const value = this.refreshTokens.get(token);
    if (!value) {
      return { ok: false, code: "INVALID_TOKEN", message: "refresh token invalid" };
    }
    if (nowEpochSec() >= value.exp) {
      this.refreshTokens.delete(token);
      return { ok: false, code: "EXPIRED_TOKEN", message: "refresh token expired" };
    }
    return { ok: true, value };
  }

  getClient(clientId) {
    return this.clientsById.get(clientId) || null;
  }

  getUser(userId) {
    return this.usersById.get(userId) || null;
  }

  getDiscordIdentityByUserId(userId) {
    const key = typeof userId === "string" ? userId.trim() : "";
    if (!key) return null;
    return this.discordIdentityByUserId.get(key) || null;
  }

  getDiscordIdentityByDiscordUserId(discordUserId) {
    const key = typeof discordUserId === "string" ? discordUserId.trim() : "";
    if (!key) return null;
    const userId = this.userIdByDiscordUserId.get(key);
    if (!userId) return null;
    return this.getDiscordIdentityByUserId(userId);
  }

  linkDiscordIdentity({
    user_id,
    discord_user_id,
    identity_source = "oauth",
    verification_method = "oauth_pkce",
    discord_display_name = null,
    discord_username = null,
    linked_by = "integration-client",
    verified_at = null,
    linked_at = null,
    metadata = {},
    allow_relink = false
  } = {}) {
    const normalizedUserId = String(user_id || "").trim();
    const normalizedDiscordUserId = String(discord_user_id || "").trim();
    if (!normalizedUserId) {
      throw new Error("user_id is required");
    }
    if (!normalizedDiscordUserId) {
      throw new Error("discord_user_id is required");
    }
    if (!this.usersById.has(normalizedUserId)) {
      throw new Error("user not found");
    }
    if (!isPlainObject(metadata)) {
      throw new Error("metadata must be an object");
    }

    const normalizedSource = String(identity_source || "")
      .trim()
      .toLowerCase();
    if (!DISCORD_IDENTITY_SOURCES.has(normalizedSource)) {
      throw new Error("identity_source must be oauth|sdk_hint|unknown");
    }

    const normalizedMethod = String(verification_method || "").trim();
    if (!normalizedMethod) {
      throw new Error("verification_method is required");
    }

    const existingForUser = this.discordIdentityByUserId.get(normalizedUserId) || null;
    if (
      existingForUser &&
      existingForUser.discord_user_id !== normalizedDiscordUserId &&
      allow_relink !== true
    ) {
      throw new Error("user already linked to a different discord_user_id");
    }

    const existingLinkedUserId = this.userIdByDiscordUserId.get(normalizedDiscordUserId) || null;
    if (
      existingLinkedUserId &&
      existingLinkedUserId !== normalizedUserId &&
      allow_relink !== true
    ) {
      throw new Error("discord_user_id already linked to another user");
    }

    if (
      allow_relink === true &&
      existingLinkedUserId &&
      existingLinkedUserId !== normalizedUserId
    ) {
      this.discordIdentityByUserId.delete(existingLinkedUserId);
    }

    const now = nowIso();
    const normalizedDisplayName = resolveDiscordDisplayName({
      displayName: discord_display_name,
      username: discord_username,
      metadata
    });
    const normalizedUsername = normalizeOptionalString(discord_username);
    const record = {
      user_id: normalizedUserId,
      discord_user_id: normalizedDiscordUserId,
      discord_display_name: normalizedDisplayName,
      discord_username: normalizedUsername,
      discord_link_state: "linked",
      identity_source: normalizedSource,
      verification_method: normalizedMethod,
      linked_by: String(linked_by || "integration-client").trim() || "integration-client",
      linked_at: normalizeTimestampOrNull(linked_at) || now,
      verified_at: normalizeTimestampOrNull(verified_at) || now,
      updated_at: now,
      metadata
    };

    this.discordIdentityByUserId.set(normalizedUserId, record);
    this.userIdByDiscordUserId.set(normalizedDiscordUserId, normalizedUserId);

    if (existingForUser && existingForUser.discord_user_id !== normalizedDiscordUserId) {
      this.userIdByDiscordUserId.delete(existingForUser.discord_user_id);
    }

    const session = this.getActiveSessionByUser(normalizedUserId);
    if (session) {
      if (
        session.session_binding_discord_user_id &&
        session.session_binding_discord_user_id !== normalizedDiscordUserId
      ) {
        session.session_binding_last_relink_at = now;
      } else if (!session.session_binding_discord_user_id) {
        session.session_binding_discord_user_id = normalizedDiscordUserId;
        if (!session.session_binding_bound_at) {
          session.session_binding_bound_at = now;
        }
      }
      session.discord_user_id = normalizedDiscordUserId;
      session.discord_display_name = normalizedDisplayName;
      session.discord_username = normalizedUsername;
      session.discord_link_state = "linked";
      session.identity_source = normalizedSource;
      session.updated_at = now;
    }

    this.addAuditLog({
      action: "DISCORD_IDENTITY_LINK",
      actor: record.linked_by,
      object_type: "user",
      object_id: normalizedUserId,
      detail: {
        discord_user_id: normalizedDiscordUserId,
        identity_source: normalizedSource,
        verification_method: normalizedMethod,
        relinked:
          existingForUser !== null &&
          existingForUser.discord_user_id !== normalizedDiscordUserId
      }
    });

    return {
      linked: true,
      relinked:
        existingForUser !== null &&
        existingForUser.discord_user_id !== normalizedDiscordUserId,
      record
    };
  }

  getSession(sessionId) {
    return this.sessionsById.get(sessionId) || null;
  }

  getActiveSessionByUser(userId) {
    const sessionId = this.activeSessionByUser.get(userId);
    if (!sessionId) return null;
    return this.sessionsById.get(sessionId) || null;
  }

  updateHeartbeat(clientId, health, policyVersion, identityHint = null, requestContext = null) {
    const sessionId = this.sessionByClient.get(clientId);
    if (!sessionId) return;
    const session = this.sessionsById.get(sessionId);
    if (!session) return;

    session.last_heartbeat_at = nowIso();
    session.updated_at = nowIso();
    session.policy_version = policyVersion || session.policy_version;
    session.health_firewall_state = health.firewall_state;
    session.health_observer_state = health.observer_state;
    session.health_client_agent_state =
      typeof health.client_agent_state === "string" && health.client_agent_state.trim()
        ? health.client_agent_state.trim().toLowerCase()
        : "unknown";
    session.health_kernel_bridge_state =
      typeof health.kernel_bridge_state === "string" && health.kernel_bridge_state.trim()
        ? health.kernel_bridge_state.trim().toLowerCase()
        : "unknown";
    session.health_kernel_driver_loaded = health.kernel_driver_loaded === true;
    if (isPlainObject(requestContext)) {
      const requestIp =
        typeof requestContext.ip === "string" && requestContext.ip.trim().length > 0
          ? requestContext.ip.trim()
          : null;
      const requestUserAgent =
        typeof requestContext.userAgent === "string" && requestContext.userAgent.trim().length > 0
          ? requestContext.userAgent.trim()
          : null;
      if (requestIp) {
        session.last_ip = requestIp;
      }
      if (requestUserAgent) {
        session.last_user_agent = requestUserAgent;
      }
    }
    if (isPlainObject(identityHint)) {
      const normalizedHintSource = String(identityHint.identity_source || "")
        .trim()
        .toLowerCase();
      const normalizedHintState = String(identityHint.discord_link_state || "")
        .trim()
        .toLowerCase();
      session.identity_hint_source = DISCORD_IDENTITY_SOURCES.has(normalizedHintSource)
        ? normalizedHintSource
        : "unknown";
      session.identity_hint_link_state = DISCORD_LINK_STATES.has(normalizedHintState)
        ? normalizedHintState
        : "unknown";
      session.identity_hint_discord_user_id =
        typeof identityHint.discord_user_id === "string" &&
        identityHint.discord_user_id.trim().length > 0
          ? identityHint.discord_user_id.trim()
          : null;
      session.identity_hint_discord_display_name = normalizeOptionalString(
        identityHint.discord_display_name
      );
      session.identity_hint_discord_username = normalizeOptionalString(
        identityHint.discord_username
      );
      const normalizedBindingMode = String(identityHint.device_binding_mode || "")
        .trim()
        .toLowerCase();
      const normalizedBindingState = String(identityHint.device_binding_state || "")
        .trim()
        .toLowerCase();
      session.identity_hint_device_binding_mode = DEVICE_BINDING_MODES.has(normalizedBindingMode)
        ? normalizedBindingMode
        : "unknown";
      session.identity_hint_device_binding_state = DEVICE_BINDING_STATES.has(normalizedBindingState)
        ? normalizedBindingState
        : "unknown";
      session.identity_hint_device_binding_id =
        typeof identityHint.device_binding_id === "string" &&
        identityHint.device_binding_id.trim().length > 0
          ? identityHint.device_binding_id.trim()
          : null;
      session.identity_hint_device_binding_error_code =
        typeof identityHint.device_binding_error_code === "string" &&
        identityHint.device_binding_error_code.trim().length > 0
          ? identityHint.device_binding_error_code.trim()
          : null;
    }
    this.heartbeatByClient.set(clientId, nowEpochSec());
  }

  isClientOnline(clientId) {
    const ts = this.heartbeatByClient.get(clientId);
    if (!ts) return false;
    return nowEpochSec() - ts <= this.config.heartbeatTtlSec;
  }

  isClientNoncompliant(clientId) {
    const sessionId = this.sessionByClient.get(clientId);
    if (!sessionId) return false;
    const session = this.sessionsById.get(sessionId);
    if (!session) return false;
    return (
      session.health_firewall_state === "error" || session.health_observer_state === "error"
    );
  }

  setUserBan(userId, durationSec, reasonCode = "BANNED_USER", reason = "policy block") {
    const until = durationSec > 0 ? nowEpochSec() + durationSec : null;
    this.banUsers.set(userId, { until, reason_code: reasonCode, reason });
  }

  setTeamBan(teamId, durationSec, reasonCode = "BANNED_TEAM", reason = "policy block") {
    const until = durationSec > 0 ? nowEpochSec() + durationSec : null;
    this.banTeams.set(teamId, { until, reason_code: reasonCode, reason });
  }

  setSessionBan(sessionId, durationSec, reasonCode = "BANNED_USER", reason = "policy block") {
    const until = durationSec > 0 ? nowEpochSec() + durationSec : null;
    this.banSessions.set(sessionId, { until, reason_code: reasonCode, reason });
  }

  getUserBan(userId) {
    const ban = this.banUsers.get(userId);
    if (!ban) return null;
    if (ban.until && nowEpochSec() >= ban.until) {
      this.banUsers.delete(userId);
      return null;
    }
    return ban;
  }

  getTeamBan(teamId) {
    const ban = this.banTeams.get(teamId);
    if (!ban) return null;
    if (ban.until && nowEpochSec() >= ban.until) {
      this.banTeams.delete(teamId);
      return null;
    }
    return ban;
  }

  getSessionBan(sessionId) {
    const ban = this.banSessions.get(sessionId);
    if (!ban) return null;
    if (ban.until && nowEpochSec() >= ban.until) {
      this.banSessions.delete(sessionId);
      return null;
    }
    return ban;
  }

  setActiveJti(userId, jti, exp) {
    this.activeJtiByUser.set(userId, { jti, exp });
  }

  revokeJti(jti, exp) {
    this.revokedJti.set(jti, exp || nowEpochSec() + 120);
  }

  revokeActiveJtiForUser(userId) {
    const active = this.activeJtiByUser.get(userId);
    if (!active) return false;
    this.revokeJti(active.jti, active.exp);
    return true;
  }

  resetParticipantForReconnect({
    user_id,
    actor = "system",
    reason = "manual participant reconnect reset",
    clear_bans = false
  } = {}) {
    const userId = typeof user_id === "string" ? user_id.trim() : "";
    if (!userId) {
      throw new Error("user_id is required");
    }

    const user = this.getUser(userId);
    const now = nowIso();
    const sessions = Array.from(this.sessionsById.values()).filter(
      (session) => session && session.user_id === userId
    );
    if (!user && sessions.length === 0) {
      return null;
    }

    const resetSessionIds = [];
    const resetClientIds = [];
    for (const session of sessions) {
      session.status = "OFFLINE";
      session.ended_at = session.ended_at || now;
      session.updated_at = now;
      resetSessionIds.push(session.session_id);

      if (session.client_instance_id) {
        resetClientIds.push(session.client_instance_id);
        if (this.sessionByClient.get(session.client_instance_id) === session.session_id) {
          this.sessionByClient.delete(session.client_instance_id);
        }
        this.heartbeatByClient.delete(session.client_instance_id);
      }
    }

    if (this.activeSessionByUser.get(userId)) {
      this.activeSessionByUser.delete(userId);
    }

    let revokedRefreshTokenCount = 0;
    for (const [token, value] of Array.from(this.refreshTokens.entries())) {
      if (value && value.user_id === userId) {
        this.refreshTokens.delete(token);
        revokedRefreshTokenCount += 1;
      }
    }

    const revokedJti = [];
    const activeJti = this.activeJtiByUser.get(userId);
    if (activeJti && activeJti.jti) {
      this.revokeJti(activeJti.jti, activeJti.exp);
      this.activeJtiByUser.delete(userId);
      revokedJti.push({ jti: activeJti.jti, exp_epoch_sec: activeJti.exp });
    }

    const revokedBans = [];
    if (clear_bans === true) {
      const resetSessionIdSet = new Set(resetSessionIds);
      for (const record of this.banRecords) {
        if (!record || record.status !== "ACTIVE") continue;
        const targetsUser = record.scope === "user" && record.target_id === userId;
        const targetsSession =
          record.scope === "session" && resetSessionIdSet.has(record.target_id);
        if (!targetsUser && !targetsSession) continue;

        record.status = "REVOKED";
        record.revoked_at = now;
        record.revoked_by = actor;
        if (record.scope === "user") this.banUsers.delete(record.target_id);
        if (record.scope === "session") this.banSessions.delete(record.target_id);
        revokedBans.push(record);
      }
    }

    const result = {
      reset: true,
      user_id: userId,
      username: user && typeof user.username === "string" ? user.username : null,
      reset_at: now,
      reset_session_ids: resetSessionIds,
      reset_client_instance_ids: resetClientIds,
      revoked_refresh_token_count: revokedRefreshTokenCount,
      revoked_jti: revokedJti,
      revoked_bans: revokedBans,
      clear_bans: clear_bans === true
    };

    this.addAuditLog({
      action: "ADMIN_PARTICIPANT_RECONNECT_RESET",
      actor,
      object_type: "user",
      object_id: userId,
      detail: {
        reason,
        clear_bans: clear_bans === true,
        reset_session_ids: resetSessionIds,
        reset_client_instance_ids: resetClientIds,
        revoked_refresh_token_count: revokedRefreshTokenCount,
        revoked_jti_count: revokedJti.length,
        revoked_ban_ids: revokedBans.map((record) => record.ban_id)
      }
    });

    return result;
  }

  isJtiRevoked(jti) {
    const exp = this.revokedJti.get(jti);
    if (!exp) return false;
    if (nowEpochSec() >= exp) {
      this.revokedJti.delete(jti);
      return false;
    }
    return true;
  }

  getArchiveGroupIndexForSession(sessionId) {
    const normalized = typeof sessionId === "string" ? sessionId.trim() : "";
    if (!normalized) return 0;
    const cached = this.sessionArchiveGroupById.get(normalized);
    if (Number.isFinite(Number(cached)) && Number(cached) > 0) {
      return Math.floor(Number(cached));
    }
    const session = this.sessionsById.get(normalized);
    const fromSession = session ? Number(session.archive_group_index) : 0;
    if (Number.isFinite(fromSession) && fromSession > 0) {
      const next = Math.floor(fromSession);
      this.sessionArchiveGroupById.set(normalized, next);
      return next;
    }
    return 0;
  }

  archiveRecord(kind, record) {
    if (!this.archiveDirectory) return false;
    try {
      let relativePath = `${kind}.jsonl`;
      if (kind === "session") {
        const group = archiveGroupName(record && record.archive_group_index);
        relativePath = `session-groups/${group}/sessions.jsonl`;
      } else if (kind === "event") {
        const groupIndex = this.getArchiveGroupIndexForSession(record && record.session_id);
        const group = archiveGroupName(groupIndex);
        relativePath =
          group === "ungrouped"
            ? "session-groups/ungrouped/events.jsonl"
            : `session-groups/${group}/events.jsonl`;
      } else if (kind === "review_note") {
        relativePath = "review_notes.jsonl";
      } else if (kind === "review_action") {
        relativePath = "review_actions.jsonl";
      } else if (kind === "audit_log") {
        relativePath = "audit_logs.jsonl";
      }
      return safeArchiveJsonLine(this.archiveDirectory, relativePath, record);
    } catch (error) {
      this.archiveWriteFailures.push({
        at: nowIso(),
        kind,
        message: error instanceof Error ? error.message : String(error)
      });
      if (this.archiveWriteFailures.length > 100) {
        this.archiveWriteFailures = this.archiveWriteFailures.slice(-100);
      }
      return false;
    }
  }

  trimArchivedEventsFromMemory() {
    if (!this.archiveDirectory || this.archiveMemoryEventLimit <= 0) return;
    if (this.events.length <= this.archiveMemoryEventLimit) return;
    const dropped = this.events.length - this.archiveMemoryEventLimit;
    this.events = this.events.slice(-this.archiveMemoryEventLimit);
    this.addAuditLog({
      action: "RUNTIME_EVENT_MEMORY_TRIM",
      actor: "system",
      object_type: "event_buffer",
      object_id: "runtime",
      detail: {
        dropped,
        memory_event_limit: this.archiveMemoryEventLimit,
        archive_directory: this.archiveDirectory
      }
    });
  }

  appendEvents(records) {
    for (const event of records) {
      this.archiveRecord("event", event);
      if (!isPlainObject(event) || event.event_type !== "CLIENT_UPLOAD_STATUS") continue;
      const sessionId =
        typeof event.session_id === "string" ? event.session_id.trim() : "";
      if (!sessionId) continue;
      const evidence = isPlainObject(event.evidence) ? event.evidence : {};
      const next = {
        status:
          typeof evidence.status === "string" && evidence.status.trim()
            ? evidence.status.trim().toLowerCase()
            : null,
        timestamp:
          typeof event.timestamp === "string" && event.timestamp.trim()
            ? event.timestamp
            : null,
        received_at:
          typeof event.received_at === "string" && event.received_at.trim()
            ? event.received_at
            : null,
        uploaded_events: asFiniteNumberOrNull(evidence.uploaded_events),
        pending_events: asFiniteNumberOrNull(evidence.pending_events),
        failed_events: asFiniteNumberOrNull(evidence.failed_events),
        attempted_batches: asFiniteNumberOrNull(evidence.attempted_batches),
        auth_recovered_batches: asFiniteNumberOrNull(
          evidence.auth_recovered_batches
        ),
        auth_refresh_failed_batches: asFiniteNumberOrNull(
          evidence.auth_refresh_failed_batches
        )
      };
      const current = this.latestUploadStatusBySession.get(sessionId);
      const currentTime = Date.parse(
        (current && (current.timestamp || current.received_at)) || ""
      );
      const nextTime = Date.parse(next.timestamp || next.received_at || "");
      if (!current || !Number.isFinite(currentTime) || !Number.isFinite(nextTime) || nextTime >= currentTime) {
        this.latestUploadStatusBySession.set(sessionId, next);
      }
    }
    this.events.push(...records);
    this.trimArchivedEventsFromMemory();
  }

  getEventsBySession(sessionId) {
    return this.events.filter((event) => event.session_id === sessionId);
  }

  setSessionDecision(sessionId, decision) {
    this.sessionDecisions.set(sessionId, {
      ...decision,
      decided_at: nowIso()
    });
  }

  getSessionDecision(sessionId) {
    return this.sessionDecisions.get(sessionId) || null;
  }

  createBan({
    scope,
    target_id,
    reason,
    reason_code,
    duration_sec = 0,
    created_by = "system"
  }) {
    if (!["user", "team", "session"].includes(scope)) {
      throw new Error("scope must be one of user, team, session");
    }
    if (!target_id || String(target_id).trim() === "") {
      throw new Error("target_id is required");
    }

    const banId = crypto.randomUUID();
    const now = nowIso();
    const expiresAt =
      duration_sec > 0 ? new Date((nowEpochSec() + duration_sec) * 1000).toISOString() : null;

    if (scope === "user") {
      this.setUserBan(target_id, duration_sec, reason_code || "BANNED_USER", reason);
    } else if (scope === "team") {
      this.setTeamBan(target_id, duration_sec, reason_code || "BANNED_TEAM", reason);
    } else if (scope === "session") {
      this.setSessionBan(target_id, duration_sec, reason_code || "BANNED_USER", reason);
    }

    const record = {
      ban_id: banId,
      scope,
      target_id,
      reason,
      reason_code: reason_code || null,
      created_by,
      created_at: now,
      expires_at: expiresAt,
      revoked_at: null,
      revoked_by: null,
      status: "ACTIVE"
    };
    this.banRecords.push(record);
    this.addAuditLog({
      action: "BAN_CREATE",
      actor: created_by,
      object_type: scope,
      object_id: target_id,
      detail: { ban_id: banId, reason, duration_sec }
    });
    return record;
  }

  revokeBan(banId, actor = "system") {
    const record = this.banRecords.find((item) => item.ban_id === banId);
    if (!record) return null;
    if (record.status !== "ACTIVE") return record;

    record.status = "REVOKED";
    record.revoked_at = nowIso();
    record.revoked_by = actor;

    if (record.scope === "user") this.banUsers.delete(record.target_id);
    if (record.scope === "team") this.banTeams.delete(record.target_id);
    if (record.scope === "session") this.banSessions.delete(record.target_id);

    this.addAuditLog({
      action: "BAN_REVOKE",
      actor,
      object_type: record.scope,
      object_id: record.target_id,
      detail: { ban_id: record.ban_id }
    });
    return record;
  }

  listBans({ status, scope, limit = 100, offset = 0 } = {}) {
    let records = [...this.banRecords];
    if (status) records = records.filter((item) => item.status === status);
    if (scope) records = records.filter((item) => item.scope === scope);
    records.sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
    const safeLimit = Number.isFinite(limit) ? Math.max(1, Math.floor(limit)) : 100;
    const safeOffset = Number.isFinite(offset) ? Math.max(0, Math.floor(offset)) : 0;
    const total = records.length;
    const items = records.slice(safeOffset, safeOffset + safeLimit);
    return {
      items,
      page: {
        total,
        offset: safeOffset,
        limit: safeLimit,
        has_more: safeOffset + safeLimit < total,
        next_offset: safeOffset + safeLimit < total ? safeOffset + safeLimit : null
      }
    };
  }

  listSessions({
    status,
    upload_status,
    team_id,
    user_id,
    decision_reason_code,
    limit = 100,
    offset = 0
  } = {}) {
    const latestUploadStatusBySession = this.latestUploadStatusBySession || new Map();

    const sessionRows = Array.from(this.sessionsById.values()).map((session) => {
      const client = this.getClient(session.client_instance_id);
      const decision = this.getSessionDecision(session.session_id);
      const user = this.usersById.get(session.user_id) || null;
      const latestUploadStatus =
        latestUploadStatusBySession.get(session.session_id) || null;
      const normalizedUploadStatus =
        latestUploadStatus &&
        Number(latestUploadStatus.auth_refresh_failed_batches || 0) > 0
          ? "failed"
          : latestUploadStatus &&
              typeof latestUploadStatus.status === "string" &&
              latestUploadStatus.status.length > 0
            ? latestUploadStatus.status
            : null;
      let computedStatus = "ACTIVE";
      if (
        this.getTeamBan(session.team_id) ||
        this.getUserBan(session.user_id) ||
        this.getSessionBan(session.session_id)
      ) {
        computedStatus = "BLOCKED";
      } else if (session.ended_at || !this.isClientOnline(session.client_instance_id)) {
        computedStatus = "OFFLINE";
      } else if (decision && decision.status === "blocked") {
        computedStatus = "BLOCKED";
      } else if (decision && decision.status === "warn") {
        computedStatus = "WARN";
      }
      return {
        ...session,
        status: computedStatus,
        client_version: client ? client.app_version : null,
        device_id: client ? client.device_id : null,
        username: user && typeof user.username === "string" ? user.username : null,
        decision_reason_code: decision ? decision.reason_code || null : null,
        final_risk_score: decision && typeof decision.score === "number" ? decision.score : 0,
        risk_tier: decision ? decision.tier : "normal",
        discord_user_id:
          typeof session.discord_user_id === "string" ? session.discord_user_id : null,
        discord_display_name:
          typeof session.discord_display_name === "string" ? session.discord_display_name : null,
        discord_username:
          typeof session.discord_username === "string" ? session.discord_username : null,
        discord_link_state:
          typeof session.discord_link_state === "string"
            ? session.discord_link_state
            : "unknown",
        discord_require_linked_policy:
          typeof session.discord_require_linked_policy === "string"
            ? session.discord_require_linked_policy
            : "none",
        discord_require_linked_reason_code:
          typeof session.discord_require_linked_reason_code === "string"
            ? session.discord_require_linked_reason_code
            : null,
        discord_require_linked_since:
          typeof session.discord_require_linked_since === "string"
            ? session.discord_require_linked_since
            : null,
        discord_require_linked_grace_expires_at:
          typeof session.discord_require_linked_grace_expires_at === "string"
            ? session.discord_require_linked_grace_expires_at
            : null,
        discord_require_linked_enforcement_state:
          typeof session.discord_require_linked_enforcement_state === "string"
            ? session.discord_require_linked_enforcement_state
            : "none",
        identity_source:
          typeof session.identity_source === "string" ? session.identity_source : "unknown",
        identity_hint_source:
          typeof session.identity_hint_source === "string"
            ? session.identity_hint_source
            : "unknown",
        identity_hint_link_state:
          typeof session.identity_hint_link_state === "string"
            ? session.identity_hint_link_state
            : "unknown",
        identity_hint_discord_user_id:
          typeof session.identity_hint_discord_user_id === "string"
            ? session.identity_hint_discord_user_id
            : null,
        identity_hint_discord_display_name:
          typeof session.identity_hint_discord_display_name === "string"
            ? session.identity_hint_discord_display_name
            : null,
        identity_hint_discord_username:
          typeof session.identity_hint_discord_username === "string"
            ? session.identity_hint_discord_username
            : null,
        identity_hint_device_binding_mode:
          typeof session.identity_hint_device_binding_mode === "string"
            ? session.identity_hint_device_binding_mode
            : "unknown",
        identity_hint_device_binding_state:
          typeof session.identity_hint_device_binding_state === "string"
            ? session.identity_hint_device_binding_state
            : "unknown",
        identity_hint_device_binding_id:
          typeof session.identity_hint_device_binding_id === "string"
            ? session.identity_hint_device_binding_id
            : null,
        identity_hint_device_binding_error_code:
          typeof session.identity_hint_device_binding_error_code === "string"
            ? session.identity_hint_device_binding_error_code
            : null,
        session_binding_device_id:
          typeof session.session_binding_device_id === "string"
            ? session.session_binding_device_id
            : null,
        session_binding_discord_user_id:
          typeof session.session_binding_discord_user_id === "string"
            ? session.session_binding_discord_user_id
            : null,
        session_binding_bound_at:
          typeof session.session_binding_bound_at === "string"
            ? session.session_binding_bound_at
            : null,
        session_binding_last_relink_at:
          typeof session.session_binding_last_relink_at === "string"
            ? session.session_binding_last_relink_at
            : null,
        session_binding_policy:
          typeof session.session_binding_policy === "string"
            ? session.session_binding_policy
            : "none",
        session_binding_reason_code:
          typeof session.session_binding_reason_code === "string"
            ? session.session_binding_reason_code
            : null,
        session_binding_risk_type:
          typeof session.session_binding_risk_type === "string"
            ? session.session_binding_risk_type
            : null,
        session_binding_conflicting_session_ids: Array.isArray(
          session.session_binding_conflicting_session_ids
        )
          ? session.session_binding_conflicting_session_ids
          : [],
        session_binding_enforcement_state:
          typeof session.session_binding_enforcement_state === "string"
            ? session.session_binding_enforcement_state
            : "none",
        session_binding_checked_at:
          typeof session.session_binding_checked_at === "string"
            ? session.session_binding_checked_at
            : null,
        discord_identity_policy:
          typeof session.discord_identity_policy === "string"
            ? session.discord_identity_policy
            : "none",
        discord_identity_policy_reason_code:
          typeof session.discord_identity_policy_reason_code === "string"
            ? session.discord_identity_policy_reason_code
            : null,
        discord_identity_loss_since:
          typeof session.discord_identity_loss_since === "string"
            ? session.discord_identity_loss_since
            : null,
        discord_identity_grace_expires_at:
          typeof session.discord_identity_grace_expires_at === "string"
            ? session.discord_identity_grace_expires_at
            : null,
        discord_identity_enforcement_state:
          typeof session.discord_identity_enforcement_state === "string"
            ? session.discord_identity_enforcement_state
            : "none",
        discord_identity_revoke_state:
          typeof session.discord_identity_revoke_state === "string"
            ? session.discord_identity_revoke_state
            : "none",
        discord_identity_revoke_action_id:
          typeof session.discord_identity_revoke_action_id === "string"
            ? session.discord_identity_revoke_action_id
            : null,
        discord_identity_revoke_requested_at:
          typeof session.discord_identity_revoke_requested_at === "string"
            ? session.discord_identity_revoke_requested_at
            : null,
        discord_identity_revoke_skip_reason:
          typeof session.discord_identity_revoke_skip_reason === "string"
            ? session.discord_identity_revoke_skip_reason
            : null,
        discord_gate_role_state:
          typeof session.discord_gate_role_state === "string"
            ? session.discord_gate_role_state
            : "none",
        discord_gate_role_last_action_id:
          typeof session.discord_gate_role_last_action_id === "string"
            ? session.discord_gate_role_last_action_id
            : null,
        discord_gate_role_last_requested_at:
          typeof session.discord_gate_role_last_requested_at === "string"
            ? session.discord_gate_role_last_requested_at
            : null,
        discord_gate_role_skip_reason:
          typeof session.discord_gate_role_skip_reason === "string"
            ? session.discord_gate_role_skip_reason
            : null,
        upload_status: normalizedUploadStatus,
        upload_status_at: latestUploadStatus
          ? latestUploadStatus.received_at || latestUploadStatus.timestamp
          : null,
        upload_status_summary: latestUploadStatus
      };
    });

    let filtered = sessionRows;
    if (status) filtered = filtered.filter((item) => item.status === status);
    if (upload_status) {
      const normalizedUploadStatus = String(upload_status).trim().toLowerCase();
      filtered = filtered.filter((item) => item.upload_status === normalizedUploadStatus);
    }
    if (team_id) filtered = filtered.filter((item) => item.team_id === team_id);
    if (user_id) filtered = filtered.filter((item) => item.user_id === user_id);
    const decisionReasonCodes = normalizeStringArray(decision_reason_code);
    if (decisionReasonCodes.length > 0) {
      const allowedReasonCodes = new Set(decisionReasonCodes);
      filtered = filtered.filter((item) => allowedReasonCodes.has(item.decision_reason_code));
    }
    filtered.sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at));
    const safeLimit = Number.isFinite(limit) ? Math.max(1, Math.floor(limit)) : 100;
    const safeOffset = Number.isFinite(offset) ? Math.max(0, Math.floor(offset)) : 0;
    const total = filtered.length;
    const items = filtered.slice(safeOffset, safeOffset + safeLimit);
    return {
      items,
      page: {
        total,
        offset: safeOffset,
        limit: safeLimit,
        has_more: safeOffset + safeLimit < total,
        next_offset: safeOffset + safeLimit < total ? safeOffset + safeLimit : null
      }
    };
  }

  listEvents({ team_id, user_id, type, limit = 200, offset = 0 } = {}) {
    let filtered = [...this.events];
    if (team_id) filtered = filtered.filter((item) => item.team_id === team_id);
    if (user_id) filtered = filtered.filter((item) => item.user_id === user_id);
    if (type) filtered = filtered.filter((item) => item.event_type === type);
    filtered.sort((a, b) => Date.parse(b.received_at) - Date.parse(a.received_at));
    const safeLimit = Number.isFinite(limit) ? Math.max(1, Math.floor(limit)) : 200;
    const safeOffset = Number.isFinite(offset) ? Math.max(0, Math.floor(offset)) : 0;
    const total = filtered.length;
    const items = filtered.slice(safeOffset, safeOffset + safeLimit);
    return {
      items,
      page: {
        total,
        offset: safeOffset,
        limit: safeLimit,
        has_more: safeOffset + safeLimit < total,
        next_offset: safeOffset + safeLimit < total ? safeOffset + safeLimit : null
      }
    };
  }

  addReviewNote({ session_id, author, note, metadata = {} }) {
    if (!session_id || !author || !note || String(note).trim() === "") {
      throw new Error("session_id, author, and note are required");
    }
    validateReviewMetadata(metadata);
    const record = {
      note_id: crypto.randomUUID(),
      session_id,
      author,
      note,
      metadata,
      created_at: nowIso()
    };
    this.reviewNotes.push(record);
    this.archiveRecord("review_note", record);
    this.addAuditLog({
      action: "REVIEW_NOTE_CREATE",
      actor: author,
      object_type: "session",
      object_id: session_id,
      detail: {
        note_id: record.note_id,
        related_event_type: metadata.related_event_type || null,
        related_severity: metadata.related_severity || null
      }
    });
    return record;
  }

  addReviewAction({ session_id, actor, action, reason, metadata = {} }) {
    const sensitive = new Set(["mark_as_suspicious", "escalate", "clear_with_reason"]);
    if (!session_id || !actor || !action) {
      throw new Error("session_id, actor, and action are required");
    }
    validateReviewMetadata(metadata);
    if (sensitive.has(action) && (!reason || String(reason).trim() === "")) {
      throw new Error("reason is required for sensitive manual actions");
    }
    const record = {
      action_id: crypto.randomUUID(),
      session_id,
      actor,
      action,
      reason: reason || null,
      metadata,
      created_at: nowIso()
    };
    this.reviewActions.push(record);
    this.archiveRecord("review_action", record);
    this.addAuditLog({
      action: "REVIEW_MANUAL_ACTION",
      actor,
      object_type: "session",
      object_id: session_id,
      detail: { action_id: record.action_id, action, reason: record.reason }
    });
    return record;
  }

  listReviewNotes(input = {}) {
    if (typeof input === "string") {
      return this.reviewNotes.filter((item) => item.session_id === input);
    }

    const {
      session_id,
      author,
      related_event_type,
      related_severity,
      from,
      to,
      limit = 100,
      offset = 0
    } = input || {};
    let records = [...this.reviewNotes];
    if (session_id) records = records.filter((item) => item.session_id === session_id);
    if (author) records = records.filter((item) => item.author === author);
    if (related_event_type) {
      records = records.filter(
        (item) =>
          item.metadata &&
          typeof item.metadata.related_event_type === "string" &&
          item.metadata.related_event_type === related_event_type
      );
    }
    if (related_severity) {
      records = records.filter(
        (item) =>
          item.metadata &&
          typeof item.metadata.related_severity === "string" &&
          item.metadata.related_severity === related_severity
      );
    }
    if (from) {
      const fromTs = Date.parse(from);
      if (!Number.isNaN(fromTs)) {
        records = records.filter((item) => Date.parse(item.created_at) >= fromTs);
      }
    }
    if (to) {
      const toTs = Date.parse(to);
      if (!Number.isNaN(toTs)) {
        records = records.filter((item) => Date.parse(item.created_at) <= toTs);
      }
    }
    records.sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
    return paginate(records, 100, limit, offset);
  }

  listReviewActions(input = {}) {
    if (typeof input === "string") {
      return this.reviewActions.filter((item) => item.session_id === input);
    }

    const {
      session_id,
      actor,
      action,
      related_event_type,
      related_severity,
      from,
      to,
      limit = 100,
      offset = 0
    } = input || {};
    let records = [...this.reviewActions];
    if (session_id) records = records.filter((item) => item.session_id === session_id);
    if (actor) records = records.filter((item) => item.actor === actor);
    if (action) records = records.filter((item) => item.action === action);
    if (related_event_type) {
      records = records.filter(
        (item) =>
          item.metadata &&
          typeof item.metadata.related_event_type === "string" &&
          item.metadata.related_event_type === related_event_type
      );
    }
    if (related_severity) {
      records = records.filter(
        (item) =>
          item.metadata &&
          typeof item.metadata.related_severity === "string" &&
          item.metadata.related_severity === related_severity
      );
    }
    if (from) {
      const fromTs = Date.parse(from);
      if (!Number.isNaN(fromTs)) {
        records = records.filter((item) => Date.parse(item.created_at) >= fromTs);
      }
    }
    if (to) {
      const toTs = Date.parse(to);
      if (!Number.isNaN(toTs)) {
        records = records.filter((item) => Date.parse(item.created_at) <= toTs);
      }
    }
    records.sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
    return paginate(records, 100, limit, offset);
  }

  buildDiscordActionFingerprint({
    action_type,
    discord_user_id,
    guild_id,
    role_id,
    reason_code,
    reason_text
  }) {
    return JSON.stringify({
      action_type: String(action_type || "").trim().toLowerCase(),
      discord_user_id: String(discord_user_id || "").trim(),
      guild_id: guild_id ? String(guild_id).trim() : null,
      role_id: role_id ? String(role_id).trim() : null,
      reason_code: reason_code ? String(reason_code).trim().toUpperCase() : null,
      reason_text: reason_text ? String(reason_text).trim() : null
    });
  }

  buildDiscordCallbackFingerprint({
    status,
    callback_at,
    retry_after_at,
    error_code,
    error_message,
    metadata
  }) {
    return JSON.stringify({
      status: String(status || "").trim().toLowerCase(),
      callback_at: callback_at ? String(callback_at).trim() : null,
      retry_after_at: retry_after_at ? String(retry_after_at).trim() : null,
      error_code: error_code ? String(error_code).trim().toUpperCase() : null,
      error_message: error_message ? String(error_message).trim() : null,
      metadata: isPlainObject(metadata) ? metadata : {}
    });
  }

  createDiscordAction({
    action_id,
    action_type,
    discord_user_id,
    guild_id,
    role_id,
    reason_code = null,
    reason_text = null,
    created_by = "integration-client",
    expires_at = null,
    metadata = {}
  }) {
    const normalizedActionType = String(action_type || "").trim().toLowerCase();
    if (!DISCORD_ACTION_TYPES.has(normalizedActionType)) {
      throw new Error("action_type must be assign_role|remove_role|announce");
    }

    const normalizedDiscordUserId = String(discord_user_id || "").trim();
    if (!normalizedDiscordUserId) {
      throw new Error("discord_user_id is required");
    }

    const normalizedGuildId = guild_id ? String(guild_id).trim() : null;
    const normalizedRoleId = role_id ? String(role_id).trim() : null;
    if (
      (normalizedActionType === "assign_role" || normalizedActionType === "remove_role") &&
      (!normalizedGuildId || !normalizedRoleId)
    ) {
      throw new Error("guild_id and role_id are required for role actions");
    }
    if (normalizedActionType === "announce" && !normalizedGuildId) {
      throw new Error("guild_id is required for announce action");
    }

    if (!isPlainObject(metadata)) {
      throw new Error("metadata must be an object");
    }

    const normalizedExpiresAt = normalizeTimestampOrThrow(expires_at, "expires_at");
    const normalizedReasonCode =
      reason_code && String(reason_code).trim()
        ? String(reason_code).trim().toUpperCase()
        : null;
    const normalizedReasonText =
      reason_text && String(reason_text).trim() ? String(reason_text).trim() : null;
    const normalizedActionId =
      action_id && String(action_id).trim() ? String(action_id).trim() : crypto.randomUUID();

    const fingerprint = this.buildDiscordActionFingerprint({
      action_type: normalizedActionType,
      discord_user_id: normalizedDiscordUserId,
      guild_id: normalizedGuildId,
      role_id: normalizedRoleId,
      reason_code: normalizedReasonCode,
      reason_text: normalizedReasonText
    });

    const existing = this.discordActionsById.get(normalizedActionId);
    if (existing) {
      if (existing.idempotency_fingerprint !== fingerprint) {
        throw new Error("action_id already exists with different payload");
      }
      return { created: false, record: existing };
    }

    const now = nowIso();
    const record = {
      action_id: normalizedActionId,
      action_type: normalizedActionType,
      status: "pending",
      discord_user_id: normalizedDiscordUserId,
      guild_id: normalizedGuildId,
      role_id: normalizedRoleId,
      reason_code: normalizedReasonCode,
      reason_text: normalizedReasonText,
      metadata: {
        ...metadata
      },
      created_by: String(created_by || "integration-client"),
      created_at: now,
      updated_at: now,
      expires_at: normalizedExpiresAt,
      callback_status: null,
      callback_at: null,
      applied_at: null,
      failed_at: null,
      retry_after_at: null,
      attempt_count: 0,
      last_error: null,
      callback_receipts: [],
      idempotency_fingerprint: fingerprint
    };
    this.discordActions.push(record);
    this.discordActionsById.set(record.action_id, record);
    this.addAuditLog({
      action: "DISCORD_ACTION_REQUEST_CREATE",
      actor: record.created_by,
      object_type: "discord_action",
      object_id: record.action_id,
      detail: {
        action_type: record.action_type,
        discord_user_id: record.discord_user_id,
        guild_id: record.guild_id,
        role_id: record.role_id,
        reason_code: record.reason_code
      }
    });
    return { created: true, record };
  }

  applyDiscordActionCallback({
    action_id,
    callback_id,
    status,
    callback_at = null,
    retry_after_at = null,
    error_code = null,
    error_message = null,
    metadata = {},
    processed_by = "integration-client"
  }) {
    const normalizedActionId = String(action_id || "").trim();
    if (!normalizedActionId) {
      throw new Error("action_id is required");
    }
    const record = this.discordActionsById.get(normalizedActionId);
    if (!record) {
      throw new Error("discord action not found");
    }

    const normalizedCallbackId = String(callback_id || "").trim();
    if (!normalizedCallbackId) {
      throw new Error("callback_id is required");
    }

    const normalizedStatus = String(status || "").trim().toLowerCase();
    if (!DISCORD_ACTION_STATUSES.has(normalizedStatus) || normalizedStatus === "pending") {
      throw new Error("status must be applied|failed|retrying|expired");
    }

    if (!isPlainObject(metadata)) {
      throw new Error("metadata must be an object");
    }

    const hasCallbackAtInput =
      callback_at !== undefined && callback_at !== null && String(callback_at).trim() !== "";
    const normalizedCallbackAt = normalizeTimestampOrThrow(callback_at, "callback_at") || nowIso();
    const normalizedRetryAfterAt = normalizeTimestampOrThrow(retry_after_at, "retry_after_at");
    const normalizedErrorCode =
      error_code && String(error_code).trim() ? String(error_code).trim().toUpperCase() : null;
    const normalizedErrorMessage =
      error_message && String(error_message).trim() ? String(error_message).trim() : null;

    const callbackFingerprint = this.buildDiscordCallbackFingerprint({
      status: normalizedStatus,
      callback_at: hasCallbackAtInput ? normalizedCallbackAt : null,
      retry_after_at: normalizedRetryAfterAt,
      error_code: normalizedErrorCode,
      error_message: normalizedErrorMessage,
      metadata
    });

    const existingReceipt = Array.isArray(record.callback_receipts)
      ? record.callback_receipts.find((receipt) => receipt.callback_id === normalizedCallbackId)
      : null;
    if (existingReceipt) {
      if (existingReceipt.idempotency_fingerprint !== callbackFingerprint) {
        throw new Error("callback_id already exists with different payload");
      }
      return { updated: false, record, idempotent: true, receipt: existingReceipt };
    }

    const now = nowIso();
    record.status = normalizedStatus;
    record.callback_status = normalizedStatus;
    record.callback_at = normalizedCallbackAt;
    record.updated_at = now;
    record.attempt_count = Number.isFinite(record.attempt_count) ? record.attempt_count + 1 : 1;

    if (normalizedStatus === "applied") {
      record.applied_at = normalizedCallbackAt;
      record.failed_at = null;
      record.retry_after_at = null;
      record.last_error = null;
    } else {
      record.failed_at = normalizedStatus === "failed" || normalizedStatus === "expired"
        ? normalizedCallbackAt
        : record.failed_at;
      record.retry_after_at = normalizedStatus === "retrying" ? normalizedRetryAfterAt : null;
      record.last_error = {
        code: normalizedErrorCode,
        message: normalizedErrorMessage
      };
    }

    const receipt = {
      callback_id: normalizedCallbackId,
      status: normalizedStatus,
      callback_at: normalizedCallbackAt,
      retry_after_at: normalizedRetryAfterAt,
      error_code: normalizedErrorCode,
      error_message: normalizedErrorMessage,
      metadata: {
        ...metadata
      },
      processed_by: String(processed_by || "integration-client"),
      processed_at: now,
      idempotency_fingerprint: callbackFingerprint
    };
    if (!Array.isArray(record.callback_receipts)) {
      record.callback_receipts = [];
    }
    record.callback_receipts.push(receipt);
    if (record.callback_receipts.length > MAX_DISCORD_CALLBACK_RECEIPTS) {
      record.callback_receipts.splice(
        0,
        record.callback_receipts.length - MAX_DISCORD_CALLBACK_RECEIPTS
      );
    }

    this.addAuditLog({
      action: "DISCORD_ACTION_CALLBACK_APPLY",
      actor: receipt.processed_by,
      object_type: "discord_action",
      object_id: record.action_id,
      detail: {
        callback_id: receipt.callback_id,
        status: receipt.status,
        error_code: receipt.error_code,
        retry_after_at: receipt.retry_after_at
      }
    });

    return { updated: true, record, idempotent: false, receipt };
  }

  listDiscordActions({
    status,
    action_type,
    discord_user_id,
    updated_since,
    limit = 100,
    offset = 0
  } = {}) {
    let records = [...this.discordActions];
    const normalizedStatus = status ? String(status).trim().toLowerCase() : "";
    if (normalizedStatus) {
      if (!DISCORD_ACTION_STATUSES.has(normalizedStatus)) {
        throw new Error("status must be pending|applied|failed|retrying|expired");
      }
      records = records.filter((item) => item.status === normalizedStatus);
    }
    const normalizedActionType = action_type ? String(action_type).trim().toLowerCase() : "";
    if (normalizedActionType) {
      if (!DISCORD_ACTION_TYPES.has(normalizedActionType)) {
        throw new Error("action_type must be assign_role|remove_role|announce");
      }
      records = records.filter((item) => item.action_type === normalizedActionType);
    }
    if (discord_user_id) {
      const normalizedDiscordUserId = String(discord_user_id).trim();
      records = records.filter((item) => item.discord_user_id === normalizedDiscordUserId);
    }
    if (updated_since) {
      const updatedSinceTs = Date.parse(String(updated_since));
      if (Number.isNaN(updatedSinceTs)) {
        throw new Error("updated_since must be an ISO timestamp");
      }
      records = records.filter((item) => Date.parse(item.updated_at) >= updatedSinceTs);
    }
    records.sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at));
    return paginate(records, 100, limit, offset);
  }

  getDetectionQualityMetrics({
    from,
    to,
    team_id,
    user_id,
    sample_limit = 20,
    include_samples = true
  } = {}) {
    const fromTs = from ? Date.parse(from) : null;
    const toTs = to ? Date.parse(to) : null;
    const hasFrom = Number.isFinite(fromTs);
    const hasTo = Number.isFinite(toTs);
    const safeSampleLimit = Number.isFinite(sample_limit)
      ? Math.max(0, Math.floor(sample_limit))
      : 20;
    const includeSamples = include_samples !== false;

    let sessions = Array.from(this.sessionsById.values());
    if (team_id) sessions = sessions.filter((session) => session.team_id === team_id);
    if (user_id) sessions = sessions.filter((session) => session.user_id === user_id);
    if (hasFrom) {
      sessions = sessions.filter((session) => {
        const createdAt = Date.parse(session.created_at);
        return !Number.isNaN(createdAt) && createdAt >= fromTs;
      });
    }
    if (hasTo) {
      sessions = sessions.filter((session) => {
        const createdAt = Date.parse(session.created_at);
        return !Number.isNaN(createdAt) && createdAt <= toTs;
      });
    }
    const sessionIdSet = new Set(sessions.map((session) => session.session_id));

    const actionsBySession = new Map();
    for (const action of this.reviewActions) {
      if (!action || typeof action !== "object") continue;
      if (!action.session_id || !this.sessionsById.has(action.session_id)) continue;
      if (!actionsBySession.has(action.session_id)) {
        actionsBySession.set(action.session_id, []);
      }
      actionsBySession.get(action.session_id).push(action);
    }

    let truePositive = 0;
    let falsePositive = 0;
    let trueNegative = 0;
    let falseNegative = 0;
    let unresolved = 0;
    let predictedPositive = 0;
    let predictedNegative = 0;
    let manualPositive = 0;
    let manualNegative = 0;

    const falsePositiveSessions = [];
    const falseNegativeSessions = [];

    for (const session of sessions) {
      const decision = this.getSessionDecision(session.session_id);
      const predicted = POSITIVE_DECISION_STATUSES.has(decision && decision.status)
        ? "positive"
        : "negative";
      if (predicted === "positive") predictedPositive += 1;
      else predictedNegative += 1;

      const sessionActions = actionsBySession.get(session.session_id) || [];
      const decisiveActions = sessionActions
        .filter((action) => {
          const actionType = action && typeof action.action === "string" ? action.action : "";
          return (
            POSITIVE_REVIEW_ACTIONS.has(actionType) || NEGATIVE_REVIEW_ACTIONS.has(actionType)
          );
        })
        .sort((a, b) => Date.parse(a.created_at) - Date.parse(b.created_at));

      const lastDecisiveAction =
        decisiveActions.length > 0 ? decisiveActions[decisiveActions.length - 1] : null;
      const actual =
        lastDecisiveAction &&
        POSITIVE_REVIEW_ACTIONS.has(lastDecisiveAction.action)
          ? "positive"
          : lastDecisiveAction &&
              NEGATIVE_REVIEW_ACTIONS.has(lastDecisiveAction.action)
            ? "negative"
            : "unresolved";

      if (actual === "positive") manualPositive += 1;
      if (actual === "negative") manualNegative += 1;

      if (actual === "unresolved") {
        unresolved += 1;
        continue;
      }

      const descriptor = {
        session_id: session.session_id,
        user_id: session.user_id,
        team_id: session.team_id,
        predicted,
        decision_status: decision ? decision.status : null,
        decision_reason_code: decision ? decision.reason_code || null : null,
        score: decision && Number.isFinite(decision.score) ? decision.score : null,
        actual,
        manual_action: lastDecisiveAction ? lastDecisiveAction.action : null,
        manual_reason: lastDecisiveAction ? lastDecisiveAction.reason || null : null,
        manual_actor: lastDecisiveAction ? lastDecisiveAction.actor || null : null,
        reviewed_at: normalizeTimestampOrNull(
          lastDecisiveAction ? lastDecisiveAction.created_at : null
        )
      };

      if (predicted === "positive" && actual === "positive") {
        truePositive += 1;
      } else if (predicted === "positive" && actual === "negative") {
        falsePositive += 1;
        if (includeSamples && falsePositiveSessions.length < safeSampleLimit) {
          falsePositiveSessions.push(descriptor);
        }
      } else if (predicted === "negative" && actual === "negative") {
        trueNegative += 1;
      } else if (predicted === "negative" && actual === "positive") {
        falseNegative += 1;
        if (includeSamples && falseNegativeSessions.length < safeSampleLimit) {
          falseNegativeSessions.push(descriptor);
        }
      }
    }

    const reviewed = truePositive + falsePositive + trueNegative + falseNegative;
    const kernelSignalTrust = buildKernelSignalTrustMetrics(this.events, {
      sessionIdSet,
      hasFrom,
      fromTs,
      hasTo,
      toTs,
      sampleLimit: safeSampleLimit
    });
    return {
      generated_at: nowIso(),
      window: {
        from: hasFrom ? new Date(fromTs).toISOString() : null,
        to: hasTo ? new Date(toTs).toISOString() : null
      },
      filters: {
        team_id: team_id || null,
        user_id: user_id || null
      },
      counters: {
        sessions_considered: sessions.length,
        sessions_reviewed: reviewed,
        sessions_unresolved: unresolved,
        predicted_positive: predictedPositive,
        predicted_negative: predictedNegative,
        manual_positive: manualPositive,
        manual_negative: manualNegative
      },
      confusion_matrix: {
        true_positive: truePositive,
        false_positive: falsePositive,
        true_negative: trueNegative,
        false_negative: falseNegative
      },
      rates: {
        precision: safeRatio(truePositive, truePositive + falsePositive),
        recall: safeRatio(truePositive, truePositive + falseNegative),
        false_positive_rate: safeRatio(falsePositive, falsePositive + trueNegative),
        false_negative_rate: safeRatio(falseNegative, falseNegative + truePositive)
      },
      kernel_signal_trust: kernelSignalTrust,
      samples: {
        false_positive: includeSamples ? falsePositiveSessions : [],
        false_negative: includeSamples ? falseNegativeSessions : []
      }
    };
  }

  getDetectionQualityMetricsTimeseries({
    from,
    to,
    team_id,
    user_id,
    max_buckets = 90
  } = {}) {
    const hasFrom = typeof from === "string" && !Number.isNaN(Date.parse(from));
    const hasTo = typeof to === "string" && !Number.isNaN(Date.parse(to));
    const baseSessions = Array.from(this.sessionsById.values()).filter((session) => {
      if (team_id && session.team_id !== team_id) return false;
      if (user_id && session.user_id !== user_id) return false;
      return true;
    });

    const createdAtMsValues = baseSessions
      .map((session) => Date.parse(session.created_at))
      .filter((value) => Number.isFinite(value));

    const nowMs = Date.now();
    const minCreatedAt = createdAtMsValues.length > 0 ? Math.min(...createdAtMsValues) : nowMs;
    const maxCreatedAt = createdAtMsValues.length > 0 ? Math.max(...createdAtMsValues) : nowMs;

    const fromBoundaryMs = hasFrom ? Date.parse(from) : startOfUtcDayMs(minCreatedAt);
    const toBoundaryMs = hasTo ? Date.parse(to) : maxCreatedAt;
    const safeMaxBuckets = clampPositiveInteger(max_buckets, 90, 365);

    if (!Number.isFinite(fromBoundaryMs) || !Number.isFinite(toBoundaryMs)) {
      return {
        generated_at: nowIso(),
        bucket: "day",
        window: { from: null, to: null },
        filters: { team_id: team_id || null, user_id: user_id || null },
        buckets: [],
        total_buckets: 0,
        aggregate: this.getDetectionQualityMetrics({
          team_id,
          user_id
        }),
        has_more_range: false
      };
    }

    if (fromBoundaryMs > toBoundaryMs) {
      return {
        generated_at: nowIso(),
        bucket: "day",
        window: {
          from: new Date(fromBoundaryMs).toISOString(),
          to: new Date(toBoundaryMs).toISOString()
        },
        filters: { team_id: team_id || null, user_id: user_id || null },
        buckets: [],
        total_buckets: 0,
        aggregate: this.getDetectionQualityMetrics({
          from: new Date(fromBoundaryMs).toISOString(),
          to: new Date(toBoundaryMs).toISOString(),
          team_id,
          user_id
        }),
        has_more_range: false
      };
    }

    const buckets = [];
    let cursor = startOfUtcDayMs(fromBoundaryMs);
    const finalCursor = startOfUtcDayMs(toBoundaryMs);
    while (cursor <= finalCursor && buckets.length < safeMaxBuckets) {
      const bucketStartMs = cursor;
      const bucketEndMs = Math.min(cursor + DAY_MS - 1, toBoundaryMs);
      const bucketStartIso = new Date(bucketStartMs).toISOString();
      const bucketEndIso = new Date(bucketEndMs).toISOString();
      const summary = this.getDetectionQualityMetrics({
        from: bucketStartIso,
        to: bucketEndIso,
        team_id,
        user_id,
        include_samples: false
      });
      buckets.push({
        label: bucketStartIso.slice(0, 10),
        bucket_start: bucketStartIso,
        bucket_end: bucketEndIso,
        counters: summary.counters,
        confusion_matrix: summary.confusion_matrix,
        rates: summary.rates,
        kernel_signal_trust: {
          counters: summary.kernel_signal_trust.counters,
          rates: summary.kernel_signal_trust.rates,
          top_failed_rules: summary.kernel_signal_trust.top_failed_rules
        }
      });
      cursor += DAY_MS;
    }

    const aggregate = this.getDetectionQualityMetrics({
      from: new Date(fromBoundaryMs).toISOString(),
      to: new Date(toBoundaryMs).toISOString(),
      team_id,
      user_id
    });

    return {
      generated_at: nowIso(),
      bucket: "day",
      window: {
        from: new Date(fromBoundaryMs).toISOString(),
        to: new Date(toBoundaryMs).toISOString()
      },
      filters: {
        team_id: team_id || null,
        user_id: user_id || null
      },
      buckets,
      total_buckets: buckets.length,
      aggregate,
      has_more_range: cursor <= finalCursor
    };
  }

  getGateFailureCounters({ contest_from, contest_to, now } = {}) {
    const nowMs = Number.isFinite(Number(now)) ? Number(now) : Date.now();
    const dayFromMs = nowMs - DAY_MS;
    const weekFromMs = nowMs - DAY_MS * 7;
    const contestFromMs =
      typeof contest_from === "string" && !Number.isNaN(Date.parse(contest_from))
        ? Date.parse(contest_from)
        : null;
    const contestToMs =
      typeof contest_to === "string" && !Number.isNaN(Date.parse(contest_to))
        ? Date.parse(contest_to)
        : nowMs;

    const gateRecords = this.auditLogs.filter((record) => {
      if (!isPlainObject(record)) return false;
      if (!GATE_FAILURE_ACTIONS.has(String(record.action || ""))) return false;
      const atMs = Date.parse(String(record.at || ""));
      return Number.isFinite(atMs);
    });

    const selectWindow = (fromMs, toMs) =>
      gateRecords.filter((record) => {
        const atMs = Date.parse(record.at);
        if (Number.isFinite(fromMs) && atMs < fromMs) return false;
        if (Number.isFinite(toMs) && atMs > toMs) return false;
        return true;
      });

    const resolveUserIdFromSessionId = (sessionId) => {
      const session = this.getSession(sessionId);
      return session && typeof session.user_id === "string" ? session.user_id : null;
    };

    const dayRecords = selectWindow(dayFromMs, nowMs);
    const weekRecords = selectWindow(weekFromMs, nowMs);
    const contestRecords = selectWindow(contestFromMs, contestToMs);

    return {
      generated_at: nowIso(),
      windows: {
        day: {
          from: new Date(dayFromMs).toISOString(),
          to: new Date(nowMs).toISOString()
        },
        week: {
          from: new Date(weekFromMs).toISOString(),
          to: new Date(nowMs).toISOString()
        },
        contest: {
          from: Number.isFinite(contestFromMs) ? new Date(contestFromMs).toISOString() : null,
          to: Number.isFinite(contestToMs) ? new Date(contestToMs).toISOString() : null
        }
      },
      counters: {
        day: summarizeGateFailures(dayRecords, resolveUserIdFromSessionId),
        week: summarizeGateFailures(weekRecords, resolveUserIdFromSessionId),
        contest: summarizeGateFailures(contestRecords, resolveUserIdFromSessionId)
      }
    };
  }

  addEventRejections(rejections, { maxEntries = MAX_EVENT_REJECTION_RECORDS } = {}) {
    if (!Array.isArray(rejections) || rejections.length === 0) {
      return { added: 0, total: this.eventRejections.length };
    }
    let added = 0;
    for (const item of rejections) {
      if (!isPlainObject(item)) continue;
      const normalized = {
        received_at: normalizeTimestampOrNull(item.received_at) || nowIso(),
        event_type: typeof item.event_type === "string" ? item.event_type : null,
        index: Number.isFinite(Number(item.index)) ? Math.floor(Number(item.index)) : null,
        error: typeof item.error === "string" ? item.error : "unknown rejection",
        event: isPlainObject(item.event) ? item.event : null
      };
      this.eventRejections.push(normalized);
      added += 1;
    }
    const limit = clampPositiveInteger(maxEntries, MAX_EVENT_REJECTION_RECORDS, 200000);
    if (this.eventRejections.length > limit) {
      this.eventRejections = this.eventRejections.slice(this.eventRejections.length - limit);
    }
    return { added, total: this.eventRejections.length };
  }

  purgeSubmissionProofReplayCaches({ nowSec = nowEpochSec(), maxEntries = MAX_SUBMISSION_PROOF_REPLAY_ENTRIES } = {}) {
    const nowValue = Number.isFinite(Number(nowSec)) ? Math.floor(Number(nowSec)) : nowEpochSec();
    for (const [key, expiresAtSec] of this.submissionProofNonceCache.entries()) {
      if (!Number.isFinite(expiresAtSec) || expiresAtSec <= nowValue) {
        this.submissionProofNonceCache.delete(key);
      }
    }
    for (const [key, expiresAtSec] of this.submissionProofJtiCache.entries()) {
      if (!Number.isFinite(expiresAtSec) || expiresAtSec <= nowValue) {
        this.submissionProofJtiCache.delete(key);
      }
    }
    const limit = clampPositiveInteger(
      maxEntries,
      MAX_SUBMISSION_PROOF_REPLAY_ENTRIES,
      200000
    );
    while (this.submissionProofNonceCache.size > limit) {
      const firstKey = this.submissionProofNonceCache.keys().next().value;
      if (!firstKey) break;
      this.submissionProofNonceCache.delete(firstKey);
    }
    while (this.submissionProofJtiCache.size > limit) {
      const firstKey = this.submissionProofJtiCache.keys().next().value;
      if (!firstKey) break;
      this.submissionProofJtiCache.delete(firstKey);
    }
  }

  consumeSubmissionProofReplayEntry({
    nonce,
    jti,
    expSec = 0,
    nonceTtlSec = 120,
    nowSec = nowEpochSec(),
    maxEntries = MAX_SUBMISSION_PROOF_REPLAY_ENTRIES
  } = {}) {
    const nonceKey = typeof nonce === "string" ? nonce.trim() : "";
    const jtiKey = typeof jti === "string" ? jti.trim() : "";
    if (!nonceKey || !jtiKey) {
      return { accepted: false, code: "INVALID_REPLAY_KEY" };
    }

    this.purgeSubmissionProofReplayCaches({ nowSec, maxEntries });
    if (this.submissionProofNonceCache.has(nonceKey) || this.submissionProofJtiCache.has(jtiKey)) {
      return { accepted: false, code: "REPLAY_DETECTED" };
    }

    const nowValue = Number.isFinite(Number(nowSec)) ? Math.floor(Number(nowSec)) : nowEpochSec();
    const expValue = Number.isFinite(Number(expSec)) ? Math.floor(Number(expSec)) : 0;
    const ttl = clampPositiveInteger(nonceTtlSec, 120, 3600);
    const expiry = Math.max(nowValue + ttl, expValue);
    this.submissionProofNonceCache.set(nonceKey, expiry);
    this.submissionProofJtiCache.set(jtiKey, expiry);
    this.purgeSubmissionProofReplayCaches({ nowSec: nowValue, maxEntries });
    return { accepted: true, code: null, expires_at_epoch_sec: expiry };
  }

  addAuditLog({ action, actor, object_type = null, object_id = null, detail = {} }) {
    const record = {
      audit_id: crypto.randomUUID(),
      at: nowIso(),
      actor,
      action,
      object_type,
      object_id,
      detail
    };
    this.auditLogs.push(record);
    this.archiveRecord("audit_log", record);
    return record;
  }

  listAuditLogs({ actor, action, from, to, limit = 200, offset = 0 } = {}) {
    let records = [...this.auditLogs];
    if (actor) records = records.filter((item) => item.actor === actor);
    if (action) records = records.filter((item) => item.action === action);
    if (from) {
      const fromTs = Date.parse(from);
      if (!Number.isNaN(fromTs)) {
        records = records.filter((item) => Date.parse(item.at) >= fromTs);
      }
    }
    if (to) {
      const toTs = Date.parse(to);
      if (!Number.isNaN(toTs)) {
        records = records.filter((item) => Date.parse(item.at) <= toTs);
      }
    }
    records.sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
    const safeLimit = Number.isFinite(limit) ? Math.max(1, Math.floor(limit)) : 200;
    const safeOffset = Number.isFinite(offset) ? Math.max(0, Math.floor(offset)) : 0;
    const total = records.length;
    const items = records.slice(safeOffset, safeOffset + safeLimit);
    return {
      items,
      page: {
        total,
        offset: safeOffset,
        limit: safeLimit,
        has_more: safeOffset + safeLimit < total,
        next_offset: safeOffset + safeLimit < total ? safeOffset + safeLimit : null
      }
    };
  }

  transact(executor) {
    if (typeof executor !== "function") {
      throw new Error("executor must be a function");
    }
    const runtimeCopy = this.toJSON();
    try {
      const result = executor();
      if (result && typeof result.then === "function") {
        throw new Error("state.transact does not support async callbacks");
      }
      return result;
    } catch (error) {
      const restored = RuntimeState.fromJSON(runtimeCopy, this.config || {});
      for (const key of Object.keys(restored)) {
        this[key] = restored[key];
      }
      throw error;
    }
  }

  toJSON() {
    return {
      config: this.config,
      usersByCredential: Array.from(this.usersByCredential.entries()),
      usersById: Array.from(this.usersById.entries()),
      teamsById: Array.from(this.teamsById.entries()),
      clientByUserDevice: Array.from(this.clientByUserDevice.entries()),
      clientsById: Array.from(this.clientsById.entries()),
      sessionsById: Array.from(this.sessionsById.entries()),
      activeSessionByUser: Array.from(this.activeSessionByUser.entries()),
      sessionByClient: Array.from(this.sessionByClient.entries()),
      refreshTokens: Array.from(this.refreshTokens.entries()),
      banUsers: Array.from(this.banUsers.entries()),
      banTeams: Array.from(this.banTeams.entries()),
      banSessions: Array.from(this.banSessions.entries()),
      banRecords: this.banRecords,
      revokedJti: Array.from(this.revokedJti.entries()),
      activeJtiByUser: Array.from(this.activeJtiByUser.entries()),
      heartbeatByClient: Array.from(this.heartbeatByClient.entries()),
      latestUploadStatusBySession: Array.from(this.latestUploadStatusBySession.entries()),
      sessionArchiveGroupById: Array.from(this.sessionArchiveGroupById.entries()),
      archiveWriteFailures: this.archiveWriteFailures,
      events: this.events,
      sessionDecisions: Array.from(this.sessionDecisions.entries()),
      reviewNotes: this.reviewNotes,
      reviewActions: this.reviewActions,
      discordActions: this.discordActions,
      discordIdentityByUserId: Array.from(this.discordIdentityByUserId.entries()),
      userIdByDiscordUserId: Array.from(this.userIdByDiscordUserId.entries()),
      eventRejections: this.eventRejections,
      submissionProofNonceCache: Array.from(this.submissionProofNonceCache.entries()),
      submissionProofJtiCache: Array.from(this.submissionProofJtiCache.entries()),
      auditLogs: this.auditLogs
    };
  }

  static fromJSON(serializedState, config = {}) {
    const state = new RuntimeState({
      ...serializedState.config,
      ...config
    });
    state.usersByCredential = new Map(serializedState.usersByCredential || []);
    state.usersById = new Map(serializedState.usersById || []);
    state.teamsById = new Map(serializedState.teamsById || []);
    state.clientByUserDevice = new Map(serializedState.clientByUserDevice || []);
    state.clientsById = new Map(serializedState.clientsById || []);
    state.sessionsById = new Map(serializedState.sessionsById || []);
    state.activeSessionByUser = new Map(serializedState.activeSessionByUser || []);
    state.sessionByClient = new Map(serializedState.sessionByClient || []);
    state.refreshTokens = new Map(serializedState.refreshTokens || []);
    state.banUsers = new Map(serializedState.banUsers || []);
    state.banTeams = new Map(serializedState.banTeams || []);
    state.banSessions = new Map(serializedState.banSessions || []);
    state.banRecords = Array.isArray(serializedState.banRecords) ? serializedState.banRecords : [];
    state.revokedJti = new Map(serializedState.revokedJti || []);
    state.activeJtiByUser = new Map(serializedState.activeJtiByUser || []);
    state.heartbeatByClient = new Map(serializedState.heartbeatByClient || []);
    state.latestUploadStatusBySession = new Map(serializedState.latestUploadStatusBySession || []);
    state.sessionArchiveGroupById = new Map(serializedState.sessionArchiveGroupById || []);
    state.archiveWriteFailures = Array.isArray(serializedState.archiveWriteFailures)
      ? serializedState.archiveWriteFailures
      : [];
    if (state.sessionArchiveGroupById.size === 0 && state.sessionsById.size > 0) {
      const orderedSessions = Array.from(state.sessionsById.values()).sort(
        (a, b) => Date.parse(a.created_at || "") - Date.parse(b.created_at || "")
      );
      orderedSessions.forEach((session, index) => {
        const existing = Number(session.archive_group_index);
        const groupIndex =
          Number.isFinite(existing) && existing > 0
            ? Math.floor(existing)
            : Math.ceil((index + 1) / state.archiveSessionGroupSize);
        session.archive_group_index = groupIndex;
        state.sessionArchiveGroupById.set(session.session_id, groupIndex);
      });
    }
    state.events = Array.isArray(serializedState.events) ? serializedState.events : [];
    if (state.latestUploadStatusBySession.size === 0 && state.events.length > 0) {
      for (const event of state.events) {
        if (!isPlainObject(event) || event.event_type !== "CLIENT_UPLOAD_STATUS") continue;
        const sessionId =
          typeof event.session_id === "string" ? event.session_id.trim() : "";
        if (!sessionId) continue;
        const evidence = isPlainObject(event.evidence) ? event.evidence : {};
        state.latestUploadStatusBySession.set(sessionId, {
          status:
            typeof evidence.status === "string" && evidence.status.trim()
              ? evidence.status.trim().toLowerCase()
              : null,
          timestamp:
            typeof event.timestamp === "string" && event.timestamp.trim()
              ? event.timestamp
              : null,
          received_at:
            typeof event.received_at === "string" && event.received_at.trim()
              ? event.received_at
              : null,
          uploaded_events: asFiniteNumberOrNull(evidence.uploaded_events),
          pending_events: asFiniteNumberOrNull(evidence.pending_events),
          failed_events: asFiniteNumberOrNull(evidence.failed_events),
          attempted_batches: asFiniteNumberOrNull(evidence.attempted_batches),
          auth_recovered_batches: asFiniteNumberOrNull(evidence.auth_recovered_batches),
          auth_refresh_failed_batches: asFiniteNumberOrNull(evidence.auth_refresh_failed_batches)
        });
      }
    }
    state.sessionDecisions = new Map(serializedState.sessionDecisions || []);
    state.reviewNotes = Array.isArray(serializedState.reviewNotes) ? serializedState.reviewNotes : [];
    state.reviewActions = Array.isArray(serializedState.reviewActions) ? serializedState.reviewActions : [];
    state.discordActions = Array.isArray(serializedState.discordActions) ? serializedState.discordActions : [];
    state.discordActionsById = new Map(
      state.discordActions
        .filter((item) => item && typeof item.action_id === "string" && item.action_id.trim())
        .map((item) => [item.action_id, item])
    );
    state.discordIdentityByUserId = new Map(serializedState.discordIdentityByUserId || []);
    state.userIdByDiscordUserId = new Map(serializedState.userIdByDiscordUserId || []);
    state.eventRejections = Array.isArray(serializedState.eventRejections) ? serializedState.eventRejections : [];
    state.submissionProofNonceCache = new Map(serializedState.submissionProofNonceCache || []);
    state.submissionProofJtiCache = new Map(serializedState.submissionProofJtiCache || []);
    state.auditLogs = Array.isArray(serializedState.auditLogs) ? serializedState.auditLogs : [];
    return state;
  }
}

module.exports = {
  RuntimeState
};
