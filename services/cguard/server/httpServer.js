const http = require("node:http");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const zlib = require("node:zlib");

const { createStateAdapter } = require("./state/stateFactory");
const { createIngestionPipeline, InMemoryEventStore } = require("./ingestionPipeline");
const { scoreEvents, DEFAULT_EVENT_WEIGHTS } = require("./scoringEngine");
const {
  issueAttestationToken,
  verifyAttestationToken,
  issueKernelBindingToken,
  issueAdminToken,
  verifyAdminToken
} = require("./tokenService");
const { evaluateClientVersion, buildVersionPolicyEvent } = require("./versionPolicy");
const { logStructured } = require("./structuredLogger");
const {
  buildInvestigationViewModel,
  selectEvidenceDetail
} = require("../admin/investigationView");

function json(res, statusCode, payload, headers = {}) {
  res.writeHead(statusCode, {
    "content-type": "application/json",
    ...headers
  });
  res.end(JSON.stringify(payload));
}

function textDownload(res, statusCode, body, { contentType, filename } = {}) {
  const headers = {
    "content-type": contentType || "text/plain; charset=utf-8"
  };
  if (filename) {
    headers["content-disposition"] = `attachment; filename="${filename.replace(/"/g, "")}"`;
  }
  res.writeHead(statusCode, headers);
  res.end(body);
}

function fileDownload(res, filePath, { contentType, filename } = {}) {
  const headers = {
    "content-type": contentType || "application/octet-stream"
  };
  if (filename) {
    headers["content-disposition"] = `attachment; filename="${filename.replace(/"/g, "")}"`;
  }
  const stat = fs.statSync(filePath);
  headers["content-length"] = String(stat.size);
  res.writeHead(200, headers);
  const stream = fs.createReadStream(filePath);
  stream.on("close", () => {
    fs.rm(filePath, { force: true }, () => {});
  });
  stream.on("error", () => {
    fs.rm(filePath, { force: true }, () => {});
    if (!res.headersSent) {
      json(res, 500, { code: "EXPORT_STREAM_FAILED", message: "failed to stream export file" });
    } else {
      res.destroy();
    }
  });
  stream.pipe(res);
}

function csvEscape(value) {
  if (value === undefined || value === null) return "";
  const raw = typeof value === "string" ? value : JSON.stringify(value);
  let normalized = raw === undefined ? "" : String(raw);
  if (/^[=+\-@\t\r]/.test(normalized)) {
    normalized = `'${normalized}`;
  }
  if (/[",\r\n]/.test(normalized)) {
    return `"${normalized.replace(/"/g, '""')}"`;
  }
  return normalized;
}

function toCsv(headers, rows) {
  const lines = [headers.map(csvEscape).join(",")];
  for (const row of rows) {
    lines.push(headers.map((header) => csvEscape(row[header])).join(","));
  }
  return `${lines.join("\r\n")}\r\n`;
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let value = 0xffffffff;
  for (const byte of buffer) {
    value = CRC32_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
}

function toDosDateTime(date = new Date()) {
  const year = Math.max(1980, date.getFullYear());
  const dosTime =
    (date.getHours() << 11) |
    (date.getMinutes() << 5) |
    Math.floor(date.getSeconds() / 2);
  const dosDate = ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
  return { dosTime, dosDate };
}

function writeZipEntry(fd, centralDirectory, name, content, date = new Date()) {
  const source = Buffer.isBuffer(content) ? content : Buffer.from(String(content), "utf8");
  const compressed = zlib.deflateRawSync(source, { level: 6 });
  const nameBuffer = Buffer.from(name.replace(/\\/g, "/"), "utf8");
  const checksum = crc32(source);
  const { dosTime, dosDate } = toDosDateTime(date);
  const localOffset = fs.fstatSync(fd).size;

  const localHeader = Buffer.alloc(30);
  localHeader.writeUInt32LE(0x04034b50, 0);
  localHeader.writeUInt16LE(20, 4);
  localHeader.writeUInt16LE(0x0800, 6);
  localHeader.writeUInt16LE(8, 8);
  localHeader.writeUInt16LE(dosTime, 10);
  localHeader.writeUInt16LE(dosDate, 12);
  localHeader.writeUInt32LE(checksum, 14);
  localHeader.writeUInt32LE(compressed.length, 18);
  localHeader.writeUInt32LE(source.length, 22);
  localHeader.writeUInt16LE(nameBuffer.length, 26);
  localHeader.writeUInt16LE(0, 28);
  fs.writeSync(fd, localHeader);
  fs.writeSync(fd, nameBuffer);
  fs.writeSync(fd, compressed);

  const centralHeader = Buffer.alloc(46);
  centralHeader.writeUInt32LE(0x02014b50, 0);
  centralHeader.writeUInt16LE(20, 4);
  centralHeader.writeUInt16LE(20, 6);
  centralHeader.writeUInt16LE(0x0800, 8);
  centralHeader.writeUInt16LE(8, 10);
  centralHeader.writeUInt16LE(dosTime, 12);
  centralHeader.writeUInt16LE(dosDate, 14);
  centralHeader.writeUInt32LE(checksum, 16);
  centralHeader.writeUInt32LE(compressed.length, 20);
  centralHeader.writeUInt32LE(source.length, 24);
  centralHeader.writeUInt16LE(nameBuffer.length, 28);
  centralHeader.writeUInt16LE(0, 30);
  centralHeader.writeUInt16LE(0, 32);
  centralHeader.writeUInt16LE(0, 34);
  centralHeader.writeUInt16LE(0, 36);
  centralHeader.writeUInt32LE(0, 38);
  centralHeader.writeUInt32LE(localOffset, 42);
  centralDirectory.push(Buffer.concat([centralHeader, nameBuffer]));
}

function finishZip(fd, centralDirectory) {
  const centralOffset = fs.fstatSync(fd).size;
  for (const entry of centralDirectory) {
    fs.writeSync(fd, entry);
  }
  const centralSize = fs.fstatSync(fd).size - centralOffset;
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(centralDirectory.length, 8);
  end.writeUInt16LE(centralDirectory.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(centralOffset, 16);
  end.writeUInt16LE(0, 20);
  fs.writeSync(fd, end);
}

function listFilesRecursive(rootDir) {
  if (!rootDir || !fs.existsSync(rootDir)) return [];
  const files = [];
  const stack = [rootDir];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current) continue;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile()) {
        files.push(fullPath);
      }
    }
  }
  return files.sort((a, b) => a.localeCompare(b));
}

function exportTimestampForFilename(date = new Date()) {
  return date.toISOString().replace(/[:.]/g, "-");
}

function parseBearer(req) {
  const value = req.headers.authorization;
  if (!value) return null;
  const matched = /^Bearer\s+(.+)$/i.exec(value);
  if (!matched) return null;
  return matched[1];
}

function parseVerifyToken(req) {
  return parseBearer(req) || req.headers["x-attest-token"] || null;
}

const ADMIN_ROLE_PERMISSIONS = Object.freeze({
  viewer: new Set(["read"]),
  reviewer: new Set(["read", "review", "audit"]),
  enforcer: new Set(["read", "review", "audit", "enforce"]),
  admin: new Set(["read", "review", "audit", "enforce", "admin"])
});

const DEFAULT_ADMIN_USERS = Object.freeze([
  { username: "admin-viewer", password: "admin-viewer", role: "viewer" },
  { username: "admin-reviewer", password: "admin-reviewer", role: "reviewer" },
  { username: "admin-enforcer", password: "admin-enforcer", role: "enforcer" }
]);

const INTEGRATION_REASON_CODE_DEFINITIONS = Object.freeze({
  CLIENT_AGENT_REQUIRED: "antiLLM client agent is not running",
  KERNEL_CONNECTION_REQUIRED: "kernel bridge is disconnected or kernel driver is not loaded",
  HEARTBEAT_STALE: "client heartbeat is stale",
  BANNED_USER: "user is blocked by policy",
  BANNED_TEAM: "team is blocked by policy",
  BANNED_SESSION: "session is blocked by policy",
  CLIENT_VERSION_INVALID: "client version is invalid",
  CLIENT_VERSION_UNSUPPORTED: "client version is unsupported",
  CLIENT_VERSION_DEPRECATED: "client version is deprecated",
  SESSION_INTEGRITY_FAILURE: "session integrity check failed",
  KERNEL_REQUIRED_SIGNAL_MISSING: "required kernel signal is missing",
  KERNEL_SIGNAL_RATE_TOO_LOW: "kernel signal rate is below required threshold",
  KERNEL_INTEGRITY_WARN_BLOCK: "kernel integrity warning reached blocking policy",
  KERNEL_INTEGRITY_WARN: "kernel integrity warning detected",
  RISK_SCORE_BLOCK: "risk score reached blocking threshold",
  HIGH_RISK_SCORE: "risk score reached warning threshold",
  CLIENT_NONCOMPLIANT: "client reported noncompliant state",
  DISCORD_IDENTITY_LOGOUT_DETECTED: "discord identity appears logged out in client telemetry",
  DISCORD_IDENTITY_REQUIRED: "discord identity must be linked before participation",
  DISCORD_IDENTITY_ACCOUNT_MISMATCH:
    "discord identity hint does not match server-linked discord account",
  DISCORD_CLIENT_UNAVAILABLE: "discord client/rpc hint is unavailable",
  CLI_USAGE_DETECTED: "cli usage indicators detected above configured confidence threshold",
  CLI_USAGE_RESTRICTED: "cli usage indicators triggered restricted participation policy",
  CLI_USAGE_BLOCKED: "cli usage indicators triggered immediate block policy",
  INTEGRATION_SUBMISSION_PROOF_INVALID:
    "submission proof token payload is invalid",
  INTEGRATION_SUBMISSION_PROOF_NONCE_MISMATCH:
    "submission proof nonce does not match token binding",
  INTEGRATION_SUBMISSION_PROOF_BINDING_MISMATCH:
    "submission proof binding does not match expected session/client/device fields",
  INTEGRATION_SUBMISSION_PROOF_REPLAY_DETECTED:
    "submission proof token or nonce was already consumed",
  INTEGRATION_SOURCE_CONSISTENCY_MISMATCH:
    "submission source does not match latest heartbeat source",
  INTEGRATION_SOURCE_CONSISTENCY_RESTRICTED:
    "submission source mismatch triggered restricted policy",
  INTEGRATION_SOURCE_CONSISTENCY_BLOCKED:
    "submission source mismatch triggered block policy",
  DISCORD_MULTI_DEVICE_CONFLICT:
    "same discord identity is active on multiple concurrent sessions",
  DISCORD_MULTI_DEVICE_CONFLICT_RESTRICTED:
    "same discord identity multi-device conflict triggered restricted policy",
  DISCORD_MULTI_DEVICE_CONFLICT_BLOCKED:
    "same discord identity multi-device conflict triggered block policy",
  DISCORD_DEVICE_SWITCH_DETECTED:
    "discord identity switched across different devices within the guarded transition window",
  DISCORD_DEVICE_SWITCH_RESTRICTED:
    "discord identity device switch triggered restricted transition policy",
  DISCORD_DEVICE_SWITCH_BLOCKED:
    "discord identity device switch triggered block transition policy",
  DISCORD_RELINK_RACE_DETECTED:
    "discord identity relink race detected during active protected session",
  DISCORD_RELINK_RACE_RESTRICTED:
    "discord identity relink race triggered restricted transition policy",
  DISCORD_RELINK_RACE_BLOCKED:
    "discord identity relink race triggered block transition policy",
  DISCORD_IDENTITY_OFFLINE_STALE:
    "session heartbeat is stale while discord identity is linked",
  GATE_POLICY_PASS: "participant gate checks are healthy",
  GATE_POLICY_FAIL: "participant gate check failed",
  GATE_POLICY_OFFLINE: "session moved to offline state and role access should be removed"
});
const INTEGRATION_REASON_CODE_SET = new Set(Object.keys(INTEGRATION_REASON_CODE_DEFINITIONS));
const DISCORD_IDENTITY_SOURCES = new Set(["oauth", "sdk_hint", "unknown"]);
const DISCORD_LINK_STATES = new Set(["linked", "unlinked", "unknown", "error"]);
const DISCORD_IDENTITY_POLICY_ACTIONS = new Set(["warn", "restricted", "blocked"]);
const CLI_ENFORCEMENT_ACTIONS = new Set(["off", "warn", "restricted", "blocked"]);
const MULTI_DEVICE_POLICY_ACTIONS = new Set(["off", "warn", "restricted", "blocked"]);
const SOURCE_CONSISTENCY_POLICY_ACTIONS = new Set(["off", "warn", "restricted", "blocked"]);
const DEVICE_BINDING_MODES = new Set(["static", "dpapi", "unknown"]);
const DEVICE_BINDING_STATES = new Set(["ready", "fallback", "error", "unknown"]);
const CLI_OVERRIDE_REVIEW_ACTIONS = new Set(["clear_with_reason", "mark_as_reviewed"]);
const HIGH_IMPACT_RUNTIME_POLICY_FIELDS = new Set([
  "require_discord_linked",
  "require_discord_linked_action",
  "require_discord_linked_grace_sec",
  "cli_detection_action",
  "cli_confidence_threshold",
  "cli_min_evidence_count",
  "cli_enforcement_cooldown_sec",
  "cli_override_window_sec"
]);
const DEFAULT_LLM_CLI_HINTS = Object.freeze([
  "codex",
  "@openai/codex",
  "openai",
  "cursor-agent",
  "cursor",
  "aider",
  "ollama",
  "chatgpt-cli",
  "claude-code",
  "@anthropic-ai/claude-code",
  "claude",
  "gemini-cli",
  "@google/gemini-cli",
  "gemini"
]);
const BROWSER_PROCESS_NAMES = new Set([
  "chrome.exe",
  "msedge.exe",
  "firefox.exe",
  "brave.exe",
  "opera.exe",
  "vivaldi.exe",
  "iexplore.exe"
]);
const HIGH_RISK_LLM_NETWORK_DOMAINS = Object.freeze([
  "play.googleapis.com"
]);
const CANONICAL_LLM_CLI_HINTS = new Set([
  "codex",
  "cursor-agent",
  "cursor",
  "aider",
  "ollama",
  "chatgpt-cli",
  "claude-code",
  "claude",
  "gemini-cli",
  "gemini"
]);

function parseAdminToken(req) {
  return parseBearer(req) || req.headers["x-admin-token"] || null;
}

function parseIntegrationToken(req) {
  return parseBearer(req) || req.headers["x-integration-token"] || null;
}

function normalizeDiscordCallbackSignature(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim().toLowerCase();
  const normalized = trimmed.startsWith("sha256=") ? trimmed.slice(7) : trimmed;
  return /^[0-9a-f]{64}$/.test(normalized) ? normalized : null;
}

function normalizeDiscordCallbackNonce(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (!/^[a-zA-Z0-9._:-]{8,128}$/.test(trimmed)) return null;
  return trimmed;
}

function normalizeSubmissionProofNonce(value) {
  return normalizeDiscordCallbackNonce(value);
}

function parseDiscordCallbackTimestampSec(value) {
  if (typeof value !== "string" && typeof value !== "number") return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return Math.floor(parsed);
}

function buildDiscordCallbackSigningPayload({
  timestampSec,
  nonce,
  method,
  pathname,
  body
}) {
  return `${timestampSec}\n${nonce}\n${String(method || "").toUpperCase()}\n${pathname}\n${body || ""}`;
}

function computeDiscordCallbackSignature({
  signingSecret,
  timestampSec,
  nonce,
  method,
  pathname,
  body
}) {
  if (typeof signingSecret !== "string" || signingSecret.length === 0) return null;
  const payload = buildDiscordCallbackSigningPayload({
    timestampSec,
    nonce,
    method,
    pathname,
    body
  });
  return crypto.createHmac("sha256", signingSecret).update(payload).digest("hex");
}

function verifyDiscordCallbackHeaders({
  req,
  pathname,
  rawBody,
  config,
  nonceCache
}) {
  const signatureRequired = config.integrationApi.discordCallbackRequireSignature === true;
  const signingSecret =
    typeof config.integrationApi.discordCallbackSigningSecret === "string"
      ? config.integrationApi.discordCallbackSigningSecret
      : "";
  if (!signatureRequired) {
    return { ok: true, mode: "disabled" };
  }
  if (!signingSecret) {
    return {
      ok: false,
      code: "INTEGRATION_CALLBACK_MISCONFIG",
      message: "discord callback signature verification is enabled but signing secret is missing",
      statusCode: 500
    };
  }

  const providedSignature = normalizeDiscordCallbackSignature(req.headers["x-signature"]);
  const nonce = normalizeDiscordCallbackNonce(req.headers["x-nonce"]);
  const timestampSec = parseDiscordCallbackTimestampSec(req.headers["x-timestamp"]);
  if (!providedSignature || !nonce || !timestampSec) {
    return {
      ok: false,
      code: "INTEGRATION_CALLBACK_UNAUTHORIZED",
      message: "missing or invalid callback signature headers",
      statusCode: 401
    };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const toleranceSec = normalizePositiveInteger(
    config.integrationApi.discordCallbackTimestampToleranceSec,
    300
  );
  if (Math.abs(nowSec - timestampSec) > toleranceSec) {
    return {
      ok: false,
      code: "INTEGRATION_CALLBACK_STALE",
      message: "callback timestamp outside allowed window",
      statusCode: 401
    };
  }

  const nonceTtlSec = normalizePositiveInteger(config.integrationApi.discordCallbackNonceTtlSec, 600);
  for (const [key, expiresAtSec] of nonceCache.entries()) {
    if (!Number.isFinite(expiresAtSec) || expiresAtSec <= nowSec) {
      nonceCache.delete(key);
    }
  }
  if (nonceCache.has(nonce)) {
    return {
      ok: false,
      code: "INTEGRATION_CALLBACK_REPLAY_DETECTED",
      message: "callback nonce already used",
      statusCode: 409
    };
  }

  const expectedSignature = computeDiscordCallbackSignature({
    signingSecret,
    timestampSec,
    nonce,
    method: req.method,
    pathname,
    body: rawBody
  });
  if (!expectedSignature) {
    return {
      ok: false,
      code: "INTEGRATION_CALLBACK_MISCONFIG",
      message: "callback signature verifier is not configured",
      statusCode: 500
    };
  }

  const providedBuffer = Buffer.from(providedSignature, "hex");
  const expectedBuffer = Buffer.from(expectedSignature, "hex");
  const matches =
    providedBuffer.length === expectedBuffer.length &&
    crypto.timingSafeEqual(providedBuffer, expectedBuffer);
  if (!matches) {
    return {
      ok: false,
      code: "INTEGRATION_CALLBACK_UNAUTHORIZED",
      message: "callback signature mismatch",
      statusCode: 401
    };
  }

  nonceCache.set(nonce, nowSec + nonceTtlSec);
  const maxNonceEntries = normalizePositiveInteger(
    config.integrationApi.maxDiscordCallbackNonceEntries,
    20000
  );
  while (nonceCache.size > maxNonceEntries) {
    const firstKey = nonceCache.keys().next().value;
    if (!firstKey) break;
    nonceCache.delete(firstKey);
  }
  return { ok: true, mode: "verified", nonce, timestampSec };
}

function parseIntegrationContext(req, config) {
  const actorHeader = req.headers["x-integration-client"];
  const actor =
    typeof actorHeader === "string" && actorHeader.trim().length > 0
      ? actorHeader.trim()
      : "integration-client";

  if (!config.integrationApi || config.integrationApi.enabled !== true) {
    return {
      ok: false,
      actor,
      statusCode: 404,
      code: "NOT_FOUND",
      message: "integration api disabled"
    };
  }

  const token = parseIntegrationToken(req);
  if (!token) {
    return {
      ok: false,
      actor,
      statusCode: 401,
      code: "INTEGRATION_UNAUTHORIZED",
      message: "missing integration token"
    };
  }
  if (token !== config.integrationApi.token) {
    return {
      ok: false,
      actor,
      statusCode: 403,
      code: "INTEGRATION_FORBIDDEN",
      message: "invalid integration token"
    };
  }

  if (config.integrationApi.apiKey) {
    const apiKey = req.headers["x-integration-key"];
    if (apiKey !== config.integrationApi.apiKey) {
      return {
        ok: false,
        actor,
        statusCode: 403,
        code: "INTEGRATION_FORBIDDEN",
        message: "invalid integration api key"
      };
    }
  }
  return { ok: true, actor };
}

function parseAdminContext(req, config) {
  const token = parseAdminToken(req);
  if (!token) {
    return {
      ok: false,
      statusCode: 401,
      code: "ADMIN_UNAUTHORIZED",
      message: "missing admin token"
    };
  }

  const verified = verifyAdminToken(token, { secret: config.adminSigningSecret });
  if (!verified.ok) {
    return {
      ok: false,
      statusCode: 401,
      code: verified.code,
      message: verified.message
    };
  }

  const claims = verified.claims || {};
  const actor = typeof claims.sub === "string" ? claims.sub.trim() : "";
  const role = typeof claims.role === "string" ? claims.role.trim() : "";
  if (!actor || !role) {
    return {
      ok: false,
      statusCode: 401,
      code: "ADMIN_UNAUTHORIZED",
      message: "admin token missing actor or role"
    };
  }

  if (config.adminApiKey) {
    const apiKey = req.headers["x-admin-key"];
    if (apiKey !== config.adminApiKey) {
      return {
        ok: false,
        statusCode: 403,
        code: "ADMIN_FORBIDDEN",
        message: "invalid admin api key"
      };
    }
  }

  return { ok: true, actor, role };
}

function hasAdminPermission(role, permission) {
  const permissions = ADMIN_ROLE_PERMISSIONS[role];
  return Boolean(permissions && permissions.has(permission));
}

function requirePermission(res, admin, permission) {
  if (hasAdminPermission(admin.role, permission)) {
    return true;
  }
  json(res, 403, {
    code: "ADMIN_FORBIDDEN",
    message: `role '${admin.role}' cannot perform '${permission}'`
  });
  return false;
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 1024 * 1024) {
        reject(new Error("payload too large"));
        req.destroy();
      }
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

async function readJsonBody(req) {
  const rawBody = await readRawBody(req);
  try {
    return rawBody ? JSON.parse(rawBody) : {};
  } catch (_error) {
    throw new Error("invalid json body");
  }
}

function normalizeSourceIp(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  const primary = trimmed.split(",")[0].trim();
  if (!primary) return null;
  if (/^::ffff:/i.test(primary)) {
    return primary.slice(7);
  }
  return primary.toLowerCase();
}

function resolveServerBaseUrlFromRequest(req, config) {
  const configured =
    config &&
    config.integrationApi &&
    typeof config.integrationApi.publicBaseUrl === "string"
      ? config.integrationApi.publicBaseUrl.trim()
      : "";
  if (configured) {
    try {
      const parsed = new URL(configured);
      const protocol = String(parsed.protocol || "").toLowerCase();
      if ((protocol === "http:" || protocol === "https:") && !parsed.search && !parsed.hash) {
        const normalizedPath =
          parsed.pathname && parsed.pathname !== "/" ? parsed.pathname.replace(/\/+$/, "") : "";
        return `${parsed.protocol}//${parsed.host}${normalizedPath}`;
      }
    } catch (_error) {
      // Ignore malformed configured URL and fallback to request-derived origin.
    }
  }

  const forwardedHostRaw =
    typeof req.headers["x-forwarded-host"] === "string" ? req.headers["x-forwarded-host"] : "";
  const hostCandidate = forwardedHostRaw.split(",")[0].trim();
  const host =
    hostCandidate ||
    (typeof req.headers.host === "string" ? req.headers.host.trim() : "");
  if (!host) return "";
  const forwardedProtoRaw =
    typeof req.headers["x-forwarded-proto"] === "string" ? req.headers["x-forwarded-proto"] : "";
  const protoToken = forwardedProtoRaw.split(",")[0].trim().toLowerCase();
  const protocol =
    protoToken === "https" || protoToken === "http"
      ? protoToken
      : req.socket && req.socket.encrypted
        ? "https"
        : "http";
  return `${protocol}://${host}`;
}

function renderDiscordAuthUrlTemplate(template, context = {}) {
  if (typeof template !== "string" || template.trim() === "") return null;
  const values = {
    user_id: String(context.userId || "").trim(),
    session_id: String(context.sessionId || "").trim(),
    server_base_url: String(context.serverBaseUrl || "").trim(),
    reason_code: String(context.reasonCode || "").trim()
  };
  const rendered = template.replace(
    /\{(user_id|session_id|server_base_url|reason_code)\}/g,
    (_match, key) => encodeURIComponent(values[key] || "")
  );
  try {
    const parsed = new URL(rendered);
    const protocol = String(parsed.protocol || "").toLowerCase();
    if (protocol !== "http:" && protocol !== "https:") return null;
    return parsed.toString();
  } catch (_error) {
    return null;
  }
}

function buildDiscordIdentityAuthorizationUrl({ req, config, session, reasonCode }) {
  const normalizedReasonCode = String(reasonCode || "")
    .trim()
    .toUpperCase() || "DISCORD_IDENTITY_REQUIRED";
  const serverBaseUrl = resolveServerBaseUrlFromRequest(req, config);
  const template =
    config &&
    config.integrationApi &&
    typeof config.integrationApi.discordIdentityAuthorizationUrlTemplate === "string"
      ? config.integrationApi.discordIdentityAuthorizationUrlTemplate
      : "";

  const templateUrl = renderDiscordAuthUrlTemplate(template, {
    userId: session && typeof session.user_id === "string" ? session.user_id : "",
    sessionId: session && typeof session.session_id === "string" ? session.session_id : "",
    reasonCode: normalizedReasonCode,
    serverBaseUrl
  });
  if (templateUrl) return templateUrl;
  if (!serverBaseUrl) return null;

  try {
    const fallbackUrl = new URL("/v1/integration/discord/identity/authorize", serverBaseUrl);
    if (session && typeof session.user_id === "string" && session.user_id.trim()) {
      fallbackUrl.searchParams.set("user_id", session.user_id.trim());
    }
    if (session && typeof session.session_id === "string" && session.session_id.trim()) {
      fallbackUrl.searchParams.set("session_id", session.session_id.trim());
    }
    fallbackUrl.searchParams.set("reason_code", normalizedReasonCode);
    return fallbackUrl.toString();
  } catch (_error) {
    return null;
  }
}

function resolveSubmissionSourceIp(req, body = {}) {
  const bodySource =
    typeof body.submission_source_ip === "string"
      ? body.submission_source_ip
      : typeof body.source_ip === "string"
        ? body.source_ip
        : isPlainObject(body.submission_source) && typeof body.submission_source.ip === "string"
          ? body.submission_source.ip
          : null;
  const headerSource =
    typeof req.headers["x-cguard-submission-source-ip"] === "string"
      ? req.headers["x-cguard-submission-source-ip"]
      : typeof req.headers["x-submission-source-ip"] === "string"
        ? req.headers["x-submission-source-ip"]
        : null;
  return normalizeSourceIp(bodySource) || normalizeSourceIp(headerSource) || null;
}

function evaluateSubmissionSourceConsistency({
  heartbeatSourceIp,
  submissionSourceIp,
  policyAction
}) {
  const normalizedAction = normalizeSourceConsistencyPolicyAction(policyAction, "off");
  const heartbeatIp = normalizeSourceIp(heartbeatSourceIp);
  const submissionIp = normalizeSourceIp(submissionSourceIp);
  if (!heartbeatIp || !submissionIp) {
    return {
      verdict: "missing",
      policy_action: normalizedAction,
      enforced: false,
      reason_code: null,
      heartbeat_source_ip: heartbeatIp,
      submission_source_ip: submissionIp
    };
  }
  if (heartbeatIp === submissionIp) {
    return {
      verdict: "matched",
      policy_action: normalizedAction,
      enforced: false,
      reason_code: null,
      heartbeat_source_ip: heartbeatIp,
      submission_source_ip: submissionIp
    };
  }
  if (normalizedAction === "restricted") {
    return {
      verdict: "mismatch",
      policy_action: normalizedAction,
      enforced: true,
      reason_code: "INTEGRATION_SOURCE_CONSISTENCY_RESTRICTED",
      heartbeat_source_ip: heartbeatIp,
      submission_source_ip: submissionIp
    };
  }
  if (normalizedAction === "blocked") {
    return {
      verdict: "mismatch",
      policy_action: normalizedAction,
      enforced: true,
      reason_code: "INTEGRATION_SOURCE_CONSISTENCY_BLOCKED",
      heartbeat_source_ip: heartbeatIp,
      submission_source_ip: submissionIp
    };
  }
  return {
    verdict: "mismatch",
    policy_action: normalizedAction,
    enforced: false,
    reason_code:
      normalizedAction === "warn" ? "INTEGRATION_SOURCE_CONSISTENCY_MISMATCH" : null,
    heartbeat_source_ip: heartbeatIp,
    submission_source_ip: submissionIp
  };
}

function getRequestContext(req) {
  const sourceIpHeader =
    typeof req.headers["x-forwarded-for"] === "string" ? req.headers["x-forwarded-for"] : "";
  return {
    ip: normalizeSourceIp(sourceIpHeader) || normalizeSourceIp(req.socket.remoteAddress) || "",
    userAgent: req.headers["user-agent"] || ""
  };
}

function parseNumberParam(value, fallback, max = 1000) {
  if (value === null || value === undefined || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(1, Math.floor(parsed)), Math.max(1, Math.floor(max)));
}

function parseNonNegativeNumberParam(value, fallback, max = 100000) {
  if (value === null || value === undefined || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(0, Math.floor(parsed)), Math.max(0, Math.floor(max)));
}

function normalizeOptionalIsoTimestamp(value) {
  if (value === undefined || value === null || String(value).trim() === "") return null;
  const parsed = Date.parse(String(value));
  if (!Number.isFinite(parsed)) return null;
  return new Date(parsed).toISOString();
}

function parseStringListParam(params, key) {
  const allValues = params.getAll(key);
  if (!Array.isArray(allValues) || allValues.length === 0) return undefined;
  const values = allValues
    .flatMap((entry) => String(entry).split(","))
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  return values.length > 0 ? values : undefined;
}

function normalizeStringArray(value, fallback = []) {
  if (!Array.isArray(value)) return [...fallback];
  const normalized = value
    .map((item) => String(item || "").trim())
    .filter((item) => item.length > 0);
  return normalized.length > 0 ? normalized : [...fallback];
}

function normalizePositiveInteger(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.floor(parsed);
}

function normalizeNonNegativeInteger(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return fallback;
  return Math.floor(parsed);
}

function normalizePositiveNumber(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return parsed;
}

function normalizeBooleanFlag(value, fallback = false) {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (value === 1) return true;
    if (value === 0) return false;
  }
  if (typeof value !== "string") return fallback;
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
}

function normalizeStateToken(value, fallback = "unknown") {
  if (typeof value !== "string") return fallback;
  const normalized = value.trim().toLowerCase();
  return normalized || fallback;
}

function normalizeIdentitySource(value, fallback = "unknown") {
  const normalized = normalizeStateToken(value, fallback);
  return DISCORD_IDENTITY_SOURCES.has(normalized) ? normalized : fallback;
}

function normalizeDiscordLinkState(value, fallback = "unknown") {
  const normalized = normalizeStateToken(value, fallback);
  return DISCORD_LINK_STATES.has(normalized) ? normalized : fallback;
}

function normalizeDiscordIdentityPolicyAction(value, fallback = "warn") {
  const normalized = normalizeStateToken(value, fallback);
  return DISCORD_IDENTITY_POLICY_ACTIONS.has(normalized) ? normalized : fallback;
}

function normalizeCliEnforcementAction(value, fallback = "warn") {
  const normalized = normalizeStateToken(value, fallback);
  return CLI_ENFORCEMENT_ACTIONS.has(normalized) ? normalized : fallback;
}

function normalizeMultiDevicePolicyAction(value, fallback = "off") {
  const normalized = normalizeStateToken(value, fallback);
  return MULTI_DEVICE_POLICY_ACTIONS.has(normalized) ? normalized : fallback;
}

function normalizeSourceConsistencyPolicyAction(value, fallback = "off") {
  const normalized = normalizeStateToken(value, fallback);
  return SOURCE_CONSISTENCY_POLICY_ACTIONS.has(normalized) ? normalized : fallback;
}

function normalizeConfidenceThreshold(value, fallback = 85) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  if (parsed < 0) return 0;
  if (parsed > 100) return 100;
  return Math.floor(parsed);
}

function parseIsoToMs(value) {
  if (typeof value !== "string" || value.trim().length === 0) return null;
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return null;
  return parsed;
}

function isTrueBoolean(value) {
  return value === true || value === 1 || value === "1" || value === "true";
}

function resolveCliOverrideContext(state, sessionId, overrideWindowSec, nowMs = Date.now()) {
  const windowSec = normalizeNonNegativeInteger(overrideWindowSec, 0);
  const fallback = {
    enabled: windowSec > 0,
    active: false,
    window_sec: windowSec,
    source: null,
    action_id: null,
    action: null,
    actor: null,
    created_at: null,
    age_sec: null,
    remaining_sec: null
  };
  if (windowSec <= 0 || !state || typeof state.listReviewActions !== "function" || !sessionId) {
    return fallback;
  }

  const actionsPage = state.listReviewActions({
    session_id: sessionId,
    limit: 50,
    offset: 0
  });
  const actions = actionsPage && Array.isArray(actionsPage.items) ? actionsPage.items : [];
  if (actions.length === 0) return fallback;

  const candidate = actions.find((entry) => {
    if (!entry || typeof entry !== "object") return false;
    const metadata = isPlainObject(entry.metadata) ? entry.metadata : {};
    const explicitOverride =
      normalizeStateToken(metadata.policy_override, "") === "cli_enforcement";
    const implicitOverride = CLI_OVERRIDE_REVIEW_ACTIONS.has(String(entry.action || ""));
    return explicitOverride || implicitOverride;
  });
  if (!candidate) return fallback;

  const createdMs = parseIsoToMs(candidate.created_at);
  if (!Number.isFinite(createdMs)) return fallback;
  const ageSec = Math.max(0, Math.floor((nowMs - createdMs) / 1000));
  if (ageSec > windowSec) return fallback;

  return {
    enabled: true,
    active: true,
    window_sec: windowSec,
    source:
      normalizeStateToken(
        isPlainObject(candidate.metadata) ? candidate.metadata.policy_override : "",
        ""
      ) === "cli_enforcement"
        ? "metadata"
        : "manual_action",
    action_id: candidate.action_id || null,
    action: candidate.action || null,
    actor: candidate.actor || null,
    created_at: candidate.created_at || null,
    age_sec: ageSec,
    remaining_sec: Math.max(0, windowSec - ageSec)
  };
}

function applyCliFpGuardrails(cliEvaluation, options = {}) {
  const base = cliEvaluation && typeof cliEvaluation === "object" ? cliEvaluation : {};
  const minEvidenceCount = Math.max(1, normalizePositiveInteger(options.minEvidenceCount, 1));
  const cooldownSec = normalizeNonNegativeInteger(options.cooldownSec, 0);
  const nowMs = Number.isFinite(options.nowMs) ? options.nowMs : Date.now();
  const lastEnforcedAtMs = Number.isFinite(options.lastEnforcedAtMs) ? options.lastEnforcedAtMs : null;
  const override = options.override && typeof options.override === "object" ? options.override : null;

  const guardrails = {
    min_evidence_count: minEvidenceCount,
    cooldown_sec: cooldownSec,
    override_window_sec: override && Number.isFinite(override.window_sec) ? override.window_sec : 0,
    suppressed: false,
    suppress_reason_code: null,
    suppress_reason: null,
    cooldown_remaining_sec: null,
    override_active: override ? override.active === true : false,
    override_action_id: override && override.active === true ? override.action_id || null : null,
    override_action: override && override.active === true ? override.action || null : null,
    override_actor: override && override.active === true ? override.actor || null : null,
    override_created_at: override && override.active === true ? override.created_at || null : null
  };

  const output = {
    ...base,
    guardrails,
    candidate_enforced: base.enforced === true
  };
  if (base.enforced !== true) return output;

  const reasonCount = Number.isFinite(base.reason_count) ? base.reason_count : 0;
  if (reasonCount < minEvidenceCount) {
    output.enforced = false;
    output.status = null;
    output.reason_code = null;
    output.message = null;
    output.issue_user_ban = false;
    guardrails.suppressed = true;
    guardrails.suppress_reason_code = "CLI_FP_GUARD_MIN_EVIDENCE";
    guardrails.suppress_reason = "minimum evidence count not reached";
    return output;
  }

  if (override && override.active === true) {
    output.enforced = false;
    output.status = null;
    output.reason_code = null;
    output.message = null;
    output.issue_user_ban = false;
    guardrails.suppressed = true;
    guardrails.suppress_reason_code = "CLI_FP_GUARD_OVERRIDE_ACTIVE";
    guardrails.suppress_reason = "operator override window is active";
    return output;
  }

  if (cooldownSec > 0 && Number.isFinite(lastEnforcedAtMs)) {
    const elapsedSec = Math.max(0, Math.floor((nowMs - lastEnforcedAtMs) / 1000));
    if (elapsedSec < cooldownSec) {
      output.enforced = false;
      output.status = null;
      output.reason_code = null;
      output.message = null;
      output.issue_user_ban = false;
      guardrails.suppressed = true;
      guardrails.suppress_reason_code = "CLI_FP_GUARD_COOLDOWN";
      guardrails.suppress_reason = "cli enforcement cooldown is active";
      guardrails.cooldown_remaining_sec = Math.max(0, cooldownSec - elapsedSec);
      return output;
    }
  }

  return output;
}

function parseHeartbeatIdentityHint(rawIdentity) {
  if (!isPlainObject(rawIdentity)) return null;
  const rawDeviceBinding = isPlainObject(rawIdentity.device_binding)
    ? rawIdentity.device_binding
    : {};
  const normalizedBindingMode = normalizeStateToken(rawDeviceBinding.mode, "unknown");
  const normalizedBindingState = normalizeStateToken(rawDeviceBinding.state, "unknown");
  return {
    identity_source: normalizeIdentitySource(rawIdentity.identity_source, "unknown"),
    discord_link_state: normalizeDiscordLinkState(rawIdentity.discord_link_state, "unknown"),
    discord_user_id:
      typeof rawIdentity.discord_user_id === "string" && rawIdentity.discord_user_id.trim().length > 0
        ? rawIdentity.discord_user_id.trim()
        : null,
    discord_display_name:
      typeof rawIdentity.discord_display_name === "string" &&
      rawIdentity.discord_display_name.trim().length > 0
        ? rawIdentity.discord_display_name.trim()
        : typeof rawIdentity.display_name === "string" && rawIdentity.display_name.trim().length > 0
          ? rawIdentity.display_name.trim()
          : typeof rawIdentity.global_name === "string" && rawIdentity.global_name.trim().length > 0
            ? rawIdentity.global_name.trim()
            : null,
    discord_username:
      typeof rawIdentity.discord_username === "string" &&
      rawIdentity.discord_username.trim().length > 0
        ? rawIdentity.discord_username.trim()
        : typeof rawIdentity.username === "string" && rawIdentity.username.trim().length > 0
          ? rawIdentity.username.trim()
          : null,
    device_binding_mode: DEVICE_BINDING_MODES.has(normalizedBindingMode)
      ? normalizedBindingMode
      : "unknown",
    device_binding_state: DEVICE_BINDING_STATES.has(normalizedBindingState)
      ? normalizedBindingState
      : "unknown",
    device_binding_id:
      typeof rawDeviceBinding.binding_id === "string" && rawDeviceBinding.binding_id.trim().length > 0
        ? rawDeviceBinding.binding_id.trim()
        : null,
    device_binding_error_code:
      typeof rawDeviceBinding.error_code === "string" && rawDeviceBinding.error_code.trim().length > 0
        ? rawDeviceBinding.error_code.trim().toUpperCase()
        : null
  };
}

function normalizeEvidenceText(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function normalizeNetworkDomain(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");
}

function doesNetworkDomainMatchRule(domain, rule) {
  const observed = normalizeNetworkDomain(domain);
  const normalizedRule = normalizeNetworkDomain(rule);
  if (!observed || !normalizedRule) return false;
  return observed === normalizedRule || observed.endsWith(`.${normalizedRule}`);
}

function extractNetworkEventDomains(event) {
  if (!isPlainObject(event) || !isPlainObject(event.evidence)) return [];
  const evidence = event.evidence;
  return [
    evidence.remote_host,
    evidence.remote_hostname,
    evidence.destination_host,
    evidence.domain,
    evidence.hostname
  ]
    .map((item) => normalizeNetworkDomain(item))
    .filter((item) => item.length > 0);
}

function matchHighRiskLlmNetworkDomain(event) {
  if (!isPlainObject(event)) return null;
  if (String(event.event_type || "") !== "NETWORK_CONNECTION_OBSERVED") return null;
  for (const domain of extractNetworkEventDomains(event)) {
    const matchedRule = HIGH_RISK_LLM_NETWORK_DOMAINS.find((rule) =>
      doesNetworkDomainMatchRule(domain, rule)
    );
    if (matchedRule) {
      return {
        observed_domain: domain,
        matched_domain: matchedRule
      };
    }
  }
  return null;
}

function normalizeLlmNetworkEventSeverity(event) {
  if (!isPlainObject(event)) return event;
  const severity = String(event.severity || "").trim().toLowerCase();
  if (severity !== "low" && severity !== "medium") return event;
  const matched = matchHighRiskLlmNetworkDomain(event);
  if (!matched) return event;
  return {
    ...event,
    severity: "high",
    evidence: {
      ...(isPlainObject(event.evidence) ? event.evidence : {}),
      server_severity_override: {
        from: severity,
        to: "high",
        reason: "high_risk_llm_network_domain",
        observed_domain: matched.observed_domain,
        matched_domain: matched.matched_domain
      }
    }
  };
}

function collectCliEvidenceTexts(event) {
  const bag = [];
  if (!event || typeof event !== "object") return bag;
  const evidence = isPlainObject(event.evidence) ? event.evidence : {};

  const push = (value) => {
    const normalized = normalizeEvidenceText(value);
    if (!normalized) return;
    bag.push(normalized);
  };

  push(event.process);
  push(event.event_type);
  push(evidence.command_line);
  push(evidence.executable_path);
  push(evidence.process_name);
  push(evidence.description);

  const matches = Array.isArray(evidence.matches) ? evidence.matches : [];
  for (const item of matches) {
    if (!isPlainObject(item)) continue;
    for (const value of Object.values(item)) {
      push(value);
    }
  }

  return bag;
}

function normalizeProcessNameForCli(event) {
  if (!event || typeof event !== "object") return "";
  const evidence = isPlainObject(event.evidence) ? event.evidence : {};
  return normalizeEvidenceText(event.process || evidence.process_name || "");
}

function isBrowserProcessForCli(event) {
  const processName = normalizeProcessNameForCli(event);
  return processName.length > 0 && BROWSER_PROCESS_NAMES.has(processName);
}

function isChatGptDesktopOrWebSignal(event) {
  if (!event || typeof event !== "object") return false;
  const evidence = isPlainObject(event.evidence) ? event.evidence : {};
  const values = [
    event.process,
    event.event_type,
    evidence.process_name,
    evidence.command_line,
    evidence.executable_path,
    evidence.description,
    evidence.remote_host,
    evidence.domain,
    evidence.host,
    evidence.window_title
  ]
    .map((value) => normalizeEvidenceText(value))
    .filter(Boolean);
  if (values.some((value) => value.includes("chatgpt-cli"))) return false;
  const processName = normalizeProcessNameForCli(event);
  if (processName === "chatgpt.exe") return true;
  return values.some(
    (value) =>
      value.includes("chatgpt.exe") ||
      value.includes("chatgpt.com") ||
      value.includes("chat.openai.com") ||
      value.includes("\\chatgpt\\") ||
      value.includes("/chatgpt/") ||
      value.includes("openai chatgpt")
  );
}

function isStrongCliProcessSignal(event, cliHints) {
  if (!event || typeof event !== "object") return false;
  if (isBrowserProcessForCli(event)) return false;
  if (isChatGptDesktopOrWebSignal(event)) return false;
  const eventType = String(event.event_type || "");
  if (eventType !== "PROCESS_STARTED" && eventType !== "PROCESS_POLICY_MATCH") {
    return false;
  }
  const texts = collectCliEvidenceTexts(event);
  if (texts.length === 0) return false;
  const hints = normalizeStringArray(cliHints, DEFAULT_LLM_CLI_HINTS).map((item) =>
    normalizeEvidenceText(item)
  );
  return hints.some((hint) => texts.some((text) => text.includes(hint)));
}

function normalizeCliProcessEventSeverity(event, cliHints) {
  if (!isPlainObject(event)) return event;
  const severity = String(event.severity || "").trim().toLowerCase();
  if (severity !== "low" && severity !== "medium") return event;
  if (!isStrongCliProcessSignal(event, cliHints)) return event;
  return {
    ...event,
    severity: "high",
    evidence: {
      ...(isPlainObject(event.evidence) ? event.evidence : {}),
      server_severity_override: {
        from: severity,
        to: "high",
        reason: "llm_cli_process_detected"
      }
    }
  };
}

function normalizeServerEventSeverity(event, cliHints) {
  return normalizeLlmNetworkEventSeverity(normalizeCliProcessEventSeverity(event, cliHints));
}

function detectCliSignalsFromEvents(events, cliHints) {
  const timeline = Array.isArray(events) ? events : [];
  const hints = normalizeStringArray(cliHints, DEFAULT_LLM_CLI_HINTS).map((item) =>
    normalizeEvidenceText(item)
  );
  const reasons = [];
  const dedupe = new Set();
  let strongMatches = 0;
  let weakMatches = 0;

  for (const event of timeline) {
    if (!event || typeof event !== "object") continue;
    if (isBrowserProcessForCli(event)) continue;
    if (isChatGptDesktopOrWebSignal(event)) continue;
    const texts = collectCliEvidenceTexts(event);
    if (texts.length === 0) continue;
    const matchedHint = hints.find((hint) => texts.some((text) => text.includes(hint)));
    if (!matchedHint) continue;

    const eventType = String(event.event_type || "");
    const isStrongSignal =
      eventType === "PROCESS_STARTED" ||
      eventType === "PROCESS_POLICY_MATCH" ||
      (eventType === "NETWORK_POLICY_MATCH" &&
        texts.some((text) => text.includes("cli")));
    if (isStrongSignal) strongMatches += 1;
    else weakMatches += 1;

    const key = `${eventType}|${event.timestamp || ""}|${matchedHint}`;
    if (dedupe.has(key)) continue;
    dedupe.add(key);

    const evidence = isPlainObject(event.evidence) ? event.evidence : {};
    reasons.push({
      event_type: eventType || "unknown",
      timestamp: event.timestamp || null,
      process: normalizeProcessNameForCli(event) || null,
      matched_hint: matchedHint,
      command_line:
        typeof evidence.command_line === "string" ? evidence.command_line : null,
      executable_path:
        typeof evidence.executable_path === "string" ? evidence.executable_path : null,
      strength: isStrongSignal ? "strong" : "weak"
    });
  }

  return {
    detected: reasons.length > 0,
    reasons,
    strongMatches,
    weakMatches
  };
}

function calculateCliSignalConfidence(signal) {
  if (!signal || signal.detected !== true) return 0;
  const strong = Number.isFinite(signal.strongMatches) ? signal.strongMatches : 0;
  const weak = Number.isFinite(signal.weakMatches) ? signal.weakMatches : 0;
  const reasonCount = Array.isArray(signal.reasons) ? signal.reasons.length : 0;
  const hasCanonicalCliTool = Array.isArray(signal.reasons)
    ? signal.reasons.some((item) => {
        if (!item || item.strength !== "strong") return false;
        const matchedHint = normalizeEvidenceText(item.matched_hint);
        return CANONICAL_LLM_CLI_HINTS.has(matchedHint);
      })
    : false;
  if (hasCanonicalCliTool) return 100;
  const hasCommandLine = Array.isArray(signal.reasons)
    ? signal.reasons.some(
        (item) => item && typeof item.command_line === "string" && item.command_line.trim().length > 0
      )
    : false;
  const hasExecutablePath = Array.isArray(signal.reasons)
    ? signal.reasons.some(
        (item) =>
          item && typeof item.executable_path === "string" && item.executable_path.trim().length > 0
      )
    : false;

  let score = 0;
  score += Math.min(55, strong * 20);
  score += Math.min(25, weak * 8);
  score += Math.min(15, reasonCount * 4);
  if (hasCommandLine) score += 15;
  if (hasExecutablePath) score += 8;
  if (score > 100) return 100;
  if (score < 0) return 0;
  return Math.floor(score);
}

function evaluateCliEnforcementFromEvents(events, llmMonitorConfig = {}) {
  const action = normalizeCliEnforcementAction(llmMonitorConfig.cliDetectionAction, "warn");
  const threshold = normalizeConfidenceThreshold(llmMonitorConfig.cliConfidenceThreshold, 85);
  if (action === "off") {
    return {
      policy_action: action,
      threshold,
      detected: false,
      confidence: 0,
      enforced: false,
      status: null,
      reason_code: null,
      message: null,
      reason_count: 0,
      top_reasons: []
    };
  }

  const signal = detectCliSignalsFromEvents(events, llmMonitorConfig.cliHints);
  const confidence = calculateCliSignalConfidence(signal);
  const detected = signal.detected === true;
  const reasonCount = Array.isArray(signal.reasons) ? signal.reasons.length : 0;
  const maxTopEvidence = normalizePositiveInteger(llmMonitorConfig.maxTopEvidence, 3);
  const topReasons = Array.isArray(signal.reasons)
    ? signal.reasons.slice(0, Math.max(1, maxTopEvidence))
    : [];
  if (!detected || confidence < threshold) {
    return {
      policy_action: action,
      threshold,
      detected,
      confidence,
      enforced: false,
      status: null,
      reason_code: null,
      message: null,
      reason_count: reasonCount,
      top_reasons: topReasons
    };
  }

  if (action === "warn") {
    return {
      policy_action: action,
      threshold,
      detected: true,
      confidence,
      enforced: true,
      status: "warn",
      reason_code: "CLI_USAGE_DETECTED",
      message: "cli usage indicators exceeded warning threshold",
      issue_user_ban: false,
      reason_count: reasonCount,
      top_reasons: topReasons
    };
  }
  if (action === "restricted") {
    return {
      policy_action: action,
      threshold,
      detected: true,
      confidence,
      enforced: true,
      status: "blocked",
      reason_code: "CLI_USAGE_RESTRICTED",
      message: "cli usage indicators exceeded restricted threshold",
      issue_user_ban: false,
      reason_count: reasonCount,
      top_reasons: topReasons
    };
  }
  return {
    policy_action: action,
    threshold,
    detected: true,
    confidence,
    enforced: true,
    status: "blocked",
    reason_code: "CLI_USAGE_BLOCKED",
    message: "cli usage indicators exceeded block threshold",
    issue_user_ban: true,
    reason_count: reasonCount,
    top_reasons: topReasons
  };
}

function decodeBase64UrlPart(value) {
  if (typeof value !== "string" || value.trim() === "") return null;
  const normalized = value.trim().replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4;
  const padded = padding === 0 ? normalized : `${normalized}${"=".repeat(4 - padding)}`;
  try {
    return Buffer.from(padded, "base64");
  } catch (_error) {
    return null;
  }
}

function safeParseJsonBuffer(buffer) {
  if (!Buffer.isBuffer(buffer)) return null;
  try {
    return JSON.parse(buffer.toString("utf8"));
  } catch (_error) {
    return null;
  }
}

function verifyDiscordIdentityAssertion(assertionToken, options = {}) {
  const token = typeof assertionToken === "string" ? assertionToken.trim() : "";
  if (!token) {
    return {
      ok: false,
      code: "INTEGRATION_DISCORD_IDENTITY_ASSERTION_REQUIRED",
      message: "identity_assertion is required"
    };
  }

  const secret = typeof options.secret === "string" ? options.secret : "";
  if (!secret) {
    return {
      ok: false,
      code: "INTEGRATION_DISCORD_IDENTITY_ASSERTION_MISCONFIG",
      message: "discord identity assertion secret is missing"
    };
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    return {
      ok: false,
      code: "INTEGRATION_DISCORD_IDENTITY_ASSERTION_INVALID",
      message: "identity_assertion must be JWT-like (header.payload.signature)"
    };
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = safeParseJsonBuffer(decodeBase64UrlPart(encodedHeader));
  const payload = safeParseJsonBuffer(decodeBase64UrlPart(encodedPayload));
  const providedSignature = decodeBase64UrlPart(encodedSignature);
  if (!isPlainObject(header) || !isPlainObject(payload) || !providedSignature) {
    return {
      ok: false,
      code: "INTEGRATION_DISCORD_IDENTITY_ASSERTION_INVALID",
      message: "identity_assertion structure is invalid"
    };
  }

  if (String(header.alg || "").toUpperCase() !== "HS256") {
    return {
      ok: false,
      code: "INTEGRATION_DISCORD_IDENTITY_ASSERTION_INVALID",
      message: "identity_assertion alg must be HS256"
    };
  }

  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const expectedSignature = crypto.createHmac("sha256", secret).update(signingInput).digest();
  const signatureMatches =
    expectedSignature.length === providedSignature.length &&
    crypto.timingSafeEqual(expectedSignature, providedSignature);
  if (!signatureMatches) {
    return {
      ok: false,
      code: "INTEGRATION_DISCORD_IDENTITY_ASSERTION_INVALID",
      message: "identity_assertion signature mismatch"
    };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const exp = Number(payload.exp);
  if (!Number.isFinite(exp) || exp <= nowSec) {
    return {
      ok: false,
      code: "INTEGRATION_DISCORD_IDENTITY_ASSERTION_EXPIRED",
      message: "identity_assertion has expired"
    };
  }

  const expectedUserId =
    typeof options.expectedUserId === "string" ? options.expectedUserId.trim() : "";
  const expectedDiscordUserId =
    typeof options.expectedDiscordUserId === "string"
      ? options.expectedDiscordUserId.trim()
      : "";

  const claimUserId = typeof payload.cgu === "string" ? payload.cgu.trim() : "";
  const claimDiscordUserId = typeof payload.sub === "string" ? payload.sub.trim() : "";
  if (!claimUserId || !claimDiscordUserId) {
    return {
      ok: false,
      code: "INTEGRATION_DISCORD_IDENTITY_ASSERTION_INVALID",
      message: "identity_assertion missing required claims"
    };
  }

  if (expectedUserId && claimUserId !== expectedUserId) {
    return {
      ok: false,
      code: "INTEGRATION_DISCORD_IDENTITY_ASSERTION_MISMATCH",
      message: "identity_assertion user_id mismatch"
    };
  }
  if (expectedDiscordUserId && claimDiscordUserId !== expectedDiscordUserId) {
    return {
      ok: false,
      code: "INTEGRATION_DISCORD_IDENTITY_ASSERTION_MISMATCH",
      message: "identity_assertion discord_user_id mismatch"
    };
  }

  return { ok: true, claims: payload };
}

function evaluateParticipantEligibility(healthLike, participantGateConfig) {
  const gate = isPlainObject(participantGateConfig) ? participantGateConfig : {};
  const requireClientAgentRunning = gate.requireClientAgentRunning === true;
  const requireKernelConnected = gate.requireKernelConnected === true;

  const healthState = {
    client_agent_state: normalizeStateToken(healthLike?.client_agent_state),
    kernel_bridge_state: normalizeStateToken(healthLike?.kernel_bridge_state),
    kernel_driver_loaded: healthLike?.kernel_driver_loaded === true
  };

  if (requireClientAgentRunning && healthState.client_agent_state !== "running") {
    return {
      ok: false,
      code: "CLIENT_AGENT_REQUIRED",
      message: "antiLLM client agent must be running before participation",
      health_state: healthState
    };
  }

  if (
    requireKernelConnected &&
    (healthState.kernel_bridge_state !== "connected" || healthState.kernel_driver_loaded !== true)
  ) {
    return {
      ok: false,
      code: "KERNEL_CONNECTION_REQUIRED",
      message: "kernel bridge must be connected before participation",
      health_state: healthState
    };
  }

  return { ok: true, health_state: healthState };
}

function hasLinkedDiscordIdentity(sessionLike) {
  if (!sessionLike || typeof sessionLike !== "object") return false;
  return (
    typeof sessionLike.discord_user_id === "string" && sessionLike.discord_user_id.trim().length > 0
  );
}

function evaluateDiscordLinkedParticipationGate(sessionLike, integrationApiConfig, nowMs = Date.now()) {
  const requireDiscordLinked =
    integrationApiConfig &&
    typeof integrationApiConfig === "object" &&
    integrationApiConfig.discordRequireLinked === true;
  const policyAction =
    integrationApiConfig && typeof integrationApiConfig === "object"
      ? normalizeDiscordIdentityPolicyAction(integrationApiConfig.discordRequireLinkedAction, "blocked")
      : "blocked";
  const graceSec =
    integrationApiConfig && typeof integrationApiConfig === "object"
      ? normalizeNonNegativeInteger(integrationApiConfig.discordRequireLinkedGraceSec, 0)
      : 0;
  if (!requireDiscordLinked) {
    return {
      ok: true,
      active: false,
      reasonCode: "DISCORD_IDENTITY_REQUIRED",
      message: INTEGRATION_REASON_CODE_DEFINITIONS.DISCORD_IDENTITY_REQUIRED,
      action: policyAction,
      graceSec,
      lossSinceIso: null,
      graceExpiresAtIso: null,
      graceExceeded: false,
      enforced: false
    };
  }
  if (hasLinkedDiscordIdentity(sessionLike)) {
    return {
      ok: true,
      active: false,
      reasonCode: "DISCORD_IDENTITY_REQUIRED",
      message: INTEGRATION_REASON_CODE_DEFINITIONS.DISCORD_IDENTITY_REQUIRED,
      action: policyAction,
      graceSec,
      lossSinceIso: null,
      graceExpiresAtIso: null,
      graceExceeded: false,
      enforced: false
    };
  }
  const normalizedNowMs = Number.isFinite(nowMs) ? Math.floor(nowMs) : Date.now();
  let lossSinceMs = Number.NaN;
  if (
    sessionLike &&
    typeof sessionLike === "object" &&
    typeof sessionLike.discord_require_linked_since === "string" &&
    sessionLike.discord_require_linked_since.trim()
  ) {
    const parsed = Date.parse(sessionLike.discord_require_linked_since);
    if (!Number.isNaN(parsed)) {
      lossSinceMs = parsed;
    }
  }
  if (Number.isNaN(lossSinceMs)) {
    lossSinceMs = normalizedNowMs;
  }
  const graceExpiresMs = lossSinceMs + graceSec * 1000;
  const graceExceeded = graceSec <= 0 ? true : normalizedNowMs >= graceExpiresMs;
  const enforced =
    graceExceeded === true && (policyAction === "restricted" || policyAction === "blocked");
  return {
    ok: !enforced,
    active: true,
    code: "DISCORD_IDENTITY_REQUIRED",
    reasonCode: "DISCORD_IDENTITY_REQUIRED",
    message: INTEGRATION_REASON_CODE_DEFINITIONS.DISCORD_IDENTITY_REQUIRED,
    action: policyAction,
    graceSec,
    lossSinceIso: new Date(lossSinceMs).toISOString(),
    graceExpiresAtIso: graceSec > 0 ? new Date(graceExpiresMs).toISOString() : null,
    graceExceeded,
    enforced
  };
}

function applyDiscordLinkedParticipationGateState(sessionLike, evaluation) {
  if (!sessionLike || typeof sessionLike !== "object") return;
  if (!evaluation || evaluation.active !== true) {
    sessionLike.discord_require_linked_policy = "none";
    sessionLike.discord_require_linked_reason_code = null;
    sessionLike.discord_require_linked_since = null;
    sessionLike.discord_require_linked_grace_expires_at = null;
    sessionLike.discord_require_linked_enforcement_state = "none";
    return;
  }
  sessionLike.discord_require_linked_policy = evaluation.action;
  sessionLike.discord_require_linked_reason_code = evaluation.reasonCode || "DISCORD_IDENTITY_REQUIRED";
  sessionLike.discord_require_linked_since = evaluation.lossSinceIso || new Date().toISOString();
  sessionLike.discord_require_linked_grace_expires_at = evaluation.graceExpiresAtIso || null;
  if (evaluation.graceExceeded !== true) {
    sessionLike.discord_require_linked_enforcement_state = "grace";
  } else if (evaluation.action === "blocked") {
    sessionLike.discord_require_linked_enforcement_state = "blocked";
  } else if (evaluation.action === "restricted") {
    sessionLike.discord_require_linked_enforcement_state = "restricted";
  } else if (evaluation.action === "warn") {
    sessionLike.discord_require_linked_enforcement_state = "warn";
  } else {
    sessionLike.discord_require_linked_enforcement_state = "none";
  }
}

function resolveEventTimestampMs(event) {
  if (!event || typeof event !== "object") return null;
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

function evaluateKernelSignalRate({
  sessionEvents,
  nowMs,
  windowSec,
  minSignalsPerMinute
}) {
  const normalizedNowMs = Number.isFinite(nowMs) ? Math.floor(nowMs) : Date.now();
  const normalizedWindowSec = normalizePositiveInteger(windowSec, 300);
  const normalizedMinSignalsPerMinute =
    Number.isFinite(minSignalsPerMinute) && minSignalsPerMinute > 0
      ? Number(minSignalsPerMinute)
      : 0;
  if (normalizedMinSignalsPerMinute <= 0) {
    return {
      enabled: false,
      window_sec: normalizedWindowSec,
      min_signals_per_minute: 0,
      observed_signals: 0,
      observed_signals_per_minute: 0,
      below_required_rate: false
    };
  }

  const windowMs = normalizedWindowSec * 1000;
  const thresholdMs = normalizedNowMs - windowMs;
  let observedSignals = 0;
  for (const event of Array.isArray(sessionEvents) ? sessionEvents : []) {
    if (!event || typeof event !== "object") continue;
    if (!String(event.event_type || "").startsWith("KERNEL_")) continue;
    const eventTimeMs = resolveEventTimestampMs(event);
    if (!Number.isFinite(eventTimeMs)) continue;
    if (eventTimeMs < thresholdMs) continue;
    observedSignals += 1;
  }

  const observedSignalsPerMinute = observedSignals / (windowMs / (60 * 1000));
  return {
    enabled: true,
    evaluated_at: new Date(normalizedNowMs).toISOString(),
    window_sec: normalizedWindowSec,
    min_signals_per_minute: normalizedMinSignalsPerMinute,
    observed_signals: observedSignals,
    observed_signals_per_minute: Number(observedSignalsPerMinute.toFixed(4)),
    below_required_rate: observedSignalsPerMinute < normalizedMinSignalsPerMinute
  };
}

function normalizeKernelWarnAction(value, fallback = "monitor") {
  if (typeof value !== "string") return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === "monitor") return "monitor";
  if (normalized === "warn" || normalized === "warn_only") return "warn";
  if (normalized === "block" || normalized === "block_on_warn") return "block";
  return fallback;
}

function buildHeartbeatDeniedSecurityContext(policyVersion) {
  return {
    attestation: {
      issued: false,
      token: null,
      expires_at: null,
      token_type: null,
      policy_version: policyVersion
    },
    kernel_binding: {
      issued: false,
      token: null,
      expires_at: null,
      token_type: null,
      policy_version: policyVersion
    }
  };
}

function buildHeartbeatIssuedSecurityContext(policyVersion, attestationIssued, kernelBindingIssued) {
  return {
    attestation: {
      issued: true,
      token: attestationIssued.token,
      expires_at: new Date(attestationIssued.claims.exp * 1000).toISOString(),
      token_type: "bearer",
      policy_version: policyVersion
    },
    kernel_binding: {
      issued: true,
      token: kernelBindingIssued.token,
      expires_at: new Date(kernelBindingIssued.claims.exp * 1000).toISOString(),
      token_type: "bearer",
      policy_version: policyVersion
    }
  };
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const ADMIN_STATIC_FILES = Object.freeze({
  "/admin": {
    filePath: path.resolve(__dirname, "..", "admin", "llm", "index.html"),
    contentType: "text/html; charset=utf-8"
  },
  "/admin/": {
    filePath: path.resolve(__dirname, "..", "admin", "llm", "index.html"),
    contentType: "text/html; charset=utf-8"
  },
  "/admin/classic": {
    filePath: path.resolve(__dirname, "..", "admin", "index.html"),
    contentType: "text/html; charset=utf-8"
  },
  "/admin/classic/": {
    filePath: path.resolve(__dirname, "..", "admin", "index.html"),
    contentType: "text/html; charset=utf-8"
  },
  "/admin/app.js": {
    filePath: path.resolve(__dirname, "..", "admin", "app.js"),
    contentType: "text/javascript; charset=utf-8"
  },
  "/admin/styles.css": {
    filePath: path.resolve(__dirname, "..", "admin", "styles.css"),
    contentType: "text/css; charset=utf-8"
  },
  "/admin/llm": {
    filePath: path.resolve(__dirname, "..", "admin", "llm", "index.html"),
    contentType: "text/html; charset=utf-8"
  },
  "/admin/llm/": {
    filePath: path.resolve(__dirname, "..", "admin", "llm", "index.html"),
    contentType: "text/html; charset=utf-8"
  },
  "/admin/llm/app.js": {
    filePath: path.resolve(__dirname, "..", "admin", "llm", "app.js"),
    contentType: "text/javascript; charset=utf-8"
  },
  "/admin/llm/styles.css": {
    filePath: path.resolve(__dirname, "..", "admin", "llm", "styles.css"),
    contentType: "text/css; charset=utf-8"
  },
  "/admin/llm/reason": {
    filePath: path.resolve(__dirname, "..", "admin", "llm", "reason.html"),
    contentType: "text/html; charset=utf-8"
  },
  "/admin/llm/reason/": {
    filePath: path.resolve(__dirname, "..", "admin", "llm", "reason.html"),
    contentType: "text/html; charset=utf-8"
  },
  "/admin/llm/reason.js": {
    filePath: path.resolve(__dirname, "..", "admin", "llm", "reason.js"),
    contentType: "text/javascript; charset=utf-8"
  },
  "/admin/llm/reason.css": {
    filePath: path.resolve(__dirname, "..", "admin", "llm", "reason.css"),
    contentType: "text/css; charset=utf-8"
  }
});

function tryServeAdminStatic(pathname, res) {
  const file = ADMIN_STATIC_FILES[pathname];
  if (!file) return false;
  if (!fs.existsSync(file.filePath)) {
    json(res, 404, { code: "NOT_FOUND", message: "admin asset not found" });
    return true;
  }
  const body = fs.readFileSync(file.filePath);
  res.writeHead(200, {
    "content-type": file.contentType,
    "cache-control": "no-store"
  });
  res.end(body);
  return true;
}

function createApp(options = {}) {
  const kernelIntegrityOptions = isPlainObject(options.kernelIntegrity)
    ? options.kernelIntegrity
    : {};
  const participantGateOptions = isPlainObject(options.participantGate)
    ? options.participantGate
    : {};
  const integrationApiOptions = isPlainObject(options.integrationApi)
    ? options.integrationApi
    : {};
  const config = {
    attestationTokenTtlSec: options.attestationTokenTtlSec || 60,
    signingSecret: options.signingSecret || "dev-signing-secret",
    adminSigningSecret: options.adminSigningSecret || "dev-admin-signing-secret",
    adminTokenTtlSec: options.adminTokenTtlSec || 60 * 60 * 4,
    adminApiKey: options.adminApiKey || null,
    adminUsers: Array.isArray(options.adminUsers) ? options.adminUsers : DEFAULT_ADMIN_USERS,
    archive: {
      directory:
        typeof options.archiveDirectory === "string" && options.archiveDirectory.trim().length > 0
          ? options.archiveDirectory.trim()
          : "",
      sessionGroupSize: normalizePositiveInteger(options.archiveSessionGroupSize, 7),
      memoryEventLimit: normalizePositiveInteger(options.archiveMemoryEventLimit, 50000)
    },
    competition: {
      name:
        typeof options.competitionName === "string" && options.competitionName.trim().length > 0
          ? options.competitionName.trim()
          : "",
      startsAt: normalizeOptionalIsoTimestamp(options.competitionStartsAt),
      endsAt: normalizeOptionalIsoTimestamp(options.competitionEndsAt)
    },
    kernelIntegrity: {
      maxKernelSignalsPerBatch: normalizePositiveInteger(
        kernelIntegrityOptions.maxKernelSignalsPerBatch ?? options.maxKernelSignalsPerBatch,
        5
      ),
      maxBridgeEmitDeltaMs: normalizePositiveInteger(
        kernelIntegrityOptions.maxBridgeEmitDeltaMs ?? options.maxBridgeEmitDeltaMs,
        60 * 1000
      ),
      maxBridgeCounterGap: normalizePositiveInteger(
        kernelIntegrityOptions.maxBridgeCounterGap ?? options.maxBridgeCounterGap,
        1000
      ),
      maxBridgeStalenessMs: normalizePositiveInteger(
        kernelIntegrityOptions.maxBridgeStalenessMs ?? options.maxBridgeStalenessMs,
        0
      ),
      warnAction: normalizeKernelWarnAction(
        kernelIntegrityOptions.warnAction ?? options.kernelIntegrityWarnAction,
        "block"
      ),
      requireSignals: normalizeBooleanFlag(
        kernelIntegrityOptions.requireSignals ?? options.kernelIntegrityRequireSignals,
        true
      ),
      minKernelSignalsPerBatch: normalizePositiveInteger(
        kernelIntegrityOptions.minKernelSignalsPerBatch ?? options.minKernelSignalsPerBatch,
        1
      ),
      signalRateWindowSec: normalizePositiveInteger(
        kernelIntegrityOptions.signalRateWindowSec ?? options.signalRateWindowSec,
        300
      ),
      minKernelSignalsPerMinute: normalizePositiveNumber(
        kernelIntegrityOptions.minKernelSignalsPerMinute ?? options.minKernelSignalsPerMinute,
        0
      ),
      requireBridgeSignature: normalizeBooleanFlag(
        kernelIntegrityOptions.requireBridgeSignature ??
          options.kernelIntegrityRequireBridgeSignature,
        false
      ),
      requireBridgeNonce: normalizeBooleanFlag(
        kernelIntegrityOptions.requireBridgeNonce ??
          options.kernelIntegrityRequireBridgeNonce,
        false
      ),
      requireBridgeEmittedAt: normalizeBooleanFlag(
        kernelIntegrityOptions.requireBridgeEmittedAt ??
          options.kernelIntegrityRequireBridgeEmittedAt,
        false
      ),
      requireSessionBindingToken: normalizeBooleanFlag(
        kernelIntegrityOptions.requireSessionBindingToken ??
          options.kernelIntegrityRequireSessionBindingToken,
        false
      ),
      kernelBindingTokenTtlSec: normalizePositiveInteger(
        kernelIntegrityOptions.kernelBindingTokenTtlSec ??
          options.kernelIntegrityBindingTokenTtlSec,
        90
      ),
      kernelBridgeSigningSecret:
        typeof (kernelIntegrityOptions.kernelBridgeSigningSecret ??
          options.kernelBridgeSigningSecret) === "string"
          ? String(
              kernelIntegrityOptions.kernelBridgeSigningSecret ??
                options.kernelBridgeSigningSecret
            )
          : "",
      kernelBindingSigningSecret:
        typeof (kernelIntegrityOptions.kernelBindingSigningSecret ??
          options.kernelBindingSigningSecret) === "string"
          ? String(
              kernelIntegrityOptions.kernelBindingSigningSecret ??
                options.kernelBindingSigningSecret
            )
          : options.signingSecret || "dev-signing-secret"
    },
    kernelBridgeSigning: {
      verificationEnabled:
        typeof (kernelIntegrityOptions.kernelBridgeSigningSecret ??
          options.kernelBridgeSigningSecret) === "string" &&
        String(
          kernelIntegrityOptions.kernelBridgeSigningSecret ?? options.kernelBridgeSigningSecret
        ).length > 0
    },
    kernelSessionBinding: {
      verificationEnabled:
        typeof (kernelIntegrityOptions.kernelBindingSigningSecret ??
          options.kernelBindingSigningSecret) === "string" &&
        String(
          kernelIntegrityOptions.kernelBindingSigningSecret ?? options.kernelBindingSigningSecret
        ).length > 0
    },
    participantGate: {
      requireClientAgentRunning: normalizeBooleanFlag(
        participantGateOptions.requireClientAgentRunning ??
          options.participantRequireClientAgentRunning,
        true
      ),
      requireKernelConnected: normalizeBooleanFlag(
        participantGateOptions.requireKernelConnected ?? options.participantRequireKernelConnected,
        true
      ),
      autoBanClientAgentStopped: normalizeBooleanFlag(
        participantGateOptions.autoBanClientAgentStopped ??
          options.participantAutoBanClientAgentStopped,
        false
      )
    },
    versionPolicy: options.versionPolicy || {
      latestVersion: "1.4.0",
      deprecatedBelowVersion: "1.3.0",
      minimumSupportedVersion: "1.2.0"
    },
    integrationApi: {
      enabled: normalizeBooleanFlag(
        integrationApiOptions.enabled ?? options.integrationApiEnabled,
        false
      ),
      token:
        typeof (integrationApiOptions.token ?? options.integrationApiToken) === "string"
          ? String(integrationApiOptions.token ?? options.integrationApiToken)
          : "dev-integration-token",
      apiKey:
        typeof (integrationApiOptions.apiKey ?? options.integrationApiKey) === "string"
          ? String(integrationApiOptions.apiKey ?? options.integrationApiKey)
          : null,
      heartbeatStaleSec: normalizePositiveInteger(
        integrationApiOptions.heartbeatStaleSec ?? options.integrationHeartbeatStaleSec,
        30
      ),
      autoBanOfflineSession: normalizeBooleanFlag(
        integrationApiOptions.autoBanOfflineSession ?? options.integrationAutoBanOfflineSession,
        false
      ),
      autoBanBlockedDecision: normalizeBooleanFlag(
        integrationApiOptions.autoBanBlockedDecision ?? options.integrationAutoBanBlockedDecision,
        false
      ),
      rateLimitMaxRequests: normalizeNonNegativeInteger(
        integrationApiOptions.rateLimitMaxRequests ?? options.integrationRateLimitMaxRequests,
        120
      ),
      rateLimitWindowSec: normalizePositiveInteger(
        integrationApiOptions.rateLimitWindowSec ?? options.integrationRateLimitWindowSec,
        60
      ),
      maxRateLimitEntries: normalizePositiveInteger(
        integrationApiOptions.maxRateLimitEntries ?? options.integrationMaxRateLimitEntries,
        10000
      ),
      discordCallbackRequireSignature: normalizeBooleanFlag(
        integrationApiOptions.discordCallbackRequireSignature ??
          options.integrationDiscordCallbackRequireSignature,
        false
      ),
      discordCallbackSigningSecret:
        typeof (
          integrationApiOptions.discordCallbackSigningSecret ??
          options.integrationDiscordCallbackSigningSecret
        ) === "string"
          ? String(
              integrationApiOptions.discordCallbackSigningSecret ??
                options.integrationDiscordCallbackSigningSecret
            )
          : "",
      discordCallbackTimestampToleranceSec: normalizePositiveInteger(
        integrationApiOptions.discordCallbackTimestampToleranceSec ??
          options.integrationDiscordCallbackTimestampToleranceSec,
        300
      ),
      discordCallbackNonceTtlSec: normalizePositiveInteger(
        integrationApiOptions.discordCallbackNonceTtlSec ??
          options.integrationDiscordCallbackNonceTtlSec,
        600
      ),
      maxDiscordCallbackNonceEntries: normalizePositiveInteger(
        integrationApiOptions.maxDiscordCallbackNonceEntries ??
          options.integrationDiscordCallbackNonceMaxEntries,
        20000
      ),
      discordIdentityRequireAssertion: normalizeBooleanFlag(
        integrationApiOptions.discordIdentityRequireAssertion ??
          options.integrationDiscordIdentityRequireAssertion,
        false
      ),
      publicBaseUrl:
        typeof (integrationApiOptions.publicBaseUrl ?? options.integrationPublicBaseUrl) ===
        "string"
          ? String(integrationApiOptions.publicBaseUrl ?? options.integrationPublicBaseUrl).trim()
          : "",
      discordIdentityAuthorizationUrlTemplate:
        typeof (
          integrationApiOptions.discordIdentityAuthorizationUrlTemplate ??
          options.integrationDiscordIdentityAuthorizationUrlTemplate
        ) === "string"
          ? String(
              integrationApiOptions.discordIdentityAuthorizationUrlTemplate ??
                options.integrationDiscordIdentityAuthorizationUrlTemplate
            ).trim()
          : "",
      discordIdentityAssertionSecret:
        typeof (
          integrationApiOptions.discordIdentityAssertionSecret ??
          options.integrationDiscordIdentityAssertionSecret
        ) === "string"
          ? String(
              integrationApiOptions.discordIdentityAssertionSecret ??
                options.integrationDiscordIdentityAssertionSecret
            )
          : "",
      discordIdentityAllowRelink: normalizeBooleanFlag(
        integrationApiOptions.discordIdentityAllowRelink ??
          options.integrationDiscordIdentityAllowRelink,
        false
      ),
      discordRequireLinked: normalizeBooleanFlag(
        integrationApiOptions.discordRequireLinked ?? options.integrationDiscordRequireLinked,
        false
      ),
      discordRequireLinkedAction: normalizeDiscordIdentityPolicyAction(
        integrationApiOptions.discordRequireLinkedAction ??
          options.integrationDiscordRequireLinkedAction,
        "blocked"
      ),
      discordRequireLinkedGraceSec: normalizeNonNegativeInteger(
        integrationApiOptions.discordRequireLinkedGraceSec ??
          options.integrationDiscordRequireLinkedGraceSec,
        0
      ),
      submissionProofTtlSec: normalizePositiveInteger(
        integrationApiOptions.submissionProofTtlSec ??
          options.integrationSubmissionProofTtlSec,
        45
      ),
      submissionProofNonceTtlSec: normalizePositiveInteger(
        integrationApiOptions.submissionProofNonceTtlSec ??
          options.integrationSubmissionProofNonceTtlSec,
        120
      ),
      maxSubmissionProofNonceEntries: normalizePositiveInteger(
        integrationApiOptions.maxSubmissionProofNonceEntries ??
          options.integrationSubmissionProofNonceMaxEntries,
        20000
      ),
      submissionProofSigningSecret:
        typeof (
          integrationApiOptions.submissionProofSigningSecret ??
          options.integrationSubmissionProofSigningSecret
        ) === "string"
          ? String(
              integrationApiOptions.submissionProofSigningSecret ??
                options.integrationSubmissionProofSigningSecret
            )
          : options.signingSecret || "dev-signing-secret",
      sourceConsistencyAction: normalizeSourceConsistencyPolicyAction(
        integrationApiOptions.sourceConsistencyAction ??
          options.integrationSourceConsistencyAction,
        "off"
      ),
      discordMultiDevicePolicy: normalizeMultiDevicePolicyAction(
        integrationApiOptions.discordMultiDevicePolicy ??
          options.integrationDiscordMultiDevicePolicy,
        "off"
      ),
      discordDeviceSwitchPolicy: normalizeMultiDevicePolicyAction(
        integrationApiOptions.discordDeviceSwitchPolicy ??
          options.integrationDiscordDeviceSwitchPolicy,
        "off"
      ),
      discordDeviceSwitchWindowSec: normalizePositiveInteger(
        integrationApiOptions.discordDeviceSwitchWindowSec ??
          options.integrationDiscordDeviceSwitchWindowSec,
        120
      ),
      discordRelinkRacePolicy: normalizeMultiDevicePolicyAction(
        integrationApiOptions.discordRelinkRacePolicy ??
          options.integrationDiscordRelinkRacePolicy,
        "off"
      ),
      discordIdentityLossPolicy: normalizeDiscordIdentityPolicyAction(
        integrationApiOptions.discordIdentityLossPolicy ??
          options.integrationDiscordIdentityLossPolicy,
        "restricted"
      ),
      discordIdentityLossGraceSec: normalizePositiveInteger(
        integrationApiOptions.discordIdentityLossGraceSec ??
          options.integrationDiscordIdentityLossGraceSec,
        30
      ),
      discordClientUnavailablePolicy: normalizeDiscordIdentityPolicyAction(
        integrationApiOptions.discordClientUnavailablePolicy ??
          options.integrationDiscordClientUnavailablePolicy,
        "warn"
      ),
      discordClientUnavailableGraceSec: normalizePositiveInteger(
        integrationApiOptions.discordClientUnavailableGraceSec ??
          options.integrationDiscordClientUnavailableGraceSec,
        120
      ),
      discordRoleRevokeGuildId:
        typeof (
          integrationApiOptions.discordRoleRevokeGuildId ??
          options.integrationDiscordRoleRevokeGuildId
        ) === "string"
          ? String(
              integrationApiOptions.discordRoleRevokeGuildId ??
                options.integrationDiscordRoleRevokeGuildId
            ).trim()
          : "",
      discordRoleRevokeRoleId:
        typeof (
          integrationApiOptions.discordRoleRevokeRoleId ??
          options.integrationDiscordRoleRevokeRoleId
        ) === "string"
          ? String(
              integrationApiOptions.discordRoleRevokeRoleId ??
                options.integrationDiscordRoleRevokeRoleId
            ).trim()
          : "",
      discordGateRoleSyncEnabled: normalizeBooleanFlag(
        integrationApiOptions.discordGateRoleSyncEnabled ??
          options.integrationDiscordGateRoleSyncEnabled,
        false
      ),
      discordGateRoleGuildId:
        typeof (
          integrationApiOptions.discordGateRoleGuildId ??
          options.integrationDiscordGateRoleGuildId
        ) === "string"
          ? String(
              integrationApiOptions.discordGateRoleGuildId ??
                options.integrationDiscordGateRoleGuildId
            ).trim()
          : "",
      discordGateRoleId:
        typeof (
          integrationApiOptions.discordGateRoleId ??
          options.integrationDiscordGateRoleId
        ) === "string"
          ? String(
              integrationApiOptions.discordGateRoleId ??
                options.integrationDiscordGateRoleId
            ).trim()
          : "",
      discordGateRoleAssignOnHealthy: normalizeBooleanFlag(
        integrationApiOptions.discordGateRoleAssignOnHealthy ??
          options.integrationDiscordGateRoleAssignOnHealthy,
        true
      ),
      discordGateRoleRemoveOnGateFailure: normalizeBooleanFlag(
        integrationApiOptions.discordGateRoleRemoveOnGateFailure ??
          options.integrationDiscordGateRoleRemoveOnGateFailure,
        true
      ),
      discordGateRoleRemoveOnOffline: normalizeBooleanFlag(
        integrationApiOptions.discordGateRoleRemoveOnOffline ??
          options.integrationDiscordGateRoleRemoveOnOffline,
        true
      )
    },
    llmMonitor: {
      cliHints: normalizeStringArray(options.llmMonitor && options.llmMonitor.cliHints, DEFAULT_LLM_CLI_HINTS),
      cliDetectionAction: normalizeCliEnforcementAction(
        options.llmMonitor &&
          (options.llmMonitor.cliDetectionAction ?? options.llmMonitor.cli_detection_action),
        "warn"
      ),
      cliConfidenceThreshold: normalizeConfidenceThreshold(
        options.llmMonitor &&
          (options.llmMonitor.cliConfidenceThreshold ?? options.llmMonitor.cli_confidence_threshold),
        85
      ),
      weakConfidenceThreshold: normalizePositiveNumber(
        options.llmMonitor && options.llmMonitor.weakConfidenceThreshold,
        60
      ),
      mediumConfidenceThreshold: normalizePositiveNumber(
        options.llmMonitor && options.llmMonitor.mediumConfidenceThreshold,
        60
      ),
      highConfidenceThreshold: normalizePositiveNumber(
        options.llmMonitor && options.llmMonitor.highConfidenceThreshold,
        80
      ),
      maxTopEvidence: normalizePositiveInteger(
        options.llmMonitor && options.llmMonitor.maxTopEvidence,
        3
      ),
      cliMinEvidenceCount: normalizePositiveInteger(
        options.llmMonitor &&
          (options.llmMonitor.cliMinEvidenceCount ?? options.llmMonitor.cli_min_evidence_count),
        1
      ),
      cliEnforcementCooldownSec: normalizeNonNegativeInteger(
        options.llmMonitor &&
          (options.llmMonitor.cliEnforcementCooldownSec ??
            options.llmMonitor.cli_enforcement_cooldown_sec),
        0
      ),
      cliOverrideWindowSec: normalizeNonNegativeInteger(
        options.llmMonitor &&
          (options.llmMonitor.cliOverrideWindowSec ?? options.llmMonitor.cli_override_window_sec),
        0
      )
    }
  };
  config.kernelBridgeSigning.verificationEnabled =
    typeof config.kernelIntegrity.kernelBridgeSigningSecret === "string" &&
    config.kernelIntegrity.kernelBridgeSigningSecret.length > 0;
  config.kernelSessionBinding.verificationEnabled =
    typeof config.kernelIntegrity.kernelBindingSigningSecret === "string" &&
    config.kernelIntegrity.kernelBindingSigningSecret.length > 0;

  const state =
    options.state ||
    createStateAdapter({
      ...options,
      archiveDirectory: config.archive.directory,
      archiveSessionGroupSize: config.archive.sessionGroupSize,
      archiveMemoryEventLimit: config.archive.memoryEventLimit,
      heartbeatTtlSec: config.integrationApi.heartbeatStaleSec
    });
  const logSink = options.logSink || console.log;
  const eventStore = options.eventStore || new InMemoryEventStore();
  const eventPipeline = createIngestionPipeline({
    store: eventStore,
    versionPolicyConfig: config.versionPolicy,
    logSink
  });

  async function handleLogin(req, res) {
    const body = await readJsonBody(req);
    const clientInfo = body.client_info;
    if (
      !body.grant_type ||
      !body.credential ||
      !clientInfo ||
      clientInfo.os !== "windows" ||
      !clientInfo.os_version ||
      !clientInfo.app_version ||
      !clientInfo.device_id
    ) {
      return json(res, 400, {
        code: "BAD_REQUEST",
        message: "invalid login payload"
      });
    }

    const user = state.ensureUser(body.credential);
    const team = state.ensureTeam(body.requested_team_id);
    const client = state.registerClient(user.user_id, team.team_id, clientInfo);
    const ctx = getRequestContext(req);
    const session = state.createSession({
      userId: user.user_id,
      teamId: team.team_id,
      clientId: client.client_instance_id,
      policyVersion: "policy-v1",
      ip: String(ctx.ip),
      userAgent: String(ctx.userAgent)
    });
    const refresh = state.issueRefreshToken(session);
    const linkedIdentity = state.getDiscordIdentityByUserId(user.user_id);

    return json(res, 200, {
      user_id: user.user_id,
      team_id: team.team_id,
      session_id: session.session_id,
      client_instance_id: client.client_instance_id,
      refresh_token: refresh.refresh_token,
      refresh_expires_at: refresh.refresh_expires_at,
      server_time: new Date().toISOString(),
      policy_version: "policy-v1",
      discord_identity: {
        linked: Boolean(linkedIdentity),
        discord_user_id: linkedIdentity ? linkedIdentity.discord_user_id : null,
        discord_display_name: linkedIdentity ? linkedIdentity.discord_display_name || null : null,
        discord_username: linkedIdentity ? linkedIdentity.discord_username || null : null,
        identity_source: linkedIdentity ? linkedIdentity.identity_source : "unknown"
      }
    });
  }

  async function handleHeartbeat(req, res) {
    const refreshToken = parseBearer(req);
    if (!refreshToken) {
      return json(res, 401, { code: "INVALID_TOKEN", message: "missing refresh token" });
    }
    const tokenCheck = state.validateRefreshToken(refreshToken);
    if (!tokenCheck.ok) {
      return json(res, 401, { code: tokenCheck.code, message: tokenCheck.message });
    }

    const body = await readJsonBody(req);
    if (
      !body.client_instance_id ||
      !body.device_id ||
      !body.policy_version ||
      !body.health ||
      !body.health.firewall_state ||
      !body.health.observer_state
    ) {
      return json(res, 400, { code: "BAD_REQUEST", message: "invalid heartbeat payload" });
    }

    const ref = tokenCheck.value;
    if (ref.client_instance_id !== body.client_instance_id) {
      return json(res, 403, {
        code: "CLIENT_NONCOMPLIANT",
        message: "client instance mismatch"
      });
    }

    const client = state.getClient(body.client_instance_id);
    const session = state.getSession(ref.session_id);
    if (!client || !session) {
      return json(res, 401, { code: "INVALID_TOKEN", message: "session not found" });
    }
    if (client.device_id !== body.device_id) {
      return json(res, 403, {
        code: "CLIENT_NONCOMPLIANT",
        message: "device mismatch"
      });
    }

    const teamBan = state.getTeamBan(session.team_id);
    if (teamBan) {
      return json(res, 200, {
        server_time: new Date().toISOString(),
        decision: {
          status: "blocked",
          reason_code: "BANNED_TEAM",
          message: teamBan.reason
        },
        ...buildHeartbeatDeniedSecurityContext(body.policy_version)
      });
    }

    const userBan = state.getUserBan(session.user_id);
    if (userBan) {
      return json(res, 200, {
        server_time: new Date().toISOString(),
        decision: {
          status: "blocked",
          reason_code: "BANNED_USER",
          message: userBan.reason
        },
        ...buildHeartbeatDeniedSecurityContext(body.policy_version)
      });
    }

    const sessionBan = state.getSessionBan(session.session_id);
    if (sessionBan) {
      return json(res, 200, {
        server_time: new Date().toISOString(),
        decision: {
          status: "blocked",
          reason_code: "BANNED_SESSION",
          message: sessionBan.reason
        },
        ...buildHeartbeatDeniedSecurityContext(body.policy_version)
      });
    }

    const heartbeatNowMs = Date.now();
    const discordLinkedGate = evaluateDiscordLinkedParticipationGate(
      session,
      config.integrationApi,
      heartbeatNowMs
    );
    applyDiscordLinkedParticipationGateState(session, discordLinkedGate);
    if (discordLinkedGate.active === true && discordLinkedGate.enforced === true) {
      const linkedGateReasonCode = normalizeReasonCode(discordLinkedGate.reasonCode) || "DISCORD_IDENTITY_REQUIRED";
      const linkedGateMessage =
        INTEGRATION_REASON_CODE_DEFINITIONS[linkedGateReasonCode] || discordLinkedGate.message;
      const discordAuthUrl = buildDiscordIdentityAuthorizationUrl({
        req,
        config,
        session,
        reasonCode: linkedGateReasonCode
      });
      state.addAuditLog({
        action: linkedGateReasonCode,
        actor: "server",
        object_type: "session",
        object_id: session.session_id,
        detail: {
          require_discord_linked: config.integrationApi.discordRequireLinked === true,
          policy_action: discordLinkedGate.action,
          grace_sec: discordLinkedGate.graceSec,
          grace_expires_at: discordLinkedGate.graceExpiresAtIso,
          grace_exceeded: discordLinkedGate.graceExceeded === true,
          source: "heartbeat",
          discord_link_state: normalizeDiscordLinkState(session.discord_link_state, "unlinked"),
          identity_source: normalizeIdentitySource(session.identity_source, "unknown")
        }
      });
      state.setSessionDecision(session.session_id, {
        status: "blocked",
        reason_code: linkedGateReasonCode,
        message: linkedGateMessage,
        score: 0,
        tier: "normal"
      });
      if (discordLinkedGate.action === "blocked") {
        state.setSessionBan(session.session_id, 0, linkedGateReasonCode, linkedGateMessage);
      }
      state.revokeActiveJtiForUser(session.user_id);
      const deniedPayload = {
        server_time: new Date().toISOString(),
        decision: {
          status: "blocked",
          reason_code: linkedGateReasonCode,
          message: linkedGateMessage
        },
        ...buildHeartbeatDeniedSecurityContext(body.policy_version)
      };
      if (typeof discordAuthUrl === "string" && discordAuthUrl.trim()) {
        deniedPayload.discord_auth_url = discordAuthUrl;
      }
      return json(res, 200, deniedPayload);
    }

    const versionResult = evaluateClientVersion(client.app_version, config.versionPolicy);
    const versionEvent = buildVersionPolicyEvent(
      {
        session_id: session.session_id,
        user_id: session.user_id,
        client_version: client.app_version
      },
      versionResult,
      config.versionPolicy
    );

    if (versionEvent) {
      logStructured(versionEvent, logSink);
    }

    if (versionResult.status === "invalid" || versionResult.status === "unsupported") {
      return json(res, 200, {
        server_time: new Date().toISOString(),
        decision: {
          status: "blocked",
          reason_code:
            versionResult.status === "invalid"
              ? "CLIENT_VERSION_INVALID"
              : "CLIENT_VERSION_UNSUPPORTED",
          message: versionResult.reason
        },
        ...buildHeartbeatDeniedSecurityContext(body.policy_version)
      });
    }

    const identityHint = parseHeartbeatIdentityHint(body.identity);
    const heartbeatRequestContext = getRequestContext(req);
    state.updateHeartbeat(
      body.client_instance_id,
      body.health,
      body.policy_version,
      identityHint,
      heartbeatRequestContext
    );

    if (identityHint) {
      if (
        typeof session.discord_user_id === "string" &&
        session.discord_user_id &&
        identityHint.discord_user_id &&
        identityHint.discord_user_id !== session.discord_user_id
      ) {
        state.addAuditLog({
          action: "DISCORD_IDENTITY_HINT_MISMATCH",
          actor: "server",
          object_type: "session",
          object_id: session.session_id,
          detail: {
            canonical_discord_user_id: session.discord_user_id,
            hinted_discord_user_id: identityHint.discord_user_id,
            identity_source: identityHint.identity_source
          }
        });
      }

      state.appendEvents([
        {
          event_id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          event_type: "CLIENT_IDENTITY_STATE_REPORTED",
          severity: "low",
          session_id: session.session_id,
          team_id: session.team_id,
          user_id: session.user_id,
          client_version: client.app_version,
          evidence: {
            schema_version: "identity-v1",
            identity_source: identityHint.identity_source,
            discord_link_state: identityHint.discord_link_state,
            discord_user_id_hint: identityHint.discord_user_id,
            discord_display_name_hint: identityHint.discord_display_name,
            discord_username_hint: identityHint.discord_username,
            device_binding_mode: identityHint.device_binding_mode,
            device_binding_state: identityHint.device_binding_state,
            device_binding_id: identityHint.device_binding_id,
            device_binding_error_code: identityHint.device_binding_error_code,
            canonical_discord_user_id:
              typeof session.discord_user_id === "string" ? session.discord_user_id : null
          },
          received_at: new Date().toISOString()
        }
      ]);
    }

    const heartbeatFreshnessSec = resolveHeartbeatFreshnessSec(session, heartbeatNowMs);
    const identityPolicyEvaluation = evaluateDiscordIdentityPolicyState(
      session,
      heartbeatFreshnessSec,
      heartbeatNowMs
    );
    applyDiscordIdentityPolicyState(session, identityPolicyEvaluation);
    const multiDeviceEvaluation = evaluateDiscordMultiDevicePolicyState(session, heartbeatNowMs);
    applyDiscordMultiDevicePolicyState(session, multiDeviceEvaluation);
    const bindingTransitionEvaluation = evaluateDiscordBindingTransitionState(
      session,
      heartbeatNowMs
    );
    applyDiscordBindingTransitionState(session, bindingTransitionEvaluation);
    if (
      identityPolicyEvaluation.active === true &&
      identityPolicyEvaluation.graceExceeded === true
    ) {
      maybeQueueDiscordIdentityRoleRevoke(session, identityPolicyEvaluation, "server");
    }
    const preGateComputedStatus = resolveComputedSessionStatus(
      session,
      state.getSessionDecision(session.session_id)
    );
    const preGateDirective = resolveDiscordGateRoleDirective({
      session,
      computedStatus: preGateComputedStatus,
      identityPolicyEvaluation,
      freshnessSec: heartbeatFreshnessSec
    });
    if (preGateDirective.action === "remove_role") {
      maybeQueueDiscordGateRoleAction(session, preGateDirective, "server");
    }
    if (
      identityPolicyEvaluation.active === true &&
      identityPolicyEvaluation.graceExceeded === true &&
      (identityPolicyEvaluation.action === "restricted" ||
        identityPolicyEvaluation.action === "blocked")
    ) {
      if (identityPolicyEvaluation.action === "blocked") {
        state.setSessionBan(
          session.session_id,
          0,
          identityPolicyEvaluation.reasonCode,
          INTEGRATION_REASON_CODE_DEFINITIONS[identityPolicyEvaluation.reasonCode] ||
            "discord identity policy blocked session"
        );
      }
      state.revokeActiveJtiForUser(session.user_id);
      return json(res, 200, {
        server_time: new Date().toISOString(),
        decision: {
          status: "blocked",
          reason_code: identityPolicyEvaluation.reasonCode,
          message:
            INTEGRATION_REASON_CODE_DEFINITIONS[identityPolicyEvaluation.reasonCode] ||
            "discord identity policy restricted session"
        },
        ...buildHeartbeatDeniedSecurityContext(body.policy_version)
      });
    }
    if (multiDeviceEvaluation.active === true && multiDeviceEvaluation.enforced === true) {
      state.addAuditLog({
        action: "DISCORD_MULTI_DEVICE_CONFLICT_ENFORCED",
        actor: "server",
        object_type: "session",
        object_id: session.session_id,
        detail: {
          policy_action: multiDeviceEvaluation.action,
          reason_code: multiDeviceEvaluation.reasonCode,
          conflict_count: multiDeviceEvaluation.conflictCount,
          conflicting_session_ids: multiDeviceEvaluation.conflictingSessionIds,
          canonical_discord_user_id: multiDeviceEvaluation.canonicalDiscordUserId
        }
      });
      state.revokeActiveJtiForUser(session.user_id);
      return json(res, 200, {
        server_time: new Date().toISOString(),
        decision: {
          status: "blocked",
          reason_code: multiDeviceEvaluation.reasonCode,
          message:
            INTEGRATION_REASON_CODE_DEFINITIONS[multiDeviceEvaluation.reasonCode] ||
            "multi-device conflict policy enforced"
        },
        ...buildHeartbeatDeniedSecurityContext(body.policy_version)
      });
    }
    if (
      bindingTransitionEvaluation.active === true &&
      bindingTransitionEvaluation.enforced === true
    ) {
      state.addAuditLog({
        action: "DISCORD_SESSION_BINDING_ENFORCED",
        actor: "server",
        object_type: "session",
        object_id: session.session_id,
        detail: {
          policy_action: bindingTransitionEvaluation.action,
          reason_code: bindingTransitionEvaluation.reasonCode,
          risk_type: bindingTransitionEvaluation.riskType,
          conflicting_session_ids: bindingTransitionEvaluation.conflictingSessionIds,
          ...bindingTransitionEvaluation.metadata
        }
      });
      state.revokeActiveJtiForUser(session.user_id);
      return json(res, 200, {
        server_time: new Date().toISOString(),
        decision: {
          status: "blocked",
          reason_code: bindingTransitionEvaluation.reasonCode,
          message:
            INTEGRATION_REASON_CODE_DEFINITIONS[bindingTransitionEvaluation.reasonCode] ||
            "session binding transition policy enforced"
        },
        ...buildHeartbeatDeniedSecurityContext(body.policy_version)
      });
    }

    const participantGateResult = evaluateParticipantEligibility(
      body.health,
      config.participantGate
    );
    if (!participantGateResult.ok) {
      if (
        config.participantGate.autoBanClientAgentStopped === true &&
        participantGateResult.code === "CLIENT_AGENT_REQUIRED" &&
        !state.getSessionBan(session.session_id)
      ) {
        const reasonCode =
          normalizeReasonCode(participantGateResult.code) || "CLIENT_AGENT_REQUIRED";
        state.createBan({
          scope: "session",
          target_id: session.session_id,
          reason: participantGateResult.message,
          reason_code: reasonCode,
          duration_sec: 0,
          created_by: "system:auto_client_agent"
        });
        state.setSessionDecision(session.session_id, {
          status: "blocked",
          reason_code: reasonCode,
          message: participantGateResult.message,
          score: 0,
          tier: "normal"
        });
        state.revokeActiveJtiForUser(session.user_id);
        state.addAuditLog({
          action: "AUTO_SESSION_BAN_ON_CLIENT_AGENT_STOPPED",
          actor: "server",
          object_type: "session",
          object_id: session.session_id,
          detail: participantGateResult.health_state
        });
      }
      const gateFailureDirective = resolveDiscordGateRoleDirective({
        session,
        computedStatus: preGateComputedStatus,
        participantGateResult,
        identityPolicyEvaluation,
        freshnessSec: heartbeatFreshnessSec
      });
      if (gateFailureDirective.action === "remove_role") {
        maybeQueueDiscordGateRoleAction(session, gateFailureDirective, "server");
      }
      state.addAuditLog({
        action: participantGateResult.code,
        actor: "server",
        object_type: "session",
        object_id: session.session_id,
        detail: participantGateResult.health_state
      });
      return json(res, 200, {
        server_time: new Date().toISOString(),
        decision: {
          status: "blocked",
          reason_code: participantGateResult.code,
          message: participantGateResult.message
        },
        ...buildHeartbeatDeniedSecurityContext(body.policy_version)
      });
    }

    if (state.isClientNoncompliant(body.client_instance_id)) {
      const nonCompliantDirective = resolveDiscordGateRoleDirective({
        session,
        computedStatus: "BLOCKED",
        participantGateResult: {
          ok: false,
          code: "CLIENT_NONCOMPLIANT"
        },
        identityPolicyEvaluation,
        freshnessSec: heartbeatFreshnessSec
      });
      if (nonCompliantDirective.action === "remove_role") {
        maybeQueueDiscordGateRoleAction(session, nonCompliantDirective, "server");
      }
      return json(res, 200, {
        server_time: new Date().toISOString(),
        decision: {
          status: "blocked",
          reason_code: "CLIENT_NONCOMPLIANT",
          message: "client health reported error"
        },
        ...buildHeartbeatDeniedSecurityContext(body.policy_version)
      });
    }

    const issued = issueAttestationToken(
      {
        sub: session.user_id,
        tid: session.team_id,
        sid: session.session_id,
        cid: session.client_instance_id,
        pv: body.policy_version
      },
      { secret: config.signingSecret, ttlSec: config.attestationTokenTtlSec }
    );

    const successDirective = resolveDiscordGateRoleDirective({
      session,
      computedStatus: "ACTIVE",
      participantGateResult: { ok: true },
      identityPolicyEvaluation,
      freshnessSec: heartbeatFreshnessSec
    });
    if (successDirective.action === "assign_role") {
      maybeQueueDiscordGateRoleAction(session, successDirective, "server");
    }
    const kernelBindingIssued = issueKernelBindingToken(
      {
        sub: session.user_id,
        sid: session.session_id,
        cid: session.client_instance_id,
        did: body.device_id,
        pv: body.policy_version,
        scope: "kernel_bridge"
      },
      {
        secret: config.kernelIntegrity.kernelBindingSigningSecret,
        ttlSec: config.kernelIntegrity.kernelBindingTokenTtlSec
      }
    );

    state.setActiveJti(session.user_id, issued.claims.jti, issued.claims.exp);

    const decisionStatus = versionResult.status === "deprecated" ? "warn" : "ok";
    const reasonCode = (() => {
      if (multiDeviceEvaluation.active === true && multiDeviceEvaluation.action === "warn") {
        return multiDeviceEvaluation.reasonCode;
      }
      if (
        bindingTransitionEvaluation.active === true &&
        bindingTransitionEvaluation.action === "warn"
      ) {
        return bindingTransitionEvaluation.reasonCode;
      }
      if (
        identityPolicyEvaluation.active === true &&
        identityPolicyEvaluation.graceExceeded === true &&
        identityPolicyEvaluation.action === "warn"
      ) {
        return identityPolicyEvaluation.reasonCode;
      }
      if (versionResult.status === "deprecated") return "CLIENT_VERSION_DEPRECATED";
      return null;
    })();
    const effectiveDecisionStatus = reasonCode ? "warn" : decisionStatus;

    return json(res, 200, {
      server_time: new Date().toISOString(),
      decision: {
        status: effectiveDecisionStatus,
        reason_code: reasonCode,
        message: null
      },
      ...buildHeartbeatIssuedSecurityContext(body.policy_version, issued, kernelBindingIssued)
    });
  }

  async function handleVerify(req, res) {
    const token = parseVerifyToken(req);
    if (!token) {
      return json(res, 401, {
        ok: false,
        code: "INVALID_TOKEN",
        message: "attestation token missing"
      });
    }

    const verified = verifyAttestationToken(token, { secret: config.signingSecret });
    if (!verified.ok) {
      return json(res, 401, {
        ok: false,
        code: verified.code,
        message: verified.message
      });
    }

    const claims = verified.claims;
    const teamBan = state.getTeamBan(claims.tid);
    if (teamBan) {
      return json(res, 403, {
        ok: false,
        code: "BANNED_TEAM",
        message: teamBan.reason || "team banned"
      });
    }

    const userBan = state.getUserBan(claims.sub);
    if (userBan) {
      return json(res, 403, {
        ok: false,
        code: "BANNED_USER",
        message: userBan.reason || "user banned"
      });
    }

    const sessionBan = state.getSessionBan(claims.sid);
    if (sessionBan) {
      return json(res, 403, {
        ok: false,
        code: "BANNED_SESSION",
        message: sessionBan.reason || "session banned"
      });
    }

    if (state.isJtiRevoked(claims.jti)) {
      return json(res, 401, {
        ok: false,
        code: "REVOKED_TOKEN",
        message: "token revoked"
      });
    }

    if (!state.isClientOnline(claims.cid)) {
      return json(res, 403, {
        ok: false,
        code: "CLIENT_OFFLINE",
        message: "client heartbeat stale"
      });
    }

    if (state.isClientNoncompliant(claims.cid)) {
      return json(res, 403, {
        ok: false,
        code: "CLIENT_NONCOMPLIANT",
        message: "client health noncompliant"
      });
    }

    const verifySession = state.getSession(claims.sid);
    if (!verifySession) {
      return json(res, 401, {
        ok: false,
        code: "INVALID_TOKEN",
        message: "session not found"
      });
    }

    const verifyClient = state.getClient(verifySession.client_instance_id);
    if (!verifyClient) {
      return json(res, 401, {
        ok: false,
        code: "INVALID_TOKEN",
        message: "client not found"
      });
    }

    const discordLinkedGate = evaluateDiscordLinkedParticipationGate(
      verifySession,
      config.integrationApi,
      Date.now()
    );
    applyDiscordLinkedParticipationGateState(verifySession, discordLinkedGate);
    if (discordLinkedGate.active === true && discordLinkedGate.enforced === true) {
      const linkedGateReasonCode =
        normalizeReasonCode(discordLinkedGate.reasonCode) || "DISCORD_IDENTITY_REQUIRED";
      const linkedGateMessage =
        INTEGRATION_REASON_CODE_DEFINITIONS[linkedGateReasonCode] || discordLinkedGate.message;
      state.addAuditLog({
        action: linkedGateReasonCode,
        actor: "server",
        object_type: "session",
        object_id: verifySession.session_id,
        detail: {
          require_discord_linked: config.integrationApi.discordRequireLinked === true,
          policy_action: discordLinkedGate.action,
          grace_sec: discordLinkedGate.graceSec,
          grace_expires_at: discordLinkedGate.graceExpiresAtIso,
          grace_exceeded: discordLinkedGate.graceExceeded === true,
          source: "verify",
          discord_link_state: normalizeDiscordLinkState(verifySession.discord_link_state, "unlinked"),
          identity_source: normalizeIdentitySource(verifySession.identity_source, "unknown")
        }
      });
      state.setSessionDecision(verifySession.session_id, {
        status: "blocked",
        reason_code: linkedGateReasonCode,
        message: linkedGateMessage,
        score: 0,
        tier: "normal"
      });
      if (discordLinkedGate.action === "blocked") {
        state.setSessionBan(verifySession.session_id, 0, linkedGateReasonCode, linkedGateMessage);
      }
      state.revokeActiveJtiForUser(verifySession.user_id);
      return json(res, 403, {
        ok: false,
        code: linkedGateReasonCode,
        message: linkedGateMessage
      });
    }

    const verifyMultiDeviceEvaluation = evaluateDiscordMultiDevicePolicyState(verifySession);
    applyDiscordMultiDevicePolicyState(verifySession, verifyMultiDeviceEvaluation);
    if (
      verifyMultiDeviceEvaluation.active === true &&
      verifyMultiDeviceEvaluation.enforced === true
    ) {
      state.addAuditLog({
        action: "DISCORD_MULTI_DEVICE_CONFLICT_ENFORCED",
        actor: "server",
        object_type: "session",
        object_id: verifySession.session_id,
        detail: {
          policy_action: verifyMultiDeviceEvaluation.action,
          reason_code: verifyMultiDeviceEvaluation.reasonCode,
          conflict_count: verifyMultiDeviceEvaluation.conflictCount,
          conflicting_session_ids: verifyMultiDeviceEvaluation.conflictingSessionIds,
          canonical_discord_user_id: verifyMultiDeviceEvaluation.canonicalDiscordUserId,
          source: "verify"
        }
      });
      state.revokeActiveJtiForUser(verifySession.user_id);
      return json(res, 403, {
        ok: false,
        code: verifyMultiDeviceEvaluation.reasonCode,
        message:
          INTEGRATION_REASON_CODE_DEFINITIONS[verifyMultiDeviceEvaluation.reasonCode] ||
          "multi-device conflict policy enforced"
      });
    }
    const verifyBindingTransitionEvaluation = evaluateDiscordBindingTransitionState(verifySession);
    applyDiscordBindingTransitionState(verifySession, verifyBindingTransitionEvaluation);
    if (
      verifyBindingTransitionEvaluation.active === true &&
      verifyBindingTransitionEvaluation.enforced === true
    ) {
      state.addAuditLog({
        action: "DISCORD_SESSION_BINDING_ENFORCED",
        actor: "server",
        object_type: "session",
        object_id: verifySession.session_id,
        detail: {
          policy_action: verifyBindingTransitionEvaluation.action,
          reason_code: verifyBindingTransitionEvaluation.reasonCode,
          risk_type: verifyBindingTransitionEvaluation.riskType,
          conflicting_session_ids: verifyBindingTransitionEvaluation.conflictingSessionIds,
          source: "verify",
          ...verifyBindingTransitionEvaluation.metadata
        }
      });
      state.revokeActiveJtiForUser(verifySession.user_id);
      return json(res, 403, {
        ok: false,
        code: verifyBindingTransitionEvaluation.reasonCode,
        message:
          INTEGRATION_REASON_CODE_DEFINITIONS[verifyBindingTransitionEvaluation.reasonCode] ||
          "session binding transition policy enforced"
      });
    }

    const verifyVersionResult = evaluateClientVersion(
      verifyClient.app_version,
      config.versionPolicy
    );
    if (
      verifyVersionResult.status === "invalid" ||
      verifyVersionResult.status === "unsupported"
    ) {
      const versionEvent = buildVersionPolicyEvent(
        {
          session_id: verifySession.session_id,
          user_id: verifySession.user_id,
          client_version: verifyClient.app_version
        },
        verifyVersionResult,
        config.versionPolicy
      );
      if (versionEvent) {
        logStructured(versionEvent, logSink);
      }
      return json(res, 403, {
        ok: false,
        code:
          verifyVersionResult.status === "invalid"
            ? "CLIENT_VERSION_INVALID"
            : "CLIENT_VERSION_UNSUPPORTED",
        message: verifyVersionResult.reason
      });
    }

    const participantGateResult = evaluateParticipantEligibility(
      {
        client_agent_state: verifySession.health_client_agent_state,
        kernel_bridge_state: verifySession.health_kernel_bridge_state,
        kernel_driver_loaded: verifySession.health_kernel_driver_loaded
      },
      config.participantGate
    );
    if (!participantGateResult.ok) {
      return json(res, 403, {
        ok: false,
        code: participantGateResult.code,
        message: participantGateResult.message
      });
    }

    return json(
      res,
      200,
      {
        ok: true,
        user_id: claims.sub,
        team_id: claims.tid,
        client_instance_id: claims.cid,
        policy_version: claims.pv,
        exp: new Date(claims.exp * 1000).toISOString()
      },
      {
        "X-Attest-User": claims.sub,
        "X-Attest-Team": claims.tid,
        "X-Attest-Client": claims.cid,
        "X-Attest-Policy": claims.pv
      }
    );
  }

  function evaluateSubmissionProofEligibility(session, client) {
    const teamBan = state.getTeamBan(session.team_id);
    if (teamBan) {
      return {
        ok: false,
        code: "BANNED_TEAM",
        message: teamBan.reason || "team banned"
      };
    }
    const userBan = state.getUserBan(session.user_id);
    if (userBan) {
      return {
        ok: false,
        code: "BANNED_USER",
        message: userBan.reason || "user banned"
      };
    }
    const sessionBan = state.getSessionBan(session.session_id);
    if (sessionBan) {
      return {
        ok: false,
        code: "BANNED_SESSION",
        message: sessionBan.reason || "session banned"
      };
    }
    if (!state.isClientOnline(session.client_instance_id)) {
      return {
        ok: false,
        code: "CLIENT_OFFLINE",
        message: "client heartbeat stale"
      };
    }
    if (state.isClientNoncompliant(session.client_instance_id)) {
      return {
        ok: false,
        code: "CLIENT_NONCOMPLIANT",
        message: "client health noncompliant"
      };
    }

    const discordLinkedGate = evaluateDiscordLinkedParticipationGate(
      session,
      config.integrationApi,
      Date.now()
    );
    applyDiscordLinkedParticipationGateState(session, discordLinkedGate);
    if (discordLinkedGate.active === true && discordLinkedGate.enforced === true) {
      const linkedGateReasonCode =
        normalizeReasonCode(discordLinkedGate.reasonCode) || "DISCORD_IDENTITY_REQUIRED";
      const linkedGateMessage =
        INTEGRATION_REASON_CODE_DEFINITIONS[linkedGateReasonCode] || discordLinkedGate.message;
      return {
        ok: false,
        code: linkedGateReasonCode,
        message: linkedGateMessage,
        policy_action: discordLinkedGate.action,
        grace_sec: discordLinkedGate.graceSec,
        grace_expires_at: discordLinkedGate.graceExpiresAtIso,
        grace_exceeded: discordLinkedGate.graceExceeded === true
      };
    }

    const multiDeviceEvaluation = evaluateDiscordMultiDevicePolicyState(session);
    applyDiscordMultiDevicePolicyState(session, multiDeviceEvaluation);
    if (multiDeviceEvaluation.active === true && multiDeviceEvaluation.enforced === true) {
      return {
        ok: false,
        code: multiDeviceEvaluation.reasonCode,
        message:
          INTEGRATION_REASON_CODE_DEFINITIONS[multiDeviceEvaluation.reasonCode] ||
          "multi-device conflict policy enforced"
      };
    }
    const bindingTransitionEvaluation = evaluateDiscordBindingTransitionState(session);
    applyDiscordBindingTransitionState(session, bindingTransitionEvaluation);
    if (
      bindingTransitionEvaluation.active === true &&
      bindingTransitionEvaluation.enforced === true
    ) {
      return {
        ok: false,
        code: bindingTransitionEvaluation.reasonCode,
        message:
          INTEGRATION_REASON_CODE_DEFINITIONS[bindingTransitionEvaluation.reasonCode] ||
          "session binding transition policy enforced"
      };
    }

    const freshnessSec = resolveHeartbeatFreshnessSec(session);
    const identityPolicyEvaluation = evaluateDiscordIdentityPolicyState(
      session,
      freshnessSec,
      Date.now()
    );
    applyDiscordIdentityPolicyState(session, identityPolicyEvaluation);
    if (
      identityPolicyEvaluation.active === true &&
      identityPolicyEvaluation.graceExceeded === true &&
      (identityPolicyEvaluation.action === "restricted" ||
        identityPolicyEvaluation.action === "blocked")
    ) {
      return {
        ok: false,
        code: identityPolicyEvaluation.reasonCode,
        message:
          INTEGRATION_REASON_CODE_DEFINITIONS[identityPolicyEvaluation.reasonCode] ||
          "discord identity policy restricted session"
      };
    }

    const participantGateResult = evaluateParticipantEligibility(
      {
        client_agent_state: session.health_client_agent_state,
        kernel_bridge_state: session.health_kernel_bridge_state,
        kernel_driver_loaded: session.health_kernel_driver_loaded
      },
      config.participantGate
    );
    if (!participantGateResult.ok) {
      return {
        ok: false,
        code: participantGateResult.code,
        message: participantGateResult.message
      };
    }

    const versionResult = evaluateClientVersion(client.app_version, config.versionPolicy);
    if (versionResult.status === "invalid" || versionResult.status === "unsupported") {
      return {
        ok: false,
        code:
          versionResult.status === "invalid"
            ? "CLIENT_VERSION_INVALID"
            : "CLIENT_VERSION_UNSUPPORTED",
        message: versionResult.reason
      };
    }

    return {
      ok: true
    };
  }

  async function handleClientSubmissionProof(req, res) {
    const refreshToken = parseBearer(req);
    if (!refreshToken) {
      return json(res, 401, { code: "INVALID_TOKEN", message: "missing refresh token" });
    }
    const tokenCheck = state.validateRefreshToken(refreshToken);
    if (!tokenCheck.ok) {
      return json(res, 401, { code: tokenCheck.code, message: tokenCheck.message });
    }

    const body = await readJsonBody(req);
    const clientInstanceId =
      typeof body.client_instance_id === "string" ? body.client_instance_id.trim() : "";
    const requestedDeviceId = typeof body.device_id === "string" ? body.device_id.trim() : "";
    const purposeRaw = typeof body.purpose === "string" ? body.purpose.trim().toLowerCase() : "submit";
    if (!clientInstanceId) {
      return json(res, 400, {
        code: "BAD_REQUEST",
        message: "client_instance_id is required"
      });
    }
    if (!["submit", "download"].includes(purposeRaw)) {
      return json(res, 400, {
        code: "BAD_REQUEST",
        message: "purpose must be submit|download"
      });
    }

    const ref = tokenCheck.value;
    if (ref.client_instance_id !== clientInstanceId) {
      return json(res, 403, {
        code: "CLIENT_NONCOMPLIANT",
        message: "client instance mismatch"
      });
    }

    const session = state.getSession(ref.session_id);
    if (!session) {
      return json(res, 401, { code: "INVALID_TOKEN", message: "session not found" });
    }
    const client = state.getClient(clientInstanceId);
    if (!client) {
      return json(res, 401, { code: "INVALID_TOKEN", message: "client not found" });
    }
    if (requestedDeviceId && requestedDeviceId !== client.device_id) {
      return json(res, 403, {
        code: "CLIENT_NONCOMPLIANT",
        message: "device mismatch"
      });
    }

    const eligibility = evaluateSubmissionProofEligibility(session, client);
    if (!eligibility.ok) {
      state.addAuditLog({
        action: eligibility.code,
        actor: "server",
        object_type: "session",
        object_id: session.session_id,
        detail: {
          source: "submission_proof",
          require_discord_linked: config.integrationApi.discordRequireLinked === true,
          policy_action:
            typeof eligibility.policy_action === "string" ? eligibility.policy_action : null,
          grace_sec: Number.isFinite(eligibility.grace_sec) ? eligibility.grace_sec : null,
          grace_expires_at:
            typeof eligibility.grace_expires_at === "string" ? eligibility.grace_expires_at : null,
          grace_exceeded: eligibility.grace_exceeded === true
        }
      });
      state.setSessionDecision(session.session_id, {
        status: "blocked",
        reason_code: eligibility.code,
        message: eligibility.message,
        score: 0,
        tier: "normal"
      });
      if (eligibility.policy_action === "blocked") {
        state.setSessionBan(session.session_id, 0, eligibility.code, eligibility.message);
      }
      state.revokeActiveJtiForUser(session.user_id);
      return json(res, 403, {
        code: eligibility.code,
        message: eligibility.message
      });
    }

    const providedNonce = normalizeSubmissionProofNonce(body.proof_nonce);
    const proofNonce = providedNonce || crypto.randomUUID();
    const issuedProof = issueAttestationToken(
      {
        sub: session.user_id,
        tid: session.team_id,
        sid: session.session_id,
        cid: session.client_instance_id,
        did: client.device_id,
        ppr: purposeRaw,
        pnc: proofNonce
      },
      {
        secret: config.integrationApi.submissionProofSigningSecret,
        ttlSec: config.integrationApi.submissionProofTtlSec
      }
    );
    const proofExpiresAt = new Date(issuedProof.claims.exp * 1000).toISOString();
    state.addAuditLog({
      action: "CLIENT_SUBMISSION_PROOF_ISSUED",
      actor: "server",
      object_type: "session",
      object_id: session.session_id,
      detail: {
        purpose: purposeRaw,
        user_id: session.user_id,
        client_instance_id: session.client_instance_id,
        device_id: client.device_id,
        expires_at: proofExpiresAt,
        nonce_sha256: crypto.createHash("sha256").update(proofNonce).digest("hex")
      }
    });

    return json(res, 200, {
      issued: true,
      proof_token: issuedProof.token,
      proof_nonce: proofNonce,
      expires_at: proofExpiresAt,
      binding: {
        user_id: session.user_id,
        team_id: session.team_id,
        session_id: session.session_id,
        client_instance_id: session.client_instance_id,
        device_id: client.device_id,
        purpose: purposeRaw
      },
      server_time: new Date().toISOString()
    });
  }

  async function handleEvents(req, res) {
    const refreshToken = parseBearer(req);
    if (!refreshToken) {
      return json(res, 401, { code: "INVALID_TOKEN", message: "missing refresh token" });
    }
    const tokenCheck = state.validateRefreshToken(refreshToken);
    if (!tokenCheck.ok) {
      return json(res, 401, { code: tokenCheck.code, message: tokenCheck.message });
    }

    const body = await readJsonBody(req);
    if (
      !body.client_instance_id ||
      !body.policy_version ||
      !Array.isArray(body.events) ||
      body.events.length === 0
    ) {
      return json(res, 400, { code: "BAD_REQUEST", message: "invalid events payload" });
    }

    const ref = tokenCheck.value;
    if (ref.client_instance_id !== body.client_instance_id) {
      return json(res, 403, {
        code: "CLIENT_NONCOMPLIANT",
        message: "client instance mismatch"
      });
    }

    const session = state.getSession(ref.session_id);
    if (!session) {
      return json(res, 401, { code: "INVALID_TOKEN", message: "session not found" });
    }
    if (state.getSessionBan(session.session_id)) {
      return json(res, 403, { code: "BANNED_SESSION", message: "session banned" });
    }
    const client = state.getClient(body.client_instance_id);
    if (!client) {
      return json(res, 401, { code: "INVALID_TOKEN", message: "client not found" });
    }

    const discordLinkedGate = evaluateDiscordLinkedParticipationGate(
      session,
      config.integrationApi,
      Date.now()
    );
    applyDiscordLinkedParticipationGateState(session, discordLinkedGate);
    if (discordLinkedGate.active === true && discordLinkedGate.enforced === true) {
      const linkedGateReasonCode =
        normalizeReasonCode(discordLinkedGate.reasonCode) || "DISCORD_IDENTITY_REQUIRED";
      const linkedGateMessage =
        INTEGRATION_REASON_CODE_DEFINITIONS[linkedGateReasonCode] || discordLinkedGate.message;
      state.revokeActiveJtiForUser(session.user_id);
      state.setSessionDecision(session.session_id, {
        status: "blocked",
        reason_code: linkedGateReasonCode,
        message: linkedGateMessage,
        score: 0,
        tier: "normal"
      });
      if (discordLinkedGate.action === "blocked") {
        state.setSessionBan(session.session_id, 0, linkedGateReasonCode, linkedGateMessage);
      }
      state.addAuditLog({
        action: linkedGateReasonCode,
        actor: "server",
        object_type: "session",
        object_id: session.session_id,
        detail: {
          require_discord_linked: config.integrationApi.discordRequireLinked === true,
          policy_action: discordLinkedGate.action,
          grace_sec: discordLinkedGate.graceSec,
          grace_expires_at: discordLinkedGate.graceExpiresAtIso,
          grace_exceeded: discordLinkedGate.graceExceeded === true,
          source: "events",
          discord_link_state: normalizeDiscordLinkState(session.discord_link_state, "unlinked"),
          identity_source: normalizeIdentitySource(session.identity_source, "unknown")
        }
      });
      return json(res, 403, {
        code: linkedGateReasonCode,
        message: linkedGateMessage,
        decision: {
          status: "blocked",
          reason_code: linkedGateReasonCode,
          message: linkedGateMessage
        }
      });
    }

    const multiDeviceEvaluation = evaluateDiscordMultiDevicePolicyState(session);
    applyDiscordMultiDevicePolicyState(session, multiDeviceEvaluation);
    if (multiDeviceEvaluation.active === true && multiDeviceEvaluation.enforced === true) {
      state.revokeActiveJtiForUser(session.user_id);
      state.setSessionDecision(session.session_id, {
        status: "blocked",
        reason_code: multiDeviceEvaluation.reasonCode,
        message:
          INTEGRATION_REASON_CODE_DEFINITIONS[multiDeviceEvaluation.reasonCode] ||
          "multi-device conflict policy enforced",
        score: 0,
        tier: "normal"
      });
      state.addAuditLog({
        action: "DISCORD_MULTI_DEVICE_CONFLICT_ENFORCED",
        actor: "server",
        object_type: "session",
        object_id: session.session_id,
        detail: {
          policy_action: multiDeviceEvaluation.action,
          reason_code: multiDeviceEvaluation.reasonCode,
          conflict_count: multiDeviceEvaluation.conflictCount,
          conflicting_session_ids: multiDeviceEvaluation.conflictingSessionIds,
          canonical_discord_user_id: multiDeviceEvaluation.canonicalDiscordUserId,
          source: "events"
        }
      });
      return json(res, 403, {
        code: multiDeviceEvaluation.reasonCode,
        message:
          INTEGRATION_REASON_CODE_DEFINITIONS[multiDeviceEvaluation.reasonCode] ||
          "multi-device conflict policy enforced",
        decision: {
          status: "blocked",
          reason_code: multiDeviceEvaluation.reasonCode,
          message:
            INTEGRATION_REASON_CODE_DEFINITIONS[multiDeviceEvaluation.reasonCode] ||
            "multi-device conflict policy enforced"
        }
      });
    }
    const bindingTransitionEvaluation = evaluateDiscordBindingTransitionState(session);
    applyDiscordBindingTransitionState(session, bindingTransitionEvaluation);
    if (
      bindingTransitionEvaluation.active === true &&
      bindingTransitionEvaluation.enforced === true
    ) {
      state.revokeActiveJtiForUser(session.user_id);
      state.setSessionDecision(session.session_id, {
        status: "blocked",
        reason_code: bindingTransitionEvaluation.reasonCode,
        message:
          INTEGRATION_REASON_CODE_DEFINITIONS[bindingTransitionEvaluation.reasonCode] ||
          "session binding transition policy enforced",
        score: 0,
        tier: "normal"
      });
      state.addAuditLog({
        action: "DISCORD_SESSION_BINDING_ENFORCED",
        actor: "server",
        object_type: "session",
        object_id: session.session_id,
        detail: {
          policy_action: bindingTransitionEvaluation.action,
          reason_code: bindingTransitionEvaluation.reasonCode,
          risk_type: bindingTransitionEvaluation.riskType,
          conflicting_session_ids: bindingTransitionEvaluation.conflictingSessionIds,
          source: "events",
          ...bindingTransitionEvaluation.metadata
        }
      });
      return json(res, 403, {
        code: bindingTransitionEvaluation.reasonCode,
        message:
          INTEGRATION_REASON_CODE_DEFINITIONS[bindingTransitionEvaluation.reasonCode] ||
          "session binding transition policy enforced",
        decision: {
          status: "blocked",
          reason_code: bindingTransitionEvaluation.reasonCode,
          message:
            INTEGRATION_REASON_CODE_DEFINITIONS[bindingTransitionEvaluation.reasonCode] ||
            "session binding transition policy enforced"
        }
      });
    }

    const eventsVersionResult = evaluateClientVersion(client.app_version, config.versionPolicy);
    if (
      eventsVersionResult.status === "invalid" ||
      eventsVersionResult.status === "unsupported"
    ) {
      const reasonCode =
        eventsVersionResult.status === "invalid"
          ? "CLIENT_VERSION_INVALID"
          : "CLIENT_VERSION_UNSUPPORTED";
      const versionEvent = buildVersionPolicyEvent(
        {
          session_id: session.session_id,
          user_id: session.user_id,
          client_version: client.app_version
        },
        eventsVersionResult,
        config.versionPolicy
      );
      if (versionEvent) {
        const eventRecord = {
          event_id: crypto.randomUUID(),
          received_at: new Date().toISOString(),
          team_id: session.team_id,
          client_instance_id: body.client_instance_id,
          policy_version: body.policy_version,
          ...versionEvent
        };
        state.appendEvents([eventRecord]);
        logStructured(eventRecord, logSink);
      }
      state.revokeActiveJtiForUser(session.user_id);
      state.setSessionDecision(session.session_id, {
        status: "blocked",
        reason_code: reasonCode,
        message: eventsVersionResult.reason,
        score: 0,
        tier: "normal"
      });
      state.addAuditLog({
        action: "CLIENT_VERSION_POLICY_REJECTED",
        actor: "server",
        object_type: "session",
        object_id: session.session_id,
        detail: {
          reason_code: reasonCode,
          client_version: client.app_version
        }
      });
      return json(res, 403, {
        code: reasonCode,
        message: eventsVersionResult.reason,
        decision: {
          status: "blocked",
          reason_code: reasonCode,
          message: eventsVersionResult.reason
        }
      });
    }

    const canonicalizedEvents = [];
    const identityOverrides = [];
    for (let index = 0; index < body.events.length; index += 1) {
      const rawEvent = body.events[index];
      if (!isPlainObject(rawEvent)) {
        canonicalizedEvents.push(rawEvent);
        continue;
      }

      const mismatches = {};
      if (rawEvent.session_id !== session.session_id) {
        mismatches.session_id = {
          raw: rawEvent.session_id || null,
          canonical: session.session_id
        };
      }
      if (rawEvent.user_id !== session.user_id) {
        mismatches.user_id = {
          raw: rawEvent.user_id || null,
          canonical: session.user_id
        };
      }
      if (rawEvent.client_version !== client.app_version) {
        mismatches.client_version = {
          raw: rawEvent.client_version || null,
          canonical: client.app_version
        };
      }

      if (Object.keys(mismatches).length > 0) {
        identityOverrides.push({
          index,
          mismatches
        });
      }

      canonicalizedEvents.push(normalizeServerEventSeverity({
        ...rawEvent,
        session_id: session.session_id,
        user_id: session.user_id,
        client_version: client.app_version
      }, config.llmMonitor.cliHints));
    }

    const rejectedBeforeCount = Array.isArray(eventStore.rejected) ? eventStore.rejected.length : 0;
    const ingestResults = eventPipeline.ingestEvents(canonicalizedEvents, {
      failFast: false,
      sessionHistoryById: {
        [session.session_id]: state.getEventsBySession(session.session_id)
      },
      maxKernelSignalsPerBatch: config.kernelIntegrity.maxKernelSignalsPerBatch,
      maxBridgeEmitDeltaMs: config.kernelIntegrity.maxBridgeEmitDeltaMs,
      maxBridgeCounterGap: config.kernelIntegrity.maxBridgeCounterGap,
      maxBridgeStalenessMs: config.kernelIntegrity.maxBridgeStalenessMs,
      requireBridgeSignature: config.kernelIntegrity.requireBridgeSignature,
      kernelBridgeSigningSecret: config.kernelIntegrity.kernelBridgeSigningSecret,
      requireBridgeNonce: config.kernelIntegrity.requireBridgeNonce,
      requireBridgeEmittedAt: config.kernelIntegrity.requireBridgeEmittedAt,
      requireSessionBindingToken: config.kernelIntegrity.requireSessionBindingToken,
      kernelBindingSigningSecret: config.kernelIntegrity.kernelBindingSigningSecret,
      clientInstanceId: body.client_instance_id
    });
    if (typeof state.addEventRejections === "function" && Array.isArray(eventStore.rejected)) {
      const latestRejections = eventStore.rejected.slice(rejectedBeforeCount).map((item) => ({
        received_at: new Date().toISOString(),
        event_type:
          item &&
          item.raw_event &&
          typeof item.raw_event.event_type === "string"
            ? item.raw_event.event_type
            : null,
        index: item && Number.isFinite(Number(item.index)) ? Number(item.index) : null,
        error:
          item && item.error
            ? item.error
            : {
                code: "EVENT_REJECTED",
                message: "event rejected by ingestion pipeline"
              },
        event: item && item.raw_event ? item.raw_event : null
      }));
      state.addEventRejections(latestRejections);
    }
    const acceptedEvents = [];
    for (const result of ingestResults) {
      if (!result.accepted) continue;
      for (const event of result.persistedEvents) {
        acceptedEvents.push({
          event_id: crypto.randomUUID(),
          received_at: new Date().toISOString(),
          team_id: session.team_id,
          client_instance_id: body.client_instance_id,
          policy_version: body.policy_version,
          ...event,
          session_id: session.session_id,
          user_id: session.user_id,
          client_version: client.app_version
        });
      }
    }

    for (const override of identityOverrides) {
      const overrideEvent = {
        event_id: crypto.randomUUID(),
        received_at: new Date().toISOString(),
        team_id: session.team_id,
        client_instance_id: body.client_instance_id,
        policy_version: body.policy_version,
        event_type: "EVENT_IDENTITY_OVERRIDE_APPLIED",
        severity: "medium",
        timestamp: new Date().toISOString(),
        session_id: session.session_id,
        user_id: session.user_id,
        client_version: client.app_version,
        evidence: {
          index: override.index,
          mismatches: override.mismatches
        }
      };
      acceptedEvents.push(overrideEvent);
      logStructured(overrideEvent, logSink);
      state.addAuditLog({
        action: "EVENT_IDENTITY_OVERRIDE",
        actor: "server",
        object_type: "session",
        object_id: session.session_id,
        detail: {
          index: override.index,
          mismatched_fields: Object.keys(override.mismatches)
        }
      });
    }

    let kernelSignalEvents = 0;
    let kernelValidationWarnEvents = 0;
    for (const event of acceptedEvents) {
      if (!String(event.event_type || "").startsWith("KERNEL_")) continue;
      kernelSignalEvents += 1;
      const validation =
        event.evidence &&
        typeof event.evidence === "object" &&
        event.evidence.kernel_validation &&
        typeof event.evidence.kernel_validation === "object"
          ? event.evidence.kernel_validation
          : null;
      if (!validation || validation.status !== "warn") continue;
      kernelValidationWarnEvents += 1;
      state.addAuditLog({
        action: "KERNEL_SIGNAL_VALIDATION_WARN",
        actor: "server",
        object_type: "session",
        object_id: session.session_id,
        detail: {
          event_id: event.event_id,
          event_type: event.event_type,
          failed_rules: Array.isArray(validation.failed_rules) ? validation.failed_rules : [],
          replay_key: validation.replay_key || null
        }
      });
    }

    state.appendEvents(acceptedEvents);

    const kernelSignalRate = evaluateKernelSignalRate({
      sessionEvents: state.getEventsBySession(session.session_id),
      nowMs: Date.now(),
      windowSec: config.kernelIntegrity.signalRateWindowSec,
      minSignalsPerMinute: config.kernelIntegrity.minKernelSignalsPerMinute
    });

    const scoringTargets = acceptedEvents.filter((event) =>
      Object.prototype.hasOwnProperty.call(DEFAULT_EVENT_WEIGHTS, event.event_type)
    );
    const scoring = scoreEvents(scoringTargets);
    const hasImmediateBlockSignal = scoringTargets.some(
      (event) =>
        event.event_type === "DLL_INJECTION_DETECTED" ||
        event.event_type === "SESSION_INTEGRITY_FAILURE"
    );

    const hasKernelValidationWarnSignal = kernelValidationWarnEvents > 0;
    const missingRequiredKernelSignals =
      config.kernelIntegrity.requireSignals &&
      kernelSignalEvents < config.kernelIntegrity.minKernelSignalsPerBatch;
    const lowKernelSignalRate = kernelSignalRate.enabled && kernelSignalRate.below_required_rate;
    const nowMs = Date.now();
    const rawCliEnforcement = evaluateCliEnforcementFromEvents(acceptedEvents, config.llmMonitor);
    const cliOverrideContext = resolveCliOverrideContext(
      state,
      session.session_id,
      config.llmMonitor.cliOverrideWindowSec,
      nowMs
    );
    const cliEnforcement = applyCliFpGuardrails(rawCliEnforcement, {
      minEvidenceCount: config.llmMonitor.cliMinEvidenceCount,
      cooldownSec: config.llmMonitor.cliEnforcementCooldownSec,
      nowMs,
      lastEnforcedAtMs: parseIsoToMs(session.cli_enforcement_last_at),
      override: cliOverrideContext
    });
    let decision = { status: "ok", reason_code: null, message: null };
    let issueUserBanOnBlockedDecision = true;
    if (hasImmediateBlockSignal) {
      decision = {
        status: "blocked",
        reason_code: "SESSION_INTEGRITY_FAILURE",
        message: "critical integrity event detected"
      };
    } else if (missingRequiredKernelSignals) {
      decision = {
        status: "blocked",
        reason_code: "KERNEL_REQUIRED_SIGNAL_MISSING",
        message: `required kernel telemetry missing (observed=${kernelSignalEvents}, required=${config.kernelIntegrity.minKernelSignalsPerBatch})`
      };
      state.addAuditLog({
        action: "KERNEL_REQUIRED_SIGNAL_MISSING",
        actor: "server",
        object_type: "session",
        object_id: session.session_id,
        detail: {
          observed_kernel_signals: kernelSignalEvents,
          required_kernel_signals: config.kernelIntegrity.minKernelSignalsPerBatch
        }
      });
    } else if (lowKernelSignalRate) {
      decision = {
        status: "blocked",
        reason_code: "KERNEL_SIGNAL_RATE_TOO_LOW",
        message: `kernel signal rate too low (observed=${kernelSignalRate.observed_signals_per_minute}/min, required=${kernelSignalRate.min_signals_per_minute}/min, window=${kernelSignalRate.window_sec}s)`
      };
      state.addAuditLog({
        action: "KERNEL_SIGNAL_RATE_TOO_LOW",
        actor: "server",
        object_type: "session",
        object_id: session.session_id,
        detail: {
          observed_signals_per_minute: kernelSignalRate.observed_signals_per_minute,
          required_signals_per_minute: kernelSignalRate.min_signals_per_minute,
          observed_signals: kernelSignalRate.observed_signals,
          window_sec: kernelSignalRate.window_sec
        }
      });
    } else if (
      config.kernelIntegrity.warnAction === "block" &&
      hasKernelValidationWarnSignal
    ) {
      decision = {
        status: "blocked",
        reason_code: "KERNEL_INTEGRITY_WARN_BLOCK",
        message: "kernel integrity validation warning triggered block policy"
      };
    } else if (cliEnforcement.enforced === true) {
      decision = {
        status: cliEnforcement.status,
        reason_code: cliEnforcement.reason_code,
        message: cliEnforcement.message
      };
      issueUserBanOnBlockedDecision = cliEnforcement.issue_user_ban !== false;
      session.cli_enforcement_last_at = new Date(nowMs).toISOString();
      session.cli_enforcement_last_reason_code = cliEnforcement.reason_code || null;
      session.cli_enforcement_last_confidence = Number.isFinite(cliEnforcement.confidence)
        ? cliEnforcement.confidence
        : null;
      state.addAuditLog({
        action: "CLI_ENFORCEMENT_TRIGGERED",
        actor: "server",
        object_type: "session",
        object_id: session.session_id,
        detail: {
          policy_action: cliEnforcement.policy_action,
          threshold: cliEnforcement.threshold,
          confidence: cliEnforcement.confidence,
          reason_code: cliEnforcement.reason_code,
          reason_count: cliEnforcement.reason_count,
          top_reasons: cliEnforcement.top_reasons,
          guardrails: cliEnforcement.guardrails
        }
      });
    } else if (cliEnforcement.guardrails && cliEnforcement.guardrails.suppressed === true) {
      state.addAuditLog({
        action: "CLI_ENFORCEMENT_SUPPRESSED",
        actor: "server",
        object_type: "session",
        object_id: session.session_id,
        detail: {
          policy_action: cliEnforcement.policy_action,
          threshold: cliEnforcement.threshold,
          confidence: cliEnforcement.confidence,
          reason_count: cliEnforcement.reason_count,
          suppress_reason_code: cliEnforcement.guardrails.suppress_reason_code,
          suppress_reason: cliEnforcement.guardrails.suppress_reason,
          guardrails: cliEnforcement.guardrails
        }
      });
    } else if (scoring.finalScore >= 90) {
      decision = {
        status: "blocked",
        reason_code: "RISK_SCORE_BLOCK",
        message: "risk score exceeded block threshold"
      };
    } else if (scoring.finalScore >= 60) {
      decision = {
        status: "warn",
        reason_code: "HIGH_RISK_SCORE",
        message: "risk score exceeded warn threshold"
      };
    } else if (
      config.kernelIntegrity.warnAction === "warn" &&
      hasKernelValidationWarnSignal
    ) {
      decision = {
        status: "warn",
        reason_code: "KERNEL_INTEGRITY_WARN",
        message: "kernel integrity validation warning observed"
      };
    }

    if (decision.status === "ok" && multiDeviceEvaluation.active === true && multiDeviceEvaluation.action === "warn") {
      decision = {
        status: "warn",
        reason_code: multiDeviceEvaluation.reasonCode,
        message:
          INTEGRATION_REASON_CODE_DEFINITIONS[multiDeviceEvaluation.reasonCode] ||
          "multi-device conflict detected"
      };
    }

    if (decision.status === "blocked") {
      if (
        issueUserBanOnBlockedDecision &&
        config.integrationApi.autoBanBlockedDecision === true &&
        !state.getUserBan(session.user_id)
      ) {
        state.createBan({
          scope: "user",
          target_id: session.user_id,
          reason: decision.message,
          reason_code: "BANNED_USER",
          duration_sec: 600,
          created_by: "system:auto_blocked_decision"
        });
      } else if (
        issueUserBanOnBlockedDecision &&
        config.integrationApi.autoBanBlockedDecision !== true
      ) {
        state.addAuditLog({
          action: "AUTO_USER_BAN_SKIPPED",
          actor: "server",
          object_type: "session",
          object_id: session.session_id,
          detail: {
            reason_code: decision.reason_code,
            decision_status: decision.status,
            auto_ban_blocked_decision: false
          }
        });
      }
      state.revokeActiveJtiForUser(session.user_id);
    }
    state.setSessionDecision(session.session_id, {
      ...decision,
      score: scoring.finalScore,
      tier: scoring.tier
    });

    return json(res, 202, {
      accepted: true,
      server_time: new Date().toISOString(),
      decision: {
        ...decision,
        score: scoring.finalScore,
        tier: scoring.tier
      },
      summary: {
        total_events: body.events.length,
        accepted_events: ingestResults.filter((result) => result.accepted).length,
        rejected_events: ingestResults.filter((result) => !result.accepted).length,
        canonicalized_events: identityOverrides.length,
        kernel_signal_events: kernelSignalEvents,
        kernel_validation_warn_events: kernelValidationWarnEvents,
        kernel_signal_rate: kernelSignalRate,
        cli_enforcement: {
          policy_action: cliEnforcement.policy_action,
          threshold: cliEnforcement.threshold,
          detected: cliEnforcement.detected,
          confidence: cliEnforcement.confidence,
          enforced: cliEnforcement.enforced,
          reason_code: cliEnforcement.reason_code,
          reason_count: cliEnforcement.reason_count,
          candidate_enforced: cliEnforcement.candidate_enforced === true,
          guardrails: cliEnforcement.guardrails
        },
        multi_device_enforcement: {
          policy_action: multiDeviceEvaluation.action,
          active: multiDeviceEvaluation.active,
          enforced: multiDeviceEvaluation.enforced,
          reason_code: multiDeviceEvaluation.reasonCode,
          conflict_count: multiDeviceEvaluation.conflictCount,
          conflicting_session_ids: multiDeviceEvaluation.conflictingSessionIds
        }
      }
    });
  }

  async function handleAdminLogin(req, res) {
    if (config.adminApiKey) {
      const apiKey = req.headers["x-admin-key"];
      if (apiKey !== config.adminApiKey) {
        return json(res, 403, {
          code: "ADMIN_FORBIDDEN",
          message: "invalid admin api key"
        });
      }
    }

    const body = await readJsonBody(req);
    const username = body && typeof body.username === "string" ? body.username.trim() : "";
    const password = body && typeof body.password === "string" ? body.password : "";
    if (!username || !password) {
      return json(res, 400, {
        code: "BAD_REQUEST",
        message: "username and password are required"
      });
    }

    const user = config.adminUsers.find(
      (item) =>
        item &&
        item.username === username &&
        item.password === password &&
        typeof item.role === "string"
    );
    if (!user || !ADMIN_ROLE_PERMISSIONS[user.role]) {
      return json(res, 401, {
        code: "ADMIN_AUTH_FAILED",
        message: "invalid admin credentials"
      });
    }

    const issued = issueAdminToken(
      {
        sub: user.username,
        role: user.role
      },
      {
        secret: config.adminSigningSecret,
        ttlSec: config.adminTokenTtlSec
      }
    );

    state.addAuditLog({
      action: "ADMIN_AUTH_LOGIN",
      actor: user.username,
      object_type: "admin_user",
      object_id: user.username,
      detail: { role: user.role }
    });

    return json(res, 200, {
      actor: user.username,
      role: user.role,
      access_token: issued.token,
      token_type: "bearer",
      expires_at: new Date(issued.claims.exp * 1000).toISOString()
    });
  }

  function resolveComputedSessionStatus(session, decision) {
    if (!session || typeof session !== "object") return "unknown";
    const identityEnforcementState = normalizeStateToken(
      session.discord_identity_enforcement_state,
      "none"
    );
    const multiDeviceEnforcementState = normalizeStateToken(
      session.discord_multi_device_enforcement_state,
      "none"
    );
    const bindingEnforcementState = normalizeStateToken(
      session.session_binding_enforcement_state,
      "none"
    );
    if (identityEnforcementState === "blocked" || identityEnforcementState === "restricted") {
      return "BLOCKED";
    }
    if (multiDeviceEnforcementState === "blocked" || multiDeviceEnforcementState === "restricted") {
      return "BLOCKED";
    }
    if (bindingEnforcementState === "blocked" || bindingEnforcementState === "restricted") {
      return "BLOCKED";
    }
    if (
      state.getTeamBan(session.team_id) ||
      state.getUserBan(session.user_id) ||
      state.getSessionBan(session.session_id)
    ) {
      return "BLOCKED";
    }
    if (session.ended_at || !state.isClientOnline(session.client_instance_id)) {
      return "OFFLINE";
    }
    if (decision && decision.status === "blocked") {
      return "BLOCKED";
    }
    if (
      identityEnforcementState === "warn" ||
      multiDeviceEnforcementState === "warn" ||
      bindingEnforcementState === "warn"
    ) {
      return "WARN";
    }
    if (decision && decision.status === "warn") {
      return "WARN";
    }
    return "ACTIVE";
  }

  function normalizeReasonCode(value) {
    if (typeof value !== "string") return null;
    const normalized = value.trim().toUpperCase().replace(/[^A-Z0-9_]/g, "_");
    return normalized.length > 0 ? normalized : null;
  }

  function resolveSessionDecisionReasonCode(session, decision) {
    if (decision && typeof decision.reason_code === "string" && decision.reason_code.trim()) {
      return normalizeReasonCode(decision.reason_code);
    }
    const sessionBan = state.getSessionBan(session.session_id);
    if (sessionBan && typeof sessionBan.reason_code === "string" && sessionBan.reason_code.trim()) {
      return normalizeReasonCode(sessionBan.reason_code);
    }
    const userBan = state.getUserBan(session.user_id);
    if (userBan && typeof userBan.reason_code === "string" && userBan.reason_code.trim()) {
      return normalizeReasonCode(userBan.reason_code);
    }
    const teamBan = state.getTeamBan(session.team_id);
    if (teamBan && typeof teamBan.reason_code === "string" && teamBan.reason_code.trim()) {
      return normalizeReasonCode(teamBan.reason_code);
    }
    return null;
  }

  function maybeApplyOfflineSessionAutoBan(session, freshnessSec, source = "server") {
    if (!session || typeof session !== "object") return null;
    if (config.integrationApi.autoBanOfflineSession !== true) return null;
    if (session.ended_at) return null;
    if (!Number.isFinite(freshnessSec)) return null;
    if (freshnessSec <= config.integrationApi.heartbeatStaleSec) return null;
    if (
      state.getSessionBan(session.session_id) ||
      state.getUserBan(session.user_id) ||
      state.getTeamBan(session.team_id)
    ) {
      return null;
    }

    const reasonCode = "HEARTBEAT_STALE";
    const reason = `automatic session block due to stale heartbeat (freshness_sec=${freshnessSec}, threshold_sec=${config.integrationApi.heartbeatStaleSec})`;
    const created = state.createBan({
      scope: "session",
      target_id: session.session_id,
      reason,
      reason_code: reasonCode,
      duration_sec: 0,
      created_by: "system:auto_offline"
    });
    state.setSessionDecision(session.session_id, {
      status: "blocked",
      reason_code: reasonCode,
      message: INTEGRATION_REASON_CODE_DEFINITIONS[reasonCode] || reason,
      score: 0,
      tier: "normal"
    });
    state.revokeActiveJtiForUser(session.user_id);
    state.addAuditLog({
      action: "AUTO_SESSION_BAN_ON_OFFLINE",
      actor: "server",
      object_type: "session",
      object_id: session.session_id,
      detail: {
        ban_id: created.ban_id,
        reason_code: reasonCode,
        freshness_sec: freshnessSec,
        heartbeat_stale_threshold_sec: config.integrationApi.heartbeatStaleSec,
        source
      }
    });
    return created;
  }

  function resolveHeartbeatFreshnessSec(session, nowMs = Date.now()) {
    const heartbeatTs =
      session && typeof session.last_heartbeat_at === "string"
        ? Date.parse(session.last_heartbeat_at)
        : NaN;
    if (Number.isNaN(heartbeatTs)) return null;
    const delta = Math.floor((nowMs - heartbeatTs) / 1000);
    return delta < 0 ? 0 : delta;
  }

  function resolveDiscordIdentityReasonCode(session, freshnessSec) {
    if (!session || typeof session !== "object") return null;
    const canonicalDiscordUserId =
      typeof session.discord_user_id === "string" ? session.discord_user_id.trim() : "";
    if (!canonicalDiscordUserId) return null;

    const hintSource = normalizeIdentitySource(session.identity_hint_source, "unknown");
    const hintState = normalizeDiscordLinkState(session.identity_hint_link_state, "unknown");
    const hintedDiscordUserId =
      typeof session.identity_hint_discord_user_id === "string"
        ? session.identity_hint_discord_user_id.trim()
        : "";

    if (hintSource === "sdk_hint" && hintedDiscordUserId && hintedDiscordUserId !== canonicalDiscordUserId) {
      return "DISCORD_IDENTITY_ACCOUNT_MISMATCH";
    }
    if (hintSource === "sdk_hint" && hintState === "unlinked") {
      return "DISCORD_IDENTITY_LOGOUT_DETECTED";
    }
    if (hintSource === "sdk_hint" && (hintState === "error" || hintState === "unknown")) {
      return "DISCORD_CLIENT_UNAVAILABLE";
    }
    if (freshnessSec !== null && freshnessSec > config.integrationApi.heartbeatStaleSec) {
      return "DISCORD_IDENTITY_OFFLINE_STALE";
    }
    return null;
  }

  function resolveDiscordIdentityPolicyProfile(reasonCode) {
    const normalizedReasonCode = normalizeReasonCode(reasonCode);
    if (!normalizedReasonCode) {
      return {
        action: "none",
        graceSec: 0,
        profile: "none"
      };
    }
    if (normalizedReasonCode === "DISCORD_CLIENT_UNAVAILABLE") {
      return {
        action: normalizeDiscordIdentityPolicyAction(
          config.integrationApi.discordClientUnavailablePolicy,
          "warn"
        ),
        graceSec: normalizePositiveInteger(config.integrationApi.discordClientUnavailableGraceSec, 120),
        profile: "client_unavailable"
      };
    }
    return {
      action: normalizeDiscordIdentityPolicyAction(
        config.integrationApi.discordIdentityLossPolicy,
        "restricted"
      ),
      graceSec: normalizePositiveInteger(config.integrationApi.discordIdentityLossGraceSec, 30),
      profile: "identity_loss"
    };
  }

  function evaluateDiscordIdentityPolicyState(session, freshnessSec, nowMs = Date.now()) {
    const reasonCode = resolveDiscordIdentityReasonCode(session, freshnessSec);
    if (!reasonCode) {
      return {
        active: false,
        reasonCode: null,
        action: "none",
        graceSec: 0,
        profile: "none",
        lossSinceIso: null,
        graceExpiresAtIso: null,
        graceExceeded: false
      };
    }

    const profile = resolveDiscordIdentityPolicyProfile(reasonCode);
    let lossSinceMs = Number.NaN;
    if (
      session &&
      typeof session.discord_identity_policy_reason_code === "string" &&
      normalizeReasonCode(session.discord_identity_policy_reason_code) === reasonCode &&
      typeof session.discord_identity_loss_since === "string"
    ) {
      lossSinceMs = Date.parse(session.discord_identity_loss_since);
    }
    if (!Number.isFinite(lossSinceMs)) {
      lossSinceMs = nowMs;
    }
    const graceExpiresMs = lossSinceMs + profile.graceSec * 1000;
    return {
      active: true,
      reasonCode,
      action: profile.action,
      graceSec: profile.graceSec,
      profile: profile.profile,
      lossSinceIso: new Date(lossSinceMs).toISOString(),
      graceExpiresAtIso: new Date(graceExpiresMs).toISOString(),
      graceExceeded: nowMs >= graceExpiresMs
    };
  }

  function applyDiscordIdentityPolicyState(session, evaluation) {
    if (!session || typeof session !== "object") return;
    if (!evaluation || evaluation.active !== true) {
      session.discord_identity_policy = "none";
      session.discord_identity_policy_reason_code = null;
      session.discord_identity_loss_since = null;
      session.discord_identity_grace_expires_at = null;
      session.discord_identity_enforcement_state = "none";
      if (session.discord_identity_revoke_state !== "requested") {
        session.discord_identity_revoke_state = "none";
        session.discord_identity_revoke_skip_reason = null;
        if (session.discord_identity_revoke_action_id == null) {
          session.discord_identity_revoke_requested_at = null;
        }
      }
      return;
    }

    session.discord_identity_policy = evaluation.action;
    session.discord_identity_policy_reason_code = evaluation.reasonCode;
    session.discord_identity_loss_since = evaluation.lossSinceIso;
    session.discord_identity_grace_expires_at = evaluation.graceExpiresAtIso;
    if (!evaluation.graceExceeded) {
      session.discord_identity_enforcement_state = "grace";
    } else if (evaluation.action === "warn") {
      session.discord_identity_enforcement_state = "warn";
    } else if (evaluation.action === "blocked") {
      session.discord_identity_enforcement_state = "blocked";
    } else if (evaluation.action === "restricted") {
      session.discord_identity_enforcement_state = "restricted";
    } else {
      session.discord_identity_enforcement_state = "none";
    }
  }

  function resolveCanonicalSessionDiscordUserId(session) {
    if (!session || typeof session !== "object") return "";
    const linkedIdentity = state.getDiscordIdentityByUserId(session.user_id);
    if (
      linkedIdentity &&
      typeof linkedIdentity.discord_user_id === "string" &&
      linkedIdentity.discord_user_id.trim().length > 0
    ) {
      return linkedIdentity.discord_user_id.trim();
    }
    if (typeof session.discord_user_id === "string" && session.discord_user_id.trim().length > 0) {
      return session.discord_user_id.trim();
    }
    return "";
  }

  function resolveMultiDeviceConflictReasonCode(action) {
    if (action === "blocked") return "DISCORD_MULTI_DEVICE_CONFLICT_BLOCKED";
    if (action === "restricted") return "DISCORD_MULTI_DEVICE_CONFLICT_RESTRICTED";
    return "DISCORD_MULTI_DEVICE_CONFLICT";
  }

  function evaluateDiscordMultiDevicePolicyState(session, nowMs = Date.now()) {
    const policyAction = normalizeMultiDevicePolicyAction(
      config.integrationApi.discordMultiDevicePolicy,
      "off"
    );
    if (!session || typeof session !== "object" || policyAction === "off") {
      return {
        active: false,
        action: policyAction,
        enforced: false,
        reasonCode: null,
        canonicalDiscordUserId: null,
        conflictCount: 0,
        conflictingSessionIds: [],
        checkedAtIso: new Date(nowMs).toISOString()
      };
    }

    const canonicalDiscordUserId = resolveCanonicalSessionDiscordUserId(session);
    if (!canonicalDiscordUserId) {
      return {
        active: false,
        action: policyAction,
        enforced: false,
        reasonCode: null,
        canonicalDiscordUserId: null,
        conflictCount: 0,
        conflictingSessionIds: [],
        checkedAtIso: new Date(nowMs).toISOString()
      };
    }

    const allSessions = state.listSessions({ limit: 100000, offset: 0 });
    const rows = Array.isArray(allSessions.items) ? allSessions.items : [];
    const conflictingSessionIds = [];

    for (const row of rows) {
      if (!row || typeof row !== "object") continue;
      if (row.session_id === session.session_id) continue;
      if (row.ended_at) continue;
      if (!state.isClientOnline(row.client_instance_id)) continue;
      const candidateDiscordUserId = resolveCanonicalSessionDiscordUserId(row);
      if (!candidateDiscordUserId) continue;
      if (candidateDiscordUserId !== canonicalDiscordUserId) continue;
      conflictingSessionIds.push(row.session_id);
    }

    if (conflictingSessionIds.length === 0) {
      return {
        active: false,
        action: policyAction,
        enforced: false,
        reasonCode: null,
        canonicalDiscordUserId,
        conflictCount: 0,
        conflictingSessionIds: [],
        checkedAtIso: new Date(nowMs).toISOString()
      };
    }

    const reasonCode = resolveMultiDeviceConflictReasonCode(policyAction);
    return {
      active: true,
      action: policyAction,
      enforced: policyAction === "restricted" || policyAction === "blocked",
      reasonCode,
      canonicalDiscordUserId,
      conflictCount: conflictingSessionIds.length,
      conflictingSessionIds: conflictingSessionIds.slice(0, 10),
      checkedAtIso: new Date(nowMs).toISOString()
    };
  }

  function applyDiscordMultiDevicePolicyState(session, evaluation) {
    if (!session || typeof session !== "object") return;
    if (!evaluation || evaluation.active !== true) {
      session.discord_multi_device_policy = "none";
      session.discord_multi_device_reason_code = null;
      session.discord_multi_device_conflict_count = 0;
      session.discord_multi_device_conflicting_session_ids = [];
      session.discord_multi_device_enforcement_state = "none";
      session.discord_multi_device_checked_at = new Date().toISOString();
      return;
    }
    session.discord_multi_device_policy = evaluation.action;
    session.discord_multi_device_reason_code = evaluation.reasonCode;
    session.discord_multi_device_conflict_count = evaluation.conflictCount;
    session.discord_multi_device_conflicting_session_ids = evaluation.conflictingSessionIds;
    session.discord_multi_device_enforcement_state = evaluation.enforced
      ? evaluation.action
      : "warn";
    session.discord_multi_device_checked_at = evaluation.checkedAtIso;
  }

  function resolveBindingReasonCode(riskType, action) {
    if (riskType === "device_switch") {
      if (action === "blocked") return "DISCORD_DEVICE_SWITCH_BLOCKED";
      if (action === "restricted") return "DISCORD_DEVICE_SWITCH_RESTRICTED";
      return "DISCORD_DEVICE_SWITCH_DETECTED";
    }
    if (riskType === "relink_race") {
      if (action === "blocked") return "DISCORD_RELINK_RACE_BLOCKED";
      if (action === "restricted") return "DISCORD_RELINK_RACE_RESTRICTED";
      return "DISCORD_RELINK_RACE_DETECTED";
    }
    return null;
  }

  function resolvePolicyStrength(action) {
    if (action === "blocked") return 3;
    if (action === "restricted") return 2;
    if (action === "warn") return 1;
    return 0;
  }

  function evaluateDiscordBindingTransitionState(session, nowMs = Date.now()) {
    const deviceSwitchPolicy = normalizeMultiDevicePolicyAction(
      config.integrationApi.discordDeviceSwitchPolicy,
      "off"
    );
    const relinkRacePolicy = normalizeMultiDevicePolicyAction(
      config.integrationApi.discordRelinkRacePolicy,
      "off"
    );
    const canonicalDiscordUserId = resolveCanonicalSessionDiscordUserId(session);
    const currentClient = state.getClient(session.client_instance_id);
    const currentDeviceId =
      currentClient && typeof currentClient.device_id === "string"
        ? currentClient.device_id.trim()
        : "";
    const riskCandidates = [];

    if (
      canonicalDiscordUserId &&
      currentDeviceId &&
      deviceSwitchPolicy !== "off"
    ) {
      const switchWindowSec = normalizePositiveInteger(
        config.integrationApi.discordDeviceSwitchWindowSec,
        120
      );
      const switchWindowMs = switchWindowSec * 1000;
      const allSessions = state.listSessions({ limit: 100000, offset: 0 });
      const rows = Array.isArray(allSessions.items) ? allSessions.items : [];
      const conflictingSessionIds = [];

      for (const row of rows) {
        if (!row || typeof row !== "object") continue;
        if (row.session_id === session.session_id) continue;
        const candidateDiscordUserId = resolveCanonicalSessionDiscordUserId(row);
        if (!candidateDiscordUserId || candidateDiscordUserId !== canonicalDiscordUserId) continue;
        const candidateDeviceId =
          typeof row.device_id === "string" && row.device_id.trim().length > 0
            ? row.device_id.trim()
            : "";
        if (!candidateDeviceId || candidateDeviceId === currentDeviceId) continue;
        const candidateTs = Date.parse(
          row.ended_at || row.updated_at || row.last_heartbeat_at || row.created_at || ""
        );
        if (!Number.isFinite(candidateTs)) continue;
        if (nowMs - candidateTs > switchWindowMs) continue;
        conflictingSessionIds.push(row.session_id);
      }

      if (conflictingSessionIds.length > 0) {
        riskCandidates.push({
          riskType: "device_switch",
          action: deviceSwitchPolicy,
          reasonCode: resolveBindingReasonCode("device_switch", deviceSwitchPolicy),
          conflictingSessionIds: conflictingSessionIds.slice(0, 10),
          metadata: {
            canonical_discord_user_id: canonicalDiscordUserId,
            current_device_id: currentDeviceId,
            window_sec: switchWindowSec
          }
        });
      }
    }

    if (canonicalDiscordUserId && relinkRacePolicy !== "off") {
      const boundDiscordUserId =
        typeof session.session_binding_discord_user_id === "string"
          ? session.session_binding_discord_user_id.trim()
          : "";
      if (
        boundDiscordUserId &&
        boundDiscordUserId !== canonicalDiscordUserId
      ) {
        riskCandidates.push({
          riskType: "relink_race",
          action: relinkRacePolicy,
          reasonCode: resolveBindingReasonCode("relink_race", relinkRacePolicy),
          conflictingSessionIds: [],
          metadata: {
            canonical_discord_user_id: canonicalDiscordUserId,
            bound_discord_user_id: boundDiscordUserId,
            relinked_at:
              typeof session.session_binding_last_relink_at === "string"
                ? session.session_binding_last_relink_at
                : null
          }
        });
      }
    }

    if (riskCandidates.length === 0) {
      return {
        active: false,
        action: "off",
        enforced: false,
        reasonCode: null,
        riskType: null,
        conflictingSessionIds: [],
        checkedAtIso: new Date(nowMs).toISOString(),
        metadata: {}
      };
    }

    const selected = riskCandidates.sort(
      (a, b) => resolvePolicyStrength(b.action) - resolvePolicyStrength(a.action)
    )[0];
    return {
      active: true,
      action: selected.action,
      enforced: selected.action === "restricted" || selected.action === "blocked",
      reasonCode: selected.reasonCode,
      riskType: selected.riskType,
      conflictingSessionIds: selected.conflictingSessionIds,
      checkedAtIso: new Date(nowMs).toISOString(),
      metadata: selected.metadata
    };
  }

  function applyDiscordBindingTransitionState(session, evaluation) {
    if (!session || typeof session !== "object") return;
    if (!evaluation || evaluation.active !== true) {
      session.session_binding_policy = "none";
      session.session_binding_reason_code = null;
      session.session_binding_risk_type = null;
      session.session_binding_conflicting_session_ids = [];
      session.session_binding_enforcement_state = "none";
      session.session_binding_checked_at = new Date().toISOString();
      return;
    }
    session.session_binding_policy = evaluation.action;
    session.session_binding_reason_code = evaluation.reasonCode;
    session.session_binding_risk_type = evaluation.riskType;
    session.session_binding_conflicting_session_ids = evaluation.conflictingSessionIds;
    session.session_binding_enforcement_state = evaluation.enforced
      ? evaluation.action
      : "warn";
    session.session_binding_checked_at = evaluation.checkedAtIso;
  }

  function maybeQueueDiscordIdentityRoleRevoke(session, evaluation, actor = "server") {
    if (!session || typeof session !== "object" || !evaluation || evaluation.active !== true) {
      return { queued: false, reason: "inactive" };
    }
    if (!evaluation.graceExceeded) {
      return { queued: false, reason: "grace_pending" };
    }

    const discordUserId =
      typeof session.discord_user_id === "string" ? session.discord_user_id.trim() : "";
    if (!discordUserId) {
      return { queued: false, reason: "missing_discord_user_id" };
    }

    const guildId =
      typeof config.integrationApi.discordRoleRevokeGuildId === "string"
        ? config.integrationApi.discordRoleRevokeGuildId.trim()
        : "";
    const roleId =
      typeof config.integrationApi.discordRoleRevokeRoleId === "string"
        ? config.integrationApi.discordRoleRevokeRoleId.trim()
        : "";
    if (!guildId || !roleId) {
      if (session.discord_identity_revoke_skip_reason !== "missing_target_role") {
        state.addAuditLog({
          action: "DISCORD_IDENTITY_ROLE_REVOKE_SKIPPED",
          actor,
          object_type: "session",
          object_id: session.session_id,
          detail: {
            reason_code: evaluation.reasonCode,
            policy_action: evaluation.action,
            skip_reason: "missing_target_role"
          }
        });
      }
      session.discord_identity_revoke_state = "skipped";
      session.discord_identity_revoke_skip_reason = "missing_target_role";
      return { queued: false, reason: "missing_target_role" };
    }

    const existingActionId =
      typeof session.discord_identity_revoke_action_id === "string"
        ? session.discord_identity_revoke_action_id.trim()
        : "";
    if (existingActionId) {
      session.discord_identity_revoke_state = "requested";
      session.discord_identity_revoke_skip_reason = null;
      return { queued: false, reason: "already_requested", action_id: existingActionId };
    }

    const actionId = `discord-revoke-${session.session_id}`;
    const revokeResult = state.createDiscordAction({
      action_id: actionId,
      action_type: "remove_role",
      discord_user_id: discordUserId,
      guild_id: guildId,
      role_id: roleId,
      reason_code: evaluation.reasonCode,
      reason_text:
        INTEGRATION_REASON_CODE_DEFINITIONS[evaluation.reasonCode] ||
        "discord identity policy revoke",
      created_by: actor,
      metadata: {
        source: "discord_identity_policy",
        session_id: session.session_id,
        user_id: session.user_id,
        policy_action: evaluation.action,
        profile: evaluation.profile,
        grace_sec: evaluation.graceSec,
        grace_expires_at: evaluation.graceExpiresAtIso
      }
    });

    session.discord_identity_revoke_action_id = revokeResult.record.action_id;
    session.discord_identity_revoke_requested_at = new Date().toISOString();
    session.discord_identity_revoke_state = "requested";
    session.discord_identity_revoke_skip_reason = null;

    state.addAuditLog({
      action: "DISCORD_IDENTITY_ROLE_REVOKE_REQUESTED",
      actor,
      object_type: "discord_action",
      object_id: revokeResult.record.action_id,
      detail: {
        created: revokeResult.created,
        reason_code: evaluation.reasonCode,
        policy_action: evaluation.action,
        discord_user_id: discordUserId
      }
    });

    return {
      queued: true,
      created: revokeResult.created,
      action_id: revokeResult.record.action_id
    };
  }

  function resolveDiscordGateRoleDirective({
    session,
    computedStatus,
    participantGateResult = null,
    identityPolicyEvaluation = null,
    freshnessSec = null
  }) {
    if (config.integrationApi.discordGateRoleSyncEnabled !== true) {
      return { action: null, reason: "disabled", reasonCode: null };
    }
    if (!session || typeof session !== "object") {
      return { action: null, reason: "missing_session", reasonCode: null };
    }

    if (
      config.integrationApi.discordGateRoleRemoveOnGateFailure === true &&
      participantGateResult &&
      participantGateResult.ok === false
    ) {
      return {
        action: "remove_role",
        reason: "gate_failed",
        reasonCode: normalizeReasonCode(participantGateResult.code) || "GATE_POLICY_FAIL"
      };
    }

    if (
      config.integrationApi.discordGateRoleRemoveOnOffline === true &&
      (String(computedStatus || "").toUpperCase() === "OFFLINE" ||
        freshnessSec === null ||
        freshnessSec > config.integrationApi.heartbeatStaleSec)
    ) {
      return {
        action: "remove_role",
        reason: "offline",
        reasonCode: "GATE_POLICY_OFFLINE"
      };
    }

    if (
      config.integrationApi.discordGateRoleRemoveOnGateFailure === true &&
      identityPolicyEvaluation &&
      identityPolicyEvaluation.active === true &&
      identityPolicyEvaluation.graceExceeded === true &&
      (identityPolicyEvaluation.action === "restricted" ||
        identityPolicyEvaluation.action === "blocked")
    ) {
      return {
        action: "remove_role",
        reason: "identity_policy_enforced",
        reasonCode: normalizeReasonCode(identityPolicyEvaluation.reasonCode) || "GATE_POLICY_FAIL"
      };
    }

    if (config.integrationApi.discordGateRoleAssignOnHealthy !== true) {
      return { action: null, reason: "assign_disabled", reasonCode: null };
    }

    return {
      action: "assign_role",
      reason: "gate_healthy",
      reasonCode: "GATE_POLICY_PASS"
    };
  }

  function maybeQueueDiscordGateRoleAction(session, directive, actor = "server") {
    if (
      !session ||
      typeof session !== "object" ||
      !directive ||
      typeof directive !== "object" ||
      !directive.action
    ) {
      return { queued: false, reason: "inactive" };
    }

    const discordUserId =
      typeof session.discord_user_id === "string" ? session.discord_user_id.trim() : "";
    if (!discordUserId) {
      session.discord_gate_role_skip_reason = "missing_discord_user_id";
      return { queued: false, reason: "missing_discord_user_id" };
    }

    const guildId =
      typeof config.integrationApi.discordGateRoleGuildId === "string"
        ? config.integrationApi.discordGateRoleGuildId.trim()
        : "";
    const roleId =
      typeof config.integrationApi.discordGateRoleId === "string"
        ? config.integrationApi.discordGateRoleId.trim()
        : "";
    if (!guildId || !roleId) {
      session.discord_gate_role_skip_reason = "missing_target_role";
      return { queued: false, reason: "missing_target_role" };
    }

    const targetState = directive.action === "assign_role" ? "assigned" : "removed";
    if (session.discord_gate_role_state === targetState) {
      session.discord_gate_role_skip_reason = "already_in_target_state";
      return { queued: false, reason: "already_in_target_state" };
    }

    const actionId = `discord-gate-${session.session_id}-${targetState}-${Date.now()}`;
    const reasonCode =
      normalizeReasonCode(directive.reasonCode) ||
      (directive.action === "assign_role" ? "GATE_POLICY_PASS" : "GATE_POLICY_FAIL");
    const reasonText =
      INTEGRATION_REASON_CODE_DEFINITIONS[reasonCode] || "discord gate role sync action";
    const actionResult = state.createDiscordAction({
      action_id: actionId,
      action_type: directive.action,
      discord_user_id: discordUserId,
      guild_id: guildId,
      role_id: roleId,
      reason_code: reasonCode,
      reason_text: reasonText,
      created_by: actor,
      metadata: {
        source: "discord_gate_role_policy",
        session_id: session.session_id,
        user_id: session.user_id,
        directive_reason: directive.reason || "unknown"
      }
    });

    session.discord_gate_role_state = targetState;
    session.discord_gate_role_last_action_id = actionResult.record.action_id;
    session.discord_gate_role_last_requested_at = new Date().toISOString();
    session.discord_gate_role_skip_reason = null;

    state.addAuditLog({
      action: "DISCORD_GATE_ROLE_SYNC_REQUESTED",
      actor,
      object_type: "discord_action",
      object_id: actionResult.record.action_id,
      detail: {
        action_type: actionResult.record.action_type,
        reason_code: reasonCode,
        session_id: session.session_id,
        discord_user_id: discordUserId,
        created: actionResult.created
      }
    });

    return {
      queued: true,
      action_id: actionResult.record.action_id,
      created: actionResult.created
    };
  }

  function buildCGuardStatusReasonCodes({
    session,
    computedStatus,
    decisionReasonCode,
    freshnessSec,
    discordIdentityEvaluation = null,
    multiDeviceEvaluation = null,
    bindingTransitionEvaluation = null
  }) {
    const reasonCodes = [];
    const pushCode = (code) => {
      if (!code || typeof code !== "string") return;
      if (reasonCodes.includes(code)) return;
      reasonCodes.push(code);
    };

    const clientAgentState = normalizeStateToken(session.health_client_agent_state);
    const kernelBridgeState = normalizeStateToken(session.health_kernel_bridge_state);
    const kernelDriverLoaded = session.health_kernel_driver_loaded === true;

    if (clientAgentState !== "running") {
      pushCode("CLIENT_AGENT_REQUIRED");
    }
    if (kernelBridgeState !== "connected" || kernelDriverLoaded !== true) {
      pushCode("KERNEL_CONNECTION_REQUIRED");
    }

    if (
      freshnessSec === null ||
      freshnessSec > config.integrationApi.heartbeatStaleSec
    ) {
      pushCode("HEARTBEAT_STALE");
    }

    if (config.integrationApi.discordRequireLinked === true && !hasLinkedDiscordIdentity(session)) {
      pushCode("DISCORD_IDENTITY_REQUIRED");
    }

    if (
      discordIdentityEvaluation &&
      discordIdentityEvaluation.active === true &&
      typeof discordIdentityEvaluation.reasonCode === "string"
    ) {
      pushCode(discordIdentityEvaluation.reasonCode);
    }

    if (
      multiDeviceEvaluation &&
      multiDeviceEvaluation.active === true &&
      typeof multiDeviceEvaluation.reasonCode === "string"
    ) {
      pushCode(multiDeviceEvaluation.reasonCode);
    }
    if (
      bindingTransitionEvaluation &&
      bindingTransitionEvaluation.active === true &&
      typeof bindingTransitionEvaluation.reasonCode === "string"
    ) {
      pushCode(bindingTransitionEvaluation.reasonCode);
    }

    const normalizedDecisionReasonCode = normalizeReasonCode(decisionReasonCode);

    if (computedStatus === "BLOCKED") {
      pushCode(normalizedDecisionReasonCode || "BANNED_USER");
    } else if (normalizedDecisionReasonCode) {
      pushCode(normalizedDecisionReasonCode);
    }

    return reasonCodes;
  }

  function enrichAdminSessionRow(row) {
    const session =
      row && typeof row.session_id === "string" ? state.getSession(row.session_id) : null;
    if (!session) return row;

    const freshnessSec = resolveHeartbeatFreshnessSec(session);
    maybeApplyOfflineSessionAutoBan(session, freshnessSec, "admin_sessions");
    const decision = state.getSessionDecision(session.session_id);
    const computedStatus = resolveComputedSessionStatus(session, decision);
    const decisionCode = resolveSessionDecisionReasonCode(session, decision);
    const statusReasonCodes = buildCGuardStatusReasonCodes({
      session,
      computedStatus,
      decisionReasonCode: decisionCode,
      freshnessSec
    });
    const clientAgentState = normalizeStateToken(session.health_client_agent_state);
    const kernelBridgeState = normalizeStateToken(session.health_kernel_bridge_state);
    const kernelDriverLoaded = session.health_kernel_driver_loaded === true;
    const heartbeatStale =
      freshnessSec === null || freshnessSec > config.integrationApi.heartbeatStaleSec;
    const cGuardOk =
      clientAgentState === "running" &&
      kernelBridgeState === "connected" &&
      kernelDriverLoaded === true &&
      !heartbeatStale &&
      computedStatus !== "BLOCKED";

    return {
      ...row,
      status: computedStatus,
      decision_reason_code: decisionCode || row.decision_reason_code || null,
      c_guard_ok: cGuardOk,
      status_reason_codes: statusReasonCodes,
      client_agent_state: clientAgentState,
      kernel_bridge_state: kernelBridgeState,
      kernel_driver_loaded: kernelDriverLoaded,
      freshness_sec: freshnessSec,
      heartbeat_stale: heartbeatStale,
      heartbeat_stale_threshold_sec: config.integrationApi.heartbeatStaleSec
    };
  }

  function collectPagedRows(loader, pageSize = 1000, maxRows = 100000) {
    const items = [];
    let offset = 0;
    while (items.length < maxRows) {
      const limit = Math.min(pageSize, maxRows - items.length);
      const page = loader({ limit, offset });
      const pageItems = Array.isArray(page.items) ? page.items : [];
      items.push(...pageItems);
      if (!page.page || page.page.has_more !== true || pageItems.length === 0) break;
      offset =
        Number.isFinite(Number(page.page.next_offset)) && Number(page.page.next_offset) > offset
          ? Number(page.page.next_offset)
          : offset + pageItems.length;
    }
    return items;
  }

  function filterRowsByExportTime(rows, fromMs, toMs, resolveTime) {
    return rows.filter((row) => {
      const value = resolveTime(row);
      const parsed = Date.parse(value || "");
      if (!Number.isFinite(parsed)) return true;
      if (Number.isFinite(fromMs) && parsed < fromMs) return false;
      if (Number.isFinite(toMs) && parsed > toMs) return false;
      return true;
    });
  }

  function buildAdminExportPayload({ from, to, userId } = {}) {
    const fromMs = from ? Date.parse(from) : NaN;
    const toMs = to ? Date.parse(to) : NaN;
    let sessions = collectPagedRows(({ limit, offset }) =>
      state.listSessions({ user_id: userId || undefined, limit, offset })
    ).map(enrichAdminSessionRow);
    sessions = filterRowsByExportTime(
      sessions,
      fromMs,
      toMs,
      (row) => row.updated_at || row.last_heartbeat_at || row.created_at
    );

    let events = collectPagedRows(({ limit, offset }) =>
      state.listEvents({ user_id: userId || undefined, limit, offset })
    );
    events = filterRowsByExportTime(
      events,
      fromMs,
      toMs,
      (row) => row.received_at || row.timestamp
    );

    let reviewNotes = collectPagedRows(({ limit, offset }) =>
      state.listReviewNotes({ limit, offset })
    );
    if (userId) {
      reviewNotes = reviewNotes.filter(
        (note) => note && note.metadata && note.metadata.user_id === userId
      );
    }
    reviewNotes = filterRowsByExportTime(reviewNotes, fromMs, toMs, (row) => row.created_at);

    let auditLogs = collectPagedRows(({ limit, offset }) =>
      state.listAuditLogs({ limit, offset })
    );
    auditLogs = filterRowsByExportTime(auditLogs, fromMs, toMs, (row) => row.at);

    return {
      generated_at: new Date().toISOString(),
      filters: {
        from: from || null,
        to: to || null,
        user_id: userId || null
      },
      counts: {
        sessions: sessions.length,
        events: events.length,
        review_notes: reviewNotes.length,
        audit_logs: auditLogs.length
      },
      sessions,
      events,
      review_notes: reviewNotes,
      audit_logs: auditLogs
    };
  }

  const EXPORT_SESSION_GROUP_SIZE = 7;
  const EXPORT_EVENT_MAX_ROWS = 300000;

  function shouldIncludeExportRow(row, fromMs, toMs, resolveTime) {
    const value = resolveTime(row);
    const parsed = Date.parse(value || "");
    if (!Number.isFinite(parsed)) return true;
    if (Number.isFinite(fromMs) && parsed < fromMs) return false;
    if (Number.isFinite(toMs) && parsed > toMs) return false;
    return true;
  }

  function appendJsonl(filePath, row) {
    fs.appendFileSync(filePath, `${JSON.stringify(row)}\n`, "utf8");
  }

  function rowsToJsonl(rows) {
    return rows.map((row) => JSON.stringify(row)).join("\n") + (rows.length > 0 ? "\n" : "");
  }

  function eventSummaryKey(event) {
    return `${event.event_type || ""}|${event.severity || ""}`;
  }

  function addEventSummary(summary, event) {
    const key = eventSummaryKey(event);
    const current =
      summary.byType.get(key) ||
      {
        event_type: event.event_type || "",
        severity: event.severity || "",
        count: 0,
        first_seen: null,
        last_seen: null
      };
    const timestamp = event.timestamp || event.received_at || null;
    current.count += 1;
    if (timestamp) {
      if (!current.first_seen || Date.parse(timestamp) < Date.parse(current.first_seen)) {
        current.first_seen = timestamp;
      }
      if (!current.last_seen || Date.parse(timestamp) > Date.parse(current.last_seen)) {
        current.last_seen = timestamp;
      }
    }
    summary.byType.set(key, current);

    const severity = String(event.severity || "unknown").toLowerCase();
    summary.bySeverity.set(severity, (summary.bySeverity.get(severity) || 0) + 1);
  }

  function buildAdminExportZip({ from, to, userId } = {}) {
    const fromMs = from ? Date.parse(from) : NaN;
    const toMs = to ? Date.parse(to) : NaN;
    const stamp = exportTimestampForFilename();
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "cguard-export-"));
    const zipPath = path.join(os.tmpdir(), `cguard-export-${stamp}-${crypto.randomUUID()}.zip`);
    const sessionGroupById = new Map();
    const groups = [];
    const counts = {
      sessions: 0,
      events: 0,
      ungrouped_events: 0,
      review_notes: 0,
      audit_logs: 0
    };
    const archiveFiles = config.archive.directory
      ? listFilesRecursive(config.archive.directory)
      : [];
    counts.archive_files = archiveFiles.length;
    let eventsTruncated = false;

    try {
      let sessions = collectPagedRows(({ limit, offset }) =>
        state.listSessions({ user_id: userId || undefined, limit, offset })
      ).map(enrichAdminSessionRow);
      sessions = filterRowsByExportTime(
        sessions,
        fromMs,
        toMs,
        (row) => row.updated_at || row.last_heartbeat_at || row.created_at
      );
      sessions.sort((a, b) => {
        const at = Date.parse(a.updated_at || a.last_heartbeat_at || a.created_at || "");
        const bt = Date.parse(b.updated_at || b.last_heartbeat_at || b.created_at || "");
        const aVal = Number.isFinite(at) ? at : 0;
        const bVal = Number.isFinite(bt) ? bt : 0;
        return bVal - aVal;
      });
      counts.sessions = sessions.length;

      for (let index = 0; index < sessions.length; index += EXPORT_SESSION_GROUP_SIZE) {
        const groupNumber = Math.floor(index / EXPORT_SESSION_GROUP_SIZE) + 1;
        const groupDir = path.join(tempDir, `session-group-${String(groupNumber).padStart(3, "0")}`);
        fs.mkdirSync(groupDir, { recursive: true });
        const groupSessions = sessions.slice(index, index + EXPORT_SESSION_GROUP_SIZE);
        const group = {
          number: groupNumber,
          dir: groupDir,
          sessionsFile: path.join(groupDir, "sessions.jsonl"),
          eventsFile: path.join(groupDir, "events.jsonl"),
          sessions: groupSessions.length,
          events: 0
        };
        fs.writeFileSync(group.sessionsFile, rowsToJsonl(groupSessions), "utf8");
        fs.writeFileSync(group.eventsFile, "", "utf8");
        for (const session of groupSessions) {
          if (session && typeof session.session_id === "string") {
            sessionGroupById.set(session.session_id, group);
          }
        }
        groups.push(group);
      }

      const ungroupedEventsFile = path.join(tempDir, "ungrouped-events.jsonl");
      fs.writeFileSync(ungroupedEventsFile, "", "utf8");

      const eventSummary = {
        byType: new Map(),
        bySeverity: new Map()
      };
      let offset = 0;
      while (counts.events < EXPORT_EVENT_MAX_ROWS) {
        const limit = Math.min(1000, EXPORT_EVENT_MAX_ROWS - counts.events);
        const page = state.listEvents({ user_id: userId || undefined, limit, offset });
        const items = Array.isArray(page.items) ? page.items : [];
        if (items.length === 0) break;
        for (const event of items) {
          if (
            !shouldIncludeExportRow(
              event,
              fromMs,
              toMs,
              (row) => row.received_at || row.timestamp
            )
          ) {
            continue;
          }
          const group = sessionGroupById.get(event.session_id);
          if (group) {
            appendJsonl(group.eventsFile, event);
            group.events += 1;
          } else {
            appendJsonl(ungroupedEventsFile, event);
            counts.ungrouped_events += 1;
          }
          counts.events += 1;
          addEventSummary(eventSummary, event);
          if (counts.events >= EXPORT_EVENT_MAX_ROWS) break;
        }
        if (!page.page || page.page.has_more !== true) break;
        if (counts.events >= EXPORT_EVENT_MAX_ROWS) {
          eventsTruncated = true;
          break;
        }
        offset =
          Number.isFinite(Number(page.page.next_offset)) && Number(page.page.next_offset) > offset
            ? Number(page.page.next_offset)
            : offset + items.length;
      }

      let reviewNotes = collectPagedRows(({ limit, offset }) =>
        state.listReviewNotes({ limit, offset })
      );
      if (userId) {
        reviewNotes = reviewNotes.filter(
          (note) => note && note.metadata && note.metadata.user_id === userId
        );
      }
      reviewNotes = filterRowsByExportTime(reviewNotes, fromMs, toMs, (row) => row.created_at);
      counts.review_notes = reviewNotes.length;

      const auditLogs = filterRowsByExportTime(
        collectPagedRows(({ limit, offset }) => state.listAuditLogs({ limit, offset })),
        fromMs,
        toMs,
        (row) => row.at
      );
      counts.audit_logs = auditLogs.length;

      const eventTypeRows = Array.from(eventSummary.byType.values()).sort(
        (a, b) => b.count - a.count || String(a.event_type).localeCompare(String(b.event_type))
      );
      const severityRows = Array.from(eventSummary.bySeverity.entries())
        .map(([severity, count]) => ({ severity, count }))
        .sort((a, b) => b.count - a.count);
      const sessionSummaryRows = sessions.map((row) => ({
        session_id: row.session_id,
        user_id: row.user_id,
        username: row.username,
        status: row.status,
        c_guard_ok: row.c_guard_ok,
        detection_reason: row.decision_reason_code,
        risk_tier: row.risk_tier,
        final_risk_score: row.final_risk_score,
        last_heartbeat_at: row.last_heartbeat_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
        ended_at: row.ended_at
      }));
      const metadata = {
        generated_at: new Date().toISOString(),
        format: "zip",
        session_group_size: EXPORT_SESSION_GROUP_SIZE,
        event_max_rows: EXPORT_EVENT_MAX_ROWS,
        events_truncated: eventsTruncated,
        archive: {
          enabled: config.archive.directory.length > 0,
          included_file_count: archiveFiles.length,
          zip_prefix: "archive/"
        },
        competition: {
          name: config.competition.name || null,
          starts_at: config.competition.startsAt || null,
          ends_at: config.competition.endsAt || null
        },
        filters: {
          from: from || null,
          to: to || null,
          user_id: userId || null
        },
        counts,
        groups: groups.map((group) => ({
          group: group.number,
          sessions: group.sessions,
          events: group.events
        }))
      };

      const fd = fs.openSync(zipPath, "w");
      const central = [];
      try {
        writeZipEntry(fd, central, "metadata.json", `${JSON.stringify(metadata, null, 2)}\n`);
        writeZipEntry(
          fd,
          central,
          "README.txt",
          [
            "C-Guard export bundle",
            `Generated at: ${metadata.generated_at}`,
            `Session group size: ${EXPORT_SESSION_GROUP_SIZE}`,
            "Each session-group folder contains sessions.jsonl and events.jsonl.",
            "If archive/ exists, it contains the persistent operation JSONL archive.",
            "Raw JSONL files may contain participant identifiers and evidence strings.",
            ""
          ].join("\n")
        );
        writeZipEntry(
          fd,
          central,
          "summary/sessions.csv",
          toCsv(
            [
              "session_id",
              "user_id",
              "username",
              "status",
              "c_guard_ok",
              "detection_reason",
              "risk_tier",
              "final_risk_score",
              "last_heartbeat_at",
              "created_at",
              "updated_at",
              "ended_at"
            ],
            sessionSummaryRows
          )
        );
        writeZipEntry(
          fd,
          central,
          "summary/event_type.csv",
          toCsv(["event_type", "severity", "count", "first_seen", "last_seen"], eventTypeRows)
        );
        writeZipEntry(
          fd,
          central,
          "summary/severity.csv",
          toCsv(["severity", "count"], severityRows)
        );
        writeZipEntry(fd, central, "review_notes.jsonl", rowsToJsonl(reviewNotes));
        writeZipEntry(fd, central, "audit_logs.jsonl", rowsToJsonl(auditLogs));
        if (counts.ungrouped_events > 0) {
          writeZipEntry(
            fd,
            central,
            "ungrouped-events.jsonl",
            fs.readFileSync(ungroupedEventsFile)
          );
        }
        for (const group of groups) {
          const prefix = `session-groups/group-${String(group.number).padStart(3, "0")}`;
          writeZipEntry(fd, central, `${prefix}/sessions.jsonl`, fs.readFileSync(group.sessionsFile));
          writeZipEntry(fd, central, `${prefix}/events.jsonl`, fs.readFileSync(group.eventsFile));
        }
        for (const archiveFile of archiveFiles) {
          const relativeName = path
            .relative(config.archive.directory, archiveFile)
            .split(path.sep)
            .join("/");
          if (!relativeName || relativeName.startsWith("..")) continue;
          writeZipEntry(fd, central, `archive/${relativeName}`, fs.readFileSync(archiveFile));
        }
        finishZip(fd, central);
      } finally {
        fs.closeSync(fd);
      }

      return { zipPath, metadata, stamp };
    } catch (error) {
      fs.rmSync(zipPath, { force: true });
      throw error;
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }

  function csvDatasetFromExport(payload, dataset) {
    if (dataset === "sessions") {
      const headers = [
        "session_id",
        "user_id",
        "username",
        "discord_display_name",
        "status",
        "c_guard_ok",
        "detection_reason",
        "risk_tier",
        "final_risk_score",
        "status_reason_codes",
        "last_heartbeat_at",
        "created_at",
        "updated_at",
        "ended_at"
      ];
      const rows = payload.sessions.map((row) => ({
        session_id: row.session_id,
        user_id: row.user_id,
        username: row.username,
        discord_display_name: row.discord_display_name,
        status: row.status,
        c_guard_ok: row.c_guard_ok,
        detection_reason: row.decision_reason_code,
        risk_tier: row.risk_tier,
        final_risk_score: row.final_risk_score,
        status_reason_codes: Array.isArray(row.status_reason_codes)
          ? row.status_reason_codes.join("|")
          : "",
        last_heartbeat_at: row.last_heartbeat_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
        ended_at: row.ended_at
      }));
      return { headers, rows };
    }
    if (dataset === "events") {
      const headers = [
        "timestamp",
        "received_at",
        "event_type",
        "severity",
        "session_id",
        "user_id",
        "client_version",
        "evidence"
      ];
      const rows = payload.events.map((row) => ({
        timestamp: row.timestamp,
        received_at: row.received_at,
        event_type: row.event_type,
        severity: row.severity,
        session_id: row.session_id,
        user_id: row.user_id,
        client_version: row.client_version,
        evidence: row.evidence || {}
      }));
      return { headers, rows };
    }
    if (dataset === "review_notes") {
      const headers = ["note_id", "session_id", "author", "note", "metadata", "created_at"];
      const rows = payload.review_notes.map((row) => ({
        note_id: row.note_id,
        session_id: row.session_id,
        author: row.author,
        note: row.note,
        metadata: row.metadata || {},
        created_at: row.created_at
      }));
      return { headers, rows };
    }
    if (dataset === "audit_logs") {
      const headers = ["audit_id", "at", "actor", "action", "object_type", "object_id", "detail"];
      const rows = payload.audit_logs.map((row) => ({
        audit_id: row.audit_id,
        at: row.at,
        actor: row.actor,
        action: row.action,
        object_type: row.object_type,
        object_id: row.object_id,
        detail: row.detail || {}
      }));
      return { headers, rows };
    }
    return null;
  }

  function buildIntegrationSessionSnapshot(session) {
    const client = state.getClient(session.client_instance_id);
    const user = state.getUser(session.user_id);
    const decision = state.getSessionDecision(session.session_id);
    const freshnessSec = resolveHeartbeatFreshnessSec(session);
    const discordIdentityEvaluation = evaluateDiscordIdentityPolicyState(
      session,
      freshnessSec,
      Date.now()
    );
    applyDiscordIdentityPolicyState(session, discordIdentityEvaluation);
    const multiDeviceEvaluation = evaluateDiscordMultiDevicePolicyState(session);
    applyDiscordMultiDevicePolicyState(session, multiDeviceEvaluation);
    const bindingTransitionEvaluation = evaluateDiscordBindingTransitionState(session);
    applyDiscordBindingTransitionState(session, bindingTransitionEvaluation);
    if (
      discordIdentityEvaluation.active === true &&
      discordIdentityEvaluation.graceExceeded === true &&
      (discordIdentityEvaluation.action === "restricted" ||
        discordIdentityEvaluation.action === "blocked")
    ) {
      state.revokeActiveJtiForUser(session.user_id);
    }
    maybeQueueDiscordIdentityRoleRevoke(session, discordIdentityEvaluation, "server");
    maybeApplyOfflineSessionAutoBan(session, freshnessSec, "integration_snapshot");

    const computedStatus = resolveComputedSessionStatus(session, decision);
    const gateDirective = resolveDiscordGateRoleDirective({
      session,
      computedStatus,
      identityPolicyEvaluation: discordIdentityEvaluation,
      freshnessSec
    });
    if (gateDirective.action === "assign_role" || gateDirective.action === "remove_role") {
      maybeQueueDiscordGateRoleAction(session, gateDirective, "server");
    }
    const decisionReasonCode = resolveSessionDecisionReasonCode(session, decision);
    const statusReasonCodes = buildCGuardStatusReasonCodes({
      session,
      computedStatus,
      decisionReasonCode,
      freshnessSec,
      discordIdentityEvaluation,
      multiDeviceEvaluation,
      bindingTransitionEvaluation
    });
    const clientAgentState = normalizeStateToken(session.health_client_agent_state);
    const kernelBridgeState = normalizeStateToken(session.health_kernel_bridge_state);
    const kernelDriverLoaded = session.health_kernel_driver_loaded === true;
    const heartbeatStale =
      freshnessSec === null || freshnessSec > config.integrationApi.heartbeatStaleSec;
    const cGuardOk =
      clientAgentState === "running" &&
      kernelBridgeState === "connected" &&
      kernelDriverLoaded === true &&
      !heartbeatStale &&
      (config.integrationApi.discordRequireLinked !== true || hasLinkedDiscordIdentity(session)) &&
      computedStatus !== "BLOCKED" &&
      !(
        multiDeviceEvaluation.active === true &&
        multiDeviceEvaluation.enforced === true
      ) &&
      !(
        bindingTransitionEvaluation.active === true &&
        bindingTransitionEvaluation.enforced === true
      ) &&
      !(
        discordIdentityEvaluation.active === true &&
        discordIdentityEvaluation.graceExceeded === true &&
        (discordIdentityEvaluation.action === "restricted" ||
          discordIdentityEvaluation.action === "blocked")
      );

    let decisionStatus = "ok";
    if (decision && typeof decision.status === "string" && decision.status.trim()) {
      decisionStatus = decision.status.trim().toLowerCase();
    } else if (computedStatus === "BLOCKED") {
      decisionStatus = "blocked";
    } else if (computedStatus === "WARN") {
      decisionStatus = "warn";
    }

    return {
      user_id: session.user_id,
      username: user && typeof user.username === "string" ? user.username : null,
      session_id: session.session_id,
      status: computedStatus,
      c_guard_ok: cGuardOk,
      status_reason_codes: statusReasonCodes,
      client_agent_state: clientAgentState,
      kernel_bridge_state: kernelBridgeState,
      kernel_driver_loaded: kernelDriverLoaded,
      last_heartbeat_at: session.last_heartbeat_at || null,
      freshness_sec: freshnessSec,
      heartbeat_stale: heartbeatStale,
      heartbeat_stale_threshold_sec: config.integrationApi.heartbeatStaleSec,
      client_version: client ? client.app_version : null,
      discord_user_id:
        typeof session.discord_user_id === "string" ? session.discord_user_id : null,
      discord_display_name:
        typeof session.discord_display_name === "string" ? session.discord_display_name : null,
      discord_username:
        typeof session.discord_username === "string" ? session.discord_username : null,
      discord_link_state: normalizeDiscordLinkState(session.discord_link_state, "unknown"),
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
      identity_source: normalizeIdentitySource(session.identity_source, "unknown"),
      identity_hint_source: normalizeIdentitySource(session.identity_hint_source, "unknown"),
      identity_hint_link_state: normalizeDiscordLinkState(
        session.identity_hint_link_state,
        "unknown"
      ),
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
      discord_multi_device_policy:
        typeof session.discord_multi_device_policy === "string"
          ? session.discord_multi_device_policy
          : "none",
      discord_multi_device_reason_code:
        typeof session.discord_multi_device_reason_code === "string"
          ? session.discord_multi_device_reason_code
          : null,
      discord_multi_device_conflict_count:
        typeof session.discord_multi_device_conflict_count === "number"
          ? session.discord_multi_device_conflict_count
          : 0,
      discord_multi_device_conflicting_session_ids: Array.isArray(
        session.discord_multi_device_conflicting_session_ids
      )
        ? session.discord_multi_device_conflicting_session_ids
        : [],
      discord_multi_device_enforcement_state:
        typeof session.discord_multi_device_enforcement_state === "string"
          ? session.discord_multi_device_enforcement_state
          : "none",
      discord_multi_device_checked_at:
        typeof session.discord_multi_device_checked_at === "string"
          ? session.discord_multi_device_checked_at
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
      decision_status: decisionStatus,
      decision_reason_code: decisionReasonCode,
      decision_reason_known:
        decisionReasonCode === null ? null : INTEGRATION_REASON_CODE_SET.has(decisionReasonCode),
      final_risk_score: decision && typeof decision.score === "number" ? decision.score : 0,
      risk_tier: decision ? decision.tier : "normal",
      server_time: new Date().toISOString()
    };
  }

  function resolveInvestigationInput(sessionId) {
    const session = state.getSession(sessionId);
    if (!session) return null;

    const client = state.getClient(session.client_instance_id);
    const user = state.getUser(session.user_id);
    const decision = state.getSessionDecision(sessionId);
    const events = state.getEventsBySession(sessionId);
    const rejections = Array.isArray(state.eventRejections)
      ? state.eventRejections.filter(
          (entry) =>
            entry &&
            entry.event &&
            typeof entry.event === "object" &&
            entry.event.session_id === sessionId
        )
      : eventStore.rejected.filter(
          (entry) =>
            entry &&
            entry.raw_event &&
            typeof entry.raw_event === "object" &&
            entry.raw_event.session_id === sessionId
        );

    const versionPolicyResult = evaluateClientVersion(
      client && client.app_version ? client.app_version : "",
      config.versionPolicy
    );
    const computedStatus = resolveComputedSessionStatus(session, decision);

    return {
      session,
      events,
      rejections,
      notes: state.listReviewNotes(sessionId),
      actions: state.listReviewActions(sessionId),
      decision,
      sessionView: {
        session_id: session.session_id,
        user_id: session.user_id,
        username: user && typeof user.username === "string" ? user.username : null,
        client_version: client ? client.app_version : null,
        session_start_time: session.created_at,
        session_end_time: session.ended_at,
        current_status: computedStatus,
        decision_reason_code: decision ? decision.reason_code || null : null,
        client_agent_state: session.health_client_agent_state || "unknown",
        kernel_bridge_state: session.health_kernel_bridge_state || "unknown",
        kernel_driver_loaded: session.health_kernel_driver_loaded === true,
        discord_user_id:
          typeof session.discord_user_id === "string" ? session.discord_user_id : null,
        discord_display_name:
          typeof session.discord_display_name === "string" ? session.discord_display_name : null,
        discord_username:
          typeof session.discord_username === "string" ? session.discord_username : null,
        discord_link_state: normalizeDiscordLinkState(session.discord_link_state, "unknown"),
        identity_source: normalizeIdentitySource(session.identity_source, "unknown"),
        identity_hint_source: normalizeIdentitySource(session.identity_hint_source, "unknown"),
        identity_hint_link_state: normalizeDiscordLinkState(
          session.identity_hint_link_state,
          "unknown"
        ),
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
        discord_multi_device_policy:
          typeof session.discord_multi_device_policy === "string"
            ? session.discord_multi_device_policy
            : "none",
        discord_multi_device_reason_code:
          typeof session.discord_multi_device_reason_code === "string"
            ? session.discord_multi_device_reason_code
            : null,
        discord_multi_device_conflict_count:
          typeof session.discord_multi_device_conflict_count === "number"
            ? session.discord_multi_device_conflict_count
            : 0,
        discord_multi_device_conflicting_session_ids: Array.isArray(
          session.discord_multi_device_conflicting_session_ids
        )
          ? session.discord_multi_device_conflicting_session_ids
          : [],
        discord_multi_device_enforcement_state:
          typeof session.discord_multi_device_enforcement_state === "string"
            ? session.discord_multi_device_enforcement_state
            : "none",
      discord_multi_device_checked_at:
        typeof session.discord_multi_device_checked_at === "string"
          ? session.discord_multi_device_checked_at
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
      participant_gate_result: evaluateParticipantEligibility(
          {
            client_agent_state: session.health_client_agent_state,
            kernel_bridge_state: session.health_kernel_bridge_state,
            kernel_driver_loaded: session.health_kernel_driver_loaded
          },
          config.participantGate
        ),
        version_policy_result: versionPolicyResult
      }
    };
  }

  function buildAdminRuntimeConfigPayload() {
    return {
      kernel_integrity: {
        max_kernel_signals_per_batch: config.kernelIntegrity.maxKernelSignalsPerBatch,
        max_bridge_emit_delta_ms: config.kernelIntegrity.maxBridgeEmitDeltaMs,
        max_bridge_counter_gap: config.kernelIntegrity.maxBridgeCounterGap,
        max_bridge_staleness_ms: config.kernelIntegrity.maxBridgeStalenessMs,
        warn_action: config.kernelIntegrity.warnAction,
        require_signals: config.kernelIntegrity.requireSignals,
        min_kernel_signals_per_batch: config.kernelIntegrity.minKernelSignalsPerBatch,
        signal_rate_window_sec: config.kernelIntegrity.signalRateWindowSec,
        min_kernel_signals_per_minute: config.kernelIntegrity.minKernelSignalsPerMinute,
        require_bridge_signature: config.kernelIntegrity.requireBridgeSignature,
        require_bridge_nonce: config.kernelIntegrity.requireBridgeNonce,
        require_bridge_emitted_at: config.kernelIntegrity.requireBridgeEmittedAt,
        require_session_binding_token: config.kernelIntegrity.requireSessionBindingToken,
        kernel_binding_token_ttl_sec: config.kernelIntegrity.kernelBindingTokenTtlSec,
        bridge_signature_verification_enabled:
          config.kernelBridgeSigning.verificationEnabled,
        session_binding_verification_enabled:
          config.kernelSessionBinding.verificationEnabled
      },
      participant_gate: {
        require_client_agent_running: config.participantGate.requireClientAgentRunning,
        require_kernel_connected: config.participantGate.requireKernelConnected,
        auto_ban_client_agent_stopped: config.participantGate.autoBanClientAgentStopped === true
      },
      version_policy: {
        latest_version: config.versionPolicy.latestVersion,
        deprecated_below_version: config.versionPolicy.deprecatedBelowVersion || null,
        minimum_supported_version: config.versionPolicy.minimumSupportedVersion
      },
      archive: {
        enabled: config.archive.directory.length > 0,
        directory_configured: config.archive.directory.length > 0,
        session_group_size: config.archive.sessionGroupSize,
        memory_event_limit: config.archive.memoryEventLimit
      },
      competition: {
        name: config.competition.name || null,
        starts_at: config.competition.startsAt || null,
        ends_at: config.competition.endsAt || null
      },
      integration_api: {
        enabled: config.integrationApi.enabled === true,
        discord_require_linked: config.integrationApi.discordRequireLinked === true,
        discord_require_linked_action: config.integrationApi.discordRequireLinkedAction,
        discord_require_linked_grace_sec: config.integrationApi.discordRequireLinkedGraceSec,
        submission_proof_ttl_sec: config.integrationApi.submissionProofTtlSec,
        submission_proof_nonce_ttl_sec: config.integrationApi.submissionProofNonceTtlSec,
        submission_proof_nonce_max_entries:
          config.integrationApi.maxSubmissionProofNonceEntries,
        submission_proof_signing_secret_configured:
          typeof config.integrationApi.submissionProofSigningSecret === "string" &&
          config.integrationApi.submissionProofSigningSecret.trim().length > 0,
        source_consistency_action: config.integrationApi.sourceConsistencyAction,
        discord_multi_device_policy: config.integrationApi.discordMultiDevicePolicy,
        discord_device_switch_policy: config.integrationApi.discordDeviceSwitchPolicy,
        discord_device_switch_window_sec: config.integrationApi.discordDeviceSwitchWindowSec,
        discord_relink_race_policy: config.integrationApi.discordRelinkRacePolicy,
        heartbeat_stale_sec: config.integrationApi.heartbeatStaleSec,
        auto_ban_offline_session: config.integrationApi.autoBanOfflineSession === true,
        auto_ban_blocked_decision: config.integrationApi.autoBanBlockedDecision === true,
        rate_limit_max_requests: config.integrationApi.rateLimitMaxRequests,
        rate_limit_window_sec: config.integrationApi.rateLimitWindowSec,
        rate_limit_max_entries: config.integrationApi.maxRateLimitEntries,
        discord_callback_require_signature:
          config.integrationApi.discordCallbackRequireSignature === true,
        discord_callback_timestamp_tolerance_sec:
          config.integrationApi.discordCallbackTimestampToleranceSec,
        discord_callback_nonce_ttl_sec: config.integrationApi.discordCallbackNonceTtlSec,
        discord_callback_nonce_max_entries:
          config.integrationApi.maxDiscordCallbackNonceEntries,
        discord_identity_require_assertion:
          config.integrationApi.discordIdentityRequireAssertion === true,
        discord_identity_allow_relink:
          config.integrationApi.discordIdentityAllowRelink === true,
        public_base_url_configured:
          typeof config.integrationApi.publicBaseUrl === "string" &&
          config.integrationApi.publicBaseUrl.trim().length > 0,
        discord_identity_authorization_url_template_configured:
          typeof config.integrationApi.discordIdentityAuthorizationUrlTemplate === "string" &&
          config.integrationApi.discordIdentityAuthorizationUrlTemplate.trim().length > 0,
        discord_identity_loss_policy: config.integrationApi.discordIdentityLossPolicy,
        discord_identity_loss_grace_sec: config.integrationApi.discordIdentityLossGraceSec,
        discord_client_unavailable_policy:
          config.integrationApi.discordClientUnavailablePolicy,
        discord_client_unavailable_grace_sec:
          config.integrationApi.discordClientUnavailableGraceSec,
        token_configured:
          typeof config.integrationApi.token === "string" &&
          config.integrationApi.token.trim().length > 0,
        api_key_required:
          typeof config.integrationApi.apiKey === "string" &&
          config.integrationApi.apiKey.trim().length > 0,
        discord_callback_signing_secret_configured:
          typeof config.integrationApi.discordCallbackSigningSecret === "string" &&
          config.integrationApi.discordCallbackSigningSecret.trim().length > 0,
        discord_identity_assertion_secret_configured:
          typeof config.integrationApi.discordIdentityAssertionSecret === "string" &&
          config.integrationApi.discordIdentityAssertionSecret.trim().length > 0,
        discord_role_revoke_guild_id_configured:
          typeof config.integrationApi.discordRoleRevokeGuildId === "string" &&
          config.integrationApi.discordRoleRevokeGuildId.trim().length > 0,
        discord_role_revoke_role_id_configured:
          typeof config.integrationApi.discordRoleRevokeRoleId === "string" &&
          config.integrationApi.discordRoleRevokeRoleId.trim().length > 0,
        discord_gate_role_sync_enabled:
          config.integrationApi.discordGateRoleSyncEnabled === true,
        discord_gate_role_assign_on_healthy:
          config.integrationApi.discordGateRoleAssignOnHealthy === true,
        discord_gate_role_remove_on_gate_failure:
          config.integrationApi.discordGateRoleRemoveOnGateFailure === true,
        discord_gate_role_remove_on_offline:
          config.integrationApi.discordGateRoleRemoveOnOffline === true,
        discord_gate_role_guild_id_configured:
          typeof config.integrationApi.discordGateRoleGuildId === "string" &&
          config.integrationApi.discordGateRoleGuildId.trim().length > 0,
        discord_gate_role_id_configured:
          typeof config.integrationApi.discordGateRoleId === "string" &&
          config.integrationApi.discordGateRoleId.trim().length > 0
      },
      llm_monitor: {
        cli_hints: config.llmMonitor.cliHints,
        cli_detection_action: config.llmMonitor.cliDetectionAction,
        cli_confidence_threshold: config.llmMonitor.cliConfidenceThreshold,
        weak_confidence_threshold: config.llmMonitor.weakConfidenceThreshold,
        medium_confidence_threshold: config.llmMonitor.mediumConfidenceThreshold,
        high_confidence_threshold: config.llmMonitor.highConfidenceThreshold,
        max_top_evidence: config.llmMonitor.maxTopEvidence,
        cli_min_evidence_count: config.llmMonitor.cliMinEvidenceCount,
        cli_enforcement_cooldown_sec: config.llmMonitor.cliEnforcementCooldownSec,
        cli_override_window_sec: config.llmMonitor.cliOverrideWindowSec
      }
    };
  }

  const integrationRateLimitState = new Map();
  const integrationDiscordCallbackNonceCache = new Map();
  const integrationSubmissionProofNonceCache = new Map();
  const integrationSubmissionProofJtiCache = new Map();

  function consumeIntegrationRateLimit(req, integration) {
    const maxRequests = Number(config.integrationApi.rateLimitMaxRequests || 0);
    if (!Number.isFinite(maxRequests) || maxRequests <= 0) {
      return {
        ok: true,
        enabled: false
      };
    }

    const windowSec = normalizePositiveInteger(config.integrationApi.rateLimitWindowSec, 60);
    const windowMs = windowSec * 1000;
    const nowMs = Date.now();
    const requestContext = getRequestContext(req);
    const requestIp = String(requestContext.ip || "");
    const actor =
      integration && typeof integration.actor === "string" && integration.actor.trim().length > 0
        ? integration.actor.trim()
        : "integration-client";
    const key = `${actor}|${requestIp}`;

    for (const [entryKey, entryValue] of integrationRateLimitState.entries()) {
      if (!entryValue || typeof entryValue !== "object") {
        integrationRateLimitState.delete(entryKey);
        continue;
      }
      if (nowMs - Number(entryValue.window_start_ms || 0) >= windowMs * 3) {
        integrationRateLimitState.delete(entryKey);
      }
    }

    const previous = integrationRateLimitState.get(key);
    let windowStartMs = nowMs;
    let count = 1;
    if (previous && nowMs - Number(previous.window_start_ms || 0) < windowMs) {
      windowStartMs = Number(previous.window_start_ms || nowMs);
      count = Number(previous.count || 0) + 1;
    }
    integrationRateLimitState.set(key, {
      window_start_ms: windowStartMs,
      count
    });
    const maxRateLimitEntries = normalizePositiveInteger(
      config.integrationApi.maxRateLimitEntries,
      10000
    );
    while (integrationRateLimitState.size > maxRateLimitEntries) {
      const firstKey = integrationRateLimitState.keys().next().value;
      if (!firstKey) break;
      integrationRateLimitState.delete(firstKey);
    }

    if (count > maxRequests) {
      const elapsedMs = nowMs - windowStartMs;
      const remainingMs = Math.max(1000, windowMs - elapsedMs);
      return {
        ok: false,
        enabled: true,
        limit: maxRequests,
        count,
        window_sec: windowSec,
        retry_after_sec: Math.ceil(remainingMs / 1000)
      };
    }

    return {
      ok: true,
      enabled: true,
      limit: maxRequests,
      count,
      remaining: Math.max(0, maxRequests - count),
      window_sec: windowSec
    };
  }

  function requireAdmin(req, res) {
    const admin = parseAdminContext(req, config);
    if (!admin.ok) {
      json(res, admin.statusCode, { code: admin.code, message: admin.message });
      return null;
    }
    return admin;
  }

  function requireIntegration(req, res) {
    const integration = parseIntegrationContext(req, config);
    if (!integration.ok && integration.code === "NOT_FOUND") {
      json(res, integration.statusCode, {
        code: integration.code,
        message: integration.message
      });
      return null;
    }

    const rateLimit = consumeIntegrationRateLimit(req, integration);
    if (!rateLimit.ok) {
      state.addAuditLog({
        action: "INTEGRATION_RATE_LIMITED",
        actor: integration.actor || "integration-client",
        object_type: "integration",
        object_id: req.url || null,
        detail: {
          code: "INTEGRATION_RATE_LIMITED",
          limit: rateLimit.limit,
          count: rateLimit.count,
          window_sec: rateLimit.window_sec,
          retry_after_sec: rateLimit.retry_after_sec
        }
      });
      json(
        res,
        429,
        {
          code: "INTEGRATION_RATE_LIMITED",
          message: "integration rate limit exceeded",
          retry_after_sec: rateLimit.retry_after_sec
        },
        {
          "retry-after": String(rateLimit.retry_after_sec)
        }
      );
      return null;
    }

    if (!integration.ok) {
      state.addAuditLog({
        action: "INTEGRATION_AUTH_FAILED",
        actor: integration.actor || "integration-client",
        object_type: "integration",
        object_id: req.url || null,
        detail: {
          code: integration.code,
          message: integration.message,
          status_code: integration.statusCode
        }
      });
      json(res, integration.statusCode, {
        code: integration.code,
        message: integration.message
      });
      return null;
    }
    return integration;
  }

  function runInStateTransaction(executor) {
    if (typeof state.transact === "function") {
      return state.transact(executor);
    }
    return executor();
  }

  function purgeSubmissionProofReplayCaches(nowSec) {
    if (typeof state.purgeSubmissionProofReplayCaches === "function") {
      state.purgeSubmissionProofReplayCaches({
        nowSec,
        maxEntries: normalizePositiveInteger(
          config.integrationApi.maxSubmissionProofNonceEntries,
          20000
        )
      });
      return;
    }
    for (const [key, expiresAtSec] of integrationSubmissionProofNonceCache.entries()) {
      if (!Number.isFinite(expiresAtSec) || expiresAtSec <= nowSec) {
        integrationSubmissionProofNonceCache.delete(key);
      }
    }
    for (const [key, expiresAtSec] of integrationSubmissionProofJtiCache.entries()) {
      if (!Number.isFinite(expiresAtSec) || expiresAtSec <= nowSec) {
        integrationSubmissionProofJtiCache.delete(key);
      }
    }
  }

  function registerSubmissionProofReplayEntry({
    nonce,
    jti,
    expSec,
    session_id = null,
    user_id = null,
    client_instance_id = null,
    device_id = null,
    purpose = "submit",
    source_ip = null
  }) {
    const nowSec = Math.floor(Date.now() / 1000);
    const nonceTtlSec = normalizePositiveInteger(
      config.integrationApi.submissionProofNonceTtlSec,
      120
    );
    if (typeof state.consumeSubmissionProofReplayEntry === "function") {
      return state.consumeSubmissionProofReplayEntry({
        nonce,
        jti,
        expSec,
        session_id,
        user_id,
        client_instance_id,
        device_id,
        purpose,
        source_ip,
        nonceTtlSec,
        nowSec,
        maxEntries: normalizePositiveInteger(
          config.integrationApi.maxSubmissionProofNonceEntries,
          20000
        )
      });
    }
    purgeSubmissionProofReplayCaches(nowSec);
    const nonceExpirySec = Math.max(expSec || 0, nowSec + nonceTtlSec);
    integrationSubmissionProofNonceCache.set(nonce, nonceExpirySec);
    integrationSubmissionProofJtiCache.set(jti, nonceExpirySec);
    const maxEntries = normalizePositiveInteger(
      config.integrationApi.maxSubmissionProofNonceEntries,
      20000
    );
    while (integrationSubmissionProofNonceCache.size > maxEntries) {
      const firstKey = integrationSubmissionProofNonceCache.keys().next().value;
      if (!firstKey) break;
      integrationSubmissionProofNonceCache.delete(firstKey);
    }
    while (integrationSubmissionProofJtiCache.size > maxEntries) {
      const firstKey = integrationSubmissionProofJtiCache.keys().next().value;
      if (!firstKey) break;
      integrationSubmissionProofJtiCache.delete(firstKey);
    }
    return { accepted: true, code: null, expires_at_epoch_sec: nonceExpirySec };
  }

  async function handler(req, res) {
    try {
      const requestUrl = new URL(req.url, "http://localhost");
      const pathname = requestUrl.pathname;
      const params = requestUrl.searchParams;
      const integrationParticipantMatch =
        /^\/v1\/integration\/cguard\/participants\/([^/]+)$/.exec(pathname);
      const integrationSessionMatch =
        /^\/v1\/integration\/cguard\/sessions\/([^/]+)$/.exec(pathname);
      const integrationDiscordCallbackMatch =
        /^\/v1\/integration\/discord\/actions\/([^/]+)\/callback$/.exec(pathname);
      const integrationDiscordIdentityUserMatch =
        /^\/v1\/integration\/discord\/identity\/users\/([^/]+)$/.exec(pathname);
      const investigationMatch = /^\/v1\/admin\/investigation\/([^/]+)$/.exec(pathname);
      const sessionSummaryMatch = /^\/v1\/admin\/session-summary\/([^/]+)$/.exec(pathname);
      const sessionEventsMatch = /^\/v1\/admin\/session-events\/([^/]+)$/.exec(pathname);
      const scoreBreakdownMatch = /^\/v1\/admin\/score-breakdown\/([^/]+)$/.exec(pathname);
      const revokeBanMatch = /^\/v1\/admin\/bans\/([^/]+)$/.exec(pathname);
      const participantResetMatch = /^\/v1\/admin\/participants\/([^/]+)\/reset$/.exec(pathname);

      if (req.method === "GET" && pathname === "/health") {
        return json(res, 200, { status: "ok", time: new Date().toISOString() });
      }
      if (req.method === "GET" && tryServeAdminStatic(pathname, res)) {
        return;
      }
      if (req.method === "POST" && pathname === "/v1/auth/login") {
        return await handleLogin(req, res);
      }
      if (req.method === "POST" && pathname === "/v1/client/heartbeat") {
        return await handleHeartbeat(req, res);
      }
      if (req.method === "POST" && pathname === "/v1/client/proof") {
        return await handleClientSubmissionProof(req, res);
      }
      if (req.method === "POST" && pathname === "/v1/events") {
        return await handleEvents(req, res);
      }
      if (req.method === "POST" && pathname === "/v1/verify") {
        return await handleVerify(req, res);
      }
      if (req.method === "GET" && pathname === "/v1/integration/discord/identity/authorize") {
        const userId = params.get("user_id") || "";
        const sessionId = params.get("session_id") || "";
        const reasonCode =
          normalizeReasonCode(params.get("reason_code")) || "DISCORD_IDENTITY_REQUIRED";
        const requestContextBaseUrl = resolveServerBaseUrlFromRequest(req, config);
        const renderedAuthUrl = renderDiscordAuthUrlTemplate(
          config.integrationApi.discordIdentityAuthorizationUrlTemplate,
          {
            userId,
            sessionId,
            reasonCode,
            serverBaseUrl: requestContextBaseUrl
          }
        );
        const destination =
          renderedAuthUrl && renderedAuthUrl.length > 0
            ? renderedAuthUrl
            : "https://discord.com/login";
        state.addAuditLog({
          action: "INTEGRATION_DISCORD_IDENTITY_AUTH_REDIRECT",
          actor: "server",
          object_type: "user",
          object_id: userId || null,
          detail: {
            session_id: sessionId || null,
            reason_code: reasonCode,
            destination_type: renderedAuthUrl ? "configured_template" : "discord_login_fallback",
            request_ip: getRequestContext(req).ip || null
          }
        });
        res.writeHead(302, {
          Location: destination,
          "cache-control": "no-store"
        });
        res.end();
        return;
      }

      if (pathname.startsWith("/v1/integration/")) {
        const integration = requireIntegration(req, res);
        if (!integration) return;

        if (req.method === "POST" && pathname === "/v1/integration/discord/identity/link") {
          const body = await readJsonBody(req);
          const userId = typeof body.user_id === "string" ? body.user_id.trim() : "";
          const discordUserId =
            typeof body.discord_user_id === "string" ? body.discord_user_id.trim() : "";
          const identitySource = normalizeIdentitySource(body.identity_source, "oauth");
          const verificationMethod =
            typeof body.verification_method === "string" && body.verification_method.trim()
              ? body.verification_method.trim()
              : "oauth_pkce";
          const assertionToken =
            typeof body.identity_assertion === "string" ? body.identity_assertion.trim() : "";

          const shouldVerifyAssertion =
            config.integrationApi.discordIdentityRequireAssertion === true || assertionToken.length > 0;
          if (shouldVerifyAssertion) {
            const verification = verifyDiscordIdentityAssertion(assertionToken, {
              secret: config.integrationApi.discordIdentityAssertionSecret,
              expectedUserId: userId,
              expectedDiscordUserId: discordUserId
            });
            if (!verification.ok) {
              state.addAuditLog({
                action: "INTEGRATION_DISCORD_IDENTITY_VERIFY_FAILED",
                actor: integration.actor,
                object_type: "user",
                object_id: userId || null,
                detail: {
                  code: verification.code,
                  message: verification.message
                }
              });
              const statusCode =
                verification.code === "INTEGRATION_DISCORD_IDENTITY_ASSERTION_MISCONFIG"
                  ? 500
                  : verification.code === "INTEGRATION_DISCORD_IDENTITY_ASSERTION_REQUIRED"
                    ? 400
                    : verification.code === "INTEGRATION_DISCORD_IDENTITY_ASSERTION_EXPIRED"
                      ? 401
                      : verification.code === "INTEGRATION_DISCORD_IDENTITY_ASSERTION_MISMATCH"
                        ? 409
                        : 401;
              return json(res, statusCode, {
                code: verification.code,
                message: verification.message
              });
            }
          }

          try {
            const result = state.linkDiscordIdentity({
              user_id: userId,
              discord_user_id: discordUserId,
              identity_source: identitySource,
              verification_method: verificationMethod,
              discord_display_name:
                typeof body.discord_display_name === "string"
                  ? body.discord_display_name
                  : typeof body.display_name === "string"
                    ? body.display_name
                    : undefined,
              discord_username:
                typeof body.discord_username === "string"
                  ? body.discord_username
                  : typeof body.username === "string"
                    ? body.username
                    : undefined,
              linked_by: integration.actor,
              verified_at: body.verified_at,
              linked_at: body.linked_at,
              metadata: isPlainObject(body.metadata) ? body.metadata : {},
              allow_relink:
                config.integrationApi.discordIdentityAllowRelink === true &&
                body.allow_relink === true
            });
            state.addAuditLog({
              action: "INTEGRATION_DISCORD_IDENTITY_LINK",
              actor: integration.actor,
              object_type: "user",
              object_id: userId,
              detail: {
                discord_user_id: discordUserId,
                identity_source: identitySource,
                verification_method: verificationMethod,
                relinked: result.relinked
              }
            });
            return json(res, 200, {
              linked: result.linked,
              relinked: result.relinked,
              identity: result.record
            });
          } catch (error) {
            const message = String(error.message || "invalid discord identity payload");
            const statusCode =
              message.includes("already linked") ? 409 : message.includes("not found") ? 404 : 400;
            return json(res, statusCode, {
              code: statusCode === 409 ? "CONFLICT" : statusCode === 404 ? "NOT_FOUND" : "BAD_REQUEST",
              message
            });
          }
        }

        if (req.method === "GET" && integrationDiscordIdentityUserMatch) {
          const userId = decodeURIComponent(integrationDiscordIdentityUserMatch[1]);
          const identity = state.getDiscordIdentityByUserId(userId);
          if (!identity) {
            return json(res, 404, {
              code: "NOT_FOUND",
              message: "discord identity not linked"
            });
          }
          state.addAuditLog({
            action: "INTEGRATION_DISCORD_IDENTITY_READ",
            actor: integration.actor,
            object_type: "user",
            object_id: userId,
            detail: {
              discord_user_id: identity.discord_user_id,
              identity_source: identity.identity_source
            }
          });
          return json(res, 200, { identity });
        }

        if (req.method === "POST" && pathname === "/v1/integration/discord/actions") {
          const body = await readJsonBody(req);
          try {
            const created = state.createDiscordAction({
              action_id: body.action_id,
              action_type: body.action_type,
              discord_user_id: body.discord_user_id,
              guild_id: body.guild_id,
              role_id: body.role_id,
              reason_code: body.reason_code,
              reason_text: body.reason_text,
              created_by: integration.actor,
              expires_at: body.expires_at,
              metadata: isPlainObject(body.metadata) ? body.metadata : {}
            });
            state.addAuditLog({
              action: "INTEGRATION_DISCORD_ACTION_REQUEST",
              actor: integration.actor,
              object_type: "discord_action",
              object_id: created.record.action_id,
              detail: {
                created: created.created,
                action_type: created.record.action_type,
                discord_user_id: created.record.discord_user_id
              }
            });
            return json(res, created.created ? 201 : 200, {
              created: created.created,
              action: created.record
            });
          } catch (error) {
            const message = String(error.message || "invalid discord action payload");
            const statusCode = message.includes("already exists with different payload") ? 409 : 400;
            return json(res, statusCode, {
              code: statusCode === 409 ? "CONFLICT" : "BAD_REQUEST",
              message
            });
          }
        }

        if (req.method === "GET" && pathname === "/v1/integration/discord/actions") {
          try {
            const actions = state.listDiscordActions({
              status: params.get("status") || undefined,
              action_type: params.get("action_type") || undefined,
              discord_user_id: params.get("discord_user_id") || undefined,
              updated_since: params.get("updated_since") || undefined,
              limit: parseNumberParam(params.get("limit"), 100),
              offset: parseNonNegativeNumberParam(params.get("offset"), 0)
            });
            state.addAuditLog({
              action: "INTEGRATION_DISCORD_ACTION_LIST_READ",
              actor: integration.actor,
              object_type: "discord_action",
              object_id: null,
              detail: {
                total: actions.page.total,
                offset: actions.page.offset,
                limit: actions.page.limit
              }
            });
            return json(res, 200, actions);
          } catch (error) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: error.message
            });
          }
        }

        if (req.method === "POST" && integrationDiscordCallbackMatch) {
          const actionId = decodeURIComponent(integrationDiscordCallbackMatch[1]);
          const rawBody = await readRawBody(req);
          let body = {};
          try {
            body = rawBody ? JSON.parse(rawBody) : {};
          } catch (_error) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "invalid json body"
            });
          }

          const signatureCheck = verifyDiscordCallbackHeaders({
            req,
            pathname,
            rawBody,
            config,
            nonceCache: integrationDiscordCallbackNonceCache
          });
          if (!signatureCheck.ok) {
            state.addAuditLog({
              action: "INTEGRATION_DISCORD_CALLBACK_AUTH_FAILED",
              actor: integration.actor,
              object_type: "discord_action",
              object_id: actionId,
              detail: {
                code: signatureCheck.code,
                message: signatureCheck.message
              }
            });
            return json(res, signatureCheck.statusCode || 401, {
              code: signatureCheck.code,
              message: signatureCheck.message
            });
          }

          try {
            const callbackResult = runInStateTransaction(() => {
              const applied = state.applyDiscordActionCallback({
                action_id: actionId,
                callback_id: body.callback_id,
                status: body.status,
                callback_at: body.callback_at,
                retry_after_at: body.retry_after_at,
                error_code: body.error_code,
                error_message: body.error_message,
                metadata: isPlainObject(body.metadata) ? body.metadata : {},
                processed_by: integration.actor
              });
              state.addAuditLog({
                action: "INTEGRATION_DISCORD_ACTION_CALLBACK",
                actor: integration.actor,
                object_type: "discord_action",
                object_id: actionId,
                detail: {
                  updated: applied.updated,
                  idempotent: applied.idempotent,
                  callback_id: applied.receipt ? applied.receipt.callback_id : null,
                  status: applied.record.status
                }
              });
              return applied;
            });
            return json(res, 200, {
              updated: callbackResult.updated,
              idempotent: callbackResult.idempotent,
              action: callbackResult.record
            });
          } catch (error) {
            const message = String(error.message || "invalid discord callback payload");
            if (message.includes("not found")) {
              return json(res, 404, {
                code: "NOT_FOUND",
                message
              });
            }
            const statusCode =
              message.includes("already exists with different payload") ? 409 : 400;
            return json(res, statusCode, {
              code: statusCode === 409 ? "CONFLICT" : "BAD_REQUEST",
              message
            });
          }
        }

        if (req.method === "POST" && pathname === "/v1/integration/cguard/proof/verify") {
          const body = await readJsonBody(req);
          const proofToken =
            typeof body.proof_token === "string" ? body.proof_token.trim() : "";
          const proofNonce = normalizeSubmissionProofNonce(body.proof_nonce);
          const submissionSourceIp = resolveSubmissionSourceIp(req, body);
          if (!proofToken || !proofNonce) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "proof_token and proof_nonce are required"
            });
          }

          const verifiedProof = verifyAttestationToken(proofToken, {
            secret: config.integrationApi.submissionProofSigningSecret
          });
          if (!verifiedProof.ok) {
            state.addAuditLog({
              action: "INTEGRATION_SUBMISSION_PROOF_VERIFY_FAILED",
              actor: integration.actor,
              object_type: "submission_proof",
              object_id: null,
              detail: {
                code: verifiedProof.code,
                message: verifiedProof.message
              }
            });
            const statusCode = verifiedProof.code === "EXPIRED_TOKEN" ? 401 : 401;
            return json(res, statusCode, {
              code: verifiedProof.code,
              message: verifiedProof.message
            });
          }

          const claims = verifiedProof.claims || {};
          const requiredStringClaims = ["sub", "tid", "sid", "cid", "did", "ppr", "pnc", "jti"];
          for (const claimKey of requiredStringClaims) {
            if (typeof claims[claimKey] !== "string" || !claims[claimKey].trim()) {
              state.addAuditLog({
                action: "INTEGRATION_SUBMISSION_PROOF_VERIFY_FAILED",
                actor: integration.actor,
                object_type: "submission_proof",
                object_id: null,
                detail: {
                  code: "INTEGRATION_SUBMISSION_PROOF_INVALID",
                  message: `missing claim: ${claimKey}`
                }
              });
              return json(res, 400, {
                code: "INTEGRATION_SUBMISSION_PROOF_INVALID",
                message: `proof token missing required claim: ${claimKey}`
              });
            }
          }

          if (claims.pnc !== proofNonce) {
            state.addAuditLog({
              action: "INTEGRATION_SUBMISSION_PROOF_VERIFY_FAILED",
              actor: integration.actor,
              object_type: "submission_proof",
              object_id: claims.jti || null,
              detail: {
                code: "INTEGRATION_SUBMISSION_PROOF_NONCE_MISMATCH",
                expected_nonce: claims.pnc,
                provided_nonce: proofNonce
              }
            });
            return json(res, 409, {
              code: "INTEGRATION_SUBMISSION_PROOF_NONCE_MISMATCH",
              message: "proof nonce does not match token binding"
            });
          }

          const checkBinding = (fieldName, claimValue) => {
            if (!Object.prototype.hasOwnProperty.call(body, fieldName)) return null;
            const provided = String(body[fieldName] || "").trim();
            if (!provided) return `invalid expected ${fieldName}`;
            if (provided !== claimValue) {
              return `${fieldName} mismatch`;
            }
            return null;
          };

          const bindingErrors = [
            checkBinding("user_id", claims.sub),
            checkBinding("team_id", claims.tid),
            checkBinding("session_id", claims.sid),
            checkBinding("client_instance_id", claims.cid),
            checkBinding("device_id", claims.did),
            checkBinding("purpose", claims.ppr)
          ].filter(Boolean);
          if (bindingErrors.length > 0) {
            state.addAuditLog({
              action: "INTEGRATION_SUBMISSION_PROOF_VERIFY_FAILED",
              actor: integration.actor,
              object_type: "submission_proof",
              object_id: claims.jti || null,
              detail: {
                code: "INTEGRATION_SUBMISSION_PROOF_BINDING_MISMATCH",
                errors: bindingErrors
              }
            });
            return json(res, 409, {
              code: "INTEGRATION_SUBMISSION_PROOF_BINDING_MISMATCH",
              message: "proof token binding mismatch",
              errors: bindingErrors
            });
          }

          const sessionForConsistency = state.getSession(claims.sid);
          const sourceConsistency = evaluateSubmissionSourceConsistency({
            heartbeatSourceIp: sessionForConsistency ? sessionForConsistency.last_ip : null,
            submissionSourceIp,
            policyAction: config.integrationApi.sourceConsistencyAction
          });

          const verifyResult = runInStateTransaction(() => {
            const nowSec = Math.floor(Date.now() / 1000);
            purgeSubmissionProofReplayCaches(nowSec);
            const replayEntry = registerSubmissionProofReplayEntry({
              nonce: proofNonce,
              jti: claims.jti,
              expSec: Number(claims.exp || 0),
              session_id: claims.sid,
              user_id: claims.sub,
              client_instance_id: claims.cid,
              device_id: claims.did,
              purpose: claims.ppr,
              source_ip: submissionSourceIp
            });
            const replayDetected =
              replayEntry &&
              replayEntry.accepted === false &&
              replayEntry.code === "REPLAY_DETECTED";
            if (replayDetected) {
              state.addAuditLog({
                action: "INTEGRATION_SUBMISSION_PROOF_VERIFY_FAILED",
                actor: integration.actor,
                object_type: "submission_proof",
                object_id: claims.jti || null,
                detail: {
                  code: "INTEGRATION_SUBMISSION_PROOF_REPLAY_DETECTED",
                  nonce: proofNonce
                }
              });
              return {
                status: 409,
                body: {
                  code: "INTEGRATION_SUBMISSION_PROOF_REPLAY_DETECTED",
                  message: "submission proof already consumed"
                }
              };
            }

            if (sourceConsistency.verdict !== "matched") {
              state.addAuditLog({
                action: "INTEGRATION_SUBMISSION_SOURCE_CONSISTENCY",
                actor: integration.actor,
                object_type: "submission_proof",
                object_id: claims.jti || null,
                detail: {
                  verdict: sourceConsistency.verdict,
                  policy_action: sourceConsistency.policy_action,
                  enforced: sourceConsistency.enforced === true,
                  reason_code: sourceConsistency.reason_code || null,
                  heartbeat_source_ip: sourceConsistency.heartbeat_source_ip,
                  submission_source_ip: sourceConsistency.submission_source_ip
                }
              });
            }

            if (sourceConsistency.enforced === true && sourceConsistency.reason_code) {
              state.addAuditLog({
                action: "INTEGRATION_SUBMISSION_PROOF_VERIFY_FAILED",
                actor: integration.actor,
                object_type: "submission_proof",
                object_id: claims.jti || null,
                detail: {
                  code: sourceConsistency.reason_code,
                  verdict: sourceConsistency.verdict,
                  policy_action: sourceConsistency.policy_action,
                  heartbeat_source_ip: sourceConsistency.heartbeat_source_ip,
                  submission_source_ip: sourceConsistency.submission_source_ip
                }
              });
              return {
                status: 409,
                body: {
                  code: sourceConsistency.reason_code,
                  message:
                    INTEGRATION_REASON_CODE_DEFINITIONS[sourceConsistency.reason_code] ||
                    "submission source consistency policy blocked request",
                  source_consistency: sourceConsistency
                }
              };
            }

            state.addAuditLog({
              action: "INTEGRATION_SUBMISSION_PROOF_VERIFIED",
              actor: integration.actor,
              object_type: "submission_proof",
              object_id: claims.jti,
              detail: {
                user_id: claims.sub,
                team_id: claims.tid,
                session_id: claims.sid,
                client_instance_id: claims.cid,
                device_id: claims.did,
                purpose: claims.ppr,
                source_consistency: sourceConsistency
              }
            });
            return {
              status: 200,
              body: {
                accepted: true,
                proof: {
                  user_id: claims.sub,
                  team_id: claims.tid,
                  session_id: claims.sid,
                  client_instance_id: claims.cid,
                  device_id: claims.did,
                  purpose: claims.ppr,
                  nonce: claims.pnc,
                  jti: claims.jti,
                  iat:
                    typeof claims.iat === "number"
                      ? new Date(claims.iat * 1000).toISOString()
                      : null,
                  expires_at:
                    typeof claims.exp === "number"
                      ? new Date(claims.exp * 1000).toISOString()
                      : null
                },
                source_consistency: sourceConsistency,
                server_time: new Date().toISOString()
              }
            };
          });
          return json(res, verifyResult.status, verifyResult.body);
        }

        if (req.method === "GET" && pathname === "/v1/integration/cguard/reason-codes") {
          const reasonCodes = Object.entries(INTEGRATION_REASON_CODE_DEFINITIONS).map(
            ([reasonCode, description]) => ({
              reason_code: reasonCode,
              description
            })
          );
          state.addAuditLog({
            action: "INTEGRATION_REASON_CODES_READ",
            actor: integration.actor,
            object_type: "schema",
            object_id: "cguard_reason_codes",
            detail: {
              reason_code_count: reasonCodes.length
            }
          });
          return json(res, 200, {
            reason_codes: reasonCodes,
            server_time: new Date().toISOString()
          });
        }

        if (req.method === "GET" && integrationParticipantMatch) {
          const userId = decodeURIComponent(integrationParticipantMatch[1]);
          const latestSessionPage = state.listSessions({
            user_id: userId,
            limit: 1,
            offset: 0
          });
          const latestSessionRow =
            latestSessionPage && Array.isArray(latestSessionPage.items)
              ? latestSessionPage.items[0]
              : null;
          if (!latestSessionRow) {
            return json(res, 404, {
              code: "NOT_FOUND",
              message: "participant session not found"
            });
          }
          const targetSession = state.getSession(latestSessionRow.session_id);
          if (!targetSession) {
            return json(res, 404, {
              code: "NOT_FOUND",
              message: "participant session not found"
            });
          }
          const payload = buildIntegrationSessionSnapshot(targetSession);
          state.addAuditLog({
            action: "INTEGRATION_STATUS_READ",
            actor: integration.actor,
            object_type: "user",
            object_id: userId,
            detail: {
              session_id: payload.session_id,
              c_guard_ok: payload.c_guard_ok,
              status_reason_codes: payload.status_reason_codes
            }
          });
          return json(res, 200, payload);
        }

        if (req.method === "GET" && integrationSessionMatch) {
          const sessionId = decodeURIComponent(integrationSessionMatch[1]);
          const session = state.getSession(sessionId);
          if (!session) {
            return json(res, 404, {
              code: "NOT_FOUND",
              message: "session not found"
            });
          }
          const payload = buildIntegrationSessionSnapshot(session);
          state.addAuditLog({
            action: "INTEGRATION_STATUS_READ",
            actor: integration.actor,
            object_type: "session",
            object_id: sessionId,
            detail: {
              c_guard_ok: payload.c_guard_ok,
              status_reason_codes: payload.status_reason_codes
            }
          });
          return json(res, 200, payload);
        }

        if (req.method === "GET" && pathname === "/v1/integration/cguard/summary") {
          const allSessionRows = [];
          let offset = 0;
          const pageLimit = 500;
          for (;;) {
            const page = state.listSessions({ limit: pageLimit, offset });
            const items = page && Array.isArray(page.items) ? page.items : [];
            allSessionRows.push(...items);
            if (!page || !page.page || page.page.has_more !== true) break;
            if (!Number.isFinite(page.page.next_offset)) break;
            offset = page.page.next_offset;
          }
          const sessionViews = allSessionRows
            .map((item) => state.getSession(item.session_id))
            .filter((item) => Boolean(item))
            .map((session) => buildIntegrationSessionSnapshot(session));

          const summary = {
            total_sessions: sessionViews.length,
            c_guard_ok_count: sessionViews.filter((item) => item.c_guard_ok === true).length,
            c_guard_off_count: sessionViews.filter((item) => item.c_guard_ok !== true).length,
            blocked_count: sessionViews.filter((item) => item.status === "BLOCKED").length,
            warn_count: sessionViews.filter((item) => item.status === "WARN").length,
            stale_heartbeat_count: sessionViews.filter((item) => item.heartbeat_stale === true).length,
            heartbeat_stale_threshold_sec: config.integrationApi.heartbeatStaleSec,
            server_time: new Date().toISOString()
          };
          state.addAuditLog({
            action: "INTEGRATION_STATUS_SUMMARY_READ",
            actor: integration.actor,
            object_type: "summary",
            object_id: "cguard",
            detail: {
              total_sessions: summary.total_sessions,
              c_guard_ok_count: summary.c_guard_ok_count,
              c_guard_off_count: summary.c_guard_off_count
            }
          });
          return json(res, 200, summary);
        }

        return json(res, 404, { code: "NOT_FOUND", message: "integration route not found" });
      }

      if (pathname.startsWith("/v1/admin/")) {
        if (req.method === "POST" && pathname === "/v1/admin/auth/login") {
          return await handleAdminLogin(req, res);
        }

        const admin = requireAdmin(req, res);
        if (!admin) return;

        if (req.method === "GET" && pathname === "/v1/admin/auth/me") {
          return json(res, 200, {
            actor: admin.actor,
            role: admin.role
          });
        }

        if (req.method === "GET" && pathname === "/v1/admin/runtime-config") {
          if (!requirePermission(res, admin, "read")) return;
          return json(res, 200, buildAdminRuntimeConfigPayload());
        }

        if (req.method === "POST" && pathname === "/v1/admin/runtime-config/policy") {
          if (!requirePermission(res, admin, "enforce")) return;
          const body = await readJsonBody(req);
          if (!isPlainObject(body)) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "invalid runtime policy payload"
            });
          }

          const reason = typeof body.reason === "string" ? body.reason.trim() : "";
          if (reason.length < 12) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "reason must be at least 12 characters for runtime policy updates"
            });
          }

          const participantGatePatch = isPlainObject(body.participant_gate)
            ? body.participant_gate
            : {};
          const integrationApiPatch = isPlainObject(body.integration_api)
            ? body.integration_api
            : {};
          const llmMonitorPatch = isPlainObject(body.llm_monitor) ? body.llm_monitor : {};
          const competitionPatch = isPlainObject(body.competition) ? body.competition : {};
          const changes = {};
          const rollback = {
            integrationApi: {
              discordRequireLinked: config.integrationApi.discordRequireLinked,
              discordRequireLinkedAction: config.integrationApi.discordRequireLinkedAction,
              discordRequireLinkedGraceSec: config.integrationApi.discordRequireLinkedGraceSec,
              discordMultiDevicePolicy: config.integrationApi.discordMultiDevicePolicy,
              discordDeviceSwitchPolicy: config.integrationApi.discordDeviceSwitchPolicy,
              discordDeviceSwitchWindowSec: config.integrationApi.discordDeviceSwitchWindowSec,
              discordRelinkRacePolicy: config.integrationApi.discordRelinkRacePolicy,
              sourceConsistencyAction: config.integrationApi.sourceConsistencyAction
            },
            llmMonitor: {
              cliDetectionAction: config.llmMonitor.cliDetectionAction,
              cliConfidenceThreshold: config.llmMonitor.cliConfidenceThreshold,
              cliMinEvidenceCount: config.llmMonitor.cliMinEvidenceCount,
              cliEnforcementCooldownSec: config.llmMonitor.cliEnforcementCooldownSec,
              cliOverrideWindowSec: config.llmMonitor.cliOverrideWindowSec
            },
            competition: {
              name: config.competition.name,
              startsAt: config.competition.startsAt,
              endsAt: config.competition.endsAt
            }
          };
          const restoreRuntimePolicyFromRollback = () => {
            Object.assign(config.integrationApi, rollback.integrationApi);
            Object.assign(config.llmMonitor, rollback.llmMonitor);
            Object.assign(config.competition, rollback.competition);
          };

          if (Object.prototype.hasOwnProperty.call(participantGatePatch, "require_discord_linked")) {
            const previous = config.integrationApi.discordRequireLinked === true;
            const next = normalizeBooleanFlag(
              participantGatePatch.require_discord_linked,
              previous
            );
            if (previous !== next) {
              config.integrationApi.discordRequireLinked = next;
              changes.require_discord_linked = {
                before: previous,
                after: next
              };
            }
          }

          if (
            Object.prototype.hasOwnProperty.call(
              participantGatePatch,
              "require_discord_linked_action"
            )
          ) {
            const previous = normalizeDiscordIdentityPolicyAction(
              config.integrationApi.discordRequireLinkedAction,
              "blocked"
            );
            const next = normalizeDiscordIdentityPolicyAction(
              participantGatePatch.require_discord_linked_action,
              previous
            );
            if (previous !== next) {
              config.integrationApi.discordRequireLinkedAction = next;
              changes.require_discord_linked_action = {
                before: previous,
                after: next
              };
            }
          }

          if (
            Object.prototype.hasOwnProperty.call(
              participantGatePatch,
              "require_discord_linked_grace_sec"
            )
          ) {
            const previous = normalizeNonNegativeInteger(
              config.integrationApi.discordRequireLinkedGraceSec,
              0
            );
            const next = normalizeNonNegativeInteger(
              participantGatePatch.require_discord_linked_grace_sec,
              previous
            );
            if (previous !== next) {
              config.integrationApi.discordRequireLinkedGraceSec = next;
              changes.require_discord_linked_grace_sec = {
                before: previous,
                after: next
              };
            }
          }

          if (
            Object.prototype.hasOwnProperty.call(
              integrationApiPatch,
              "discord_multi_device_policy"
            )
          ) {
            const previous = normalizeMultiDevicePolicyAction(
              config.integrationApi.discordMultiDevicePolicy,
              "off"
            );
            const next = normalizeMultiDevicePolicyAction(
              integrationApiPatch.discord_multi_device_policy,
              previous
            );
            if (previous !== next) {
              config.integrationApi.discordMultiDevicePolicy = next;
              changes.discord_multi_device_policy = {
                before: previous,
                after: next
              };
            }
          }

          if (
            Object.prototype.hasOwnProperty.call(
              integrationApiPatch,
              "discord_device_switch_policy"
            )
          ) {
            const previous = normalizeMultiDevicePolicyAction(
              config.integrationApi.discordDeviceSwitchPolicy,
              "off"
            );
            const next = normalizeMultiDevicePolicyAction(
              integrationApiPatch.discord_device_switch_policy,
              previous
            );
            if (previous !== next) {
              config.integrationApi.discordDeviceSwitchPolicy = next;
              changes.discord_device_switch_policy = {
                before: previous,
                after: next
              };
            }
          }

          if (
            Object.prototype.hasOwnProperty.call(
              integrationApiPatch,
              "discord_device_switch_window_sec"
            )
          ) {
            const previous = normalizePositiveInteger(
              config.integrationApi.discordDeviceSwitchWindowSec,
              120
            );
            const next = normalizePositiveInteger(
              integrationApiPatch.discord_device_switch_window_sec,
              previous
            );
            if (previous !== next) {
              config.integrationApi.discordDeviceSwitchWindowSec = next;
              changes.discord_device_switch_window_sec = {
                before: previous,
                after: next
              };
            }
          }

          if (
            Object.prototype.hasOwnProperty.call(
              integrationApiPatch,
              "discord_relink_race_policy"
            )
          ) {
            const previous = normalizeMultiDevicePolicyAction(
              config.integrationApi.discordRelinkRacePolicy,
              "off"
            );
            const next = normalizeMultiDevicePolicyAction(
              integrationApiPatch.discord_relink_race_policy,
              previous
            );
            if (previous !== next) {
              config.integrationApi.discordRelinkRacePolicy = next;
              changes.discord_relink_race_policy = {
                before: previous,
                after: next
              };
            }
          }

          if (
            Object.prototype.hasOwnProperty.call(
              integrationApiPatch,
              "source_consistency_action"
            )
          ) {
            const previous = normalizeSourceConsistencyPolicyAction(
              config.integrationApi.sourceConsistencyAction,
              "off"
            );
            const next = normalizeSourceConsistencyPolicyAction(
              integrationApiPatch.source_consistency_action,
              previous
            );
            if (previous !== next) {
              config.integrationApi.sourceConsistencyAction = next;
              changes.source_consistency_action = {
                before: previous,
                after: next
              };
            }
          }

          if (Object.prototype.hasOwnProperty.call(llmMonitorPatch, "cli_detection_action")) {
            const previous = normalizeCliEnforcementAction(config.llmMonitor.cliDetectionAction, "warn");
            const next = normalizeCliEnforcementAction(
              llmMonitorPatch.cli_detection_action,
              previous
            );
            if (previous !== next) {
              config.llmMonitor.cliDetectionAction = next;
              changes.cli_detection_action = {
                before: previous,
                after: next
              };
            }
          }

          if (Object.prototype.hasOwnProperty.call(llmMonitorPatch, "cli_confidence_threshold")) {
            const previous = normalizeConfidenceThreshold(
              config.llmMonitor.cliConfidenceThreshold,
              85
            );
            const next = normalizeConfidenceThreshold(
              llmMonitorPatch.cli_confidence_threshold,
              previous
            );
            if (previous !== next) {
              config.llmMonitor.cliConfidenceThreshold = next;
              changes.cli_confidence_threshold = {
                before: previous,
                after: next
              };
            }
          }

          if (Object.prototype.hasOwnProperty.call(llmMonitorPatch, "cli_min_evidence_count")) {
            const previous = normalizePositiveInteger(config.llmMonitor.cliMinEvidenceCount, 1);
            const next = normalizePositiveInteger(
              llmMonitorPatch.cli_min_evidence_count,
              previous
            );
            if (previous !== next) {
              config.llmMonitor.cliMinEvidenceCount = next;
              changes.cli_min_evidence_count = {
                before: previous,
                after: next
              };
            }
          }

          if (
            Object.prototype.hasOwnProperty.call(
              llmMonitorPatch,
              "cli_enforcement_cooldown_sec"
            )
          ) {
            const previous = normalizeNonNegativeInteger(
              config.llmMonitor.cliEnforcementCooldownSec,
              0
            );
            const next = normalizeNonNegativeInteger(
              llmMonitorPatch.cli_enforcement_cooldown_sec,
              previous
            );
            if (previous !== next) {
              config.llmMonitor.cliEnforcementCooldownSec = next;
              changes.cli_enforcement_cooldown_sec = {
                before: previous,
                after: next
              };
            }
          }

          if (Object.prototype.hasOwnProperty.call(llmMonitorPatch, "cli_override_window_sec")) {
            const previous = normalizeNonNegativeInteger(
              config.llmMonitor.cliOverrideWindowSec,
              0
            );
            const next = normalizeNonNegativeInteger(
              llmMonitorPatch.cli_override_window_sec,
              previous
            );
            if (previous !== next) {
              config.llmMonitor.cliOverrideWindowSec = next;
              changes.cli_override_window_sec = {
                before: previous,
                after: next
              };
            }
          }

          if (Object.prototype.hasOwnProperty.call(competitionPatch, "name")) {
            const previous = config.competition.name || "";
            const next =
              typeof competitionPatch.name === "string" &&
              competitionPatch.name.trim().length > 0
                ? competitionPatch.name.trim().slice(0, 120)
                : "";
            if (previous !== next) {
              config.competition.name = next;
              changes.competition_name = { before: previous || null, after: next || null };
            }
          }

          if (Object.prototype.hasOwnProperty.call(competitionPatch, "starts_at")) {
            const previous = config.competition.startsAt || null;
            const next = normalizeOptionalIsoTimestamp(competitionPatch.starts_at);
            if (competitionPatch.starts_at && !next) {
              restoreRuntimePolicyFromRollback();
              return json(res, 400, {
                code: "BAD_REQUEST",
                message: "competition.starts_at must be an ISO timestamp or empty"
              });
            }
            if (previous !== next) {
              config.competition.startsAt = next;
              changes.competition_starts_at = { before: previous, after: next };
            }
          }

          if (Object.prototype.hasOwnProperty.call(competitionPatch, "ends_at")) {
            const previous = config.competition.endsAt || null;
            const next = normalizeOptionalIsoTimestamp(competitionPatch.ends_at);
            if (competitionPatch.ends_at && !next) {
              restoreRuntimePolicyFromRollback();
              return json(res, 400, {
                code: "BAD_REQUEST",
                message: "competition.ends_at must be an ISO timestamp or empty"
              });
            }
            if (previous !== next) {
              config.competition.endsAt = next;
              changes.competition_ends_at = { before: previous, after: next };
            }
          }

          if (
            config.competition.startsAt &&
            config.competition.endsAt &&
            Date.parse(config.competition.startsAt) > Date.parse(config.competition.endsAt)
          ) {
            restoreRuntimePolicyFromRollback();
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "competition start time must be earlier than end time"
            });
          }

          if (Object.keys(changes).length === 0) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "no valid runtime policy changes requested"
            });
          }

          const changedFields = Object.keys(changes);
          const highImpactFields = changedFields.filter((field) =>
            HIGH_IMPACT_RUNTIME_POLICY_FIELDS.has(field)
          );
          const highImpactRequired = highImpactFields.length > 0;
          const highImpactConfirmed = isTrueBoolean(body.high_impact_confirmed);
          if (highImpactRequired) {
            if (reason.length < 24) {
              restoreRuntimePolicyFromRollback();
              return json(res, 400, {
                code: "BAD_REQUEST",
                message:
                  "high-impact runtime policy updates require reason length of at least 24 characters"
              });
            }
            if (!highImpactConfirmed) {
              restoreRuntimePolicyFromRollback();
              return json(res, 400, {
                code: "BAD_REQUEST",
                message:
                  "high-impact runtime policy updates require high_impact_confirmed=true"
              });
            }
          }

          state.addAuditLog({
            action: "ADMIN_RUNTIME_POLICY_UPDATED",
            actor: admin.actor,
            object_type: "runtime_policy",
            object_id: "server",
            detail: {
              reason,
              changes,
              high_impact: {
                required: highImpactRequired,
                confirmed: highImpactRequired ? highImpactConfirmed : false,
                fields: highImpactFields
              }
            }
          });

          return json(res, 200, {
            updated: true,
            changes,
            runtime_config: buildAdminRuntimeConfigPayload()
          });
        }

        if (req.method === "GET" && pathname === "/v1/admin/metrics/detection-quality") {
          if (!requirePermission(res, admin, "read")) return;
          const from = params.get("from") || undefined;
          const to = params.get("to") || undefined;
          if (from && Number.isNaN(Date.parse(from))) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "invalid from timestamp"
            });
          }
          if (to && Number.isNaN(Date.parse(to))) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "invalid to timestamp"
            });
          }

          const metrics = state.getDetectionQualityMetrics({
            from,
            to,
            team_id: params.get("team_id") || undefined,
            user_id: params.get("user_id") || undefined,
            sample_limit: parseNonNegativeNumberParam(params.get("sample_limit"), 20)
          });
          state.addAuditLog({
            action: "ADMIN_VIEW_DETECTION_QUALITY_METRICS",
            actor: admin.actor,
            object_type: "metrics",
            object_id: "detection_quality",
            detail: {
              from: metrics.window.from,
              to: metrics.window.to,
              team_id: metrics.filters.team_id,
              user_id: metrics.filters.user_id
            }
          });
          return json(res, 200, metrics);
        }

        if (req.method === "GET" && pathname === "/v1/admin/metrics/detection-quality/timeseries") {
          if (!requirePermission(res, admin, "read")) return;
          const from = params.get("from") || undefined;
          const to = params.get("to") || undefined;
          if (from && Number.isNaN(Date.parse(from))) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "invalid from timestamp"
            });
          }
          if (to && Number.isNaN(Date.parse(to))) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "invalid to timestamp"
            });
          }
          if (from && to && Date.parse(from) > Date.parse(to)) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "from timestamp must be earlier than to timestamp"
            });
          }

          const timeseries = state.getDetectionQualityMetricsTimeseries({
            from,
            to,
            team_id: params.get("team_id") || undefined,
            user_id: params.get("user_id") || undefined,
            max_buckets: parseNumberParam(params.get("max_buckets"), 90)
          });
          state.addAuditLog({
            action: "ADMIN_VIEW_DETECTION_QUALITY_TIMESERIES",
            actor: admin.actor,
            object_type: "metrics",
            object_id: "detection_quality_timeseries",
            detail: {
              from: timeseries.window.from,
              to: timeseries.window.to,
              team_id: timeseries.filters.team_id,
              user_id: timeseries.filters.user_id,
              total_buckets: timeseries.total_buckets
            }
          });
          return json(res, 200, timeseries);
        }

        if (req.method === "GET" && pathname === "/v1/admin/metrics/gate-failures") {
          if (!requirePermission(res, admin, "read")) return;
          const contestFrom = params.get("contest_from") || undefined;
          const contestTo = params.get("contest_to") || undefined;
          if (contestFrom && Number.isNaN(Date.parse(contestFrom))) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "invalid contest_from timestamp"
            });
          }
          if (contestTo && Number.isNaN(Date.parse(contestTo))) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "invalid contest_to timestamp"
            });
          }
          if (contestFrom && contestTo && Date.parse(contestFrom) > Date.parse(contestTo)) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "contest_from timestamp must be earlier than contest_to timestamp"
            });
          }

          const metrics = state.getGateFailureCounters({
            contest_from: contestFrom,
            contest_to: contestTo
          });
          state.addAuditLog({
            action: "ADMIN_VIEW_GATE_FAILURE_COUNTERS",
            actor: admin.actor,
            object_type: "metrics",
            object_id: "gate_failures",
            detail: {
              contest_from: metrics.windows.contest.from,
              contest_to: metrics.windows.contest.to
            }
          });
          return json(res, 200, metrics);
        }

        if (req.method === "GET" && pathname === "/v1/admin/export") {
          if (!requirePermission(res, admin, "audit")) return;
          const format = String(params.get("format") || "json").trim().toLowerCase();
          const dataset = String(params.get("dataset") || "sessions").trim().toLowerCase();
          const from = params.get("from") || undefined;
          const to = params.get("to") || undefined;
          const userId = params.get("user_id") || undefined;
          if (from && Number.isNaN(Date.parse(from))) {
            return json(res, 400, { code: "BAD_REQUEST", message: "invalid from timestamp" });
          }
          if (to && Number.isNaN(Date.parse(to))) {
            return json(res, 400, { code: "BAD_REQUEST", message: "invalid to timestamp" });
          }
          if (from && to && Date.parse(from) > Date.parse(to)) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "from timestamp must be earlier than to timestamp"
            });
          }
          if (!["json", "csv", "zip"].includes(format)) {
            return json(res, 400, { code: "BAD_REQUEST", message: "format must be json, csv, or zip" });
          }

          state.addAuditLog({
            action: "ADMIN_EXPORT_CGUARD_RECORDS",
            actor: admin.actor,
            object_type: "export",
            object_id: format,
            detail: { format, dataset: format === "csv" ? dataset : "all", from, to, user_id: userId }
          });
          const stamp = exportTimestampForFilename();
          if (format === "zip") {
            const bundle = buildAdminExportZip({ from, to, userId });
            return fileDownload(res, bundle.zipPath, {
              contentType: "application/zip",
              filename: `cguard-export-${bundle.stamp || stamp}.zip`
            });
          }

          const payload = buildAdminExportPayload({ from, to, userId });
          if (format === "json") {
            return textDownload(res, 200, `${JSON.stringify(payload, null, 2)}\n`, {
              contentType: "application/json; charset=utf-8",
              filename: `cguard-export-${stamp}.json`
            });
          }

          const csvDataset = csvDatasetFromExport(payload, dataset);
          if (!csvDataset) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "dataset must be sessions, events, review_notes, or audit_logs"
            });
          }
          return textDownload(res, 200, toCsv(csvDataset.headers, csvDataset.rows), {
            contentType: "text/csv; charset=utf-8",
            filename: `cguard-${dataset}-${stamp}.csv`
          });
        }

        if (req.method === "POST" && participantResetMatch) {
          if (!requirePermission(res, admin, "enforce")) return;
          const userId = decodeURIComponent(participantResetMatch[1]);
          const body = await readJsonBody(req);
          const reason =
            typeof body.reason === "string" && body.reason.trim()
              ? body.reason.trim()
              : "manual participant reconnect reset";
          const reset = runInStateTransaction(() =>
            state.resetParticipantForReconnect({
              user_id: userId,
              actor: admin.actor,
              reason,
              clear_bans: body.clear_bans === true
            })
          );
          if (!reset) {
            return json(res, 404, { code: "NOT_FOUND", message: "participant not found" });
          }
          return json(res, 200, reset);
        }

        if (req.method === "GET" && pathname === "/v1/admin/sessions") {
          if (!requirePermission(res, admin, "read")) return;
          const decisionReasonCode = parseStringListParam(params, "decision_reason_code");
          const sessions = state.listSessions({
            status: params.get("status") || undefined,
            upload_status: params.get("upload_status") || undefined,
            team_id: params.get("team_id") || undefined,
            user_id: params.get("user_id") || undefined,
            decision_reason_code: decisionReasonCode,
            limit: parseNumberParam(params.get("limit"), 100),
            offset: parseNonNegativeNumberParam(params.get("offset"), 0)
          });
          const enrichedItems = Array.isArray(sessions.items)
            ? sessions.items.map(enrichAdminSessionRow)
            : [];
          return json(res, 200, {
            ...sessions,
            items: enrichedItems
          });
        }

        if (req.method === "GET" && pathname === "/v1/admin/events") {
          if (!requirePermission(res, admin, "read")) return;
          const events = state.listEvents({
            team_id: params.get("team_id") || undefined,
            user_id: params.get("user_id") || undefined,
            type: params.get("type") || undefined,
            limit: parseNumberParam(params.get("limit"), 200),
            offset: parseNonNegativeNumberParam(params.get("offset"), 0)
          });
          return json(res, 200, events);
        }

        if (req.method === "GET" && pathname === "/v1/admin/audit") {
          if (!requirePermission(res, admin, "audit")) return;
          const from = params.get("from") || undefined;
          const to = params.get("to") || undefined;
          if (from && Number.isNaN(Date.parse(from))) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "invalid from timestamp"
            });
          }
          if (to && Number.isNaN(Date.parse(to))) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "invalid to timestamp"
            });
          }
          const logs = state.listAuditLogs({
            actor: params.get("actor") || undefined,
            action: params.get("action") || undefined,
            from,
            to,
            limit: parseNumberParam(params.get("limit"), 100),
            offset: parseNonNegativeNumberParam(params.get("offset"), 0)
          });
          return json(res, 200, logs);
        }

        if (req.method === "GET" && pathname === "/v1/admin/bans") {
          if (!requirePermission(res, admin, "read")) return;
          const bans = state.listBans({
            status: params.get("status") || undefined,
            scope: params.get("scope") || undefined,
            limit: parseNumberParam(params.get("limit"), 100),
            offset: parseNonNegativeNumberParam(params.get("offset"), 0)
          });
          return json(res, 200, bans);
        }

        if (req.method === "POST" && pathname === "/v1/admin/bans") {
          if (!requirePermission(res, admin, "enforce")) return;
          const body = await readJsonBody(req);
          const scope = body.scope;
          const targetId = body.target_id;
          const reason = body.reason || "manual review action";
          const reasonCode = body.reason_code || null;
          const durationSec = Number(body.duration_sec || 0);
          if (!["user", "team", "session"].includes(scope) || !targetId) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "scope(user|team|session) and target_id are required"
            });
          }
          const ban = runInStateTransaction(() => {
            const created = state.createBan({
              scope,
              target_id: targetId,
              reason,
              reason_code: reasonCode,
              duration_sec: Number.isFinite(durationSec) ? Math.max(0, durationSec) : 0,
              created_by: admin.actor
            });

            if (scope === "user") {
              state.revokeActiveJtiForUser(targetId);
            } else if (scope === "session") {
              const targetSession = state.getSession(targetId);
              if (targetSession) {
                state.revokeActiveJtiForUser(targetSession.user_id);
              }
            }
            return created;
          });

          return json(res, 201, ban);
        }

        if (req.method === "DELETE" && revokeBanMatch) {
          if (!requirePermission(res, admin, "enforce")) return;
          const banId = decodeURIComponent(revokeBanMatch[1]);
          const revoked = runInStateTransaction(() => state.revokeBan(banId, admin.actor));
          if (!revoked) {
            return json(res, 404, { code: "NOT_FOUND", message: "ban not found" });
          }
          return json(res, 200, revoked);
        }

        if (req.method === "POST" && pathname === "/v1/admin/review-notes") {
          if (!requirePermission(res, admin, "review")) return;
          const body = await readJsonBody(req);
          const sessionId = body.session_id;
          if (!sessionId || !state.getSession(sessionId)) {
            return json(res, 404, {
              code: "NOT_FOUND",
              message: "session not found"
            });
          }
          try {
            const note = state.addReviewNote({
              session_id: sessionId,
              author: admin.actor,
              note: body.note,
              metadata: body.metadata || {}
            });
            return json(res, 201, note);
          } catch (error) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: error.message
            });
          }
        }

        if (req.method === "GET" && pathname === "/v1/admin/review-notes") {
          if (!requirePermission(res, admin, "read")) return;
          const from = params.get("from") || undefined;
          const to = params.get("to") || undefined;
          if (from && Number.isNaN(Date.parse(from))) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "invalid from timestamp"
            });
          }
          if (to && Number.isNaN(Date.parse(to))) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "invalid to timestamp"
            });
          }
          const notes = state.listReviewNotes({
            session_id: params.get("session_id") || undefined,
            author: params.get("author") || undefined,
            related_event_type: params.get("related_event_type") || undefined,
            related_severity: params.get("related_severity") || undefined,
            from,
            to,
            limit: parseNumberParam(params.get("limit"), 100),
            offset: parseNonNegativeNumberParam(params.get("offset"), 0)
          });
          return json(res, 200, notes);
        }

        if (req.method === "POST" && pathname === "/v1/admin/review-actions") {
          if (!requirePermission(res, admin, "review")) return;
          const body = await readJsonBody(req);
          const sessionId = body.session_id;
          if (!sessionId || !state.getSession(sessionId)) {
            return json(res, 404, {
              code: "NOT_FOUND",
              message: "session not found"
            });
          }
          try {
            const action = state.addReviewAction({
              session_id: sessionId,
              actor: admin.actor,
              action: body.action,
              reason: body.reason,
              metadata: body.metadata || {}
            });
            return json(res, 201, action);
          } catch (error) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: error.message
            });
          }
        }

        if (req.method === "GET" && pathname === "/v1/admin/review-actions") {
          if (!requirePermission(res, admin, "read")) return;
          const from = params.get("from") || undefined;
          const to = params.get("to") || undefined;
          if (from && Number.isNaN(Date.parse(from))) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "invalid from timestamp"
            });
          }
          if (to && Number.isNaN(Date.parse(to))) {
            return json(res, 400, {
              code: "BAD_REQUEST",
              message: "invalid to timestamp"
            });
          }
          const actions = state.listReviewActions({
            session_id: params.get("session_id") || undefined,
            actor: params.get("actor") || undefined,
            action: params.get("action") || undefined,
            related_event_type: params.get("related_event_type") || undefined,
            related_severity: params.get("related_severity") || undefined,
            from,
            to,
            limit: parseNumberParam(params.get("limit"), 100),
            offset: parseNonNegativeNumberParam(params.get("offset"), 0)
          });
          return json(res, 200, actions);
        }

        if (req.method === "GET" && investigationMatch) {
          if (!requirePermission(res, admin, "read")) return;
          const sessionId = decodeURIComponent(investigationMatch[1]);
          const payload = resolveInvestigationInput(sessionId);
          if (!payload) {
            return json(res, 404, { code: "NOT_FOUND", message: "session not found" });
          }
          const viewModel = buildInvestigationViewModel({
            session: payload.sessionView,
            events: payload.events,
            rejections: payload.rejections,
            notes: payload.notes,
            actions: payload.actions,
            filters: {
              severity: params.get("severity") || undefined,
              event_type: params.get("event_type") || undefined,
              collapse_noisy: params.get("collapse_noisy") === "1",
              validation_warn_only: params.get("validation_warn_only") === "1",
              validation_failed_rule: params.get("validation_failed_rule") || undefined,
              llm_domain_only: params.get("llm_domain_only") === "1"
            },
            versionPolicyConfig: config.versionPolicy
          });
          const evidenceIndex = params.get("evidence_index");
          const withEvidence =
            evidenceIndex !== null
              ? selectEvidenceDetail(viewModel, parseNumberParam(evidenceIndex, 1) - 1)
              : viewModel;
          return json(res, 200, withEvidence);
        }

        if (req.method === "GET" && sessionSummaryMatch) {
          if (!requirePermission(res, admin, "read")) return;
          const sessionId = decodeURIComponent(sessionSummaryMatch[1]);
          const payload = resolveInvestigationInput(sessionId);
          if (!payload) {
            return json(res, 404, { code: "NOT_FOUND", message: "session not found" });
          }
          const viewModel = buildInvestigationViewModel({
            session: payload.sessionView,
            events: payload.events,
            rejections: payload.rejections,
            notes: payload.notes,
            actions: payload.actions,
            versionPolicyConfig: config.versionPolicy
          });
          return json(res, 200, { session: viewModel.session_summary });
        }

        if (req.method === "GET" && sessionEventsMatch) {
          if (!requirePermission(res, admin, "read")) return;
          const sessionId = decodeURIComponent(sessionEventsMatch[1]);
          const payload = resolveInvestigationInput(sessionId);
          if (!payload) {
            return json(res, 404, { code: "NOT_FOUND", message: "session not found" });
          }
          const viewModel = buildInvestigationViewModel({
            session: payload.sessionView,
            events: payload.events,
            rejections: payload.rejections,
            notes: payload.notes,
            actions: payload.actions,
            versionPolicyConfig: config.versionPolicy
          });
          return json(res, 200, { timeline: viewModel.event_timeline });
        }

        if (req.method === "GET" && scoreBreakdownMatch) {
          if (!requirePermission(res, admin, "read")) return;
          const sessionId = decodeURIComponent(scoreBreakdownMatch[1]);
          const payload = resolveInvestigationInput(sessionId);
          if (!payload) {
            return json(res, 404, { code: "NOT_FOUND", message: "session not found" });
          }
          const viewModel = buildInvestigationViewModel({
            session: payload.sessionView,
            events: payload.events,
            rejections: payload.rejections,
            notes: payload.notes,
            actions: payload.actions,
            versionPolicyConfig: config.versionPolicy
          });
          return json(res, 200, { risk_overview: viewModel.risk_overview });
        }
      }
      return json(res, 404, { code: "NOT_FOUND", message: "route not found" });
    } catch (error) {
      return json(res, 500, {
        code: "INTERNAL_ERROR",
        message: error.message
      });
    }
  }

  const server = http.createServer(handler);
  return {
    server,
    state,
    config,
    eventStore
  };
}

module.exports = {
  createApp
};
