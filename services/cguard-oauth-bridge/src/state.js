"use strict";

const crypto = require("crypto");

function toBase64UrlJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function fromBase64UrlJson(value) {
  return JSON.parse(Buffer.from(String(value || ""), "base64url").toString("utf8"));
}

function normalizeNonEmptyString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : "";
}

function signStatePayload(payloadBase64, secret) {
  const normalizedSecret = normalizeNonEmptyString(secret);
  if (!normalizedSecret) {
    throw new Error("OAUTH_STATE_SIGNING_SECRET is required");
  }
  return crypto.createHmac("sha256", normalizedSecret).update(payloadBase64).digest("base64url");
}

function safeEqualString(a, b) {
  const left = Buffer.from(String(a || ""), "utf8");
  const right = Buffer.from(String(b || ""), "utf8");
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function createMemoryNonceStore({ now = Date.now } = {}) {
  const entries = new Map();

  function prune() {
    const current = now();
    for (const [nonce, expiresAtMs] of entries.entries()) {
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= current) {
        entries.delete(nonce);
      }
    }
  }

  return {
    remember(nonce, expiresAtMs) {
      prune();
      const normalizedNonce = normalizeNonEmptyString(nonce);
      if (!normalizedNonce) return false;
      entries.set(normalizedNonce, Number(expiresAtMs));
      return true;
    },
    consume(nonce) {
      prune();
      const normalizedNonce = normalizeNonEmptyString(nonce);
      if (!normalizedNonce || !entries.has(normalizedNonce)) {
        return false;
      }
      entries.delete(normalizedNonce);
      return true;
    },
    size() {
      prune();
      return entries.size;
    }
  };
}

function createSignedState(input, options) {
  const opts = options || {};
  const now = typeof opts.now === "function" ? opts.now : Date.now;
  const ttlMs = Number.isFinite(Number(opts.ttlMs)) ? Math.max(1000, Number(opts.ttlMs)) : 600000;
  const nonce =
    normalizeNonEmptyString(opts.nonce) ||
    (typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : crypto.randomBytes(16).toString("hex"));
  const expiresAtMs = now() + ttlMs;
  const payload = {
    v: 1,
    user_id: normalizeNonEmptyString(input && input.userId),
    session_id: normalizeNonEmptyString(input && input.sessionId),
    reason_code: normalizeNonEmptyString(input && input.reasonCode) || "DISCORD_IDENTITY_REQUIRED",
    server_base_url: normalizeNonEmptyString(input && input.serverBaseUrl),
    nonce,
    exp: expiresAtMs
  };
  const payloadBase64 = toBase64UrlJson(payload);
  const signature = signStatePayload(payloadBase64, opts.secret);
  if (opts.nonceStore && typeof opts.nonceStore.remember === "function") {
    opts.nonceStore.remember(nonce, expiresAtMs);
  }
  return {
    state: `${payloadBase64}.${signature}`,
    payload
  };
}

function verifySignedState(state, options) {
  const opts = options || {};
  const now = typeof opts.now === "function" ? opts.now : Date.now;
  const raw = normalizeNonEmptyString(state);
  const parts = raw.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return { ok: false, code: "INVALID_STATE_FORMAT", message: "invalid OAuth state format" };
  }
  const expectedSignature = signStatePayload(parts[0], opts.secret);
  if (!safeEqualString(parts[1], expectedSignature)) {
    return { ok: false, code: "INVALID_STATE_SIGNATURE", message: "invalid OAuth state signature" };
  }

  let payload;
  try {
    payload = fromBase64UrlJson(parts[0]);
  } catch (_error) {
    return { ok: false, code: "INVALID_STATE_PAYLOAD", message: "invalid OAuth state payload" };
  }

  if (!payload || payload.v !== 1) {
    return { ok: false, code: "UNSUPPORTED_STATE_VERSION", message: "unsupported OAuth state version" };
  }
  if (!Number.isFinite(Number(payload.exp)) || Number(payload.exp) <= now()) {
    return { ok: false, code: "EXPIRED_STATE", message: "OAuth state expired" };
  }
  if (!normalizeNonEmptyString(payload.user_id) || !normalizeNonEmptyString(payload.session_id)) {
    return { ok: false, code: "INCOMPLETE_STATE", message: "OAuth state missing C-Guard identity" };
  }
  if (opts.nonceStore && typeof opts.nonceStore.consume === "function") {
    if (!opts.nonceStore.consume(payload.nonce)) {
      return { ok: false, code: "STATE_REPLAYED", message: "OAuth state was already used" };
    }
  }

  return { ok: true, payload };
}

module.exports = {
  createMemoryNonceStore,
  createSignedState,
  verifySignedState
};
