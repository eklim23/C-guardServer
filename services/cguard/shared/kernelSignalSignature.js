"use strict";

const crypto = require("node:crypto");

const SIGNATURE_EXCLUDED_EVIDENCE_KEYS = new Set(["kernel_validation", "bridge_signature"]);

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeSecret(secret) {
  if (typeof secret !== "string") return null;
  if (secret.length === 0) return null;
  return secret;
}

function normalizeSignature(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(trimmed)) return null;
  return trimmed;
}

function stableClone(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => stableClone(entry));
  }
  if (isPlainObject(value)) {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = stableClone(value[key]);
    }
    return out;
  }
  return value;
}

function buildEvidencePayload(evidence) {
  if (!isPlainObject(evidence)) return null;
  const out = {};
  for (const key of Object.keys(evidence).sort()) {
    if (SIGNATURE_EXCLUDED_EVIDENCE_KEYS.has(key)) continue;
    out[key] = stableClone(evidence[key]);
  }
  return out;
}

function buildKernelBridgeSignaturePayload(event) {
  if (!isPlainObject(event)) return null;
  const evidence = buildEvidencePayload(event.evidence);
  if (!evidence) return null;
  return stableClone({
    event_type: event.event_type,
    severity: event.severity,
    timestamp: event.timestamp,
    session_id: event.session_id,
    user_id: event.user_id,
    client_version: event.client_version,
    evidence
  });
}

function computeKernelBridgeSignature(event, signingSecret) {
  const secret = normalizeSecret(signingSecret);
  if (!secret) return null;
  const payload = buildKernelBridgeSignaturePayload(event);
  if (!payload) return null;
  const body = JSON.stringify(payload);
  return crypto.createHmac("sha256", secret).update(body).digest("hex");
}

function hasKernelBridgeSigningSecret(signingSecret) {
  return normalizeSecret(signingSecret) !== null;
}

function verifyKernelBridgeSignature(event, providedSignature, signingSecret) {
  const signature = normalizeSignature(providedSignature);
  if (!signature) {
    return {
      ok: false,
      reason: "missing_or_invalid_signature_format"
    };
  }
  const expected = computeKernelBridgeSignature(event, signingSecret);
  if (!expected) {
    return {
      ok: false,
      reason: "signature_verification_not_configured"
    };
  }
  const matches = crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  return {
    ok: matches,
    reason: matches ? "ok" : "signature_mismatch"
  };
}

module.exports = {
  buildKernelBridgeSignaturePayload,
  computeKernelBridgeSignature,
  hasKernelBridgeSigningSecret,
  verifyKernelBridgeSignature
};
