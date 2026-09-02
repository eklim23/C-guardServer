"use strict";

const {
  hasKernelBridgeSigningSecret,
  verifyKernelBridgeSignature
} = require("../shared/kernelSignalSignature");
const { verifyKernelBindingToken } = require("./tokenService");

const KERNEL_EVENT_TYPES = new Set(["KERNEL_TAMPER_SIGNAL", "KERNEL_CALLBACK_ANOMALY"]);
const REPLAY_EXCLUDED_EVIDENCE_KEYS = new Set([
  "kernel_validation",
  "bridge_counter",
  "bridge_nonce",
  "bridge_session_id",
  "bridge_emitted_at",
  "bridge_signature",
  "bridge_binding_token"
]);

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function normalizeNonNegativeInteger(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  if (!Number.isInteger(value) || value < 0) return null;
  return value;
}

function normalizeBridgeNonce(value) {
  const normalized = normalizeString(value);
  if (!normalized) return null;
  if (normalized.length > 128) return null;
  return normalized;
}

function normalizePositiveInteger(value, fallback) {
  if (!Number.isFinite(value)) return fallback;
  const parsed = Math.floor(value);
  if (parsed <= 0) return fallback;
  return parsed;
}

function parseIsoTimestampMs(value) {
  if (typeof value !== "string" || value.trim() === "") return null;
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return null;
  return parsed;
}

function isKernelEvent(event) {
  if (!isPlainObject(event)) return false;
  return KERNEL_EVENT_TYPES.has(event.event_type);
}

function buildReplayKey(event) {
  const evidence = isPlainObject(event.evidence) ? event.evidence : {};
  const normalizedEvidence = {};
  const keys = Object.keys(evidence).sort();
  for (const key of keys) {
    if (REPLAY_EXCLUDED_EVIDENCE_KEYS.has(key)) continue;
    normalizedEvidence[key] = evidence[key];
  }
  return `${event.event_type}|${JSON.stringify(normalizedEvidence)}`;
}

function ensureContextField(context, key, defaultValueFactory) {
  if (!isPlainObject(context)) {
    throw new Error("kernel integrity context must be an object");
  }
  if (!(key in context)) {
    context[key] = defaultValueFactory();
  }
  return context[key];
}

function getOrCreateMapValue(map, key, defaultValueFactory) {
  if (!(map instanceof Map)) {
    throw new Error("expected Map in kernel integrity context");
  }
  if (!map.has(key)) {
    map.set(key, defaultValueFactory());
  }
  return map.get(key);
}

function seedSessionContextFromHistory(context, sessionId) {
  const seededSessions = ensureContextField(context, "seededSessions", () => new Set());
  if (seededSessions.has(sessionId)) return;
  seededSessions.add(sessionId);

  const replayKeysBySession = ensureContextField(context, "replayKeysBySession", () => new Map());
  const countersBySession = ensureContextField(context, "lastCounterBySession", () => new Map());
  const nonceSetBySession = ensureContextField(context, "nonceSetBySession", () => new Map());
  const nonceToCounterBySession = ensureContextField(context, "nonceToCounterBySession", () => new Map());
  const counterToNonceBySession = ensureContextField(context, "counterToNonceBySession", () => new Map());
  const lastEmittedAtBySession = ensureContextField(context, "lastEmittedAtBySession", () => new Map());
  const replayKeys = getOrCreateMapValue(replayKeysBySession, sessionId, () => new Set());
  const nonceSet = getOrCreateMapValue(nonceSetBySession, sessionId, () => new Set());
  const nonceToCounter = getOrCreateMapValue(nonceToCounterBySession, sessionId, () => new Map());
  const counterToNonce = getOrCreateMapValue(counterToNonceBySession, sessionId, () => new Map());
  let lastCounter = null;
  let lastEmittedAt = null;

  const byId = context.sessionHistoryById;
  const history = isPlainObject(byId) && Array.isArray(byId[sessionId]) ? byId[sessionId] : [];
  for (const event of history) {
    if (!isKernelEvent(event)) continue;
    replayKeys.add(buildReplayKey(event));
    const evidence = isPlainObject(event.evidence) ? event.evidence : {};
    const counter = normalizeNonNegativeInteger(evidence.bridge_counter);
    if (counter !== null && (lastCounter === null || counter > lastCounter)) {
      lastCounter = counter;
    }
    const bridgeNonce = normalizeBridgeNonce(evidence.bridge_nonce);
    if (bridgeNonce) {
      nonceSet.add(bridgeNonce);
      if (counter !== null && !nonceToCounter.has(bridgeNonce)) {
        nonceToCounter.set(bridgeNonce, counter);
      }
    }
    if (counter !== null && bridgeNonce && !counterToNonce.has(counter)) {
      counterToNonce.set(counter, bridgeNonce);
    }
    const bridgeEmittedAtMs = parseIsoTimestampMs(evidence.bridge_emitted_at);
    if (
      bridgeEmittedAtMs !== null &&
      (lastEmittedAt === null || bridgeEmittedAtMs > lastEmittedAt)
    ) {
      lastEmittedAt = bridgeEmittedAtMs;
    }
  }

  if (lastCounter !== null) {
    countersBySession.set(sessionId, lastCounter);
  }
  if (lastEmittedAt !== null) {
    lastEmittedAtBySession.set(sessionId, lastEmittedAt);
  }
}

function makeRule(rule, status, message, details) {
  const entry = { rule, status, message };
  if (details && isPlainObject(details)) {
    entry.details = details;
  }
  return entry;
}

function evaluateKernelSignalIntegrity(event, context = {}) {
  if (!isKernelEvent(event)) return null;
  const evidence = isPlainObject(event.evidence) ? event.evidence : {};
  const sessionId = String(event.session_id || "");
  if (!sessionId) return null;

  seedSessionContextFromHistory(context, sessionId);
  const replayKeysBySession = ensureContextField(context, "replayKeysBySession", () => new Map());
  const countersBySession = ensureContextField(context, "lastCounterBySession", () => new Map());
  const nonceSetBySession = ensureContextField(context, "nonceSetBySession", () => new Map());
  const nonceToCounterBySession = ensureContextField(context, "nonceToCounterBySession", () => new Map());
  const counterToNonceBySession = ensureContextField(context, "counterToNonceBySession", () => new Map());
  const lastEmittedAtBySession = ensureContextField(context, "lastEmittedAtBySession", () => new Map());
  const kernelCountBySession = ensureContextField(context, "kernelCountBySession", () => new Map());
  const replayKeys = getOrCreateMapValue(replayKeysBySession, sessionId, () => new Set());
  const nonceSet = getOrCreateMapValue(nonceSetBySession, sessionId, () => new Set());
  const nonceToCounter = getOrCreateMapValue(nonceToCounterBySession, sessionId, () => new Map());
  const counterToNonce = getOrCreateMapValue(counterToNonceBySession, sessionId, () => new Map());
  const maxKernelSignalsPerBatch =
    Number.isFinite(context.maxKernelSignalsPerBatch) && context.maxKernelSignalsPerBatch > 0
      ? Math.floor(context.maxKernelSignalsPerBatch)
      : 5;
  const maxBridgeCounterGap = normalizePositiveInteger(context.maxBridgeCounterGap, 1000);
  const maxBridgeEmitDeltaMs =
    Number.isFinite(context.maxBridgeEmitDeltaMs) && context.maxBridgeEmitDeltaMs > 0
      ? Math.floor(context.maxBridgeEmitDeltaMs)
      : 60 * 1000;
  const maxBridgeStalenessMs = normalizePositiveInteger(context.maxBridgeStalenessMs, 0);
  const requireBridgeNonce = context.requireBridgeNonce === true;
  const requireBridgeEmittedAt = context.requireBridgeEmittedAt === true;
  const requireBridgeSignature = context.requireBridgeSignature === true;
  const kernelBridgeSigningSecret =
    typeof context.kernelBridgeSigningSecret === "string"
      ? context.kernelBridgeSigningSecret
      : "";
  const requireSessionBindingToken = context.requireSessionBindingToken === true;
  const kernelBindingSigningSecret =
    typeof context.kernelBindingSigningSecret === "string"
      ? context.kernelBindingSigningSecret
      : "";
  const canonicalClientInstanceId =
    typeof context.clientInstanceId === "string" ? context.clientInstanceId : "";
  const checkedAtMs =
    Number.isFinite(context.nowMs) && context.nowMs > 0
      ? Math.floor(context.nowMs)
      : Date.now();

  const rules = [];
  const source = normalizeString(evidence.detection_source);
  if (source === null) {
    rules.push(
      makeRule("source_presence", "warn", "missing evidence.detection_source for kernel event")
    );
  } else if (source !== "kernel_bridge") {
    rules.push(
      makeRule(
        "source_expected_kernel_bridge",
        "warn",
        "kernel event detection_source is not kernel_bridge",
        { detection_source: source }
      )
    );
  } else {
    rules.push(makeRule("source_expected_kernel_bridge", "pass", "kernel_bridge source confirmed"));
  }

  const bridgeSessionId = normalizeString(evidence.bridge_session_id);
  if (bridgeSessionId && bridgeSessionId !== sessionId) {
    rules.push(
      makeRule(
        "session_binding",
        "warn",
        "bridge_session_id does not match canonical session_id",
        { bridge_session_id: bridgeSessionId, session_id: sessionId }
      )
    );
  } else {
    rules.push(makeRule("session_binding", "pass", "session binding check passed"));
  }

  const replayKey = buildReplayKey(event);
  if (replayKeys.has(replayKey)) {
    rules.push(makeRule("replay_pattern", "warn", "duplicate kernel signal replay fingerprint"));
  } else {
    rules.push(makeRule("replay_pattern", "pass", "no replay fingerprint conflict detected"));
  }
  replayKeys.add(replayKey);

  const bridgeCounter = normalizeNonNegativeInteger(evidence.bridge_counter);
  const previousCounter = countersBySession.has(sessionId) ? countersBySession.get(sessionId) : null;
  if (bridgeCounter !== null) {
    if (previousCounter !== null && bridgeCounter <= previousCounter) {
      rules.push(
        makeRule(
          "bridge_counter_monotonic",
          "warn",
          "bridge_counter is not strictly increasing",
          { previous: previousCounter, current: bridgeCounter }
        )
      );
    } else {
      rules.push(makeRule("bridge_counter_monotonic", "pass", "bridge_counter monotonicity passed"));
    }
    if (previousCounter !== null && bridgeCounter > previousCounter) {
      const counterGap = bridgeCounter - previousCounter;
      if (counterGap > maxBridgeCounterGap) {
        rules.push(
          makeRule(
            "bridge_counter_gap",
            "warn",
            "bridge_counter jumped beyond allowed gap",
            {
              previous: previousCounter,
              current: bridgeCounter,
              gap: counterGap,
              max_gap: maxBridgeCounterGap
            }
          )
        );
      } else {
        rules.push(
          makeRule(
            "bridge_counter_gap",
            "pass",
            "bridge_counter gap check passed"
          )
        );
      }
    } else {
      rules.push(
        makeRule(
          "bridge_counter_gap",
          "pass",
          "bridge_counter gap check skipped (no previous counter)"
        )
      );
    }
    countersBySession.set(sessionId, bridgeCounter);
  } else {
    rules.push(
      makeRule(
        "bridge_counter_monotonic",
        "warn",
        "missing or invalid evidence.bridge_counter for kernel event"
      )
    );
    rules.push(
      makeRule(
        "bridge_counter_gap",
        "pass",
        "bridge_counter gap check skipped (missing bridge_counter)"
      )
    );
  }

  const bridgeNonce = normalizeBridgeNonce(evidence.bridge_nonce);
  if (bridgeNonce === null) {
    if (requireBridgeNonce) {
      rules.push(
        makeRule(
          "bridge_nonce_presence",
          "warn",
          "missing evidence.bridge_nonce for kernel bridge event"
        )
      );
    } else {
      rules.push(
        makeRule(
          "bridge_nonce_presence",
          "pass",
          "bridge_nonce not provided; compatibility mode applied"
        )
      );
    }
    rules.push(
      makeRule(
        "bridge_nonce_reuse",
        "pass",
        "bridge_nonce not provided; compatibility mode applied"
      )
    );
  } else if (nonceSet.has(bridgeNonce)) {
    rules.push(makeRule("bridge_nonce_presence", "pass", "bridge_nonce presence check passed"));
    rules.push(
      makeRule("bridge_nonce_reuse", "warn", "bridge_nonce already observed for this session")
    );
  } else {
    rules.push(makeRule("bridge_nonce_presence", "pass", "bridge_nonce presence check passed"));
    rules.push(makeRule("bridge_nonce_reuse", "pass", "bridge_nonce uniqueness check passed"));
    nonceSet.add(bridgeNonce);
  }
  if (bridgeNonce !== null && bridgeCounter !== null) {
    const priorCounterForNonce = nonceToCounter.get(bridgeNonce);
    const priorNonceForCounter = counterToNonce.get(bridgeCounter);
    if (priorCounterForNonce !== undefined && priorCounterForNonce !== bridgeCounter) {
      rules.push(
        makeRule(
          "bridge_nonce_counter_consistency",
          "warn",
          "bridge_nonce observed with different bridge_counter",
          {
            bridge_nonce: bridgeNonce,
            previous_counter: priorCounterForNonce,
            current_counter: bridgeCounter
          }
        )
      );
    } else if (priorNonceForCounter !== undefined && priorNonceForCounter !== bridgeNonce) {
      rules.push(
        makeRule(
          "bridge_nonce_counter_consistency",
          "warn",
          "bridge_counter observed with different bridge_nonce",
          {
            bridge_counter: bridgeCounter,
            previous_nonce: priorNonceForCounter,
            current_nonce: bridgeNonce
          }
        )
      );
    } else {
      rules.push(
        makeRule(
          "bridge_nonce_counter_consistency",
          "pass",
          "bridge nonce/counter consistency check passed"
        )
      );
      if (priorCounterForNonce === undefined) {
        nonceToCounter.set(bridgeNonce, bridgeCounter);
      }
      if (priorNonceForCounter === undefined) {
        counterToNonce.set(bridgeCounter, bridgeNonce);
      }
    }
  } else {
    rules.push(
      makeRule(
        "bridge_nonce_counter_consistency",
        "pass",
        "bridge nonce/counter consistency check skipped (missing nonce or counter)"
      )
    );
  }

  const hasBridgeEmittedAtField = Object.prototype.hasOwnProperty.call(evidence, "bridge_emitted_at");
  const bridgeEmittedAtMs = parseIsoTimestampMs(evidence.bridge_emitted_at);
  const previousEmittedAtMs = lastEmittedAtBySession.has(sessionId)
    ? lastEmittedAtBySession.get(sessionId)
    : null;
  if (!hasBridgeEmittedAtField) {
    if (requireBridgeEmittedAt) {
      rules.push(
        makeRule(
          "bridge_emitted_at_monotonic",
          "warn",
          "missing evidence.bridge_emitted_at for kernel bridge event"
        )
      );
    } else {
      rules.push(
        makeRule(
          "bridge_emitted_at_monotonic",
          "pass",
          "bridge_emitted_at not provided; compatibility mode applied"
        )
      );
    }
    rules.push(
      makeRule(
        "bridge_emitted_at_freshness",
        "pass",
        "bridge_emitted_at not provided; compatibility mode applied"
      )
    );
    rules.push(
      makeRule(
        "bridge_staleness",
        "pass",
        "bridge_staleness check skipped (bridge_emitted_at missing)"
      )
    );
  } else if (bridgeEmittedAtMs === null) {
    rules.push(
      makeRule(
        "bridge_emitted_at_monotonic",
        "warn",
        "bridge_emitted_at is missing or invalid timestamp"
      )
    );
    rules.push(
      makeRule(
        "bridge_emitted_at_freshness",
        "warn",
        "bridge_emitted_at is missing or invalid timestamp"
      )
    );
    rules.push(
      makeRule(
        "bridge_staleness",
        "warn",
        "bridge_staleness check failed due to invalid bridge_emitted_at timestamp"
      )
    );
  } else {
    if (previousEmittedAtMs !== null && bridgeEmittedAtMs <= previousEmittedAtMs) {
      rules.push(
        makeRule(
          "bridge_emitted_at_monotonic",
          "warn",
          "bridge_emitted_at is not strictly increasing",
          {
            previous: new Date(previousEmittedAtMs).toISOString(),
            current: new Date(bridgeEmittedAtMs).toISOString()
          }
        )
      );
    } else {
      rules.push(
        makeRule(
          "bridge_emitted_at_monotonic",
          "pass",
          "bridge_emitted_at monotonicity check passed"
        )
      );
    }
    lastEmittedAtBySession.set(sessionId, bridgeEmittedAtMs);
    const eventTimestampMs = Date.parse(event.timestamp);
    const deltaMs = Math.abs(eventTimestampMs - bridgeEmittedAtMs);
    if (deltaMs > maxBridgeEmitDeltaMs) {
      rules.push(
        makeRule(
          "bridge_emitted_at_freshness",
          "warn",
          "bridge_emitted_at differs from event timestamp beyond allowed threshold",
          {
            delta_ms: deltaMs,
            threshold_ms: maxBridgeEmitDeltaMs
          }
        )
      );
    } else {
      rules.push(
        makeRule(
          "bridge_emitted_at_freshness",
          "pass",
          "bridge_emitted_at freshness check passed"
        )
      );
    }
    if (maxBridgeStalenessMs <= 0) {
      rules.push(
        makeRule(
          "bridge_staleness",
          "pass",
          "bridge_staleness policy disabled (compatibility mode)"
        )
      );
    } else {
      const stalenessMs = checkedAtMs - bridgeEmittedAtMs;
      if (stalenessMs > maxBridgeStalenessMs) {
        rules.push(
          makeRule(
            "bridge_staleness",
            "warn",
            "bridge signal exceeded max staleness threshold",
            {
              staleness_ms: stalenessMs,
              max_staleness_ms: maxBridgeStalenessMs
            }
          )
        );
      } else {
        rules.push(
          makeRule(
            "bridge_staleness",
            "pass",
            "bridge staleness check passed",
            {
              staleness_ms: stalenessMs,
              max_staleness_ms: maxBridgeStalenessMs
            }
          )
        );
      }
    }
  }

  const bridgeSignature = normalizeString(evidence.bridge_signature);
  const hasSigningSecret = hasKernelBridgeSigningSecret(kernelBridgeSigningSecret);
  if (!hasSigningSecret) {
    if (requireBridgeSignature) {
      rules.push(
        makeRule(
          "bridge_signature_verification",
          "warn",
          "kernel bridge signature is required but server signing secret is not configured"
        )
      );
    } else if (bridgeSignature) {
      rules.push(
        makeRule(
          "bridge_signature_verification",
          "warn",
          "bridge_signature provided but verification secret is not configured"
        )
      );
    } else {
      rules.push(
        makeRule(
          "bridge_signature_verification",
          "pass",
          "bridge signature verification disabled (no signing secret configured)"
        )
      );
    }
  } else if (!bridgeSignature) {
    if (requireBridgeSignature) {
      rules.push(
        makeRule(
          "bridge_signature_verification",
          "warn",
          "missing evidence.bridge_signature for kernel bridge event"
        )
      );
    } else {
      rules.push(
        makeRule(
          "bridge_signature_verification",
          "pass",
          "bridge_signature not provided; compatibility mode applied"
        )
      );
    }
  } else {
    const signatureCheck = verifyKernelBridgeSignature(
      event,
      bridgeSignature,
      kernelBridgeSigningSecret
    );
    if (!signatureCheck.ok) {
      rules.push(
        makeRule(
          "bridge_signature_verification",
          "warn",
          "bridge_signature verification failed",
          {
            reason: signatureCheck.reason
          }
        )
      );
    } else {
      rules.push(
        makeRule(
          "bridge_signature_verification",
          "pass",
          "bridge_signature verification passed"
        )
      );
    }
  }

  const bridgeBindingToken = normalizeString(evidence.bridge_binding_token);
  const hasBindingSecret = kernelBindingSigningSecret.length > 0;
  if (!hasBindingSecret) {
    if (requireSessionBindingToken) {
      rules.push(
        makeRule(
          "bridge_session_binding_verification",
          "warn",
          "bridge session binding token is required but server binding secret is not configured"
        )
      );
    } else if (bridgeBindingToken) {
      rules.push(
        makeRule(
          "bridge_session_binding_verification",
          "warn",
          "bridge binding token provided but server binding secret is not configured"
        )
      );
    } else {
      rules.push(
        makeRule(
          "bridge_session_binding_verification",
          "pass",
          "bridge session binding verification disabled (no server binding secret configured)"
        )
      );
    }
  } else if (!bridgeBindingToken) {
    if (requireSessionBindingToken) {
      rules.push(
        makeRule(
          "bridge_session_binding_verification",
          "warn",
          "missing evidence.bridge_binding_token for kernel bridge event"
        )
      );
    } else {
      rules.push(
        makeRule(
          "bridge_session_binding_verification",
          "pass",
          "bridge binding token not provided; compatibility mode applied"
        )
      );
    }
  } else {
    const bindingCheck = verifyKernelBindingToken(bridgeBindingToken, {
      secret: kernelBindingSigningSecret
    });
    if (!bindingCheck.ok || !isPlainObject(bindingCheck.claims)) {
      rules.push(
        makeRule(
          "bridge_session_binding_verification",
          "warn",
          "bridge binding token verification failed",
          {
            reason: bindingCheck.code || "invalid_binding_token"
          }
        )
      );
    } else {
      const claims = bindingCheck.claims;
      const mismatches = {};
      if (claims.scope !== "kernel_bridge") {
        mismatches.scope = {
          expected: "kernel_bridge",
          actual: claims.scope || null
        };
      }
      if (claims.sid !== sessionId) {
        mismatches.session_id = {
          expected: sessionId,
          actual: claims.sid || null
        };
      }
      if (claims.sub !== event.user_id) {
        mismatches.user_id = {
          expected: event.user_id,
          actual: claims.sub || null
        };
      }
      if (canonicalClientInstanceId && claims.cid !== canonicalClientInstanceId) {
        mismatches.client_instance_id = {
          expected: canonicalClientInstanceId,
          actual: claims.cid || null
        };
      }
      if (Object.keys(mismatches).length > 0) {
        rules.push(
          makeRule(
            "bridge_session_binding_verification",
            "warn",
            "bridge binding token claims mismatch canonical session context",
            {
              mismatches
            }
          )
        );
      } else {
        rules.push(
          makeRule(
            "bridge_session_binding_verification",
            "pass",
            "bridge session binding token verification passed"
          )
        );
      }
    }
  }

  const nextCount = (kernelCountBySession.get(sessionId) || 0) + 1;
  kernelCountBySession.set(sessionId, nextCount);
  if (nextCount > maxKernelSignalsPerBatch) {
    rules.push(
      makeRule("kernel_signal_burst", "warn", "kernel signal burst threshold exceeded", {
        count: nextCount,
        threshold: maxKernelSignalsPerBatch
      })
    );
  } else {
    rules.push(makeRule("kernel_signal_burst", "pass", "kernel signal burst threshold not exceeded"));
  }

  const failedRules = rules.filter((rule) => rule.status === "warn").map((rule) => rule.rule);
  return {
    status: failedRules.length > 0 ? "warn" : "pass",
    failed_rules: failedRules,
    rule_results: rules,
    replay_key: replayKey,
    checked_at: new Date(checkedAtMs).toISOString(),
    checker: "server_kernel_integrity_v1"
  };
}

module.exports = {
  evaluateKernelSignalIntegrity
};
