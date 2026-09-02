"use strict";

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function makeError(code, message, field) {
  return { code, message, field };
}

function normalizeString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed;
}

function normalizeSignalLevel(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  if (value < 0 || value > 100) return null;
  return Math.round(value);
}

function validateKernelTamperSignal(event) {
  const evidence = event.evidence;
  const driverName = normalizeString(evidence.driver_name);
  const detectionVector = normalizeString(evidence.detection_vector);
  const signalLevel = normalizeSignalLevel(evidence.signal_level);

  if (!driverName) {
    return {
      ok: false,
      error: makeError(
        "INVALID_KERNEL_EVIDENCE",
        "kernel tamper signal requires evidence.driver_name",
        "evidence.driver_name"
      )
    };
  }
  if (!detectionVector) {
    return {
      ok: false,
      error: makeError(
        "INVALID_KERNEL_EVIDENCE",
        "kernel tamper signal requires evidence.detection_vector",
        "evidence.detection_vector"
      )
    };
  }
  if (signalLevel === null) {
    return {
      ok: false,
      error: makeError(
        "INVALID_KERNEL_EVIDENCE",
        "kernel tamper signal requires evidence.signal_level (0-100)",
        "evidence.signal_level"
      )
    };
  }
  if (event.severity !== "high" && event.severity !== "critical") {
    return {
      ok: false,
      error: makeError(
        "INVALID_KERNEL_SEVERITY",
        "kernel tamper signal severity must be high or critical",
        "severity"
      )
    };
  }

  return {
    ok: true,
    value: {
      ...event,
      evidence: {
        ...evidence,
        driver_name: driverName,
        detection_vector: detectionVector,
        signal_level: signalLevel
      }
    }
  };
}

function validateKernelCallbackAnomaly(event) {
  const evidence = event.evidence;
  const callbackName = normalizeString(evidence.callback_name);
  const expectedHash = normalizeString(evidence.expected_hash);
  const observedHash = normalizeString(evidence.observed_hash);
  const signalLevel = normalizeSignalLevel(evidence.signal_level);

  if (!callbackName) {
    return {
      ok: false,
      error: makeError(
        "INVALID_KERNEL_EVIDENCE",
        "kernel callback anomaly requires evidence.callback_name",
        "evidence.callback_name"
      )
    };
  }
  if (!expectedHash) {
    return {
      ok: false,
      error: makeError(
        "INVALID_KERNEL_EVIDENCE",
        "kernel callback anomaly requires evidence.expected_hash",
        "evidence.expected_hash"
      )
    };
  }
  if (!observedHash) {
    return {
      ok: false,
      error: makeError(
        "INVALID_KERNEL_EVIDENCE",
        "kernel callback anomaly requires evidence.observed_hash",
        "evidence.observed_hash"
      )
    };
  }
  if (signalLevel === null) {
    return {
      ok: false,
      error: makeError(
        "INVALID_KERNEL_EVIDENCE",
        "kernel callback anomaly requires evidence.signal_level (0-100)",
        "evidence.signal_level"
      )
    };
  }

  return {
    ok: true,
    value: {
      ...event,
      evidence: {
        ...evidence,
        callback_name: callbackName,
        expected_hash: expectedHash,
        observed_hash: observedHash,
        signal_level: signalLevel
      }
    }
  };
}

function validateKernelSignalEvent(event) {
  if (!isPlainObject(event) || !isPlainObject(event.evidence)) {
    return {
      ok: false,
      error: makeError("INVALID_KERNEL_EVIDENCE", "kernel event evidence must be an object", "evidence")
    };
  }

  if (event.event_type === "KERNEL_TAMPER_SIGNAL") {
    return validateKernelTamperSignal(event);
  }

  if (event.event_type === "KERNEL_CALLBACK_ANOMALY") {
    return validateKernelCallbackAnomaly(event);
  }

  return { ok: true, value: event };
}

module.exports = {
  validateKernelSignalEvent
};

