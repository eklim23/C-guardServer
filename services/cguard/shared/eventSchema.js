const { EVENT_TYPES, SEVERITIES } = require("./eventTypes");

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isIsoTimestamp(value) {
  if (typeof value !== "string") {
    return false;
  }
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    return false;
  }
  // Keep a strict RFC3339-like requirement to avoid loose Date parsing.
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(value);
}

function makeError(code, message, field) {
  return { code, message, field };
}

function validateEvent(input, options = {}) {
  const allowUnknownEventType = options.allowUnknownEventType === true;

  if (!isPlainObject(input)) {
    return {
      ok: false,
      error: makeError("MALFORMED_ROOT_OBJECT", "event must be an object", "root")
    };
  }

  if (typeof input.event_type !== "string" || input.event_type.trim() === "") {
    return {
      ok: false,
      error: makeError("MISSING_EVENT_TYPE", "event_type is required", "event_type")
    };
  }

  if (!allowUnknownEventType && !EVENT_TYPES.includes(input.event_type)) {
    return {
      ok: false,
      error: makeError("UNKNOWN_EVENT_TYPE", "event_type is not supported", "event_type")
    };
  }

  if (typeof input.severity !== "string" || !SEVERITIES.includes(input.severity)) {
    return {
      ok: false,
      error: makeError("INVALID_SEVERITY", "severity is invalid", "severity")
    };
  }

  if (!isIsoTimestamp(input.timestamp)) {
    return {
      ok: false,
      error: makeError("INVALID_TIMESTAMP", "timestamp must be ISO-8601", "timestamp")
    };
  }

  if (typeof input.session_id !== "string" || input.session_id.trim() === "") {
    return {
      ok: false,
      error: makeError("INVALID_SESSION_ID", "session_id must be non-empty", "session_id")
    };
  }

  if (typeof input.user_id !== "string" || input.user_id.trim() === "") {
    return {
      ok: false,
      error: makeError("INVALID_USER_ID", "user_id must be non-empty", "user_id")
    };
  }

  if (typeof input.client_version !== "string" || input.client_version.trim() === "") {
    return {
      ok: false,
      error: makeError(
        "INVALID_CLIENT_VERSION",
        "client_version must be non-empty",
        "client_version"
      )
    };
  }

  if (!isPlainObject(input.evidence)) {
    return {
      ok: false,
      error: makeError("INVALID_EVIDENCE", "evidence must be an object", "evidence")
    };
  }

  return { ok: true, value: input };
}

module.exports = {
  validateEvent,
  EVENT_TYPES,
  SEVERITIES
};
