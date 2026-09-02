function toStructuredLog(payload) {
  return {
    timestamp: payload.timestamp || new Date().toISOString(),
    event_type: payload.event_type || "UNKNOWN_EVENT",
    severity: payload.severity || "medium",
    session_id: payload.session_id || "unknown-session",
    user_id: payload.user_id || "unknown-user",
    client_version: payload.client_version || "unknown-version",
    evidence: payload.evidence && typeof payload.evidence === "object" ? payload.evidence : {}
  };
}

function logStructured(payload, sink = console.log) {
  const entry = toStructuredLog(payload);
  sink(JSON.stringify(entry));
  return entry;
}

function logValidationRejection(rawEvent, error, meta = {}, sink = console.log) {
  return logStructured(
    {
      event_type: "SCHEMA_VALIDATION_REJECTED",
      severity: "high",
      timestamp: new Date().toISOString(),
      session_id:
        rawEvent && typeof rawEvent === "object" && rawEvent.session_id
          ? rawEvent.session_id
          : "unknown-session",
      user_id:
        rawEvent && typeof rawEvent === "object" && rawEvent.user_id
          ? rawEvent.user_id
          : "unknown-user",
      client_version:
        rawEvent && typeof rawEvent === "object" && rawEvent.client_version
          ? rawEvent.client_version
          : "unknown-version",
      evidence: {
        code: error.code,
        message: error.message,
        field: error.field,
        index: meta.index
      }
    },
    sink
  );
}

module.exports = {
  toStructuredLog,
  logStructured,
  logValidationRejection
};
