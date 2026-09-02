const { logStructured } = require("./structuredLogger");

const SENSITIVE_ACTIONS = new Set(["mark_as_suspicious", "escalate", "clear_with_reason"]);

function createReviewAuditStore(options = {}) {
  const logSink = options.logSink || console.log;
  const notes = [];
  const actions = [];

  function addNote(input) {
    if (!input || !input.session_id || !input.author || !input.note) {
      throw new Error("session_id, author, and note are required");
    }

    const record = {
      note_id: `note-${notes.length + 1}`,
      session_id: input.session_id,
      author: input.author,
      note: input.note,
      created_at: new Date().toISOString()
    };

    notes.push(record);
    logStructured(
      {
        event_type: "ADMIN_REVIEW_NOTE_CREATED",
        severity: "low",
        timestamp: record.created_at,
        session_id: input.session_id,
        user_id: input.author,
        client_version: "admin-console",
        evidence: { note_id: record.note_id }
      },
      logSink
    );
    return record;
  }

  function recordAction(input) {
    if (!input || !input.session_id || !input.actor || !input.action) {
      throw new Error("session_id, actor, and action are required");
    }
    if (SENSITIVE_ACTIONS.has(input.action) && (!input.reason || input.reason.trim() === "")) {
      throw new Error("reason is required for sensitive manual actions");
    }

    const record = {
      action_id: `action-${actions.length + 1}`,
      session_id: input.session_id,
      actor: input.actor,
      action: input.action,
      reason: input.reason || null,
      metadata: input.metadata || {},
      created_at: new Date().toISOString()
    };
    actions.push(record);

    logStructured(
      {
        event_type: "ADMIN_MANUAL_DECISION_ACTION",
        severity: "medium",
        timestamp: record.created_at,
        session_id: input.session_id,
        user_id: input.actor,
        client_version: "admin-console",
        evidence: {
          action_id: record.action_id,
          action: record.action,
          reason: record.reason
        }
      },
      logSink
    );

    return record;
  }

  return {
    notes,
    actions,
    addNote,
    recordAction
  };
}

module.exports = {
  createReviewAuditStore
};
