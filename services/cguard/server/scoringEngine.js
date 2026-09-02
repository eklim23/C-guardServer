const DEFAULT_EVENT_WEIGHTS = Object.freeze({
  DEBUGGER_DETECTED: 30,
  DLL_INJECTION_DETECTED: 40,
  FOCUS_LOSS_REPEATED: 10,
  CLIPBOARD_ABUSE_DETECTED: 15,
  HEARTBEAT_ANOMALY: 25,
  SESSION_INTEGRITY_FAILURE: 35,
  KERNEL_TAMPER_SIGNAL: 45,
  KERNEL_CALLBACK_ANOMALY: 30
});

function tierFromScore(score) {
  if (score >= 90) return "review-required";
  if (score >= 60) return "high-risk";
  if (score >= 30) return "suspicious";
  return "normal";
}

function scoreEvent(event, weights = DEFAULT_EVENT_WEIGHTS) {
  return weights[event.event_type] || 0;
}

function scoreEvents(events, weights = DEFAULT_EVENT_WEIGHTS) {
  let total = 0;
  const timeline = [];

  events.forEach((event, index) => {
    const delta = scoreEvent(event, weights);
    total += delta;
    timeline.push({
      index,
      timestamp: event.timestamp,
      event_type: event.event_type,
      severity: event.severity,
      score_delta: delta,
      total_score: total
    });
  });

  return {
    finalScore: total,
    tier: tierFromScore(total),
    timeline
  };
}

module.exports = {
  DEFAULT_EVENT_WEIGHTS,
  scoreEvent,
  scoreEvents,
  tierFromScore
};
