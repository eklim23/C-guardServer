const { scoreEvents, scoreEvent, tierFromScore } = require("../server/scoringEngine");
const { evaluateClientVersion } = require("../server/versionPolicy");

const NOISY_EVENT_TYPES = new Set(["FOCUS_LOSS_REPEATED", "HEARTBEAT_ANOMALY"]);
const KNOWN_LLM_DOMAINS = Object.freeze([
  "openai.com",
  "chatgpt.com",
  "claude.ai",
  "anthropic.com",
  "cursor.com",
  "cursor.sh",
  "gemini.google.com",
  "aistudio.google.com",
  "ai.google.dev",
  "makersuite.google.com",
  "play.googleapis.com",
  "generativelanguage.googleapis.com"
]);

function sortByTimestamp(events) {
  return [...events].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
}

function isNoisyEvent(event) {
  return NOISY_EVENT_TYPES.has(event.event_type);
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function extractKernelValidation(event) {
  if (!isPlainObject(event) || !isPlainObject(event.evidence)) return null;
  const validation = event.evidence.kernel_validation;
  if (!isPlainObject(validation)) return null;
  return validation;
}

function normalizeDomain(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");
}

function matchKnownLlmDomain(domain) {
  const normalized = normalizeDomain(domain);
  if (!normalized || !normalized.includes(".")) return null;
  for (const known of KNOWN_LLM_DOMAINS) {
    if (normalized === known || normalized.endsWith(`.${known}`)) {
      return {
        observed_domain: normalized,
        matched_domain: known
      };
    }
  }
  return null;
}

function extractObservedDomains(event) {
  if (!isPlainObject(event) || !isPlainObject(event.evidence)) return [];
  const evidence = event.evidence;
  const candidates = [
    evidence.remote_host,
    evidence.remote_hostname,
    evidence.destination_host,
    evidence.domain,
    evidence.hostname
  ];
  return candidates
    .map((item) => normalizeDomain(item))
    .filter((item) => item.length > 0);
}

function evaluateLlmDomainTelemetry(event) {
  if (!isPlainObject(event)) {
    return { llm_domain_match: false, llm_domain: null, llm_domain_rule: null };
  }
  if (event.event_type !== "NETWORK_CONNECTION_OBSERVED") {
    return { llm_domain_match: false, llm_domain: null, llm_domain_rule: null };
  }

  const observedDomains = extractObservedDomains(event);
  for (const domain of observedDomains) {
    const matched = matchKnownLlmDomain(domain);
    if (matched) {
      return {
        llm_domain_match: true,
        llm_domain: matched.observed_domain,
        llm_domain_rule: matched.matched_domain
      };
    }
  }

  // Fallback: if policy already says blockedDomains on network event,
  // still surface as LLM-domain relevant to keep operator visibility.
  if (String(event.policy_rule || "") === "blockedDomains") {
    return {
      llm_domain_match: true,
      llm_domain: observedDomains[0] || null,
      llm_domain_rule: "blockedDomains"
    };
  }

  return { llm_domain_match: false, llm_domain: null, llm_domain_rule: null };
}

function toValidationNotes(validation) {
  if (!isPlainObject(validation) || !Array.isArray(validation.rule_results)) return [];
  return validation.rule_results
    .filter((rule) => isPlainObject(rule))
    .map((rule) => ({
      rule: typeof rule.rule === "string" ? rule.rule : "unknown_rule",
      status: typeof rule.status === "string" ? rule.status : "unknown",
      message: typeof rule.message === "string" ? rule.message : ""
    }));
}

function collapseNoisyEvents(events) {
  const collapsed = [];
  for (const event of events) {
    const previous = collapsed[collapsed.length - 1];
    const noisy = isNoisyEvent(event);
    if (
      noisy &&
      previous &&
      previous.event_type === event.event_type &&
      previous.severity === event.severity &&
      previous.user_id === event.user_id &&
      previous.session_id === event.session_id
    ) {
      previous.__collapsed_count += 1;
      previous.__collapsed_end_timestamp = event.timestamp;
      continue;
    }
    collapsed.push({
      ...event,
      __collapsed_count: 1,
      __collapsed_start_timestamp: event.timestamp,
      __collapsed_end_timestamp: event.timestamp
    });
  }
  return collapsed;
}

function applyTimelineFilters(events, filters = {}) {
  const failedRule =
    typeof filters.validation_failed_rule === "string"
      ? filters.validation_failed_rule.trim()
      : "";
  const filtered = events.filter((event) => {
    if (filters.severity && event.severity !== filters.severity) {
      return false;
    }
    if (filters.event_type && event.event_type !== filters.event_type) {
      return false;
    }
    if (filters.validation_warn_only) {
      const validation = extractKernelValidation(event);
      if (!validation || validation.status !== "warn") {
        return false;
      }
    }
    if (failedRule) {
      const validation = extractKernelValidation(event);
      if (!validation || !Array.isArray(validation.failed_rules)) {
        return false;
      }
      if (!validation.failed_rules.includes(failedRule)) {
        return false;
      }
    }
    if (filters.llm_domain_only) {
      const llmTelemetry = evaluateLlmDomainTelemetry(event);
      if (!llmTelemetry.llm_domain_match) {
        return false;
      }
    }
    return true;
  });
  if (!filters.collapse_noisy) {
    return filtered.map((event) => ({
      ...event,
      __collapsed_count: event.__collapsed_count || 1,
      __collapsed_start_timestamp: event.timestamp,
      __collapsed_end_timestamp: event.timestamp
    }));
  }
  return collapseNoisyEvents(filtered);
}

function toTimelineItem(event, index) {
  const collapsedCount = Number.isFinite(event.__collapsed_count) ? event.__collapsed_count : 1;
  const scoreDelta = scoreEvent(event) * collapsedCount;
  const kernelValidation = extractKernelValidation(event);
  const llmTelemetry = evaluateLlmDomainTelemetry(event);
  const baseDescription =
    event.evidence && event.evidence.description ? event.evidence.description : "";
  const collapsedSuffix = collapsedCount > 1 ? ` (collapsed x${collapsedCount})` : "";
  const llmSuffix = llmTelemetry.llm_domain_match
    ? ` [llm_domain=${llmTelemetry.llm_domain || llmTelemetry.llm_domain_rule}]`
    : "";

  return {
    index,
    timestamp: event.timestamp,
    event_type: event.event_type,
    severity: event.severity,
    short_description: `${baseDescription}${collapsedSuffix}${llmSuffix}`.trim(),
    score_delta: scoreDelta,
    collapsed_count: collapsedCount,
    collapsed_start_timestamp: event.__collapsed_start_timestamp || event.timestamp,
    collapsed_end_timestamp: event.__collapsed_end_timestamp || event.timestamp,
    evidence: event.evidence,
    ingestion_status: "accepted",
    policy_rule: event.policy_rule || "",
    policy_reason: event.policy_reason || "",
    llm_domain_match: llmTelemetry.llm_domain_match,
    llm_domain: llmTelemetry.llm_domain,
    llm_domain_rule: llmTelemetry.llm_domain_rule,
    kernel_validation_status:
      kernelValidation && typeof kernelValidation.status === "string"
        ? kernelValidation.status
        : null,
    kernel_validation_failed_rules:
      kernelValidation && Array.isArray(kernelValidation.failed_rules)
        ? [...kernelValidation.failed_rules]
        : [],
    validation_notes: toValidationNotes(kernelValidation)
  };
}

function pickMajorContributors(timeline, limit = 5) {
  return [...timeline]
    .filter((entry) => entry.score_delta > 0)
    .sort((a, b) => b.score_delta - a.score_delta)
    .slice(0, limit)
    .map((entry) => ({
      event_type: entry.event_type,
      severity: entry.severity,
      score_delta: entry.score_delta,
      timestamp: entry.timestamp
    }));
}

function buildInvestigationViewModel(input) {
  const session = input.session || {};
  const events = Array.isArray(input.events) ? input.events : [];
  const rejections = Array.isArray(input.rejections) ? input.rejections : [];
  const notes = Array.isArray(input.notes) ? input.notes : [];
  const actions = Array.isArray(input.actions) ? input.actions : [];
  const filters = input.filters || {};
  const failedRule =
    typeof filters.validation_failed_rule === "string"
      ? filters.validation_failed_rule.trim() || null
      : null;
  const versionPolicyConfig = input.versionPolicyConfig;

  const sortedEvents = sortByTimestamp(events);
  const scored = scoreEvents(sortedEvents);
  const filtered = applyTimelineFilters(sortedEvents, filters);
  const timeline = filtered.map((event, index) => toTimelineItem(event, index));

  const versionPolicyResult =
    session.version_policy_result ||
    (versionPolicyConfig
      ? evaluateClientVersion(session.client_version || "", versionPolicyConfig)
      : { status: "unknown" });

  return {
    session_summary: {
      session_id: session.session_id || null,
      user_id: session.user_id || null,
      username: session.username || null,
      client_version: session.client_version || null,
      session_start_time: session.session_start_time || null,
      session_end_time: session.session_end_time || null,
      current_status: session.current_status || "unknown",
      decision_reason_code: session.decision_reason_code || null,
      client_agent_state: session.client_agent_state || "unknown",
      kernel_bridge_state: session.kernel_bridge_state || "unknown",
      kernel_driver_loaded: session.kernel_driver_loaded === true,
      participant_gate_result: session.participant_gate_result || null,
      final_risk_score: scored.finalScore,
      risk_tier: tierFromScore(scored.finalScore),
      version_policy_result: versionPolicyResult
    },
    risk_overview: {
      total_score: scored.finalScore,
      score_tier: scored.tier,
      major_contributing_events: pickMajorContributors(scored.timeline),
      score_timeline: scored.timeline,
      rejected_event_count: rejections.length
    },
    event_timeline: timeline,
    evidence_detail: null,
    reviewer_notes: notes,
    manual_decisions: actions,
    states: {
      loading: false,
      error: null,
      session_not_found: !session.session_id,
      no_events_available: events.length === 0,
      partial_evidence_available: events.some((event) => !event.evidence || Object.keys(event.evidence).length === 0),
      scoring_unavailable: false,
      noisy_events_collapsed: Boolean(filters.collapse_noisy),
      validation_warn_only: Boolean(filters.validation_warn_only),
      validation_failed_rule: failedRule || null,
      llm_domain_only: Boolean(filters.llm_domain_only)
    }
  };
}

function selectEvidenceDetail(viewModel, timelineIndex) {
  const selected = viewModel.event_timeline[timelineIndex];
  if (!selected) {
    return {
      ...viewModel,
      evidence_detail: null
    };
  }

  return {
    ...viewModel,
    evidence_detail: {
      selected_index: timelineIndex,
      event_type: selected.event_type,
      severity: selected.severity,
      timestamp: selected.timestamp,
      collapsed_count: selected.collapsed_count || 1,
      collapsed_start_timestamp: selected.collapsed_start_timestamp || selected.timestamp,
      collapsed_end_timestamp: selected.collapsed_end_timestamp || selected.timestamp,
      raw_evidence: selected.evidence,
      parsed_fields: Object.entries(selected.evidence || {}).map(([key, value]) => ({
        key,
        value
      })),
      policy_rule: selected.policy_rule || "",
      policy_reason: selected.policy_reason || "",
      llm_domain_match: selected.llm_domain_match === true,
      llm_domain: selected.llm_domain || null,
      llm_domain_rule: selected.llm_domain_rule || null,
      ingestion_status: selected.ingestion_status,
      validation_notes: Array.isArray(selected.validation_notes) ? selected.validation_notes : [],
      kernel_validation_status: selected.kernel_validation_status || null,
      kernel_validation_failed_rules: Array.isArray(selected.kernel_validation_failed_rules)
        ? [...selected.kernel_validation_failed_rules]
        : []
    }
  };
}

module.exports = {
  buildInvestigationViewModel,
  selectEvidenceDetail
};
