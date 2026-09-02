function parseSemver(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (!match) {
    return null;
  }
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function compareSemver(a, b) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) {
    return null;
  }

  for (let i = 0; i < 3; i += 1) {
    if (pa[i] > pb[i]) return 1;
    if (pa[i] < pb[i]) return -1;
  }
  return 0;
}

function evaluateClientVersion(clientVersion, config) {
  if (!clientVersion || clientVersion.trim() === "") {
    return { status: "invalid", reason: "missing client_version" };
  }

  if (compareSemver(clientVersion, config.minimumSupportedVersion) === null) {
    return { status: "invalid", reason: "invalid semantic version format" };
  }

  const minimumCmp = compareSemver(clientVersion, config.minimumSupportedVersion);
  if (minimumCmp < 0) {
    return {
      status: "unsupported",
      minimumSupportedVersion: config.minimumSupportedVersion,
      reason: "client version below minimum supported version"
    };
  }

  if (minimumCmp === 0) {
    return { status: "allowed" };
  }

  if (config.deprecatedBelowVersion) {
    const deprecatedCmp = compareSemver(clientVersion, config.deprecatedBelowVersion);
    if (deprecatedCmp !== null && deprecatedCmp < 0) {
      return {
        status: "deprecated",
        recommendedVersion: config.latestVersion,
        minimumSupportedVersion: config.minimumSupportedVersion
      };
    }
  }

  return { status: "allowed" };
}

function buildVersionPolicyEvent(baseEvent, result, config) {
  const common = {
    timestamp: new Date().toISOString(),
    session_id: baseEvent.session_id,
    user_id: baseEvent.user_id,
    client_version: baseEvent.client_version,
    evidence: {}
  };

  if (result.status === "deprecated") {
    return {
      ...common,
      event_type: "CLIENT_VERSION_DEPRECATED",
      severity: "medium",
      evidence: {
        latest_version: config.latestVersion,
        minimum_supported_version: config.minimumSupportedVersion,
        recommended_version: result.recommendedVersion
      }
    };
  }

  if (result.status === "unsupported") {
    return {
      ...common,
      event_type: "CLIENT_VERSION_UNSUPPORTED",
      severity: "high",
      evidence: {
        minimum_supported_version: config.minimumSupportedVersion,
        reason: result.reason
      }
    };
  }

  if (result.status === "invalid") {
    return {
      ...common,
      event_type: "CLIENT_VERSION_INVALID",
      severity: "high",
      evidence: {
        raw_client_version: baseEvent.client_version,
        reason: result.reason
      }
    };
  }

  return null;
}

module.exports = {
  parseSemver,
  compareSemver,
  evaluateClientVersion,
  buildVersionPolicyEvent
};
