const { validateEvent } = require("../shared/eventSchema");
const { logStructured, logValidationRejection } = require("./structuredLogger");
const { evaluateClientVersion, buildVersionPolicyEvent } = require("./versionPolicy");
const { validateKernelSignalEvent } = require("./kernelSignalPolicy");
const { evaluateKernelSignalIntegrity } = require("./kernelSignalIntegrity");

class InMemoryEventStore {
  constructor() {
    this.accepted = [];
    this.rejected = [];
  }

  persistAccepted(event) {
    this.accepted.push(event);
  }

  persistRejected(rejection) {
    this.rejected.push(rejection);
  }
}

function createIngestionPipeline(options = {}) {
  const store = options.store || new InMemoryEventStore();
  const logSink = options.logSink || console.log;
  const versionPolicyConfig = options.versionPolicyConfig || {
    latestVersion: "1.0.0",
    deprecatedBelowVersion: undefined,
    minimumSupportedVersion: "1.0.0"
  };

  function ingestEvent(rawEvent, meta = {}) {
    const validation = validateEvent(rawEvent);
    if (!validation.ok) {
      const rejection = {
        index: meta.index,
        stage: "validation",
        error: validation.error,
        raw_event: rawEvent
      };
      store.persistRejected(rejection);
      logValidationRejection(rawEvent, validation.error, meta, logSink);
      return {
        accepted: false,
        stage: "validation",
        error: validation.error
      };
    }

    const kernelValidation = validateKernelSignalEvent(validation.value);
    if (!kernelValidation.ok) {
      const rejection = {
        index: meta.index,
        stage: "kernel_signal_validation",
        error: kernelValidation.error,
        raw_event: rawEvent
      };
      store.persistRejected(rejection);
      logValidationRejection(rawEvent, kernelValidation.error, meta, logSink);
      return {
        accepted: false,
        stage: "kernel_signal_validation",
        error: kernelValidation.error
      };
    }

    let event = kernelValidation.value;
    const integrityReport = evaluateKernelSignalIntegrity(event, meta.integrityContext || {});
    if (integrityReport) {
      event = {
        ...event,
        evidence: {
          ...event.evidence,
          kernel_validation: integrityReport
        }
      };
    }
    const versionResult = evaluateClientVersion(event.client_version, versionPolicyConfig);
    const policyEvent = buildVersionPolicyEvent(event, versionResult, versionPolicyConfig);
    const persistedEvents = [];

    if (policyEvent) {
      store.persistAccepted(policyEvent);
      persistedEvents.push(policyEvent);
      logStructured(policyEvent, logSink);
    }

    if (versionResult.status === "invalid" || versionResult.status === "unsupported") {
      const rejection = {
        index: meta.index,
        stage: "version_policy",
        error: {
          code: "CLIENT_VERSION_POLICY_REJECTED",
          message: versionResult.reason || versionResult.status,
          field: "client_version"
        },
        raw_event: rawEvent
      };
      store.persistRejected(rejection);
      return {
        accepted: false,
        stage: "version_policy",
        error: rejection.error,
        versionResult,
        persistedEvents
      };
    }

    store.persistAccepted(event);
    persistedEvents.push(event);
    logStructured(event, logSink);
    return {
      accepted: true,
      stage: "ingested",
      versionResult,
      integrityReport,
      persistedEvents
    };
  }

  function ingestEvents(rawEvents, meta = {}) {
    const integrityContext = meta.integrityContext || {
      sessionHistoryById: meta.sessionHistoryById || {},
      maxKernelSignalsPerBatch: meta.maxKernelSignalsPerBatch || 5,
      maxBridgeEmitDeltaMs: meta.maxBridgeEmitDeltaMs || 60 * 1000,
      maxBridgeCounterGap: meta.maxBridgeCounterGap || 1000,
      maxBridgeStalenessMs:
        Number.isFinite(meta.maxBridgeStalenessMs) && meta.maxBridgeStalenessMs > 0
          ? Math.floor(meta.maxBridgeStalenessMs)
          : 0,
      requireBridgeSignature: meta.requireBridgeSignature === true,
      kernelBridgeSigningSecret:
        typeof meta.kernelBridgeSigningSecret === "string" ? meta.kernelBridgeSigningSecret : "",
      requireBridgeNonce: meta.requireBridgeNonce === true,
      requireBridgeEmittedAt: meta.requireBridgeEmittedAt === true,
      requireSessionBindingToken: meta.requireSessionBindingToken === true,
      kernelBindingSigningSecret:
        typeof meta.kernelBindingSigningSecret === "string" ? meta.kernelBindingSigningSecret : "",
      clientInstanceId:
        typeof meta.clientInstanceId === "string" ? meta.clientInstanceId : ""
    };
    const results = [];
    for (let i = 0; i < rawEvents.length; i += 1) {
      const result = ingestEvent(rawEvents[i], { index: i, integrityContext });
      results.push(result);
      if (!result.accepted && meta.failFast) {
        break;
      }
    }
    return results;
  }

  return {
    store,
    ingestEvent,
    ingestEvents
  };
}

module.exports = {
  InMemoryEventStore,
  createIngestionPipeline
};
