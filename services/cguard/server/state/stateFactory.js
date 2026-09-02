const { RuntimeState } = require("../runtimeState");
const { PostgresState } = require("./postgresState");

function createStateAdapter(options = {}) {
  const mode = options.stateMode || "memory";
  if (mode === "postgres") {
    return PostgresState.create({
      config: options
    });
  }
  if (mode === "snapshot") {
    throw new Error("STATE_MODE=snapshot is legacy-only and disabled for operations-portal merge builds");
  }
  return new RuntimeState(options);
}

module.exports = {
  createStateAdapter
};
