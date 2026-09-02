"use strict";

const assert = require("assert");
const {
  createMemoryNonceStore,
  createSignedState,
  verifySignedState
} = require("../src/state");

const secret = "test-secret-value";

{
  const now = () => 1000;
  const nonceStore = createMemoryNonceStore({ now });
  const signed = createSignedState(
    {
      userId: "user-1",
      sessionId: "session-1",
      reasonCode: "DISCORD_IDENTITY_REQUIRED",
      serverBaseUrl: "https://example.test"
    },
    { secret, ttlMs: 60000, nonce: "nonce-1", nonceStore, now }
  );
  const verified = verifySignedState(signed.state, { secret, nonceStore, now });
  assert.equal(verified.ok, true);
  assert.equal(verified.payload.user_id, "user-1");
  assert.equal(verified.payload.session_id, "session-1");
}

{
  const now = () => 1000;
  const nonceStore = createMemoryNonceStore({ now });
  const signed = createSignedState(
    { userId: "user-2", sessionId: "session-2" },
    { secret, ttlMs: 60000, nonce: "nonce-2", nonceStore, now }
  );
  const tampered = signed.state.replace(/.$/, "x");
  const verified = verifySignedState(tampered, { secret, nonceStore, now });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, "INVALID_STATE_SIGNATURE");
}

{
  const now = () => 1000;
  const nonceStore = createMemoryNonceStore({ now });
  const signed = createSignedState(
    { userId: "user-3", sessionId: "session-3" },
    { secret, ttlMs: 1000, nonce: "nonce-3", nonceStore, now }
  );
  const verified = verifySignedState(signed.state, {
    secret,
    nonceStore,
    now: () => 3001
  });
  assert.equal(verified.ok, false);
  assert.equal(verified.code, "EXPIRED_STATE");
}

{
  const now = () => 1000;
  const nonceStore = createMemoryNonceStore({ now });
  const signed = createSignedState(
    { userId: "user-4", sessionId: "session-4" },
    { secret, ttlMs: 60000, nonce: "nonce-4", nonceStore, now }
  );
  assert.equal(verifySignedState(signed.state, { secret, nonceStore, now }).ok, true);
  const replay = verifySignedState(signed.state, { secret, nonceStore, now });
  assert.equal(replay.ok, false);
  assert.equal(replay.code, "STATE_REPLAYED");
}

console.log("state.test.js passed");
