const crypto = require("node:crypto");

function base64urlEncode(input) {
  const value = typeof input === "string" ? input : JSON.stringify(input);
  return Buffer.from(value)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64urlDecode(input) {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(`${normalized}${padding}`, "base64").toString("utf8");
}

function sign(data, secret) {
  return crypto.createHmac("sha256", secret).update(data).digest("base64url");
}

function issueSignedToken(claims, options) {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + options.ttlSec;
  const jti = crypto.randomUUID();
  const header = { alg: "HS256", typ: "JWT" };
  const payload = {
    ...claims,
    iat: now,
    exp,
    jti
  };

  const encodedHeader = base64urlEncode(header);
  const encodedPayload = base64urlEncode(payload);
  const signature = sign(`${encodedHeader}.${encodedPayload}`, options.secret);
  const token = `${encodedHeader}.${encodedPayload}.${signature}`;

  return {
    token,
    claims: payload
  };
}

function verifySignedToken(token, options) {
  if (!token || typeof token !== "string") {
    return { ok: false, code: "INVALID_TOKEN", message: "token missing" };
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    return { ok: false, code: "INVALID_TOKEN", message: "token malformed" };
  }

  const [encodedHeader, encodedPayload, signature] = parts;
  const expected = sign(`${encodedHeader}.${encodedPayload}`, options.secret);
  const sigA = Buffer.from(signature);
  const sigB = Buffer.from(expected);

  if (sigA.length !== sigB.length || !crypto.timingSafeEqual(sigA, sigB)) {
    return { ok: false, code: "INVALID_TOKEN", message: "token signature invalid" };
  }

  try {
    const payload = JSON.parse(base64urlDecode(encodedPayload));
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== "number" || now >= payload.exp) {
      return { ok: false, code: "EXPIRED_TOKEN", message: "token expired" };
    }
    return { ok: true, claims: payload };
  } catch (_error) {
    return { ok: false, code: "INVALID_TOKEN", message: "token payload invalid" };
  }
}

function issueAttestationToken(claims, options) {
  return issueSignedToken(claims, options);
}

function verifyAttestationToken(token, options) {
  return verifySignedToken(token, options);
}

function issueAdminToken(claims, options) {
  return issueSignedToken(claims, options);
}

function verifyAdminToken(token, options) {
  return verifySignedToken(token, options);
}

function issueKernelBindingToken(claims, options) {
  return issueSignedToken(claims, options);
}

function verifyKernelBindingToken(token, options) {
  return verifySignedToken(token, options);
}

module.exports = {
  issueAttestationToken,
  verifyAttestationToken,
  issueAdminToken,
  verifyAdminToken,
  issueKernelBindingToken,
  verifyKernelBindingToken
};
