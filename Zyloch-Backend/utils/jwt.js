const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const JWT_SECRET = process.env.APP_JWT_SECRET;
let ENCRYPTION_SECRET = process.env.APP_ENCRYPTION_SECRET;

function prepareEncryptionKey(secret) {
  if (!secret) {
    throw new Error("APP_ENCRYPTION_SECRET is missing");
  }

  const keyBuffer = Buffer.from(secret, "utf8");

  if (keyBuffer.length < 32) {
    return Buffer.concat([keyBuffer, Buffer.alloc(32 - keyBuffer.length)]);
  }

  if (keyBuffer.length > 32) {
    return keyBuffer.subarray(0, 32);
  }

  return keyBuffer;
}

ENCRYPTION_SECRET = prepareEncryptionKey(ENCRYPTION_SECRET);

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENCRYPTION_SECRET, iv);

  const encryptedBuffer = Buffer.concat([
    cipher.update(text, "utf8"),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return Buffer.concat([iv, authTag, encryptedBuffer]).toString("base64");
}

function decrypt(encryptedData) {
  const data = Buffer.from(encryptedData, "base64");

  const iv = data.subarray(0, 16);
  const authTag = data.subarray(16, 32);
  const ciphertext = data.subarray(32);

  const decipher = crypto.createDecipheriv("aes-256-gcm", ENCRYPTION_SECRET, iv);
  decipher.setAuthTag(authTag);

  const decryptedBuffer = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return decryptedBuffer.toString("utf8");
}

const VALID_ROLES = ["admin", "member"];

/**
 * Build the canonical session JWT payload.
 * tenantId is omitted only for pre-org flows; protected routes require it (401).
 * @param {{ userId: string, tenantId?: string|null, email: string, provider: string, role?: string|null }} fields
 */
function buildSessionPayload({ userId, tenantId = null, email, provider, role = null }) {
  if (!userId || !email || !provider) {
    throw new Error("userId, email, and provider are required for session payload");
  }

  const payload = {
    userId: String(userId),
    email,
    provider,
  };

  if (tenantId != null && tenantId !== "") {
    payload.tenantId = String(tenantId);
  }

  if (role != null && role !== "") {
    if (!VALID_ROLES.includes(role)) {
      throw new Error(`Invalid role: ${role}`);
    }
    payload.role = role;
  }

  return payload;
}

/** True when JWT claims should be refreshed from the live user record. */
function sessionClaimsStale(session, { role }) {
  if (!session?.role) return true;
  return session.role !== role;
}

function signSession(payload) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
  return encrypt(token);
}

function verifySession(encryptedToken) {
  try {
    const decryptedToken = decrypt(encryptedToken);
    return jwt.verify(decryptedToken, JWT_SECRET);
  } catch (err) {
    throw new Error("Invalid or expired session token");
  }
}

module.exports = {
  VALID_ROLES,
  buildSessionPayload,
  sessionClaimsStale,
  signSession,
  verifySession,
};