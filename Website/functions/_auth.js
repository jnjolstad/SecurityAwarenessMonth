import { getMinigamesConfig } from "./_config.js";

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ADMIN_KEY_MIN_LEN = 24;
const SESSION_COOKIE = "sam_admin_session";
const SESSION_MAX_AGE = 60 * 60 * 8;

function normalizeEmail(value) {
  const email = String(value || "").trim().toLowerCase();
  return EMAIL_PATTERN.test(email) ? email : "";
}

export function normalizeAdminEmail(value) {
  return normalizeEmail(value);
}

function readConfiguredAdmins(env) {
  const config = getMinigamesConfig(env);
  const configured = config.adminEmailsRaw;
  const admins = new Set(
    configured
      .split(",")
      .map((v) => normalizeEmail(v))
      .filter(Boolean),
  );
  if (admins.size === 0) {
    for (const email of config.defaultAdminEmails) {
      const clean = normalizeEmail(email);
      if (clean) admins.add(clean);
    }
  }
  return admins;
}

export function isAdminEmail(email, env) {
  const clean = normalizeEmail(email);
  if (!clean) return false;
  return readConfiguredAdmins(env).has(clean);
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function parseCookieMap(cookieHeader) {
  const map = new Map();
  const raw = String(cookieHeader || "");
  if (!raw) return map;
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) continue;
    map.set(key, value);
  }
  return map;
}

function toBase64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(input) {
  const base = String(input || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (base.length % 4)) % 4);
  const bin = atob(base + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function hmacSha256(secret, text) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return toBase64Url(new Uint8Array(sig));
}

function getSessionSecret(env) {
  return getMinigamesConfig(env).sessionSecret;
}

export function getAdminAuthDebug(env) {
  const config = getMinigamesConfig(env);
  const configuredRaw = config.adminEmailsRaw;
  const configuredAdmins = configuredRaw
    .split(",")
    .map((v) => normalizeEmail(v))
    .filter(Boolean);
  const adminKey = config.adminKey;
  const sessionSecret = config.sessionSecret;
  const resendApiKey = config.resendApiKey;
  const fromEmail = normalizeEmail(config.emailFrom);
  const checks = {
    adminEmailsConfigured: configuredAdmins.length > 0,
    usingDefaultAdminFallback: configuredAdmins.length === 0,
    adminKeyConfigured: adminKey.length > 0,
    adminKeyStrongEnough: adminKey.length >= ADMIN_KEY_MIN_LEN,
    sessionSecretConfigured: sessionSecret.length > 0,
    sessionSecretUsingAdminKey: sessionSecret.length > 0 && adminKey.length > 0 && safeEqual(sessionSecret, adminKey),
    resendConfigured: resendApiKey.length > 0,
    emailSenderConfigured: !!fromEmail,
  };
  const issues = [];
  if (!checks.adminEmailsConfigured) issues.push("SAM_MINIGAMES_ADMIN_EMAILS is empty; default fallback list is active.");
  if (!checks.sessionSecretConfigured) issues.push("SAM_MINIGAMES_SESSION_SECRET is missing.");
  if (checks.sessionSecretUsingAdminKey) issues.push("SAM_MINIGAMES_SESSION_SECRET should be different from SAM_MINIGAMES_ADMIN_KEY.");
  if (!checks.resendConfigured) issues.push("RESEND_API_KEY is missing (required for email-only admin login).");
  if (!checks.emailSenderConfigured) issues.push("SAM_MINIGAMES_EMAIL_FROM is missing (required for email-only admin login).");
  return { ok: issues.length === 0, checks, issues };
}

function extractBearerToken(authHeader) {
  const raw = String(authHeader || "");
  const m = raw.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : "";
}

export function verifyAdminLogin(email, key, env) {
  const cleanEmail = normalizeEmail(email);
  const configuredKey = getMinigamesConfig(env).adminKey;
  const providedKey = String(key || "").trim();
  if (!cleanEmail || !isAdminEmail(cleanEmail, env)) return false;
  if (configuredKey.length < ADMIN_KEY_MIN_LEN) return false;
  if (providedKey.length !== configuredKey.length) return false;
  return safeEqual(configuredKey, providedKey);
}

export async function buildAdminSessionToken(email, env) {
  const cleanEmail = normalizeEmail(email);
  const secret = getSessionSecret(env);
  if (!cleanEmail || !secret) return "";
  const exp = Math.floor(Date.now() / 1000) + SESSION_MAX_AGE;
  const payload = `${cleanEmail}.${exp}`;
  return `${toBase64Url(new TextEncoder().encode(payload))}.${await hmacSha256(secret, payload)}`;
}

export async function buildAdminSessionCookie(email, env) {
  const token = await buildAdminSessionToken(email, env);
  if (!token) return "";
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_MAX_AGE}`;
}

export function clearAdminSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

async function verifySessionToken(token, env) {
  const secret = getSessionSecret(env);
  if (!secret) return "";
  const parts = token.split(".");
  if (parts.length !== 2) return "";
  let payload = "";
  try {
    payload = new TextDecoder().decode(fromBase64Url(parts[0]));
  } catch {
    return "";
  }
  const sig = parts[1];
  const expectedSig = await hmacSha256(secret, payload);
  if (!safeEqual(sig, expectedSig)) return "";
  const splitAt = payload.lastIndexOf(".");
  if (splitAt <= 0 || splitAt >= payload.length - 1) return "";
  const email = payload.slice(0, splitAt);
  const expRaw = payload.slice(splitAt + 1);
  const clean = normalizeEmail(email);
  const exp = Number(expRaw || 0);
  if (!clean || !Number.isFinite(exp) || exp < Math.floor(Date.now() / 1000)) return "";
  return clean;
}

export async function getTrustedAdminEmail(request, env) {
  const cookies = parseCookieMap(request.headers.get("cookie"));
  const cookieTokenRaw = cookies.get(SESSION_COOKIE);
  if (cookieTokenRaw) {
    const email = await verifySessionToken(decodeURIComponent(cookieTokenRaw), env);
    if (email) return email;
  }
  const bearerToken = extractBearerToken(request.headers.get("authorization"));
  if (bearerToken) {
    const email = await verifySessionToken(bearerToken, env);
    if (email) return email;
  }
  return "";
}
