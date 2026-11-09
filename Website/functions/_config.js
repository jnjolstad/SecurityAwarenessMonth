const DEFAULT_ADMIN_EMAILS = ["joar@njolstad.no"];
const DEFAULT_ADMIN_LOGIN_TTL_MS = 15 * 60 * 1000;
const MIN_ADMIN_LOGIN_TTL_MS = 60 * 1000;
const MAX_ADMIN_LOGIN_TTL_MS = 60 * 60 * 1000;

function parsePositiveInt(value, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.floor(n);
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

export function getMinigamesConfig(env = {}) {
  const adminEmailsRaw = String(env.SAM_MINIGAMES_ADMIN_EMAILS || "").trim();
  const adminKey = String(env.SAM_MINIGAMES_ADMIN_KEY || "").trim();
  const sessionSecret = String(env.SAM_MINIGAMES_SESSION_SECRET || adminKey || "").trim();
  const resendApiKey = String(env.RESEND_API_KEY || "").trim();
  const emailFrom = String(env.SAM_MINIGAMES_EMAIL_FROM || env.ADMIN_MAGICLINK_FROM || "").trim();
  const adminLoginTtlMs = clamp(
    parsePositiveInt(env.SAM_MINIGAMES_ADMIN_LOGIN_TTL_MS, DEFAULT_ADMIN_LOGIN_TTL_MS),
    MIN_ADMIN_LOGIN_TTL_MS,
    MAX_ADMIN_LOGIN_TTL_MS,
  );

  return {
    adminEmailsRaw,
    defaultAdminEmails: DEFAULT_ADMIN_EMAILS,
    adminKey,
    sessionSecret,
    resendApiKey,
    emailFrom,
    adminLoginTtlMs,
  };
}
