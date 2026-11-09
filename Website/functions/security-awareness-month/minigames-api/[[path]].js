// Leaderboard API for /security-awareness-month/minigames.
//
// Players register with first name, last name and email, then get a private key
// (only its hash is stored).
// A ranked run is opened with /start, which records the server start time.
// /finish receives the click log and re-scores it against the answer key in
// _minigames-key.js, using the server clock, so a browser cannot report its
// own score or time.
//
// Storage is D1 (AUKSJON_DB binding, tables prefixed sam_mg_), which keeps
// the free tier's 1,000 KV writes/day for the escape room.

import { buildAdminSessionCookie, buildAdminSessionToken, clearAdminSessionCookie, getAdminAuthDebug, getTrustedAdminEmail, isAdminEmail, normalizeAdminEmail, verifyAdminLogin } from "../../_auth.js";
import { getMinigamesConfig } from "../../_config.js";
import { GAMES } from "../_minigames-key.js";

const POINTS = { wrong: 25, hint: 100, missed: 100 };
const LATENCY_GRACE_MS = 1500;
// A complete run needs at least this long per required click/answer. It caps
// what a scripted client can gain over a fast human who knows the answers.
const MIN_MS_PER_ACTION = 700;
const MAX_LOG = 400;
const START_COOLDOWN_MS = 3000;
const RUN_TTL_MS = 30 * 60 * 1000;
const MAX_NEW_PLAYERS_PER_IP_HOUR = 10;
const TOP = 10;
const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{1,31}$/;

const PERSON_NAME_PATTERN = /^[\p{L}][\p{L}' -]{0,39}$/u;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const NICKNAME_PATTERN = /^[\p{L}\p{N}][\p{L}\p{N} ._-]{1,19}$/u;
const BLOCKED_TERMS = [
  "fuck", "shit", "cunt", "nigg", "fag", "rape",
  "faen", "helvete", "hore", "fitte", "kuk", "neger",
  "admin", "moderator", "northwind",
];
const LEET = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s", "!": "i" };

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS sam_mg_players (
     id TEXT PRIMARY KEY, name TEXT NOT NULL, name_key TEXT NOT NULL UNIQUE,
     key_hash TEXT NOT NULL, ip_hash TEXT, created_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS sam_mg_players_ip ON sam_mg_players (ip_hash, created_at)`,
  `CREATE TABLE IF NOT EXISTS sam_mg_runs (
     id TEXT PRIMARY KEY, player_id TEXT NOT NULL, game TEXT NOT NULL, started_at INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS sam_mg_runs_player ON sam_mg_runs (player_id, started_at)`,
  `CREATE TABLE IF NOT EXISTS sam_mg_best (
     player_id TEXT NOT NULL, game TEXT NOT NULL, score INTEGER NOT NULL, duration_ms INTEGER NOT NULL,
     wrong INTEGER NOT NULL, hints INTEGER NOT NULL, found INTEGER NOT NULL,
     attempts INTEGER NOT NULL, achieved_at INTEGER NOT NULL, first_score INTEGER,
     PRIMARY KEY (player_id, game))`,
  `CREATE INDEX IF NOT EXISTS sam_mg_best_rank ON sam_mg_best (game, score DESC, duration_ms, achieved_at)`,
  `CREATE TABLE IF NOT EXISTS sam_mg_groups (
     id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
     active INTEGER NOT NULL DEFAULT 1, force_full_names INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, created_by TEXT)` ,
  `CREATE TABLE IF NOT EXISTS sam_mg_group_admins (
     group_id TEXT NOT NULL, email TEXT NOT NULL, created_at INTEGER NOT NULL,
     PRIMARY KEY (group_id, email))`,
  `CREATE TABLE IF NOT EXISTS sam_mg_group_games (
     group_id TEXT NOT NULL, game TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
     updated_at INTEGER NOT NULL, updated_by TEXT,
     PRIMARY KEY (group_id, game))`,
  `CREATE INDEX IF NOT EXISTS sam_mg_group_games_group ON sam_mg_group_games (group_id, enabled)`,
  `CREATE TABLE IF NOT EXISTS sam_mg_admin_login_tokens (
     id TEXT PRIMARY KEY, email TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
     created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS sam_mg_admin_login_tokens_exp ON sam_mg_admin_login_tokens (expires_at, used_at)`,
];
const GAME_IDS = Object.keys(GAMES);

let schemaReady = false;

// Only a finished flag is cached. A pending promise shared across requests can
// hang forever on Workers, since I/O can't complete in another request's context.
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.batch(SCHEMA.map((sql) => db.prepare(sql)));
  // Tables created before the first-try column existed get it added once.
  try {
    await db.prepare("ALTER TABLE sam_mg_best ADD COLUMN first_score INTEGER").run();
  } catch (err) {
    if (!/duplicate column/i.test(String(err && (err.cause?.message || err.message)))) throw err;
  }
  try {
    await db.prepare("ALTER TABLE sam_mg_players ADD COLUMN group_id TEXT").run();
  } catch (err) {
    if (!/duplicate column/i.test(String(err && (err.cause?.message || err.message)))) throw err;
  }
  await db.prepare("CREATE INDEX IF NOT EXISTS sam_mg_players_group ON sam_mg_players (group_id)").run();
  try {
    await db.prepare("ALTER TABLE sam_mg_players ADD COLUMN first_name TEXT").run();
  } catch (err) {
    if (!/duplicate column/i.test(String(err && (err.cause?.message || err.message)))) throw err;
  }
  try {
    await db.prepare("ALTER TABLE sam_mg_players ADD COLUMN last_name TEXT").run();
  } catch (err) {
    if (!/duplicate column/i.test(String(err && (err.cause?.message || err.message)))) throw err;
  }
  try {
    await db.prepare("ALTER TABLE sam_mg_players ADD COLUMN email TEXT").run();
  } catch (err) {
    if (!/duplicate column/i.test(String(err && (err.cause?.message || err.message)))) throw err;
  }
  try {
    await db.prepare("ALTER TABLE sam_mg_players ADD COLUMN email_key TEXT").run();
  } catch (err) {
    if (!/duplicate column/i.test(String(err && (err.cause?.message || err.message)))) throw err;
  }
  try {
    await db.prepare("ALTER TABLE sam_mg_players ADD COLUMN is_anonymous INTEGER NOT NULL DEFAULT 1").run();
  } catch (err) {
    if (!/duplicate column/i.test(String(err && (err.cause?.message || err.message)))) throw err;
  }
  try {
    await db.prepare("ALTER TABLE sam_mg_players ADD COLUMN admin_force_public INTEGER NOT NULL DEFAULT 0").run();
  } catch (err) {
    if (!/duplicate column/i.test(String(err && (err.cause?.message || err.message)))) throw err;
  }
  try {
    await db.prepare("ALTER TABLE sam_mg_groups ADD COLUMN force_full_names INTEGER NOT NULL DEFAULT 0").run();
  } catch (err) {
    if (!/duplicate column/i.test(String(err && (err.cause?.message || err.message)))) throw err;
  }
  await db.prepare("CREATE UNIQUE INDEX IF NOT EXISTS sam_mg_players_email_key ON sam_mg_players (email_key)").run();
  schemaReady = true;
}

// Seeded shuffle, identical to Board.order in minigames/board.js. Chain answers
// are shown in this order per run, and the log records the position clicked.
export function order(seed, label, n) {
  let h = 2166136261;
  for (const ch of `${seed}:${label}`) h = Math.imul(h ^ ch.charCodeAt(0), 16777619) >>> 0;
  const next = () => {
    h = (h + 0x6d2b79f5) >>> 0;
    let t = h;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const a = Array.from({ length: n }, (_, i) => i);
  for (let i = n - 1; i > 0; i--) {
    const j = Math.floor(next() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

const fail = (status, error) => json({ error }, status);

async function sha256(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(bytes) {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function authPlayer(request, db) {
  const id = request.headers.get("x-player") || "";
  const key = request.headers.get("x-player-key") || "";
  if (!/^[0-9a-f]{24}$/.test(id) || !/^[0-9a-f]{64}$/.test(key)) return null;
  const row = await db.prepare("SELECT id, name, first_name, last_name, email, is_anonymous, admin_force_public, key_hash, group_id FROM sam_mg_players WHERE id = ?").bind(id).first();
  if (!row || !safeEqual(row.key_hash, await sha256(key))) return null;
  return row;
}

function cleanPersonName(raw, fieldLabel) {
  const name = String(raw || "").normalize("NFKC").replace(/\s+/g, " ").trim();
  if (!PERSON_NAME_PATTERN.test(name)) return { error: `${fieldLabel} must be 1-40 letters and can include spaces, apostrophes and dashes.` };
  return { name };
}

function cleanEmail(raw) {
  const email = String(raw || "").normalize("NFKC").trim().toLowerCase();
  if (!EMAIL_PATTERN.test(email)) return { error: "Enter a valid email address." };
  return { email, key: email };
}

function cleanNickname(raw) {
  const name = String(raw || "").normalize("NFKC").replace(/\s+/g, " ").trim();
  if (!NICKNAME_PATTERN.test(name)) return { error: "Nickname must be 2–20 letters, numbers, spaces, dots, dashes or underscores." };
  const folded = name
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[0134578@$!]/g, (c) => LEET[c] || c)
    .replace(/[^a-z0-9]/g, "");
  if (BLOCKED_TERMS.some((term) => folded.includes(term))) return { error: "Please pick a different nickname." };
  return { name, key: name.toLowerCase().replace(/[\s._-]/g, "") };
}

function splitLegacyName(raw) {
  const text = String(raw || "").trim();
  if (!text) return { firstName: "", lastName: "" };
  const parts = text.split(/\s+/);
  if (parts.length === 1) return { firstName: parts[0], lastName: "-" };
  return { firstName: parts.slice(0, -1).join(" "), lastName: parts[parts.length - 1] };
}

function profileFromRow(row) {
  const firstName = String(row && row.first_name || "").trim();
  const lastName = String(row && row.last_name || "").trim();
  if (firstName && lastName) return { firstName, lastName };
  return splitLegacyName(row && row.name);
}

function fullNameFromRow(row) {
  const { firstName, lastName } = profileFromRow(row);
  return `${firstName} ${lastName}`.trim();
}

function publicNameFromRow(row) {
  const { firstName, lastName } = profileFromRow(row);
  const first = firstName || "Player";
  const forcePublic = !!(row && (row.group_force_full_names || row.admin_force_public));
  if (forcePublic) return `${first} ${lastName}`.trim();
  const initial = (lastName || "").charAt(0).toUpperCase();
  return initial ? `${first} ${initial}.` : first;
}

function cleanProfile(body, allowLegacy = false) {
  const rawFirst = body && body.firstName;
  const rawLast = body && body.lastName;
  const rawEmail = body && body.email;
  const legacy = allowLegacy ? splitLegacyName(body && body.name) : { firstName: "", lastName: "" };
  const first = cleanPersonName(rawFirst || legacy.firstName, "First name");
  if (first.error) return first;
  const last = cleanPersonName(rawLast || legacy.lastName, "Last name");
  if (last.error) return last;
  const email = cleanEmail(rawEmail);
  if (email.error) return email;
  const isAnonymous = body && Object.prototype.hasOwnProperty.call(body, "isAnonymous")
    ? !!body.isAnonymous
    : true;
  return {
    firstName: first.name,
    lastName: last.name,
    fullName: `${first.name} ${last.name}`.trim(),
    email: email.email,
    emailKey: email.key,
    isAnonymous,
  };
}

function normalizeSlug(raw) {
  const slug = String(raw || "").trim().toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
  return SLUG_PATTERN.test(slug) ? slug : "";
}

async function resolveGroupBySlug(db, slug, includeInactive = false) {
  const clean = normalizeSlug(slug);
  if (!clean) return null;
  const row = await db.prepare("SELECT id, slug, name, active, force_full_names FROM sam_mg_groups WHERE slug = ?").bind(clean).first();
  if (!row || (!includeInactive && !row.active)) return null;
  return row;
}

async function enabledGamesForGroup(db, groupId) {
  const rows = await db.prepare("SELECT game, enabled FROM sam_mg_group_games WHERE group_id = ?").bind(groupId).all();
  const map = new Map((rows.results || []).map((r) => [r.game, !!r.enabled]));
  return GAME_IDS.filter((game) => map.has(game) ? map.get(game) : true);
}

async function actorContext(request, env, db) {
  const emailRaw = await getTrustedAdminEmail(request, env);
  const email = String(emailRaw || "").trim().toLowerCase();
  const globalAdmin = !!email && isAdminEmail(email, env);
  const managed = email
    ? await db.prepare("SELECT group_id FROM sam_mg_group_admins WHERE email = ?").bind(email).all()
    : { results: [] };
  const groupIds = new Set((managed.results || []).map((r) => r.group_id));
  return { email, globalAdmin, groupIds, admin: globalAdmin || groupIds.size > 0 };
}

async function canEmailAdmin(email, env, db) {
  const clean = normalizeAdminEmail(email);
  if (!clean) return false;
  if (isAdminEmail(clean, env)) return true;
  const row = await db.prepare("SELECT 1 AS ok FROM sam_mg_group_admins WHERE email = ? LIMIT 1").bind(clean).first();
  return !!(row && row.ok);
}

async function sendAdminMagicLink(email, token, env, origin) {
  const config = getMinigamesConfig(env);
  const resendApiKey = config.resendApiKey;
  const fromEmail = config.emailFrom;
  const ttlMinutes = Math.max(1, Math.round(config.adminLoginTtlMs / 60000));
  if (!resendApiKey || !fromEmail) return fail(503, "Email login is not configured on the server.");
  const link = `${origin}/admin/?login_token=${encodeURIComponent(token)}`;
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${resendApiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: fromEmail,
      to: [email],
      subject: "Your Security Awareness Month admin login link",
      html: `<p>Use this one-time login link for Security Awareness Month admin access:</p><p><a href="${link}">${link}</a></p><p>The link expires in ${ttlMinutes} minute${ttlMinutes === 1 ? "" : "s"}.</p>`,
      text: `Use this one-time login link for Security Awareness Month admin access: ${link}\n\nThe link expires in ${ttlMinutes} minute${ttlMinutes === 1 ? "" : "s"}.`,
    }),
  });
  if (!response.ok) {
    const detail = await response.text();
    console.error("resend send failed", response.status, detail);
    return fail(502, "Unable to send login email right now.");
  }
  return null;
}

async function issueAdminMagicLink(email, env, db, origin) {
  const config = getMinigamesConfig(env);
  const now = Date.now();
  const token = randomHex(24);
  const tokenHash = await sha256("sam-admin-login:" + token);
  await db.batch([
    db.prepare("DELETE FROM sam_mg_admin_login_tokens WHERE expires_at < ? OR used_at IS NOT NULL").bind(now),
    db.prepare("INSERT INTO sam_mg_admin_login_tokens (id, email, token_hash, created_at, expires_at, used_at) VALUES (?, ?, ?, ?, ?, NULL)")
      .bind(randomHex(12), email, tokenHash, now, now + config.adminLoginTtlMs),
  ]);
  return await sendAdminMagicLink(email, token, env, origin);
}

function canManageGroup(actor, groupId) {
  return !!(actor && (actor.globalAdmin || actor.groupIds.has(groupId)));
}

async function createPlayer(request, db) {
  const body = await readJson(request);
  let groupId = null;
  let group = null;
  const groupSlug = normalizeSlug(body && body.group);
  if (groupSlug) {
    group = await resolveGroupBySlug(db, groupSlug);
    if (!group) return fail(404, "Unknown group.");
    groupId = group.id;
  }
  const requireFullProfile = !!(group && group.force_full_names);
  let record;
  if (requireFullProfile) {
    const clean = cleanProfile(body, false);
    if (clean.error) return fail(400, clean.error);
    record = {
      fullName: clean.fullName,
      firstName: clean.firstName,
      lastName: clean.lastName,
      email: clean.email,
      emailKey: clean.emailKey,
      isAnonymous: clean.isAnonymous,
      nameKey: clean.emailKey,
    };
  } else if (body && typeof body.name === "string" && body.name.trim()) {
    const nick = cleanNickname(body.name);
    if (nick.error) return fail(400, nick.error);
    record = {
      fullName: nick.name,
      firstName: null,
      lastName: null,
      email: null,
      emailKey: null,
      isAnonymous: true,
      nameKey: nick.key,
    };
  } else {
    const clean = cleanProfile(body, false);
    if (clean.error) return fail(400, clean.error);
    record = {
      fullName: clean.fullName,
      firstName: clean.firstName,
      lastName: clean.lastName,
      email: clean.email,
      emailKey: clean.emailKey,
      isAnonymous: clean.isAnonymous,
      nameKey: clean.emailKey,
    };
  }
  const ipHash = (await sha256("sam-mg:" + (request.headers.get("cf-connecting-ip") || "unknown"))).slice(0, 32);
  const hourAgo = Date.now() - 3600_000;
  const recent = await db.prepare("SELECT COUNT(*) AS n FROM sam_mg_players WHERE ip_hash = ? AND created_at > ?").bind(ipHash, hourAgo).first();
  if (recent && recent.n >= MAX_NEW_PLAYERS_PER_IP_HOUR) return fail(429, "Too many new profiles from this network. Try again later.");
  const id = randomHex(12);
  const key = randomHex(32);
  try {
    await db.prepare(`INSERT INTO sam_mg_players (
      id, name, first_name, last_name, email, email_key, is_anonymous, admin_force_public, name_key, key_hash, ip_hash, created_at, group_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)`)
      .bind(
        id,
        record.fullName,
        record.firstName,
        record.lastName,
        record.email,
        record.emailKey,
        record.isAnonymous ? 1 : 0,
        record.nameKey,
        await sha256(key),
        ipHash,
        Date.now(),
        groupId,
      ).run();
  } catch (err) {
    if (String(err && err.message).includes("UNIQUE")) {
      return fail(409, requireFullProfile
        ? "That email is already registered. Use another email."
        : "That nickname is taken. Try another.");
    }
    throw err;
  }
  const viewRow = {
    first_name: record.firstName,
    last_name: record.lastName,
    name: record.fullName,
    admin_force_public: 0,
    group_force_full_names: requireFullProfile ? 1 : 0,
  };
  const player = {
    id,
    key,
    name: record.fullName,
    firstName: record.firstName || undefined,
    lastName: record.lastName || undefined,
    email: record.email || undefined,
    isAnonymous: record.isAnonymous,
    publicName: publicNameFromRow(viewRow),
  };
  return json(player);
}

async function startRun(request, db) {
  const player = await authPlayer(request, db);
  if (!player) return fail(401, "Unknown player. Register your profile again.");
  const body = await readJson(request);
  const game = body && GAMES[body.game] ? body.game : null;
  if (!game) return fail(400, "This game isn't ranked.");
  if (player.group_id) {
    const allowed = await enabledGamesForGroup(db, player.group_id);
    if (!allowed.includes(game)) return fail(403, "This game isn't enabled for your group.");
    const group = await db.prepare("SELECT force_full_names FROM sam_mg_groups WHERE id = ?").bind(player.group_id).first();
    if (group && group.force_full_names && !player.email) {
      return fail(403, "This group requires first name, last name and email. Register again.");
    }
  }
  const now = Date.now();
  const last = await db.prepare("SELECT started_at FROM sam_mg_runs WHERE player_id = ? ORDER BY started_at DESC LIMIT 1").bind(player.id).first();
  if (last && now - last.started_at < START_COOLDOWN_MS) return fail(429, "Slow down a little and try again.");
  const runId = randomHex(16);
  await db.batch([
    db.prepare("DELETE FROM sam_mg_runs WHERE player_id = ? AND started_at < ?").bind(player.id, now - RUN_TTL_MS),
    db.prepare("INSERT INTO sam_mg_runs (id, player_id, game, started_at) VALUES (?, ?, ?, ?)").bind(runId, player.id, game, now),
  ]);
  return json({ runId });
}

// Mirrors the scoring in minigames/engine.js exactly.
export function scoreRun(key, log, elapsedMs, seed = "") {
  if (!Array.isArray(log) || log.length > MAX_LOG) return { error: "Invalid run." };
  const risks = new Set(key.risks);
  const found = new Set();
  let wrong = 0;
  let hints = 0;
  let step = 0;
  let inChain = false;
  let prev = -Infinity;
  for (const e of log) {
    if (!e || typeof e !== "object" || !Number.isInteger(e.t) || e.t < 0) return { error: "Invalid run." };
    if (e.t < prev || e.t > elapsedMs + LATENCY_GRACE_MS) return { error: "Run rejected: timing doesn't add up." };
    prev = e.t;
    if (e.k === "c" && !inChain) {
      const id = typeof e.v === "string" ? e.v : "";
      if (risks.has(id)) found.add(id);
      else wrong += 1;
    } else if (e.k === "h" && !inChain) {
      if (found.size >= risks.size) return { error: "Invalid run." };
      hints += 1;
    } else if (e.k === "a") {
      if (!inChain) {
        if (found.size < key.minToContinue) return { error: "Invalid run." };
        inChain = true;
      }
      if (step >= key.chain.length || !Number.isInteger(e.v) || e.v < 0 || e.v >= key.options[step]) return { error: "Invalid run." };
      if (order(seed, "chain" + step, key.options[step])[e.v] === key.chain[step]) step += 1;
      else wrong += 1;
    } else {
      return { error: "Invalid run." };
    }
  }
  const limitMs = key.timeLimit * 1000;
  const lastT = log.length ? log[log.length - 1].t : 0;
  const complete = step === key.chain.length;
  // The client starts its clock after /start responds, so the server's elapsed
  // time is never shorter than the player's. Up to LATENCY_GRACE_MS of it is
  // forgiven as network time for the /finish request.
  let durationMs = Math.min(elapsedMs, Math.max(lastT, elapsedMs - LATENCY_GRACE_MS));
  if (!complete) {
    if (elapsedMs < limitMs) return { error: "The run isn't finished yet." };
    durationMs = limitMs;
  } else if (elapsedMs < MIN_MS_PER_ACTION * (risks.size + key.chain.length)) {
    return { error: "Run rejected: faster than humanly possible." };
  }
  const timeUp = durationMs >= limitMs;
  const missed = risks.size - found.size;
  const breakdown = {
    time: timeUp ? 0 : key.timeLimit - Math.floor(durationMs / 1000),
    wrong: -wrong * POINTS.wrong,
    hints: -hints * POINTS.hint,
    missed: -missed * POINTS.missed,
  };
  const score = Math.max(0, breakdown.time + breakdown.wrong + breakdown.hints + breakdown.missed);
  return { score, breakdown, timeUp, durationMs: Math.min(durationMs, limitMs), wrong, hints, found: found.size };
}

async function finishRun(request, db) {
  const player = await authPlayer(request, db);
  if (!player) return fail(401, "Unknown player.");
  const body = await readJson(request);
  const runId = body && typeof body.runId === "string" && /^[0-9a-f]{32}$/.test(body.runId) ? body.runId : null;
  if (!runId) return fail(400, "Invalid run.");
  const run = await db.prepare("SELECT id, player_id, game, started_at FROM sam_mg_runs WHERE id = ?").bind(runId).first();
  if (!run || run.player_id !== player.id) return fail(404, "Run not found or already submitted.");
  const key = GAMES[run.game];
  const now = Date.now();
  const elapsed = now - run.started_at;
  if (!key || elapsed > RUN_TTL_MS) {
    await db.prepare("DELETE FROM sam_mg_runs WHERE id = ?").bind(runId).run();
    return fail(410, "This run expired.");
  }
  const result = scoreRun(key, body.log, elapsed, runId);
  if (result.error) {
    if (!result.error.includes("isn't finished")) await db.prepare("DELETE FROM sam_mg_runs WHERE id = ?").bind(runId).run();
    return fail(400, result.error);
  }
  const previous = await db.prepare("SELECT score, duration_ms FROM sam_mg_best WHERE player_id = ? AND game = ?").bind(player.id, run.game).first();
  const personalBest = !previous || result.score > previous.score || (result.score === previous.score && result.durationMs < previous.duration_ms);
  // The run row is deleted in the same batch, so a run can only be scored once.
  const [deleted] = await db.batch([
    db.prepare("DELETE FROM sam_mg_runs WHERE id = ?").bind(runId),
    db.prepare(`INSERT INTO sam_mg_best (player_id, game, score, duration_ms, wrong, hints, found, attempts, achieved_at, first_score)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?3)
      ON CONFLICT (player_id, game) DO UPDATE SET
        attempts = attempts + 1,
        score = CASE WHEN excluded.score > score OR (excluded.score = score AND excluded.duration_ms < duration_ms) THEN excluded.score ELSE score END,
        wrong = CASE WHEN excluded.score > score OR (excluded.score = score AND excluded.duration_ms < duration_ms) THEN excluded.wrong ELSE wrong END,
        hints = CASE WHEN excluded.score > score OR (excluded.score = score AND excluded.duration_ms < duration_ms) THEN excluded.hints ELSE hints END,
        found = CASE WHEN excluded.score > score OR (excluded.score = score AND excluded.duration_ms < duration_ms) THEN excluded.found ELSE found END,
        achieved_at = CASE WHEN excluded.score > score OR (excluded.score = score AND excluded.duration_ms < duration_ms) THEN excluded.achieved_at ELSE achieved_at END,
        duration_ms = CASE WHEN excluded.score > score OR (excluded.score = score AND excluded.duration_ms < duration_ms) THEN excluded.duration_ms ELSE duration_ms END`)
      .bind(player.id, run.game, result.score, result.durationMs, result.wrong, result.hints, result.found, now),
  ]);
  if (!deleted.meta || deleted.meta.changes !== 1) return fail(409, "Run already submitted.");
  const board = await gameBoard(db, run.game, player.id, player.group_id || null);
  return json({
    ...result,
    personalBest,
    best: personalBest ? result.score : previous.score,
    rank: board.me ? board.me.rank : null,
    total: board.total,
    next: board.next,
    board: { entries: board.entries, total: board.total },
  });
}

function shape(rows, playerId, overall) {
  const entries = rows.map((r) => ({
    rank: r.rk,
    name: publicNameFromRow(r),
    playerId: r.player_id,
    score: r.score,
    durationMs: r.duration_ms,
    firstScore: r.first_score ?? null,
    games: overall ? r.games : undefined,
    mine: r.player_id === playerId,
  }));
  const total = rows.length ? rows[0].total : 0;
  const me = entries.find((e) => e.mine) || null;
  const above = me && entries.find((e) => e.rank === me.rank - 1);
  const next = above ? { name: above.name, gap: above.score - me.score + 1 } : null;
  return { entries, total, me, next };
}

// Top of the board, the player's own row and the row they are chasing.
const visible = (p) => `(rk <= ${TOP} OR rk = (SELECT rk FROM r WHERE player_id = ${p}) OR rk = (SELECT rk FROM r WHERE player_id = ${p}) - 1)`;

async function gameBoard(db, game, playerId, groupId = null) {
  const groupClause = groupId ? "p.group_id = ?3" : "p.group_id IS NULL";
  const binds = groupId ? [game, playerId || "", groupId] : [game, playerId || ""];
  const { results } = await db.prepare(`
    WITH scoped AS (
      SELECT
        b.player_id, b.score, b.duration_ms, b.first_score, b.achieved_at,
        p.name, p.first_name, p.last_name, p.admin_force_public,
        COALESCE(g.force_full_names, 0) AS group_force_full_names
      FROM sam_mg_best b
      JOIN sam_mg_players p ON p.id = b.player_id
      LEFT JOIN sam_mg_groups g ON g.id = p.group_id
      WHERE b.game = ?1 AND ${groupClause}
    ),
    r AS (
      SELECT player_id, name, first_name, last_name, admin_force_public, group_force_full_names, score, duration_ms, first_score,
        ROW_NUMBER() OVER (ORDER BY score DESC, duration_ms ASC, achieved_at ASC) AS rk
      FROM scoped)
    SELECT r.*, (SELECT COUNT(*) FROM r) AS total
    FROM r
    WHERE ${visible("?2")} ORDER BY rk`).bind(...binds).all();
  return shape(results, playerId, false);
}

async function overallBoard(db, playerId, groupId = null, games = GAME_IDS) {
  if (!games.length) return { entries: [], total: 0, me: null, next: null, gameCount: 0 };
  const marks = games.map((_, i) => `?${i + 2}`).join(", ");
  const groupClause = groupId ? "p.group_id = ?" + (games.length + 2) : "p.group_id IS NULL";
  const params = groupId ? [playerId || "", ...games, groupId] : [playerId || "", ...games];
  const { results } = await db.prepare(`
    WITH scoped AS (
      SELECT
        b.player_id, b.score, b.duration_ms, b.first_score, b.achieved_at,
        p.name, p.first_name, p.last_name, p.admin_force_public,
        COALESCE(g.force_full_names, 0) AS group_force_full_names
      FROM sam_mg_best b
      JOIN sam_mg_players p ON p.id = b.player_id
      LEFT JOIN sam_mg_groups g ON g.id = p.group_id
      WHERE b.game IN (${marks}) AND ${groupClause}
    ),
    t AS (
      SELECT
        player_id,
        MAX(name) AS name,
        MAX(first_name) AS first_name,
        MAX(last_name) AS last_name,
        MAX(admin_force_public) AS admin_force_public,
        MAX(group_force_full_names) AS group_force_full_names,
        SUM(score) AS score,
        SUM(duration_ms) AS duration_ms,
        SUM(first_score) AS first_score,
        COUNT(*) AS games,
        MAX(achieved_at) AS last
      FROM scoped
      GROUP BY player_id),
    r AS (SELECT t.*, ROW_NUMBER() OVER (ORDER BY score DESC, duration_ms ASC, last ASC) AS rk FROM t)
    SELECT r.*, (SELECT COUNT(*) FROM r) AS total
    FROM r
    WHERE ${visible("?1")} ORDER BY rk`).bind(...params).all();
  return { ...shape(results, playerId, true), gameCount: games.length };
}

async function getBoard(url, db) {
  const game = url.searchParams.get("game") || "overall";
  const playerId = url.searchParams.get("player") || "";
  const groupSlug = url.searchParams.get("group") || "";
  if (playerId && !/^[0-9a-f]{24}$/.test(playerId)) return fail(400, "Invalid player.");
  let group = null;
  let enabledGames = GAME_IDS;
  if (groupSlug) {
    group = await resolveGroupBySlug(db, groupSlug);
    if (!group) return fail(404, "Unknown group.");
    enabledGames = await enabledGamesForGroup(db, group.id);
  }
  if (game === "overall") return json({ ...(await overallBoard(db, playerId, group && group.id, enabledGames)), group: group ? group.slug : null });
  if (!GAMES[game]) return fail(404, "Unknown game.");
  if (group && !enabledGames.includes(game)) return fail(403, "This game isn't enabled for this group.");
  return json({ ...(await gameBoard(db, game, playerId, group && group.id)), gameCount: enabledGames.length, group: group ? group.slug : null });
}

async function getAdmin(request, env, db) {
  const actor = await actorContext(request, env, db);
  const groups = actor.groupIds.size
    ? (await db.prepare(`SELECT id, slug, name, force_full_names FROM sam_mg_groups WHERE id IN (${Array.from(actor.groupIds).map((_, i) => `?${i + 1}`).join(", ")})`)
      .bind(...Array.from(actor.groupIds)).all()).results || []
    : [];
  return json({
    admin: actor.admin,
    globalAdmin: actor.globalAdmin,
    email: actor.email || null,
    groups,
  });
}

async function listGroups(request, env, db) {
  const actor = await actorContext(request, env, db);
  if (!actor.admin) return fail(403, "Admin access required.");
  const params = [];
  let where = "";
  if (!actor.globalAdmin) {
    const ids = Array.from(actor.groupIds);
    if (!ids.length) return json({ groups: [] });
    where = `WHERE g.id IN (${ids.map((_, i) => `?${i + 1}`).join(", ")})`;
    params.push(...ids);
  }
  const groups = (await db.prepare(`
    SELECT g.id, g.slug, g.name, g.active, g.force_full_names,
      (SELECT COUNT(*) FROM sam_mg_players p WHERE p.group_id = g.id) AS members
    FROM sam_mg_groups g
    ${where}
    ORDER BY g.name ASC`).bind(...params).all()).results || [];
  for (const group of groups) {
    const admins = await db.prepare("SELECT email FROM sam_mg_group_admins WHERE group_id = ? ORDER BY email ASC").bind(group.id).all();
    const gameRows = await db.prepare("SELECT game, enabled FROM sam_mg_group_games WHERE group_id = ?").bind(group.id).all();
    const map = new Map((gameRows.results || []).map((r) => [r.game, !!r.enabled]));
    group.admins = (admins.results || []).map((r) => r.email);
    group.games = Object.fromEntries(GAME_IDS.map((id) => [id, map.has(id) ? map.get(id) : true]));
    group.forceFullNames = !!group.force_full_names;
    delete group.force_full_names;
  }
  return json({ groups, globalAdmin: actor.globalAdmin });
}

async function createGroup(request, env, db) {
  const actor = await actorContext(request, env, db);
  if (!actor.globalAdmin) return fail(403, "Global admin access required.");
  const body = await readJson(request);
  const name = String(body && body.name || "").trim().replace(/\s+/g, " ");
  if (name.length < 2 || name.length > 60) return fail(400, "Group name must be 2-60 characters.");
  const slug = normalizeSlug((body && body.slug) || name);
  if (!slug) return fail(400, "Invalid group slug.");
  const id = randomHex(12);
  const now = Date.now();
  try {
    const batch = [
      db.prepare("INSERT INTO sam_mg_groups (id, slug, name, active, created_at, created_by) VALUES (?, ?, ?, 1, ?, ?)")
        .bind(id, slug, name, now, actor.email || null),
      ...GAME_IDS.map((game) =>
        db.prepare("INSERT INTO sam_mg_group_games (group_id, game, enabled, updated_at, updated_by) VALUES (?, ?, 1, ?, ?)")
          .bind(id, game, now, actor.email || null),
      ),
    ];
    await db.batch(batch);
  } catch (err) {
    if (String(err && err.message).includes("UNIQUE")) return fail(409, "That group slug already exists.");
    throw err;
  }
  return json({ id, slug, name, active: 1 }, 201);
}

async function updateGroup(request, env, db) {
  const actor = await actorContext(request, env, db);
  if (!actor.globalAdmin) return fail(403, "Global admin access required.");
  const body = await readJson(request);
  const groupId = String(body && body.groupId || "");
  if (!/^[0-9a-f]{24}$/.test(groupId)) return fail(400, "Invalid group.");
  const updates = [];
  const args = [];
  if (body && Object.prototype.hasOwnProperty.call(body, "name")) {
    const name = String(body.name || "").trim().replace(/\s+/g, " ");
    if (name.length < 2 || name.length > 60) return fail(400, "Group name must be 2-60 characters.");
    updates.push("name = ?");
    args.push(name);
  }
  if (body && Object.prototype.hasOwnProperty.call(body, "active")) {
    updates.push("active = ?");
    args.push(body.active ? 1 : 0);
  }
  if (body && Object.prototype.hasOwnProperty.call(body, "forceFullNames")) {
    updates.push("force_full_names = ?");
    args.push(body.forceFullNames ? 1 : 0);
  }
  if (!updates.length) return fail(400, "Nothing to update.");
  const result = await db.prepare(`UPDATE sam_mg_groups SET ${updates.join(", ")} WHERE id = ?`).bind(...args, groupId).run();
  if (!result.meta || result.meta.changes !== 1) return fail(404, "Group not found.");
  return json({ ok: true });
}

async function deleteGroup(request, env, db) {
  const actor = await actorContext(request, env, db);
  if (!actor.globalAdmin) return fail(403, "Global admin access required.");
  const body = await readJson(request);
  const groupId = String(body && body.groupId || "");
  if (!/^[0-9a-f]{24}$/.test(groupId)) return fail(400, "Invalid group.");
  const group = await db.prepare("SELECT id FROM sam_mg_groups WHERE id = ?").bind(groupId).first();
  if (!group) return fail(404, "Unknown group.");
  const members = await db.prepare("SELECT COUNT(*) AS n FROM sam_mg_players WHERE group_id = ?").bind(groupId).first();
  // The players belong to the group's own leaderboard, so they go with it. Detaching them
  // would drop their scores into the group-less board.
  await db.batch([
    db.prepare("DELETE FROM sam_mg_best WHERE player_id IN (SELECT id FROM sam_mg_players WHERE group_id = ?)").bind(groupId),
    db.prepare("DELETE FROM sam_mg_runs WHERE player_id IN (SELECT id FROM sam_mg_players WHERE group_id = ?)").bind(groupId),
    db.prepare("DELETE FROM sam_mg_players WHERE group_id = ?").bind(groupId),
    db.prepare("DELETE FROM sam_mg_group_games WHERE group_id = ?").bind(groupId),
    db.prepare("DELETE FROM sam_mg_group_admins WHERE group_id = ?").bind(groupId),
    db.prepare("DELETE FROM sam_mg_groups WHERE id = ?").bind(groupId),
  ]);
  return json({ ok: true, removedPlayers: (members && members.n) || 0 });
}

async function setGroupAdmin(request, env, db, remove = false) {
  const actor = await actorContext(request, env, db);
  if (!actor.globalAdmin) return fail(403, "Global admin access required.");
  const body = await readJson(request);
  const groupId = String(body && body.groupId || "");
  const email = String(body && body.email || "").trim().toLowerCase();
  if (!/^[0-9a-f]{24}$/.test(groupId)) return fail(400, "Invalid group.");
  if (!email || !email.includes("@")) return fail(400, "Invalid email.");
  if (remove) {
    await db.prepare("DELETE FROM sam_mg_group_admins WHERE group_id = ? AND email = ?").bind(groupId, email).run();
    return json({ ok: true, invitationSent: false });
  }
  await db.prepare("INSERT OR IGNORE INTO sam_mg_group_admins (group_id, email, created_at) VALUES (?, ?, ?)")
    .bind(groupId, email, Date.now()).run();
  const sendError = await issueAdminMagicLink(email, env, db, new URL(request.url).origin);
  if (sendError) {
    return fail(502, "Group admin was added, but sending login email failed. Check RESEND_API_KEY and SAM_MINIGAMES_EMAIL_FROM.");
  }
  return json({ ok: true, invitationSent: true });
}

async function setGroupGames(request, env, db) {
  const actor = await actorContext(request, env, db);
  if (!actor.admin) return fail(403, "Admin access required.");
  const body = await readJson(request);
  const groupId = String(body && body.groupId || "");
  if (!/^[0-9a-f]{24}$/.test(groupId)) return fail(400, "Invalid group.");
  if (!canManageGroup(actor, groupId)) return fail(403, "You can't manage this group.");
  const selected = new Set(Array.isArray(body && body.games) ? body.games.filter((g) => !!GAMES[g]) : []);
  const now = Date.now();
  await db.batch(GAME_IDS.map((game) =>
    db.prepare(`INSERT INTO sam_mg_group_games (group_id, game, enabled, updated_at, updated_by)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT (group_id, game) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at, updated_by = excluded.updated_by`)
      .bind(groupId, game, selected.has(game) ? 1 : 0, now, actor.email || null),
  ));
  return json({ ok: true });
}

async function assignPlayerGroup(request, env, db) {
  const actor = await actorContext(request, env, db);
  if (!actor.globalAdmin) return fail(403, "Global admin access required.");
  const body = await readJson(request);
  const playerId = String(body && body.playerId || "");
  const groupId = body && body.groupId ? String(body.groupId) : null;
  if (!/^[0-9a-f]{24}$/.test(playerId)) return fail(400, "Invalid player.");
  if (groupId && !/^[0-9a-f]{24}$/.test(groupId)) return fail(400, "Invalid group.");
  const result = await db.prepare("UPDATE sam_mg_players SET group_id = ? WHERE id = ?").bind(groupId, playerId).run();
  if (!result.meta || result.meta.changes !== 1) return fail(404, "Player not found.");
  return json({ ok: true });
}

async function getGroupConfig(url, db) {
  const slug = url.searchParams.get("slug") || "";
  const group = await resolveGroupBySlug(db, slug);
  if (!group) return fail(404, "Unknown group.");
  return json({ slug: group.slug, name: group.name, forceFullNames: !!group.force_full_names, games: await enabledGamesForGroup(db, group.id) });
}

async function joinGroup(request, db) {
  const player = await authPlayer(request, db);
  if (!player) return fail(401, "Unknown player.");
  const body = await readJson(request);
  const group = await resolveGroupBySlug(db, body && body.group);
  if (!group) return fail(404, "Unknown group.");
  await db.prepare("UPDATE sam_mg_players SET group_id = ? WHERE id = ?").bind(group.id, player.id).run();
  return json({ ok: true, group: group.slug });
}

function canManagePlayer(actor, playerGroupId) {
  if (!actor || !actor.admin) return false;
  if (actor.globalAdmin) return true;
  return !!(playerGroupId && actor.groupIds.has(playerGroupId));
}

function rankPlayers(rows) {
  const sorted = [...rows].sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    if (a.durationMs !== b.durationMs) return a.durationMs - b.durationMs;
    return a.createdAt - b.createdAt;
  });
  return sorted.map((row, i) => ({ ...row, rank: i + 1 }));
}

async function listPlayers(request, env, db) {
  const actor = await actorContext(request, env, db);
  if (!actor.admin) return fail(403, "Admin access required.");
  const params = [];
  let where = "";
  if (!actor.globalAdmin) {
    const ids = Array.from(actor.groupIds);
    if (!ids.length) return json({ players: [] });
    where = `WHERE p.group_id IN (${ids.map((_, i) => `?${i + 1}`).join(", ")})`;
    params.push(...ids);
  }
  const rows = (await db.prepare(`
    SELECT
      p.id,
      p.name,
      p.first_name,
      p.last_name,
      p.email,
      p.is_anonymous,
      p.admin_force_public,
      p.group_id,
      p.created_at,
      g.slug AS group_slug,
      g.name AS group_name,
      COALESCE(SUM(b.score), 0) AS score,
      COALESCE(SUM(b.duration_ms), 0) AS duration_ms,
      COALESCE(SUM(b.first_score), 0) AS first_score,
      COUNT(b.game) AS games
    FROM sam_mg_players p
    LEFT JOIN sam_mg_best b ON b.player_id = p.id
    LEFT JOIN sam_mg_groups g ON g.id = p.group_id
    ${where}
    GROUP BY p.id
  `).bind(...params).all()).results || [];
  const players = rankPlayers(rows.map((row) => ({
    id: row.id,
    fullName: fullNameFromRow(row),
    firstName: profileFromRow(row).firstName,
    lastName: profileFromRow(row).lastName,
    email: String(row.email || "").trim(),
    publicName: publicNameFromRow(row),
    isAnonymous: !!row.is_anonymous,
    adminForcePublicIdentity: !!row.admin_force_public,
    score: Number(row.score || 0),
    durationMs: Number(row.duration_ms || 0),
    firstScore: Number(row.first_score || 0),
    games: Number(row.games || 0),
    groupId: row.group_id || null,
    groupSlug: row.group_slug || null,
    groupName: row.group_name || null,
    createdAt: Number(row.created_at || 0),
  })));
  return json({ players });
}

async function backfillPlayers(request, env, db) {
  const actor = await actorContext(request, env, db);
  if (!actor.globalAdmin) return fail(403, "Global admin access required.");
  const rows = (await db.prepare(`
    SELECT id, name, first_name, last_name, email, email_key, is_anonymous, admin_force_public
    FROM sam_mg_players
    WHERE
      first_name IS NULL OR TRIM(first_name) = ''
      OR last_name IS NULL OR TRIM(last_name) = ''
      OR is_anonymous IS NULL
      OR admin_force_public IS NULL
      OR (email IS NOT NULL AND TRIM(email) <> '' AND (email_key IS NULL OR TRIM(email_key) = ''))
  `).all()).results || [];
  let updated = 0;
  let touchedEmailKey = 0;
  for (const row of rows) {
    const profile = profileFromRow(row);
    const firstName = profile.firstName || "Player";
    const lastName = profile.lastName || "-";
    const rawEmail = String(row.email || "").trim().toLowerCase();
    const emailKey = rawEmail ? rawEmail : null;
    if (emailKey) touchedEmailKey += 1;
    await db.prepare(`
      UPDATE sam_mg_players
      SET
        first_name = ?,
        last_name = ?,
        is_anonymous = COALESCE(is_anonymous, 1),
        admin_force_public = COALESCE(admin_force_public, 0),
        email_key = CASE
          WHEN ? IS NOT NULL AND (? IS NULL OR TRIM(?) = '') THEN ?
          ELSE email_key
        END
      WHERE id = ?
    `).bind(
      firstName,
      lastName,
      emailKey,
      row.email_key,
      row.email_key,
      emailKey,
      row.id,
    ).run();
    updated += 1;
  }
  return json({
    ok: true,
    scanned: rows.length,
    updated,
    emailKeysNormalized: touchedEmailKey,
  });
}

async function updatePlayerProfile(request, env, db) {
  const actor = await actorContext(request, env, db);
  if (!actor.admin) return fail(403, "Admin access required.");
  const body = await readJson(request);
  const playerId = String(body && body.playerId || "");
  if (!/^[0-9a-f]{24}$/.test(playerId)) return fail(400, "Invalid player.");
  const current = await db.prepare(
    "SELECT id, name, first_name, last_name, email, email_key, is_anonymous, admin_force_public, group_id FROM sam_mg_players WHERE id = ?",
  ).bind(playerId).first();
  if (!current) return fail(404, "Player not found.");
  if (!canManagePlayer(actor, current.group_id)) return fail(403, "You can't manage this player.");

  const firstCandidate = Object.prototype.hasOwnProperty.call(body || {}, "firstName") ? body.firstName : current.first_name;
  const lastCandidate = Object.prototype.hasOwnProperty.call(body || {}, "lastName") ? body.lastName : current.last_name;
  const emailCandidate = Object.prototype.hasOwnProperty.call(body || {}, "email") ? body.email : current.email;
  const clean = cleanProfile({
    firstName: firstCandidate,
    lastName: lastCandidate,
    email: emailCandidate,
    isAnonymous: Object.prototype.hasOwnProperty.call(body || {}, "isAnonymous") ? !!body.isAnonymous : !!current.is_anonymous,
  });
  if (clean.error) return fail(400, clean.error);
  const adminForcePublic = Object.prototype.hasOwnProperty.call(body || {}, "adminForcePublicIdentity")
    ? !!body.adminForcePublicIdentity
    : !!current.admin_force_public;
  try {
    const result = await db.prepare(`
      UPDATE sam_mg_players
      SET
        name = ?,
        first_name = ?,
        last_name = ?,
        email = ?,
        email_key = ?,
        name_key = ?,
        is_anonymous = ?,
        admin_force_public = ?
      WHERE id = ?
    `).bind(
      clean.fullName,
      clean.firstName,
      clean.lastName,
      clean.email,
      clean.emailKey,
      clean.emailKey,
      clean.isAnonymous ? 1 : 0,
      adminForcePublic ? 1 : 0,
      playerId,
    ).run();
    if (!result.meta || result.meta.changes !== 1) return fail(404, "Player not found.");
  } catch (err) {
    if (String(err && err.message).includes("UNIQUE")) return fail(409, "That email is already registered.");
    throw err;
  }
  return json({
    ok: true,
    player: {
      id: playerId,
      fullName: clean.fullName,
      firstName: clean.firstName,
      lastName: clean.lastName,
      email: clean.email,
      isAnonymous: clean.isAnonymous,
      adminForcePublicIdentity: adminForcePublic,
      publicName: publicNameFromRow({
        first_name: clean.firstName,
        last_name: clean.lastName,
        admin_force_public: adminForcePublic ? 1 : 0,
      }),
    },
  });
}

async function removePlayer(request, env, url, db) {
  const actor = await actorContext(request, env, db);
  const id = url.searchParams.get("id") || "";
  if (!/^[0-9a-f]{24}$/.test(id)) return fail(400, "Invalid player.");
  const player = await db.prepare("SELECT group_id FROM sam_mg_players WHERE id = ?").bind(id).first();
  if (!player) return fail(404, "Player not found.");
  if (!canManagePlayer(actor, player.group_id)) return fail(403, "You can't remove this player.");
  await db.batch([
    db.prepare("DELETE FROM sam_mg_best WHERE player_id = ?").bind(id),
    db.prepare("DELETE FROM sam_mg_runs WHERE player_id = ?").bind(id),
    db.prepare("DELETE FROM sam_mg_players WHERE id = ?").bind(id),
  ]);
  return json({ ok: true });
}

async function loginAdmin(request, env) {
  const body = await readJson(request);
  const email = String(body && body.email || "");
  const key = String(body && body.key || "");
  if (!verifyAdminLogin(email, key, env)) return fail(403, "Invalid admin credentials.");
  const cookie = await buildAdminSessionCookie(email, env);
  const token = await buildAdminSessionToken(email, env);
  if (!cookie) return fail(503, "Admin session is not configured.");
  return new Response(JSON.stringify({ ok: true, token }), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "set-cookie": cookie,
    },
  });
}

async function requestAdminLogin(request, env, db) {
  const body = await readJson(request);
  const email = normalizeAdminEmail(body && body.email);
  if (!email) return fail(400, "Enter a valid email.");
  const authorized = await canEmailAdmin(email, env, db);
  if (!authorized) return json({ ok: true });
  const sendError = await issueAdminMagicLink(email, env, db, new URL(request.url).origin);
  if (sendError) return sendError;
  return json({ ok: true });
}

async function verifyAdminLoginToken(request, env, db) {
  const body = await readJson(request);
  const token = String(body && body.token || "").trim();
  if (!/^[0-9a-f]{48}$/.test(token)) return fail(400, "Invalid login token.");
  const tokenHash = await sha256("sam-admin-login:" + token);
  const now = Date.now();
  const row = await db.prepare(
    "SELECT id, email FROM sam_mg_admin_login_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at >= ? LIMIT 1",
  ).bind(tokenHash, now).first();
  if (!row) return fail(400, "Login link is invalid or has expired.");
  if (!await canEmailAdmin(row.email, env, db)) return fail(403, "This email no longer has admin access.");
  const used = await db.prepare("UPDATE sam_mg_admin_login_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL").bind(now, row.id).run();
  if (!used.meta || used.meta.changes !== 1) return fail(409, "Login link already used.");
  const cookie = await buildAdminSessionCookie(row.email, env);
  const signedToken = await buildAdminSessionToken(row.email, env);
  if (!cookie || !signedToken) return fail(503, "Admin session is not configured.");
  return new Response(JSON.stringify({ ok: true, token: signedToken }), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "set-cookie": cookie,
    },
  });
}

async function logoutAdmin() {
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "set-cookie": clearAdminSessionCookie(),
    },
  });
}

async function debugAdminAuth(request, env) {
  const data = getAdminAuthDebug(env);
  const actor = await getTrustedAdminEmail(request, env);
  return json({
    ...data,
    currentSessionEmail: actor || null,
  });
}

export async function onRequest(context) {
  const { request, env, params } = context;
  const db = env.AUKSJON_DB
    || env.securityawarenessmonth_minigames
    || env.SECURITYAWARENESSMONTH_MINIGAMES
    || env.MINIGAMES_DB;
  if (!db) return fail(503, "Leaderboard unavailable.");
  const route = "/" + [].concat(params.path || []).join("/");
  const url = new URL(request.url);
  const method = request.method;
  try {
    await ensureSchema(db);
    if (route === "/board" && method === "GET") return await getBoard(url, db);
    if (route === "/auth/request-login" && method === "POST") return await requestAdminLogin(request, env, db);
    if (route === "/auth/verify-login" && method === "POST") return await verifyAdminLoginToken(request, env, db);
    if (route === "/auth/login" && method === "POST") return await loginAdmin(request, env);
    if (route === "/auth/logout" && method === "POST") return await logoutAdmin();
    if (route === "/auth/debug" && method === "GET") return await debugAdminAuth(request, env);
    if (route === "/group" && method === "GET") return await getGroupConfig(url, db);
    if (route === "/group/join" && method === "POST") return await joinGroup(request, db);
    if (route === "/player" && method === "POST") return await createPlayer(request, db);
    if (route === "/player" && method === "PATCH") return await updatePlayerProfile(request, env, db);
    if (route === "/player" && method === "DELETE") return await removePlayer(request, env, url, db);
    if (route === "/players" && method === "GET") return await listPlayers(request, env, db);
    if (route === "/players/backfill" && method === "POST") return await backfillPlayers(request, env, db);
    if (route === "/group/player" && method === "POST") return await assignPlayerGroup(request, env, db);
    if (route === "/start" && method === "POST") return await startRun(request, db);
    if (route === "/finish" && method === "POST") return await finishRun(request, db);
    if (route === "/admin" && method === "GET") return await getAdmin(request, env, db);
    if (route === "/groups" && method === "GET") return await listGroups(request, env, db);
    if (route === "/groups" && method === "POST") return await createGroup(request, env, db);
    if (route === "/groups" && method === "PATCH") return await updateGroup(request, env, db);
    if (route === "/groups" && method === "DELETE") return await deleteGroup(request, env, db);
    if (route === "/groups/admin" && method === "POST") return await setGroupAdmin(request, env, db);
    if (route === "/groups/admin" && method === "DELETE") return await setGroupAdmin(request, env, db, true);
    if (route === "/groups/games" && method === "POST") return await setGroupGames(request, env, db);
    return fail(404, "Not found.");
  } catch (err) {
    console.error("minigames-api", err);
    return fail(500, "Something went wrong.");
  }
}
