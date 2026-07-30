/**
 * Host-side IPC for Buzz Web — replaces running the Tauri desktop app on Fedora.
 *
 * The browser is a thin UI; this process holds the host seckey and talks to the
 * real relay (NIP-42 / NIP-98 / EVENT) the same way desktop would.
 *
 * Scope (MVP, no workflows / no voice):
 *   identity, AUTH, sign, channels, messages, send, profiles, relay agents, models
 *
 * Security: /api/* is behind chat.f.mtt.cool nginx — treat as single-tenant host.
 */
const http = require("http");
const { execSync, exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { createRequire } = require("module");

const PORT = Number(process.env.BUZZ_HOST_IPC_PORT || process.env.PORT || 3001);
/** Agent env file (model restarts etc.). Secrets come from process.env via systemd. */
const ENV_PATH =
  process.env.BUZZ_AGENT_ENV_FILE || "/home/lary/.config/buzz-agent/env";
const RELAY_HTTP = process.env.BUZZ_RELAY_HTTP || "https://buzz.f.mtt.cool";
const RELAY_WS = process.env.BUZZ_RELAY_URL || "wss://buzz.f.mtt.cool";

const requireDesktop = createRequire(
  path.join(__dirname, "desktop", "package.json"),
);
const {
  finalizeEvent,
  getPublicKey,
  nip19,
  nip44,
  generateSecretKey,
  verifyEvent,
} = requireDesktop("nostr-tools");

/** Mirror desktop TIMELINE_KINDS minus huddle (voice out of scope). */
const TIMELINE_KINDS = [9, 40002, 40008, 40099, 43001, 43002, 43003, 43004, 43005, 43006];

/** Channels we just created: membership (kind:39002) may lag; treat as member. */
const pendingOwnedChannelIds = new Set();

/** Web-host local agent store (personas + managed agents). */
const WEB_CONFIG_DIR =
  process.env.BUZZ_WEB_CONFIG_DIR ||
  path.join(process.env.HOME || "/home/lary", ".config/buzz-web");
const PERSONAS_JSON_PATH =
  process.env.BUZZ_WEB_PERSONAS_FILE ||
  path.join(WEB_CONFIG_DIR, "personas.json");
const MANAGED_AGENTS_JSON_PATH =
  process.env.BUZZ_WEB_MANAGED_AGENTS_FILE ||
  path.join(WEB_CONFIG_DIR, "managed-agents.json");
/** Desktop-parity: Settings → Agents default runtime/provider/model/env. */
const GLOBAL_AGENT_CONFIG_PATH =
  process.env.BUZZ_WEB_GLOBAL_AGENT_CONFIG_FILE ||
  path.join(WEB_CONFIG_DIR, "global-agent-config.json");

const FIZZ_SYSTEM_PROMPT =
  "You are Fizz, an energetic maker who turns ideas into action. Be upbeat, practical, and decisive. Help users plan, create, solve problems, and finish work. Add occasional bee wordplay or 🐝✨—keep it charming, never distracting.";
const HONEY_SYSTEM_PROMPT =
  "You are Honey, a warm and thoughtful communicator. Help users write clearly, organize ideas, brainstorm, summarize, and prepare for conversations. Be kind, creative, and concise. Add occasional bee wordplay or 🍯🐝—keep it sweet, never excessive.";
const BUMBLE_SYSTEM_PROMPT =
  "You are Bumble, a curious and adventurous researcher. Explore questions, compare options, check assumptions, and explain what you find clearly. Be candid when uncertain and favor useful evidence. Add occasional bee wordplay or 🐝🔎—keep it playful, never chaotic.";

const BUILT_IN_PERSONAS = [
  {
    id: "builtin:fizz",
    display_name: "Fizz",
    system_prompt: FIZZ_SYSTEM_PROMPT,
    name_pool: [
      "Nectar",
      "Comet",
      "Bramble",
      "Clover",
      "Pollen",
      "Amber",
      "Daisy",
      "Mason",
      "Thistle",
      "Waxwing",
      "Hive",
      "Meadow",
      "Juniper",
      "Aster",
      "Sage",
      "Willow",
      "Orchard",
      "Buzz",
    ],
    default_active: true,
  },
  {
    id: "builtin:honey",
    display_name: "Honey",
    system_prompt: HONEY_SYSTEM_PROMPT,
    name_pool: ["Honey"],
    default_active: true,
  },
  {
    id: "builtin:bumble",
    display_name: "Bumble",
    system_prompt: BUMBLE_SYSTEM_PROMPT,
    name_pool: ["Bumble"],
    default_active: true,
  },
];

const FALLBACK_MODELS = [
  { id: "grok-4.5", name: "grok-4.5", description: "xAI Grok 4.5" },
  { id: "claude-sonnet-4-6", name: "claude-sonnet-4-6", description: "Anthropic Claude Sonnet 4.6" },
  { id: "gpt-5.5", name: "gpt-5.5", description: "OpenAI GPT-5.5" },
];

// ── crypto / env ────────────────────────────────────────────────────────────

function hexToBytes(hex) {
  const cleaned = hex.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(cleaned)) {
    throw new Error("private key must be 64-char hex");
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Non-secret config: process.env wins; optional agent env file fills gaps
 * (OPENAI_*, model names) so model-restart still works without re-exporting
 * every key into the unit file.
 */
function getEnvConfig() {
  const config = { ...process.env };
  if (fs.existsSync(ENV_PATH)) {
    for (const line of fs.readFileSync(ENV_PATH, "utf8").split("\n")) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const eq = t.indexOf("=");
      if (eq === -1) continue;
      const k = t.slice(0, eq).trim();
      const v = t.slice(eq + 1).trim();
      if (config[k] === undefined || config[k] === "") config[k] = v;
    }
  }
  return config;
}

/**
 * Web human identity store (host-held). Desktop uses the OS keyring; on
 * Fedora web we keep the seckey in this file + buzz-agent env and sign here.
 */
const IDENTITY_JSON_PATH =
  process.env.BUZZ_WEB_IDENTITY_FILE ||
  path.join(
    process.env.HOME || "/home/lary",
    ".config/buzz-web/desktop-identity.json",
  );

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function readIdentityFile() {
  try {
    if (!fs.existsSync(IDENTITY_JSON_PATH)) return null;
    const raw = JSON.parse(fs.readFileSync(IDENTITY_JSON_PATH, "utf8"));
    if (!raw || typeof raw !== "object") return null;
    return raw;
  } catch (err) {
    console.warn("readIdentityFile failed:", err.message);
    return null;
  }
}

function writeIdentityFile(record) {
  const dir = path.dirname(IDENTITY_JSON_PATH);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(IDENTITY_JSON_PATH, JSON.stringify(record, null, 2) + "\n", {
    mode: 0o600,
  });
  try {
    fs.chmodSync(IDENTITY_JSON_PATH, 0o600);
  } catch {
    /* ignore */
  }
}

/** Upsert key=value lines in the agent EnvironmentFile (mode 600). */
function upsertEnvFile(updates) {
  let lines = [];
  if (fs.existsSync(ENV_PATH)) {
    lines = fs.readFileSync(ENV_PATH, "utf8").split("\n");
  }
  const seen = new Set();
  const out = [];
  for (const line of lines) {
    if (!line.trim() || line.trim().startsWith("#") || !line.includes("=")) {
      out.push(line);
      continue;
    }
    const key = line.split("=")[0].trim();
    if (Object.prototype.hasOwnProperty.call(updates, key)) {
      out.push(`${key}=${updates[key]}`);
      seen.add(key);
    } else {
      out.push(line);
    }
  }
  for (const [key, val] of Object.entries(updates)) {
    if (!seen.has(key)) out.push(`${key}=${val}`);
  }
  // Drop trailing empty-only inflation
  while (out.length && out[out.length - 1] === "") out.pop();
  fs.mkdirSync(path.dirname(ENV_PATH), { recursive: true });
  fs.writeFileSync(ENV_PATH, out.join("\n") + "\n", { mode: 0o600 });
  try {
    fs.chmodSync(ENV_PATH, 0o600);
  } catch {
    /* ignore */
  }
  // Keep in-process env in sync so systemd EnvironmentFile is not required
  // until the next restart.
  for (const [key, val] of Object.entries(updates)) {
    process.env[key] = val;
  }
}

/**
 * Install (or replace) the host-held human identity.
 * @param {{ seckeyHex: string, displayName?: string, username?: string, source?: string }} opts
 */
function installHostIdentity(opts) {
  const seckeyHex = opts.seckeyHex.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(seckeyHex)) {
    throw new Error("private key must be 64-char hex");
  }
  const sk = hexToBytes(seckeyHex);
  const pubkey = getPublicKey(sk);
  const displayName = (opts.displayName || "fedora").trim() || "fedora";
  const username = (opts.username || displayName).trim() || "fedora";
  const record = {
    role: "desktop-human",
    created_at: new Date().toISOString(),
    seckey_hex: seckeyHex,
    pubkey,
    display_name: displayName,
    username,
    source: opts.source || "host-ipc",
  };
  writeIdentityFile(record);
  upsertEnvFile({
    BUZZ_WEB_PRIVATE_KEY: seckeyHex,
    BUZZ_WEB_DISPLAY_NAME: displayName,
    BUZZ_WEB_USERNAME: username,
    BUZZ_ACP_AGENT_OWNER: pubkey,
  });
  return record;
}

function generateHostIdentity(displayName = "fedora", username = "fedora") {
  const sk = crypto.randomBytes(32);
  return installHostIdentity({
    seckeyHex: bytesToHex(sk),
    displayName,
    username,
    source: "host-generated",
  });
}

/**
 * Host seckey for NIP-42 / NIP-98 / EVENT signing.
 *
 * Required (in order):
 *   1. desktop-identity.json seckey_hex  — durable host-held web identity
 *   2. process.env.BUZZ_WEB_PRIVATE_KEY  — web session override
 *   3. process.env.BUZZ_PRIVATE_KEY      — same as buzz-acp (systemd EnvironmentFile)
 *   4. process.env.BUZZ_PRIVATE_KEY_FILE — path to a file containing hex key
 */
function loadSecretKeyHex() {
  const fileId = readIdentityFile();
  if (fileId && typeof fileId.seckey_hex === "string" && fileId.seckey_hex.trim()) {
    return fileId.seckey_hex.trim();
  }

  const fromEnv =
    process.env.BUZZ_WEB_PRIVATE_KEY ||
    process.env.BUZZ_PRIVATE_KEY ||
    "";
  if (fromEnv.trim()) return fromEnv.trim();

  const keyFile = process.env.BUZZ_PRIVATE_KEY_FILE;
  if (keyFile) {
    if (!fs.existsSync(keyFile)) {
      throw new Error(`BUZZ_PRIVATE_KEY_FILE not found: ${keyFile}`);
    }
    const hex = fs.readFileSync(keyFile, "utf8").trim();
    if (!hex) throw new Error(`BUZZ_PRIVATE_KEY_FILE empty: ${keyFile}`);
    return hex;
  }

  throw new Error(
    "missing seckey: set BUZZ_PRIVATE_KEY (or BUZZ_WEB_PRIVATE_KEY) in the environment, " +
      "or BUZZ_PRIVATE_KEY_FILE to a hex key path",
  );
}

function loadSecretKeyBytes() {
  return hexToBytes(loadSecretKeyHex());
}

function hostPubkey() {
  return getPublicKey(loadSecretKeyBytes());
}

function getHostIdentity() {
  const env = getEnvConfig();
  const fileId = readIdentityFile();
  return {
    pubkey: hostPubkey(),
    display_name:
      (fileId && fileId.display_name) ||
      process.env.BUZZ_WEB_DISPLAY_NAME ||
      env.BUZZ_WEB_DISPLAY_NAME ||
      "fedora",
    username:
      (fileId && fileId.username) ||
      process.env.BUZZ_WEB_USERNAME ||
      env.BUZZ_WEB_USERNAME ||
      "fedora",
    lost: false,
    locked: false,
    owner_pubkey:
      process.env.BUZZ_ACP_AGENT_OWNER || env.BUZZ_ACP_AGENT_OWNER || null,
  };
}

function getHostNsec() {
  // Single-tenant host IPC behind chat.f.mtt.cool — needed for BackupStep.
  return nip19.nsecEncode(loadSecretKeyBytes());
}

function importHostIdentityFromNsec(nsecRaw) {
  const trimmed = String(nsecRaw || "").trim();
  if (!trimmed) throw new Error("nsec required");
  let decoded;
  try {
    decoded = nip19.decode(trimmed);
  } catch (err) {
    throw new Error("invalid nsec: " + (err.message || err));
  }
  if (decoded.type !== "nsec") {
    throw new Error("expected nsec1…, got " + decoded.type);
  }
  const skBytes = decoded.data; // Uint8Array
  const seckeyHex = bytesToHex(skBytes);
  const fileId = readIdentityFile();
  return installHostIdentity({
    seckeyHex,
    displayName:
      (fileId && fileId.display_name) ||
      process.env.BUZZ_WEB_DISPLAY_NAME ||
      "fedora",
    username:
      (fileId && fileId.username) ||
      process.env.BUZZ_WEB_USERNAME ||
      "fedora",
    source: "imported-nsec",
  });
}

// ── NIP-98 + relay HTTP ─────────────────────────────────────────────────────

function buildNip98Auth(method, url, bodyBuf, seckeyBytes = null) {
  const sk = seckeyBytes || loadSecretKeyBytes();
  const payload = crypto.createHash("sha256").update(bodyBuf).digest("hex");
  const event = finalizeEvent(
    {
      kind: 27235,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["u", url],
        ["method", method],
        ["payload", payload],
        ["nonce", crypto.randomUUID()],
      ],
      content: "",
    },
    sk,
  );
  return "Nostr " + Buffer.from(JSON.stringify(event)).toString("base64");
}

async function queryRelay(filters) {
  const url = `${RELAY_HTTP}/query`;
  const bodyBuf = Buffer.from(JSON.stringify(filters));
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: buildNip98Auth("POST", url, bodyBuf),
    },
    body: bodyBuf,
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`relay /query ${res.status}: ${text.slice(0, 200)}`);
  }
  const data = JSON.parse(text);
  if (!Array.isArray(data)) throw new Error("relay /query: expected event array");
  return data;
}

/**
 * Submit a signed event. When `authSeckeyBytes` is set, NIP-98 AUTH uses that
 * key (required for agent kind:0 — event.pubkey must match AUTH pubkey).
 */
async function submitEvent(event, authSeckeyBytes = null) {
  const url = `${RELAY_HTTP}/events`;
  const bodyBuf = Buffer.from(JSON.stringify(event));
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: buildNip98Auth("POST", url, bodyBuf, authSeckeyBytes),
    },
    body: bodyBuf,
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`relay /events ${res.status}: ${text.slice(0, 300)}`);
  }
  try {
    return text ? JSON.parse(text) : { ok: true };
  } catch {
    return { ok: true, raw: text };
  }
}

function tagValue(ev, name) {
  for (const t of ev.tags || []) {
    if (t[0] === name && t[1] != null) return t[1];
  }
  return null;
}

function hasTag(ev, name) {
  return (ev.tags || []).some((t) => t[0] === name);
}

function tagValues(ev, name) {
  const out = [];
  for (const t of ev.tags || []) {
    if (t[0] === name && t[1]) out.push(t[1]);
  }
  return out;
}

// ── Channel helpers (mirror desktop nostr_convert + get_channels) ───────────

function channelInfoFromEvent(ev, isMember) {
  const id = tagValue(ev, "d");
  if (!id) return null;
  const name = tagValue(ev, "name") || "";
  const description = tagValue(ev, "about") || "";
  const topic = tagValue(ev, "topic");
  const purpose = tagValue(ev, "purpose");
  let channel_type = tagValue(ev, "t");
  if (!channel_type) channel_type = hasTag(ev, "hidden") ? "dm" : "stream";
  const visibilityTag = tagValue(ev, "visibility");
  let visibility = "open";
  if (hasTag(ev, "public") || visibilityTag === "open") visibility = "open";
  else if (hasTag(ev, "private") || visibilityTag === "private") visibility = "private";
  const participant_pubkeys = tagValues(ev, "p");
  const archived_at =
    tagValue(ev, "archived") === "true"
      ? new Date((ev.created_at || 0) * 1000).toISOString()
      : null;
  const ttl_seconds = tagValue(ev, "ttl") ? parseInt(tagValue(ev, "ttl"), 10) : null;
  const ttl_deadline = tagValue(ev, "ttl_deadline");

  return {
    id,
    name,
    channel_type,
    visibility,
    description,
    topic,
    purpose,
    member_count: 0,
    member_pubkeys: [],
    last_message_at: null,
    archived_at,
    participants: participant_pubkeys,
    participant_pubkeys,
    is_member: isMember !== false,
    ttl_seconds: Number.isFinite(ttl_seconds) ? ttl_seconds : null,
    ttl_deadline,
  };
}

async function ipcGetChannels() {
  const pk = hostPubkey();
  const memberEvents = await queryRelay([
    { kinds: [39002], "#p": [pk], limit: 200 },
  ]);
  const memberIds = new Set();
  for (const ev of memberEvents) {
    const d = tagValue(ev, "d");
    if (d) memberIds.add(d);
  }
  const memberIdList = [...memberIds];

  let memberMeta = [];
  if (memberIdList.length > 0) {
    memberMeta = await queryRelay([
      { kinds: [39000], "#d": memberIdList, limit: memberIdList.length },
    ]);
  }

  // Open/discoverable channels (may include ones we haven't joined)
  const openMeta = await queryRelay([{ kinds: [39000], limit: 200 }]);

  const byId = new Map();
  for (const ev of memberMeta) {
    const info = channelInfoFromEvent(ev, true);
    if (info) byId.set(info.id, info);
  }
  for (const ev of openMeta) {
    const info = channelInfoFromEvent(ev, memberIds.has(tagValue(ev, "d")));
    if (!info) continue;
    if (!byId.has(info.id)) byId.set(info.id, info);
  }

  // Prefer membership list; if empty, still return open channels marked not member
  const list = [...byId.values()];
  for (const ch of list) {
    if (pendingOwnedChannelIds.has(ch.id)) ch.is_member = true;
  }
  return list.sort((a, b) => (a.name || "").localeCompare(b.name || ""));
}

async function ipcGetChannelDetails(channelId) {
  const events = await queryRelay([
    { kinds: [39000], "#d": [channelId], limit: 1 },
  ]);
  const ev = events[0];
  if (!ev) throw new Error(`channel not found: ${channelId}`);
  const base = channelInfoFromEvent(ev, true);
  return {
    ...base,
    created_by: ev.pubkey,
    created_at: new Date((ev.created_at || 0) * 1000).toISOString(),
    updated_at: new Date((ev.created_at || 0) * 1000).toISOString(),
    topic_set_by: null,
    topic_set_at: null,
    purpose_set_by: null,
    purpose_set_at: null,
    topic_required: false,
    max_members: null,
    nip29_group_id: null,
  };
}

async function ipcGetChannelMembers(channelId) {
  const events = await queryRelay([
    { kinds: [39002], "#d": [channelId], limit: 5 },
  ]);
  const ev = events[0];
  const members = [];
  if (ev) {
    for (const t of ev.tags || []) {
      if (t[0] !== "p" || !t[1]) continue;
      members.push({
        pubkey: t[1],
        role: t[3] || "member",
        is_agent: (t[3] || "") === "bot" || (t[3] || "") === "agent",
        joined_at: new Date((ev.created_at || 0) * 1000).toISOString(),
        display_name: null,
      });
    }
  }
  return { members, next_cursor: null };
}

async function ipcGetChannelMessagesBefore(args) {
  const channelId = args.channelId || args.channel_id;
  const before = args.before ?? Math.floor(Date.now() / 1000) + 60;
  const beforeId = args.beforeId ?? args.before_id ?? null;
  const cap = Math.min(args.limit ?? 200, 500);
  const filter = {
    "#h": [channelId],
    kinds: TIMELINE_KINDS,
    until: before,
    limit: cap,
  };
  if (beforeId) filter.before_id = beforeId;
  const events = await queryRelay([filter]);
  let next_cursor = null;
  if (events.length >= cap && events.length > 0) {
    const last = events[events.length - 1];
    next_cursor = { created_at: last.created_at, event_id: last.id };
  }
  return { events, next_cursor };
}

/**
 * Primary timeline load used by the desktop UI (`getChannelWindowEvents`).
 * Returns a flat RelayEvent[] (not {events, next_cursor}).
 */
async function ipcGetChannelWindow(args) {
  const channelId = args.channelId || args.channel_id;
  if (!channelId) throw new Error("channelId required");
  const cap = Math.min(args.limitRows ?? args.limit_rows ?? 50, 200);
  const cursor = args.cursor || null;
  const filter = {
    "#h": [channelId],
    kinds: TIMELINE_KINDS,
    limit: cap,
    top_level: true,
    include_summaries: true,
    include_aux: true,
  };
  if (cursor && (cursor.created_at != null || cursor.createdAt != null)) {
    filter.until = cursor.created_at ?? cursor.createdAt;
    const eid = cursor.event_id ?? cursor.eventId;
    if (eid) filter.before_id = eid;
  }
  return await queryRelay([filter]);
}

async function ipcSendChannelMessage(args) {
  const channelId = args.channelId || args.channel_id;
  const content = (args.content || "").trim();
  if (!channelId) throw new Error("channelId required");
  if (!content) throw new Error("content required");

  const kind = args.kind ?? 9;
  const mentions = args.mentionPubkeys || args.mention_pubkeys || [];
  const parentEventId = args.parentEventId || args.parent_event_id || null;

  const tags = [["h", channelId]];
  if (parentEventId) {
    // NIP-10 style reply; root=parent when no full resolve
    tags.push(["e", parentEventId, "", "reply"]);
    tags.push(["e", parentEventId, "", "root"]);
  }
  for (const p of mentions) {
    if (p) tags.push(["p", p]);
  }

  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind,
      created_at: Math.floor(Date.now() / 1000),
      tags,
      content,
    },
    sk,
  );
  await submitEvent(event);
  return {
    event_id: event.id,
    root_event_id: parentEventId,
    parent_event_id: parentEventId,
    depth: parentEventId ? 1 : 0,
    created_at: event.created_at,
  };
}

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Kind 9007 — create channel (mirrors desktop events::build_create_channel).
 * Frontend args: { name, channelType, visibility, description?, ttlSeconds? }
 */
async function ipcCreateChannel(args) {
  const name = String(args.name || "").trim();
  if (!name) throw new Error("channel name is required");
  const visibility = String(args.visibility || "open");
  if (visibility !== "open" && visibility !== "private") {
    throw new Error(`invalid visibility: ${visibility}`);
  }
  const channelType = String(
    args.channelType || args.channel_type || "stream",
  );
  if (channelType !== "stream" && channelType !== "forum") {
    throw new Error(`invalid channel_type: ${channelType}`);
  }
  const description =
    args.description != null && args.description !== ""
      ? String(args.description)
      : null;
  const ttlRaw = args.ttlSeconds ?? args.ttl_seconds;
  const ttlSeconds =
    ttlRaw === null || ttlRaw === undefined || ttlRaw === ""
      ? null
      : Number(ttlRaw);

  const channelId = crypto.randomUUID();
  const tags = [
    ["h", channelId],
    ["name", name],
    ["visibility", visibility],
    ["channel_type", channelType],
  ];
  if (description) tags.push(["about", description]);
  if (ttlSeconds != null && Number.isFinite(ttlSeconds)) {
    tags.push(["ttl", String(Math.trunc(ttlSeconds))]);
  }

  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 9007,
      created_at: Math.floor(Date.now() / 1000),
      tags,
      content: "",
    },
    sk,
  );
  await submitEvent(event);
  pendingOwnedChannelIds.add(channelId);

  // Relay materializes kind:39000 asynchronously — poll briefly.
  let meta = null;
  for (let i = 0; i < 12; i++) {
    const events = await queryRelay([
      { kinds: [39000], "#d": [channelId], limit: 1 },
    ]);
    if (events[0]) {
      meta = events[0];
      break;
    }
    await sleep(250 + i * 100);
  }

  if (meta) {
    const info = channelInfoFromEvent(meta, true);
    if (info) {
      info.is_member = true;
      return info;
    }
  }

  // Fallback shape so Welcome onboarding can proceed even if metadata lags.
  return {
    id: channelId,
    name,
    channel_type: channelType,
    visibility,
    description: description || "",
    topic: null,
    purpose: null,
    member_count: 1,
    member_pubkeys: [hostPubkey()],
    last_message_at: null,
    archived_at: null,
    participants: [hostPubkey()],
    participant_pubkeys: [hostPubkey()],
    is_member: true,
    ttl_seconds:
      ttlSeconds != null && Number.isFinite(ttlSeconds)
        ? Math.trunc(ttlSeconds)
        : null,
    ttl_deadline: null,
  };
}

/** Kind 9021 — join channel. */
async function ipcJoinChannel(args) {
  const channelId = args.channelId || args.channel_id;
  if (!channelId) throw new Error("channelId required");
  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 9021,
      created_at: Math.floor(Date.now() / 1000),
      tags: [["h", channelId]],
      content: "",
    },
    sk,
  );
  await submitEvent(event);
  pendingOwnedChannelIds.add(channelId);
  return true;
}

// ── Starter channels (mirror desktop ensure_starter_channels) ───────────────
// Frontend findStarterChannels requires open stream members named "general"
// and "welcome-everyone". Host previously only listed channels → is_member
// false → "Starter channels were not available after setup".

const STARTER_CHANNEL_NAMESPACE = "3ce33bea-8f09-5f1b-9c85-8a7d2659e6b0";
const STARTER_CHANNELS = [
  {
    slug: "general",
    name: "general",
    description: "General conversation and community updates.",
  },
  {
    slug: "welcome-everyone",
    name: "welcome-everyone",
    description: "Say hi, ask a question, or share what brought you here.",
  },
];

/** UUID v5 (SHA-1), matches Rust uuid::Uuid::new_v5. */
function uuidV5(name, namespaceUuid) {
  const nsHex = String(namespaceUuid).replace(/-/g, "");
  const ns = Buffer.from(nsHex, "hex");
  if (ns.length !== 16) throw new Error("invalid UUID namespace");
  const hash = crypto.createHash("sha1").update(ns).update(name, "utf8").digest();
  hash[6] = (hash[6] & 0x0f) | 0x50;
  hash[8] = (hash[8] & 0x3f) | 0x80;
  const h = hash.toString("hex");
  return [
    h.slice(0, 8),
    h.slice(8, 12),
    h.slice(12, 16),
    h.slice(16, 20),
    h.slice(20, 32),
  ].join("-");
}

function relayHttpScope() {
  return String(RELAY_HTTP || "")
    .trim()
    .replace(/\/+$/, "");
}

function starterChannelUuid(slug) {
  const name = `starter-channel:v1:${relayHttpScope()}:${slug}`;
  return uuidV5(name, STARTER_CHANNEL_NAMESPACE);
}

function normalizeChannelName(name) {
  return String(name || "")
    .trim()
    .toLowerCase();
}

function isMatchingStarterChannel(channel, spec) {
  return (
    normalizeChannelName(channel.name) === normalizeChannelName(spec.name) &&
    channel.channel_type === "stream" &&
    channel.visibility === "open" &&
    !channel.archived_at
  );
}

function hasAllStarterChannels(channels) {
  return STARTER_CHANNELS.every((spec) =>
    channels.some((channel) => isMatchingStarterChannel(channel, spec)),
  );
}

function isDuplicateChannelRejection(error) {
  const msg = String(error || "");
  return (
    msg.includes("duplicate") ||
    msg.includes("already exists") ||
    msg.includes("channel already exists")
  );
}

/**
 * Create a channel with a fixed UUID (starter channels use deterministic ids).
 * Mirrors desktop create with starter_channel_uuid.
 */
async function createChannelWithId(channelId, name, visibility, channelType, description) {
  const tags = [
    ["h", channelId],
    ["name", name],
    ["visibility", visibility],
    ["channel_type", channelType],
  ];
  if (description) tags.push(["about", description]);

  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 9007,
      created_at: Math.floor(Date.now() / 1000),
      tags,
      content: "",
    },
    sk,
  );
  await submitEvent(event);
  pendingOwnedChannelIds.add(channelId);
}

async function fetchStarterChannelMetadata(channelIds) {
  if (!channelIds.length) return [];
  const events = await queryRelay([
    { kinds: [39000], "#d": channelIds, limit: channelIds.length },
  ]);
  const out = [];
  for (const ev of events) {
    const info = channelInfoFromEvent(ev, false);
    if (info) out.push(info);
  }
  return out;
}

/**
 * Ensure open starter channels exist and host is a member (kind 9021 join).
 * Returns the full channel list with is_member true on starters.
 */
async function ipcEnsureStarterChannels() {
  let existing = await ipcGetChannels();
  const starterIds = [];
  const createdIds = new Set();

  for (const spec of STARTER_CHANNELS) {
    if (existing.some((ch) => isMatchingStarterChannel(ch, spec))) {
      continue;
    }
    const channelId = starterChannelUuid(spec.slug);
    starterIds.push(channelId);
    try {
      await createChannelWithId(
        channelId,
        spec.name,
        "open",
        "stream",
        spec.description,
      );
      createdIds.add(channelId);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (isDuplicateChannelRejection(msg)) {
        pendingOwnedChannelIds.add(channelId);
      } else {
        throw err;
      }
    }
  }

  for (let attempt = 0; attempt < 3; attempt++) {
    const metadata = await fetchStarterChannelMetadata(starterIds);
    for (const channel of metadata) {
      if (createdIds.has(channel.id)) channel.is_member = true;
      if (!existing.some((e) => e.id === channel.id)) {
        existing.push(channel);
      }
    }
    if (hasAllStarterChannels(existing)) break;
    await sleep(150);
  }

  if (!hasAllStarterChannels(existing)) {
    existing = await ipcGetChannels();
  }

  if (!hasAllStarterChannels(existing)) {
    // Last resort: open-directory scan may have missed membership-only lag;
    // fetch by deterministic UUID even if name match failed.
    const ids = STARTER_CHANNELS.map((s) => starterChannelUuid(s.slug));
    const metadata = await fetchStarterChannelMetadata(ids);
    for (const channel of metadata) {
      if (!existing.some((e) => e.id === channel.id)) {
        existing.push(channel);
      }
    }
  }

  if (!hasAllStarterChannels(existing)) {
    throw new Error("starter channels created but metadata not yet available");
  }

  // Join any open starter we are not yet a member of (kind 9021).
  for (const spec of STARTER_CHANNELS) {
    const channel = existing.find((ch) => isMatchingStarterChannel(ch, spec));
    if (!channel) continue;
    if (channel.is_member) continue;
    try {
      await ipcJoinChannel({ channelId: channel.id });
      channel.is_member = true;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // Already a member / race is fine; still mark pending so list is usable.
      if (
        msg.toLowerCase().includes("already") ||
        msg.toLowerCase().includes("member")
      ) {
        pendingOwnedChannelIds.add(channel.id);
        channel.is_member = true;
      } else {
        // Join failed but channel exists — still mark pending so onboard can proceed;
        // membership event may catch up via kind:39002 later.
        console.warn(
          "[ensure_starter_channels] join failed for",
          channel.id,
          msg,
        );
        pendingOwnedChannelIds.add(channel.id);
        channel.is_member = true;
      }
    }
  }

  // Refresh so membership overlays and open list stay consistent.
  const refreshed = await ipcGetChannels();
  for (const spec of STARTER_CHANNELS) {
    const ch = refreshed.find((c) => isMatchingStarterChannel(c, spec));
    if (ch && !ch.is_member) {
      pendingOwnedChannelIds.add(ch.id);
      ch.is_member = true;
    }
  }
  // Also force is_member on starters in the in-memory list if refresh missed them.
  for (const ch of refreshed) {
    for (const spec of STARTER_CHANNELS) {
      if (isMatchingStarterChannel(ch, spec)) {
        ch.is_member = true;
        pendingOwnedChannelIds.add(ch.id);
      }
    }
  }

  if (!hasAllStarterChannels(refreshed)) {
    // Merge starters from existing into refreshed if still missing from list.
    for (const ch of existing) {
      if (
        STARTER_CHANNELS.some((s) => isMatchingStarterChannel(ch, s)) &&
        !refreshed.some((r) => r.id === ch.id)
      ) {
        ch.is_member = true;
        refreshed.push(ch);
      }
    }
  }

  // Final check: both starters must be open stream members for the UI.
  for (const spec of STARTER_CHANNELS) {
    const ch = refreshed.find((c) => isMatchingStarterChannel(c, spec));
    if (!ch || !ch.is_member) {
      throw new Error(
        `starter channel "${spec.name}" not available as open member after setup`,
      );
    }
  }

  return refreshed;
}

/** Kind 9000 — add members (bot/member). */
async function ipcAddChannelMembers(args) {
  const channelId = args.channelId || args.channel_id;
  const pubkeys = args.pubkeys || args.pubKeys || [];
  const role = args.role || "member";
  if (!channelId) throw new Error("channelId required");
  if (!Array.isArray(pubkeys) || pubkeys.length === 0) {
    return { added: [], errors: [] };
  }
  const added = [];
  const errors = [];
  const sk = loadSecretKeyBytes();
  for (const pk of pubkeys) {
    if (!pk || !/^[0-9a-f]{64}$/i.test(String(pk))) {
      errors.push({ pubkey: String(pk || ""), error: "invalid pubkey" });
      continue;
    }
    try {
      const event = finalizeEvent(
        {
          kind: 9000,
          created_at: Math.floor(Date.now() / 1000),
          tags: [
            ["h", channelId],
            ["p", String(pk).toLowerCase()],
            ["role", role],
          ],
          content: "",
        },
        sk,
      );
      await submitEvent(event);
      added.push(String(pk).toLowerCase());
    } catch (err) {
      errors.push({
        pubkey: String(pk),
        error: err && err.message ? err.message : String(err),
      });
    }
  }
  return { added, errors };
}

/** Kind 9002 — update channel name/about/visibility/ttl. */
async function ipcUpdateChannel(args) {
  const channelId = args.channelId || args.channel_id;
  if (!channelId) throw new Error("channelId required");
  const tags = [["h", channelId]];
  if (args.name != null) tags.push(["name", String(args.name)]);
  if (args.description != null) tags.push(["about", String(args.description)]);
  if (args.visibility != null) tags.push(["visibility", String(args.visibility)]);
  if (Object.prototype.hasOwnProperty.call(args, "ttlSeconds") ||
      Object.prototype.hasOwnProperty.call(args, "ttl_seconds")) {
    const ttl = args.ttlSeconds !== undefined ? args.ttlSeconds : args.ttl_seconds;
    if (ttl === null || ttl === "") tags.push(["ttl", ""]);
    else if (ttl != null) tags.push(["ttl", String(ttl)]);
  }
  if (tags.length === 1) throw new Error("nothing to update");
  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 9002,
      created_at: Math.floor(Date.now() / 1000),
      tags,
      content: "",
    },
    sk,
  );
  await submitEvent(event);
  return await ipcGetChannelDetails(channelId);
}

// ── Profiles / agents ───────────────────────────────────────────────────────

function profileFromKind0(ev) {
  let content = {};
  try {
    content = JSON.parse(ev.content || "{}");
  } catch {
    content = {};
  }
  // Kind-0 often embeds huge data: URLs for avatars — drop them over IPC to
  // keep the web client usable (desktop proxies media separately).
  let avatar = content.picture || content.avatar_url || null;
  if (typeof avatar === "string" && avatar.startsWith("data:")) {
    avatar = null;
  }
  const owner =
    content.owner_pubkey || content.ownerPubkey || content.owner || null;
  return {
    pubkey: ev.pubkey,
    display_name: content.display_name || content.name || null,
    avatar_url: typeof avatar === "string" ? avatar : null,
    about: typeof content.about === "string" ? content.about : null,
    nip05_handle: content.nip05 || null,
    owner_pubkey: typeof owner === "string" ? owner : null,
    has_profile_event: true,
  };
}

async function ipcGetProfile(pubkey) {
  const pk = pubkey || hostPubkey();
  const events = await queryRelay([
    { kinds: [0], authors: [pk], limit: 1 },
  ]);
  if (events[0]) {
    const p = profileFromKind0(events[0]);
    return {
      pubkey: p.pubkey,
      display_name: p.display_name,
      avatar_url: p.avatar_url,
      about: p.about,
      nip05_handle: p.nip05_handle,
      owner_pubkey: p.owner_pubkey,
      has_profile_event: true,
    };
  }
  // Fallback: session self
  const id = getHostIdentity();
  return {
    pubkey: pk,
    display_name: pk === id.pubkey ? id.display_name : null,
    avatar_url: null,
    about: pk === id.pubkey ? "Pi Coding Agent on Fedora Host" : null,
    nip05_handle: null,
    owner_pubkey: pk === id.pubkey ? id.owner_pubkey : null,
    has_profile_event: false,
  };
}

async function ipcGetUsersBatch(args) {
  const pubkeys = args.pubkeys || args.pubKeys || [];
  const list = Array.isArray(pubkeys) ? pubkeys.filter(Boolean) : [];
  const profiles = {};
  const missing = [];
  if (list.length === 0) return { profiles, missing };

  const events = await queryRelay([
    { kinds: [0], authors: list, limit: list.length },
  ]);
  const found = new Set();
  for (const ev of events) {
    const p = profileFromKind0(ev);
    profiles[ev.pubkey.toLowerCase()] = {
      display_name: p.display_name,
      avatar_url: p.avatar_url,
      nip05_handle: p.nip05_handle,
      owner_pubkey: p.owner_pubkey,
      is_agent: false,
    };
    found.add(ev.pubkey.toLowerCase());
  }
  for (const pk of list) {
    if (!found.has(pk.toLowerCase())) missing.push(pk);
  }
  return { profiles, missing };
}

async function ipcListRelayAgents() {
  const events = await queryRelay([{ kinds: [10100], limit: 100 }]);
  const agents = events.map((ev) => {
    let content = {};
    try {
      content = JSON.parse(ev.content || "{}");
    } catch {
      content = {};
    }
    return {
      pubkey: ev.pubkey,
      name: content.name || content.display_name || ev.pubkey.slice(0, 12),
      agent_type: content.agent_type || "agent",
      channels: Array.isArray(content.channels) ? content.channels : [],
      channel_ids: Array.isArray(content.channel_ids) ? content.channel_ids : [],
      capabilities: Array.isArray(content.capabilities) ? content.capabilities : [],
      status: content.status || "online",
      respond_to: content.respond_to ?? null,
      respond_to_allowlist: Array.isArray(content.respond_to_allowlist)
        ? content.respond_to_allowlist
        : [],
    };
  });
  // Always include host buzz-acp agent if missing from directory events.
  try {
    const agentPk = getAgentPubkey();
    if (!agents.some((a) => a.pubkey === agentPk)) {
      agents.unshift({
        pubkey: agentPk,
        name: "Fedora-Agent",
        agent_type: "pi-coding-agent",
        channels: [],
        channel_ids: [],
        capabilities: ["messages", "channels"],
        status: getServiceStatus() === "running" ? "online" : "offline",
        respond_to: process.env.BUZZ_ACP_RESPOND_TO || "owner-only",
        respond_to_allowlist: [],
      });
    }
  } catch {
    /* ignore */
  }
  return agents;
}

/** Agent process key (BUZZ_PRIVATE_KEY), separate from web desktop identity. */
function getAgentPubkey() {
  const env = getEnvConfig();
  const skHex = env.BUZZ_PRIVATE_KEY;
  if (!skHex) throw new Error("BUZZ_PRIVATE_KEY missing for agent");
  return getPublicKey(hexToBytes(skHex.trim()));
}

// ── Personas + managed agents (file-backed web host) ────────────────────────

function isoNow() {
  return new Date().toISOString();
}

function readJsonFile(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const raw = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return raw ?? fallback;
  } catch (err) {
    console.warn("readJsonFile failed:", filePath, err.message);
    return fallback;
  }
}

function writeJsonFile(filePath, value) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2) + "\n", {
    mode: 0o600,
  });
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {
    /* ignore */
  }
}

function builtInPersonaRecord(def, now) {
  return {
    id: def.id,
    display_name: def.display_name,
    avatar_url: null,
    system_prompt: def.system_prompt,
    runtime: "pi-coding-agent",
    model: null,
    provider: null,
    name_pool: def.name_pool.slice(),
    is_builtin: true,
    is_active: def.default_active !== false,
    shared: false,
    source_team: null,
    catalog_source: null,
    env_vars: {},
    respond_to: null,
    respond_to_allowlist: [],
    parallelism: null,
    created_at: now,
    updated_at: now,
  };
}

function loadPersonas() {
  const now = isoNow();
  const stored = readJsonFile(PERSONAS_JSON_PATH, []);
  const list = Array.isArray(stored) ? stored.slice() : [];
  let changed = false;
  for (const def of BUILT_IN_PERSONAS) {
    const existing = list.find((p) => p && p.id === def.id);
    if (!existing) {
      list.push(builtInPersonaRecord(def, now));
      changed = true;
    } else if (!existing.is_builtin) {
      existing.is_builtin = true;
      changed = true;
    }
  }
  if (changed) writeJsonFile(PERSONAS_JSON_PATH, list);
  return list;
}

function savePersonas(list) {
  writeJsonFile(PERSONAS_JSON_PATH, list);
}

function ipcListPersonas() {
  return loadPersonas();
}

function ipcCreatePersona(args) {
  const input = args.input || args;
  const displayName = String(input.displayName || input.display_name || "").trim();
  if (!displayName) throw new Error("displayName is required");
  const now = isoNow();
  const id =
    String(input.id || "").trim() ||
    `persona:${crypto.randomUUID()}`;
  const personas = loadPersonas();
  if (personas.some((p) => p.id === id)) {
    throw new Error(`persona already exists: ${id}`);
  }
  const record = {
    id,
    display_name: displayName,
    avatar_url: input.avatarUrl ?? input.avatar_url ?? null,
    system_prompt: String(input.systemPrompt ?? input.system_prompt ?? ""),
    runtime: input.runtime ?? "pi-coding-agent",
    model: input.model ?? null,
    provider: input.provider ?? null,
    name_pool: Array.isArray(input.namePool || input.name_pool)
      ? input.namePool || input.name_pool
      : [],
    is_builtin: false,
    is_active: true,
    shared: false,
    source_team: null,
    catalog_source: input.catalogSource || input.catalog_source || null,
    env_vars: input.envVars || input.env_vars || {},
    respond_to:
      (input.behavior && input.behavior.respondTo) ||
      input.respond_to ||
      null,
    respond_to_allowlist:
      (input.behavior && input.behavior.respondToAllowlist) ||
      input.respond_to_allowlist ||
      [],
    parallelism:
      (input.behavior && input.behavior.parallelism) ??
      input.parallelism ??
      null,
    created_at: now,
    updated_at: now,
  };
  personas.push(record);
  savePersonas(personas);
  return record;
}

function ipcUpdatePersona(args) {
  const input = args.input || args;
  const id = String(input.id || "").trim();
  if (!id) throw new Error("id required");
  const personas = loadPersonas();
  const idx = personas.findIndex((p) => p.id === id);
  if (idx < 0) throw new Error(`persona not found: ${id}`);
  const existing = personas[idx];
  const next = { ...existing, updated_at: isoNow() };
  if (input.displayName != null || input.display_name != null) {
    next.display_name = String(input.displayName ?? input.display_name).trim();
  }
  if (input.avatarUrl !== undefined || input.avatar_url !== undefined) {
    next.avatar_url = input.avatarUrl ?? input.avatar_url ?? null;
  }
  if (input.systemPrompt != null || input.system_prompt != null) {
    next.system_prompt = String(input.systemPrompt ?? input.system_prompt ?? "");
  }
  if (input.runtime !== undefined) next.runtime = input.runtime;
  if (input.model !== undefined) next.model = input.model;
  if (input.provider !== undefined) next.provider = input.provider;
  if (input.namePool !== undefined || input.name_pool !== undefined) {
    next.name_pool = input.namePool ?? input.name_pool ?? [];
  }
  if (input.envVars !== undefined || input.env_vars !== undefined) {
    next.env_vars = input.envVars ?? input.env_vars ?? {};
  }
  if (input.behavior) {
    if (input.behavior.respondTo !== undefined) {
      next.respond_to = input.behavior.respondTo;
    }
    if (input.behavior.respondToAllowlist !== undefined) {
      next.respond_to_allowlist = input.behavior.respondToAllowlist;
    }
    if (input.behavior.parallelism !== undefined) {
      next.parallelism = input.behavior.parallelism;
    }
  }
  personas[idx] = next;
  savePersonas(personas);
  return next;
}

function ipcSetPersonaActive(args) {
  const id = String(args.personaId || args.persona_id || args.id || "").trim();
  const active = args.active ?? args.is_active ?? true;
  if (!id) throw new Error("personaId required");
  const personas = loadPersonas();
  const idx = personas.findIndex((p) => p.id === id);
  if (idx < 0) throw new Error(`persona not found: ${id}`);
  personas[idx] = {
    ...personas[idx],
    is_active: Boolean(active),
    updated_at: isoNow(),
  };
  savePersonas(personas);
  return personas[idx];
}

function loadManagedAgentsStore() {
  const stored = readJsonFile(MANAGED_AGENTS_JSON_PATH, { agents: [] });
  if (Array.isArray(stored)) return { agents: stored };
  if (stored && Array.isArray(stored.agents)) return stored;
  return { agents: [] };
}

function saveManagedAgentsStore(store) {
  writeJsonFile(MANAGED_AGENTS_JSON_PATH, store);
}

function managedAgentSummary(record) {
  const env = getEnvConfig();
  return {
    pubkey: record.pubkey,
    name: record.name,
    persona_id: record.persona_id ?? null,
    runtime: record.runtime ?? null,
    team_id: record.team_id ?? null,
    relay_url: record.relay_url || RELAY_WS,
    acp_command: record.acp_command || "buzz-acp",
    agent_command: record.agent_command || env.BUZZ_ACP_AGENT_COMMAND || "pi-coding-agent",
    agent_command_override: record.agent_command_override ?? null,
    agent_args: Array.isArray(record.agent_args) ? record.agent_args : ["acp"],
    mcp_command: record.mcp_command || "",
    turn_timeout_seconds: record.turn_timeout_seconds ?? 320,
    idle_timeout_seconds: record.idle_timeout_seconds ?? null,
    max_turn_duration_seconds: record.max_turn_duration_seconds ?? null,
    parallelism: record.parallelism ?? 1,
    system_prompt: record.system_prompt ?? null,
    avatar_url: record.avatar_url ?? null,
    model:
      record.model ?? env.BUZZ_ACP_MODEL ?? env.GOOSE_MODEL ?? "grok-4.5",
    model_source: record.model_source ?? null,
    provider: record.provider ?? env.GOOSE_PROVIDER ?? "openai",
    persona_out_of_date: false,
    persona_orphaned: false,
    needs_restart: false,
    env_vars: record.env_vars || {},
    status: record.status || "stopped",
    pid: record.pid ?? null,
    created_at: record.created_at,
    updated_at: record.updated_at,
    last_started_at: record.last_started_at ?? null,
    last_stopped_at: record.last_stopped_at ?? null,
    last_exit_code: record.last_exit_code ?? null,
    last_error: record.last_error ?? null,
    last_error_code: record.last_error_code ?? null,
    log_path: record.log_path || `/tmp/buzz-acp-${record.pubkey.slice(0, 12)}.log`,
    start_on_app_launch: record.start_on_app_launch !== false,
    auto_restart_on_config_change: record.auto_restart_on_config_change !== false,
    backend: record.backend || { type: "local" },
    backend_agent_id: record.backend_agent_id ?? null,
    respond_to: record.respond_to || "owner-only",
    respond_to_allowlist: Array.isArray(record.respond_to_allowlist)
      ? record.respond_to_allowlist
      : [],
  };
}

/**
 * Desktop-style managed agent list for path-3 web.
 * File-backed records + optional legacy host buzz-agent unit.
 */
function ipcListManagedAgents() {
  const store = loadManagedAgentsStore();
  const list = store.agents.map(managedAgentSummary);

  // Optional: surface the host systemd buzz-agent unit when running.
  const status = getServiceStatus();
  if (status === "running" || process.env.BUZZ_WEB_SHOW_STOPPED_AGENT === "1") {
    try {
      const agentPk = getAgentPubkey();
      if (!list.some((a) => a.pubkey === agentPk)) {
        const env = getEnvConfig();
        const ownerPk =
          process.env.BUZZ_ACP_AGENT_OWNER ||
          env.BUZZ_ACP_AGENT_OWNER ||
          hostPubkey();
        const now = isoNow();
        const running = status === "running";
        list.push(
          managedAgentSummary({
            pubkey: agentPk,
            name: "Fedora-Agent",
            persona_id: null,
            team_id: null,
            relay_url: RELAY_WS,
            acp_command: "buzz-acp",
            agent_command: env.BUZZ_ACP_AGENT_COMMAND || "pi-coding-agent",
            agent_args: ["acp"],
            model: env.BUZZ_ACP_MODEL || env.GOOSE_MODEL || "grok-4.5",
            provider: env.GOOSE_PROVIDER || "openai",
            status: running ? "running" : "stopped",
            pid: running ? 1 : null,
            created_at: now,
            updated_at: now,
            last_started_at: running ? now : null,
            last_stopped_at: running ? null : now,
            start_on_app_launch: true,
            respond_to: env.BUZZ_ACP_RESPOND_TO || "owner-only",
            respond_to_allowlist: ownerPk ? [ownerPk] : [],
            seckey_hex: null,
          }),
        );
      }
    } catch {
      /* agent key missing */
    }
  }
  return list;
}

function ipcCreateManagedAgent(args) {
  const input = args.input || args;
  const name = String(input.name || "").trim();
  if (!name) throw new Error("agent name is required");

  const skBytes = generateSecretKey();
  const seckeyHex = bytesToHex(skBytes);
  const pubkey = getPublicKey(skBytes);
  const privateKeyNsec = nip19.nsecEncode(skBytes);
  const now = isoNow();
  const env = getEnvConfig();
  const ownerPk = hostPubkey();

  // Prefer explicit create input → global preferred runtime command → env → pi wrapper.
  const globalCfg = loadGlobalAgentConfig();
  let agentCommand =
    input.agentCommand ||
    input.agent_command ||
    env.BUZZ_ACP_AGENT_COMMAND ||
    null;
  // Map catalog runtime ids / friendly names to a spawnable command when the
  // UI only sent preferred_runtime or a catalog id as the command.
  if (!agentCommand && globalCfg.preferred_runtime) {
    agentCommand = globalCfg.preferred_runtime;
  }
  if (!agentCommand) agentCommand = "pi-acp-wrapper.js";

  // Normalize catalog ids to host-local commands.
  const cmdAliases = {
    "pi-coding-agent": "pi-acp-wrapper.js",
    pi: "pi-acp-wrapper.js",
    "buzz-agent": "pi-acp-wrapper.js",
    grok: "grok",
    goose: "goose",
    claude: "claude-agent-acp",
    codex: "codex-acp",
  };
  const baseName = path.basename(String(agentCommand));
  if (cmdAliases[baseName]) agentCommand = cmdAliases[baseName];
  if (cmdAliases[String(agentCommand)]) {
    agentCommand = cmdAliases[String(agentCommand)];
  }

  let agentArgs = Array.isArray(input.agentArgs || input.agent_args)
    ? (input.agentArgs || input.agent_args).slice()
    : null;
  if (!agentArgs) {
    // Default args by harness (desktop PRESET_HARNESSES parity).
    if (agentCommand === "grok" || baseName === "grok") {
      agentArgs = ["agent", "--always-approve", "stdio"];
    } else if (agentCommand === "goose" || baseName === "goose") {
      agentArgs = ["acp"];
    } else if (
      agentCommand === "pi-acp-wrapper.js" ||
      String(agentCommand).endsWith("pi-acp-wrapper.js")
    ) {
      agentArgs = [];
    } else {
      agentArgs = ["acp"];
    }
  }

  const record = {
    pubkey,
    seckey_hex: seckeyHex,
    name,
    persona_id: input.personaId || input.persona_id || null,
    runtime: input.runtime || globalCfg.preferred_runtime || null,
    team_id: input.teamId || input.team_id || null,
    relay_url: (input.relayUrl || input.relay_url || RELAY_WS).replace(/\/+$/, ""),
    acp_command: input.acpCommand || input.acp_command || "buzz-acp",
    agent_command: agentCommand,
    agent_command_override:
      input.agentCommandOverride ??
      input.agent_command_override ??
      (input.harnessOverride || input.harness_override ? agentCommand : null),
    agent_args: agentArgs,
    mcp_command: input.mcpCommand || input.mcp_command || "",
    turn_timeout_seconds:
      input.turnTimeoutSeconds ?? input.turn_timeout_seconds ?? 320,
    idle_timeout_seconds:
      input.idleTimeoutSeconds ?? input.idle_timeout_seconds ?? null,
    max_turn_duration_seconds:
      input.maxTurnDurationSeconds ?? input.max_turn_duration_seconds ?? null,
    parallelism: input.parallelism ?? 1,
    system_prompt: input.systemPrompt ?? input.system_prompt ?? null,
    avatar_url: input.avatarUrl ?? input.avatar_url ?? null,
    model:
      input.model ??
      globalCfg.model ??
      env.BUZZ_ACP_MODEL ??
      env.GOOSE_MODEL ??
      "grok-4.5",
    provider:
      input.provider ??
      globalCfg.provider ??
      env.GOOSE_PROVIDER ??
      "openai",
    env_vars: {
      ...(globalCfg.env_vars || {}),
      ...(input.envVars || input.env_vars || {}),
    },
    status: "stopped",
    pid: null,
    created_at: now,
    updated_at: now,
    last_started_at: null,
    last_stopped_at: null,
    last_exit_code: null,
    last_error: null,
    last_error_code: null,
    log_path: `/tmp/buzz-acp-${pubkey.slice(0, 12)}.log`,
    start_on_app_launch:
      input.startOnAppLaunch ?? input.start_on_app_launch ?? true,
    auto_restart_on_config_change: true,
    backend: input.backend || { type: "local" },
    backend_agent_id: null,
    respond_to: input.respondTo || input.respond_to || "owner-only",
    respond_to_allowlist: Array.isArray(
      input.respondToAllowlist || input.respond_to_allowlist,
    )
      ? input.respondToAllowlist || input.respond_to_allowlist
      : ownerPk
        ? [ownerPk]
        : [],
  };

  const store = loadManagedAgentsStore();
  if (store.agents.some((a) => a.pubkey === pubkey)) {
    throw new Error(`agent ${pubkey} already exists`);
  }
  store.agents.push(record);
  saveManagedAgentsStore(store);

  // Publish kind:0 so the agent shows a display name on the relay even before start.
  ensureAgentProfilePublished(record).catch((err) =>
    console.warn("create agent profile publish failed:", err.message),
  );

  let spawnError = null;
  let startedSummary = null;
  const shouldSpawn =
    input.spawnAfterCreate !== false && input.spawn_after_create !== false;
  if (shouldSpawn) {
    try {
      // Host CAN spawn ACP processes — this used to be a hard-coded stub.
      startedSummary = ipcStartManagedAgent({ pubkey });
    } catch (err) {
      spawnError = err instanceof Error ? err.message : String(err);
      console.warn(
        `[create_managed_agent] spawn failed for ${name}:`,
        spawnError,
      );
      // Keep the identity record; UI can retry Start.
    }
  }

  // Re-read after optional start so status/pid reflect the live process.
  const afterStore = loadManagedAgentsStore();
  const after =
    afterStore.agents.find(
      (a) => String(a.pubkey).toLowerCase() === pubkey.toLowerCase(),
    ) || record;

  return {
    agent: startedSummary || managedAgentSummary(after),
    private_key_nsec: privateKeyNsec,
    profile_sync_error: null,
    spawn_error: spawnError,
  };
}

function ipcUpdateManagedAgent(args) {
  const input = args.input || args;
  const pubkey = String(input.pubkey || "").trim().toLowerCase();
  if (!pubkey) throw new Error("pubkey required");
  const store = loadManagedAgentsStore();
  const idx = store.agents.findIndex(
    (a) => String(a.pubkey).toLowerCase() === pubkey,
  );
  if (idx < 0) throw new Error(`managed agent not found: ${pubkey}`);
  const existing = store.agents[idx];
  const next = { ...existing, updated_at: isoNow() };
  const map = [
    ["name", "name"],
    ["personaId", "persona_id"],
    ["persona_id", "persona_id"],
    ["teamId", "team_id"],
    ["team_id", "team_id"],
    ["agentCommand", "agent_command"],
    ["agent_command", "agent_command"],
    ["agentArgs", "agent_args"],
    ["agent_args", "agent_args"],
    ["mcpCommand", "mcp_command"],
    ["mcp_command", "mcp_command"],
    ["model", "model"],
    ["provider", "provider"],
    ["systemPrompt", "system_prompt"],
    ["system_prompt", "system_prompt"],
    ["avatarUrl", "avatar_url"],
    ["avatar_url", "avatar_url"],
    ["respondTo", "respond_to"],
    ["respond_to", "respond_to"],
    ["respondToAllowlist", "respond_to_allowlist"],
    ["respond_to_allowlist", "respond_to_allowlist"],
    ["envVars", "env_vars"],
    ["env_vars", "env_vars"],
  ];
  for (const [from, to] of map) {
    if (input[from] !== undefined) next[to] = input[from];
  }
  if (input.harnessOverride && input.agentCommand) {
    next.agent_command = input.agentCommand;
  }
  store.agents[idx] = next;
  saveManagedAgentsStore(store);
  return { agent: managedAgentSummary(next) };
}

function ipcDeleteManagedAgent(args) {
  const pubkey = String(args.pubkey || "").trim().toLowerCase();
  if (!pubkey) throw new Error("pubkey required");
  // Stop process first if running.
  try {
    stopManagedAgentProcess(pubkey);
  } catch {
    /* ignore */
  }
  const store = loadManagedAgentsStore();
  store.agents = store.agents.filter(
    (a) => String(a.pubkey).toLowerCase() !== pubkey,
  );
  saveManagedAgentsStore(store);
  return true;
}

// ── Managed agent process runtime (start/stop buzz-acp) ─────────────────────
/** @type {Map<string, { child: import('child_process').ChildProcess, logPath: string }>} */
const runningAgentProcesses = new Map();

function isPidAlive(pid) {
  if (!pid || typeof pid !== "number") return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function resolveAgentCommandPath(agentCommand) {
  const raw = String(agentCommand || "").trim();
  if (!raw) throw new Error("agent_command is empty");
  if (raw.includes("/") || raw.startsWith(".")) {
    if (fs.existsSync(raw)) return path.resolve(raw);
  }
  // Common host aliases
  if (raw === "pi-acp-wrapper.js" || raw.endsWith("/pi-acp-wrapper.js")) {
    const wrapper = path.join(__dirname, "pi-acp-wrapper.js");
    if (fs.existsSync(wrapper)) return wrapper;
  }
  if (raw === "buzz-acp" || raw === "buzz-agent") {
    const release = path.join(__dirname, "target/release/buzz-acp");
    if (fs.existsSync(release)) return release;
  }
  const onPath = resolveCommandOnPath(raw);
  if (onPath) return onPath;
  // Last resort: treat as bare command name for exec (PATH at spawn time)
  return raw;
}

function resolveBuzzAcpBinary() {
  const release = path.join(__dirname, "target/release/buzz-acp");
  if (fs.existsSync(release)) return release;
  const debug = path.join(__dirname, "target/debug/buzz-acp");
  if (fs.existsSync(debug)) return debug;
  const onPath = resolveCommandOnPath("buzz-acp");
  if (onPath) return onPath;
  throw new Error(
    "buzz-acp binary not found (expected target/release/buzz-acp)",
  );
}

function personaSystemPrompt(personaId) {
  if (!personaId) return null;
  const personas = loadPersonas();
  const p = personas.find((x) => x.id === personaId);
  return p?.system_prompt || null;
}

function syncManagedAgentRuntimeStatus(record) {
  const pk = String(record.pubkey).toLowerCase();
  const tracked = runningAgentProcesses.get(pk);
  if (tracked && tracked.child && !tracked.child.killed) {
    const pid = tracked.child.pid;
    if (isPidAlive(pid)) {
      record.status = "running";
      record.pid = pid;
      return record;
    }
    runningAgentProcesses.delete(pk);
  }
  if (record.pid && isPidAlive(record.pid)) {
    record.status = "running";
    return record;
  }
  if (record.status === "running") {
    record.status = "stopped";
    record.pid = null;
    record.last_stopped_at = isoNow();
  }
  return record;
}

function stopManagedAgentProcess(pubkey) {
  const pk = String(pubkey).toLowerCase();
  const tracked = runningAgentProcesses.get(pk);
  if (tracked?.child && !tracked.child.killed) {
    try {
      tracked.child.kill("SIGTERM");
    } catch {
      /* ignore */
    }
    // Force kill after short grace
    setTimeout(() => {
      try {
        if (tracked.child && !tracked.child.killed) {
          tracked.child.kill("SIGKILL");
        }
      } catch {
        /* ignore */
      }
    }, 3000);
  }
  runningAgentProcesses.delete(pk);

  const store = loadManagedAgentsStore();
  const idx = store.agents.findIndex(
    (a) => String(a.pubkey).toLowerCase() === pk,
  );
  if (idx >= 0) {
    store.agents[idx] = {
      ...store.agents[idx],
      status: "stopped",
      pid: null,
      last_stopped_at: isoNow(),
      updated_at: isoNow(),
    };
    saveManagedAgentsStore(store);
    return store.agents[idx];
  }
  return null;
}

/**
 * Publish kind:0 profile for an arbitrary seckey (host human or agent).
 * AUTH must use the same key that signed the event.
 */
async function publishKind0Profile(seckeyHex, profile) {
  const sk = hexToBytes(seckeyHex);
  const content = {};
  if (profile.display_name || profile.displayName) {
    content.display_name = profile.display_name || profile.displayName;
  }
  if (profile.name) content.name = profile.name;
  if (profile.picture || profile.avatar_url || profile.avatarUrl) {
    content.picture =
      profile.picture || profile.avatar_url || profile.avatarUrl;
  }
  if (profile.about) content.about = profile.about;
  if (profile.nip05 || profile.nip05_handle) {
    content.nip05 = profile.nip05 || profile.nip05_handle;
  }
  if (profile.bot === true) content.bot = true;
  const event = finalizeEvent(
    {
      kind: 0,
      created_at: Math.floor(Date.now() / 1000),
      tags: [],
      content: JSON.stringify(content),
    },
    sk,
  );
  await submitEvent(event, sk);
  return event;
}

/** Ensure host human identity has a relay kind:0 so other clients show a name. */
async function ensureHostProfilePublished() {
  const id = getHostIdentity();
  const events = await queryRelay([
    { kinds: [0], authors: [id.pubkey], limit: 1 },
  ]);
  if (events[0]) {
    // Already published — optionally refresh display_name if empty
    try {
      const content = JSON.parse(events[0].content || "{}");
      if (content.display_name || content.name) return profileFromKind0(events[0]);
    } catch {
      /* republish */
    }
  }
  const seckeyHex = loadSecretKeyHex();
  const display =
    id.display_name || process.env.BUZZ_WEB_DISPLAY_NAME || "fedora";
  const username = id.username || process.env.BUZZ_WEB_USERNAME || "fedora";
  await publishKind0Profile(seckeyHex, {
    display_name: display,
    name: username,
    about: "Fedora host identity (Buzz Web)",
  });
  return {
    pubkey: id.pubkey,
    display_name: display,
    avatar_url: null,
    about: "Fedora host identity (Buzz Web)",
    nip05_handle: null,
    owner_pubkey: id.owner_pubkey,
    has_profile_event: true,
  };
}

async function ensureAgentProfilePublished(record) {
  if (!record.seckey_hex) return null;
  const events = await queryRelay([
    { kinds: [0], authors: [record.pubkey], limit: 1 },
  ]);
  if (events[0]) {
    try {
      const content = JSON.parse(events[0].content || "{}");
      if (content.display_name || content.name) return events[0];
    } catch {
      /* republish */
    }
  }
  return publishKind0Profile(record.seckey_hex, {
    display_name: record.name,
    name: record.name,
    about: record.system_prompt
      ? String(record.system_prompt).slice(0, 280)
      : `Buzz managed agent (${record.persona_id || "custom"})`,
    bot: true,
    avatar_url: record.avatar_url,
  });
}

function ipcStartManagedAgent(args) {
  const pubkey = String(args.pubkey || "").trim().toLowerCase();
  if (!pubkey) throw new Error("pubkey required");

  const store = loadManagedAgentsStore();
  const idx = store.agents.findIndex(
    (a) => String(a.pubkey).toLowerCase() === pubkey,
  );
  if (idx < 0) throw new Error(`managed agent not found: ${pubkey}`);
  let record = store.agents[idx];
  record = syncManagedAgentRuntimeStatus(record);

  if (record.status === "running" && record.pid && isPidAlive(record.pid)) {
    store.agents[idx] = record;
    saveManagedAgentsStore(store);
    return managedAgentSummary(record);
  }

  if (!record.seckey_hex) {
    throw new Error(
      "agent has no seckey_hex on host — recreate the managed agent",
    );
  }

  const buzzAcp = resolveBuzzAcpBinary();
  let agentCommand = resolveAgentCommandPath(
    record.agent_command || "pi-acp-wrapper.js",
  );
  // If agent_command accidentally points at buzz-acp itself, fall back to pi wrapper
  if (
    agentCommand.endsWith("/buzz-acp") ||
    path.basename(agentCommand) === "buzz-acp"
  ) {
    agentCommand = resolveAgentCommandPath("pi-acp-wrapper.js");
  }

  let agentArgs = Array.isArray(record.agent_args) ? record.agent_args.slice() : [];
  // pi-acp-wrapper is already an ACP server — don't append bare "acp"
  if (
    path.basename(agentCommand) === "pi-acp-wrapper.js" &&
    agentArgs.length === 1 &&
    agentArgs[0] === "acp"
  ) {
    agentArgs = [];
  }
  // grok default args if someone stored empty args for grok harness
  if (
    (path.basename(agentCommand) === "grok" || record.runtime === "grok") &&
    agentArgs.length === 0
  ) {
    agentArgs = ["agent", "--always-approve", "stdio"];
  }

  const envFile = getEnvConfig();
  const ownerPk =
    process.env.BUZZ_ACP_AGENT_OWNER ||
    envFile.BUZZ_ACP_AGENT_OWNER ||
    hostPubkey();
  const systemPrompt =
    record.system_prompt ||
    personaSystemPrompt(record.persona_id) ||
    undefined;
  const model =
    record.model ||
    envFile.BUZZ_ACP_MODEL ||
    envFile.GOOSE_MODEL ||
    envFile.BUZZ_AGENT_MODEL ||
    "grok-4.5";
  const provider =
    record.provider ||
    envFile.GOOSE_PROVIDER ||
    envFile.BUZZ_AGENT_PROVIDER ||
    "openai";

  const logPath =
    record.log_path || `/tmp/buzz-acp-${record.pubkey.slice(0, 12)}.log`;
  const logFd = fs.openSync(logPath, "a");

  const childEnv = {
    ...process.env,
    PATH: hostSearchPath(),
    BUZZ_RELAY_URL: record.relay_url || RELAY_WS,
    BUZZ_RELAY_HTTP: RELAY_HTTP,
    BUZZ_PRIVATE_KEY: record.seckey_hex,
    BUZZ_ACP_AGENT_OWNER: ownerPk,
    BUZZ_ACP_RESPOND_TO: record.respond_to || "owner-only",
    BUZZ_ACP_AGENT_COMMAND: agentCommand,
    OPENAI_BASE_URL: envFile.OPENAI_BASE_URL || process.env.OPENAI_BASE_URL,
    OPENAI_API_KEY: envFile.OPENAI_API_KEY || process.env.OPENAI_API_KEY,
    BUZZ_ACP_MODEL: model,
    BUZZ_AGENT_MODEL: model,
    GOOSE_MODEL: model,
    BUZZ_AGENT_PROVIDER: provider,
    GOOSE_PROVIDER: provider,
    ...(record.env_vars || {}),
  };
  if (systemPrompt) {
    childEnv.BUZZ_ACP_SYSTEM_PROMPT = systemPrompt;
  }
  if (
    Array.isArray(record.respond_to_allowlist) &&
    record.respond_to_allowlist.length
  ) {
    childEnv.BUZZ_ACP_RESPOND_TO_ALLOWLIST =
      record.respond_to_allowlist.join(",");
  }

  const cliArgs = [
    "--private-key",
    record.seckey_hex,
    "--relay-url",
    record.relay_url || RELAY_WS,
    "--agent-owner",
    ownerPk,
    "--agent-command",
    agentCommand,
    "--respond-to",
    record.respond_to || "owner-only",
  ];
  for (const a of agentArgs) {
    cliArgs.push("--agent-args", String(a));
  }
  if (systemPrompt) {
    cliArgs.push("--system-prompt", systemPrompt);
  }

  const child = require("child_process").spawn(buzzAcp, cliArgs, {
    env: childEnv,
    detached: false,
    stdio: ["ignore", logFd, logFd],
  });

  fs.closeSync(logFd);

  if (!child.pid) {
    throw new Error(`failed to spawn buzz-acp for ${record.name}`);
  }

  runningAgentProcesses.set(pubkey, { child, logPath });
  child.on("exit", (code, signal) => {
    const cur = runningAgentProcesses.get(pubkey);
    if (cur && cur.child === child) {
      runningAgentProcesses.delete(pubkey);
    }
    try {
      const s = loadManagedAgentsStore();
      const i = s.agents.findIndex(
        (a) => String(a.pubkey).toLowerCase() === pubkey,
      );
      if (i >= 0 && s.agents[i].pid === child.pid) {
        s.agents[i] = {
          ...s.agents[i],
          status: "stopped",
          pid: null,
          last_stopped_at: isoNow(),
          last_exit_code: code,
          last_error:
            code && code !== 0
              ? `buzz-acp exited code=${code} signal=${signal || ""}`
              : null,
          updated_at: isoNow(),
        };
        saveManagedAgentsStore(s);
      }
    } catch (err) {
      console.warn("agent exit status update failed:", err.message);
    }
  });

  const now = isoNow();
  record = {
    ...record,
    status: "running",
    pid: child.pid,
    last_started_at: now,
    last_error: null,
    last_error_code: null,
    log_path: logPath,
    agent_command: agentCommand,
    agent_args: agentArgs,
    model,
    provider,
    system_prompt: systemPrompt || record.system_prompt,
    updated_at: now,
  };
  store.agents[idx] = record;
  saveManagedAgentsStore(store);

  // Fire-and-forget profile publish for agent + host
  ensureAgentProfilePublished(record).catch((err) =>
    console.warn("agent profile publish failed:", err.message),
  );
  ensureHostProfilePublished().catch((err) =>
    console.warn("host profile publish failed:", err.message),
  );

  console.log(
    `[start_managed_agent] ${record.name} pid=${child.pid} cmd=${agentCommand} log=${logPath}`,
  );
  return managedAgentSummary(record);
}

function ipcStopManagedAgent(args) {
  const pubkey = String(args.pubkey || "").trim().toLowerCase();
  if (!pubkey) throw new Error("pubkey required");
  const stopped = stopManagedAgentProcess(pubkey);
  if (!stopped) {
    // Still return a summary shape if possible
    const store = loadManagedAgentsStore();
    const rec = store.agents.find(
      (a) => String(a.pubkey).toLowerCase() === pubkey,
    );
    if (!rec) throw new Error(`managed agent not found: ${pubkey}`);
    return managedAgentSummary(rec);
  }
  return managedAgentSummary(stopped);
}

async function ipcUpdateProfile(args) {
  const input = args.input || args;
  const seckeyHex = loadSecretKeyHex();
  const current = await ipcGetProfile(hostPubkey());
  const display_name =
    input.displayName ??
    input.display_name ??
    current.display_name ??
    "fedora";
  const name = input.name ?? current.username ?? display_name;
  const about =
    input.about ?? current.about ?? "Fedora host identity (Buzz Web)";
  const avatar_url =
    input.avatarUrl ?? input.avatar_url ?? current.avatar_url ?? null;
  const nip05 =
    input.nip05Handle ?? input.nip05_handle ?? current.nip05_handle ?? null;

  await publishKind0Profile(seckeyHex, {
    display_name,
    name,
    about,
    avatar_url,
    nip05,
  });
  return ipcGetProfile(hostPubkey());
}

// ── Global agent defaults (Settings → Agents) ───────────────────────────────
// Desktop stores this under app-data as global-agent-config.json. Web host
// persists under ~/.config/buzz-web so preferred_runtime (e.g. "grok") survives
// refresh — the old shim returned a hardcoded pi-coding-agent and discarded saves.

const EMPTY_GLOBAL_AGENT_CONFIG = {
  env_vars: {},
  provider: null,
  model: null,
  preferred_runtime: null,
};

function normalizeGlobalAgentConfig(raw) {
  const src = raw && typeof raw === "object" ? raw : {};
  const envIn =
    src.env_vars && typeof src.env_vars === "object" && !Array.isArray(src.env_vars)
      ? src.env_vars
      : src.envVars && typeof src.envVars === "object" && !Array.isArray(src.envVars)
        ? src.envVars
        : {};
  const env_vars = {};
  for (const [k, v] of Object.entries(envIn)) {
    if (typeof k !== "string" || !k.trim()) continue;
    // Empty value = "inherit" — strip on write (desktop parity).
    if (v == null || v === "") continue;
    env_vars[k] = String(v);
  }
  const blankToNull = (v) => {
    if (v == null) return null;
    const s = String(v).trim();
    return s ? s : null;
  };
  return {
    env_vars,
    provider: blankToNull(src.provider),
    model: blankToNull(src.model),
    preferred_runtime: blankToNull(
      src.preferred_runtime ?? src.preferredRuntime ?? null,
    ),
  };
}

function loadGlobalAgentConfig() {
  try {
    if (!fs.existsSync(GLOBAL_AGENT_CONFIG_PATH)) {
      return { ...EMPTY_GLOBAL_AGENT_CONFIG, env_vars: {} };
    }
    const raw = JSON.parse(fs.readFileSync(GLOBAL_AGENT_CONFIG_PATH, "utf8"));
    return normalizeGlobalAgentConfig(raw);
  } catch (err) {
    console.warn(
      "[global-agent-config] load failed:",
      err && err.message ? err.message : err,
    );
    return { ...EMPTY_GLOBAL_AGENT_CONFIG, env_vars: {} };
  }
}

function saveGlobalAgentConfigFile(config) {
  fs.mkdirSync(WEB_CONFIG_DIR, { recursive: true, mode: 0o700 });
  const tmp = `${GLOBAL_AGENT_CONFIG_PATH}.${process.pid}.tmp`;
  const body = JSON.stringify(config, null, 2);
  fs.writeFileSync(tmp, body, { mode: 0o600 });
  fs.renameSync(tmp, GLOBAL_AGENT_CONFIG_PATH);
  try {
    fs.chmodSync(GLOBAL_AGENT_CONFIG_PATH, 0o600);
  } catch {
    /* ignore */
  }
}

function ipcGetGlobalAgentConfig() {
  return loadGlobalAgentConfig();
}

/**
 * Desktop `RuntimeConfigSurface` for AgentConfigPanel / ModelPicker.
 * Web host has no ACP session cache file bridge — build a pre/post-spawn
 * surface from the managed-agent record + global defaults so UI never gets
 * `[]` (which crashes on `sources.configFilePath`).
 */
function configField(value, origin = "envVar") {
  return {
    value: value == null || value === "" ? null : String(value),
    origin,
    writeVia: { type: "readOnly" },
    overriddenValue: null,
    overriddenOrigin: null,
    isRequired: false,
  };
}

function runtimeMetaFromAgentCommand(agentCommand) {
  const raw = String(agentCommand || "").trim();
  const base = path.basename(raw).replace(/\.js$/i, "");
  const table = {
    grok: { id: "grok", label: "Grok Build", configFilePath: null },
    goose: {
      id: "goose",
      label: "Goose",
      configFilePath: "~/.config/goose/config.yaml",
    },
    "claude-agent-acp": {
      id: "claude",
      label: "Claude Code",
      configFilePath: "~/.claude/settings.json",
    },
    claude: {
      id: "claude",
      label: "Claude Code",
      configFilePath: "~/.claude/settings.json",
    },
    "codex-acp": {
      id: "codex",
      label: "Codex",
      configFilePath: "~/.codex/config.toml",
    },
    codex: {
      id: "codex",
      label: "Codex",
      configFilePath: "~/.codex/config.toml",
    },
    "pi-acp-wrapper": {
      id: "pi-coding-agent",
      label: "Pi Coding Agent",
      configFilePath: "~/.pi/agent/settings.json",
    },
    "pi-coding-agent": {
      id: "pi-coding-agent",
      label: "Pi Coding Agent",
      configFilePath: "~/.pi/agent/settings.json",
    },
    pi: {
      id: "pi-coding-agent",
      label: "Pi Coding Agent",
      configFilePath: "~/.pi/agent/settings.json",
    },
    "buzz-acp": {
      id: "buzz-agent",
      label: "Buzz Agent",
      configFilePath: null,
    },
    "buzz-agent": {
      id: "buzz-agent",
      label: "Buzz Agent",
      configFilePath: null,
    },
  };
  if (table[base]) return table[base];
  if (table[raw]) return table[raw];
  return {
    id: base || raw || null,
    label: base || raw || "Agent",
    configFilePath: null,
  };
}

function ipcGetAgentConfigSurface(args) {
  const pubkey = String(args.pubkey || args.agentPubkey || "")
    .trim()
    .toLowerCase();
  if (!pubkey || !HEX64.test(pubkey)) {
    throw new Error("pubkey required");
  }

  const store = loadManagedAgentsStore();
  let record = store.agents.find(
    (a) => String(a.pubkey).toLowerCase() === pubkey,
  );
  if (record) {
    record = syncManagedAgentRuntimeStatus(record);
  }

  // Allow host systemd Fedora-Agent if listed only via list overlay
  if (!record) {
    try {
      const agentPk = getAgentPubkey();
      if (String(agentPk).toLowerCase() === pubkey) {
        const env = getEnvConfig();
        record = {
          pubkey: agentPk,
          name: "Fedora-Agent",
          agent_command: env.BUZZ_ACP_AGENT_COMMAND || "pi-acp-wrapper.js",
          model: env.BUZZ_ACP_MODEL || env.GOOSE_MODEL || "grok-4.5",
          provider: env.GOOSE_PROVIDER || "openai",
          system_prompt: null,
          status: getServiceStatus() === "running" ? "running" : "stopped",
        };
      }
    } catch {
      /* no agent key */
    }
  }
  if (!record) throw new Error(`agent ${pubkey} not found`);

  const globalCfg = loadGlobalAgentConfig();
  const meta = runtimeMetaFromAgentCommand(record.agent_command);
  const isRunning =
    record.status === "running" &&
    record.pid &&
    isPidAlive(record.pid);
  const isPreSpawn = !isRunning;

  const model =
    record.model || globalCfg.model || null;
  const provider =
    record.provider || globalCfg.provider || null;
  const systemPrompt = record.system_prompt || null;

  const modelOrigin = record.model
    ? "envVar"
    : globalCfg.model
      ? "globalDefault"
      : "envVar";
  const providerOrigin = record.provider
    ? "envVar"
    : globalCfg.provider
      ? "globalDefault"
      : "envVar";

  return {
    runtimeId: meta.id,
    runtimeLabel: meta.label,
    isPreSpawn,
    normalized: {
      model: model != null ? configField(model, modelOrigin) : null,
      provider: provider != null ? configField(provider, providerOrigin) : null,
      mode: null,
      thinkingEffort: null,
      maxOutputTokens: null,
      contextLimit: null,
      systemPrompt:
        systemPrompt != null
          ? configField(systemPrompt, "personaDefault")
          : null,
    },
    advanced: [],
    extensions: [],
    sources: {
      acpNative: isPreSpawn ? "pending" : "available",
      acpConfigOptions: isPreSpawn ? "pending" : "notApplicable",
      envVars: "available",
      configFile: meta.configFilePath ? "available" : "notApplicable",
      configFilePath: meta.configFilePath,
      mcpConfigFilePath: null,
    },
  };
}

/** No-op session cache write (desktop stores ACP session/new capture). */
function ipcPutAgentSessionConfig(_args) {
  return true;
}

/** Optional harness file-layer subset — web host does not parse goose/codex files. */
function ipcGetRuntimeFileConfig(_args) {
  return null;
}

/**
 * Persist global defaults. Restart of running agents is best-effort and
 * optional (web host does not auto-restart on every env tweak unless
 * preferred_runtime/model/provider changes and agents are running).
 *
 * Args: { config: GlobalAgentConfig } (Tauri shape).
 */
function ipcSetGlobalAgentConfig(args) {
  const input =
    args && args.config && typeof args.config === "object"
      ? args.config
      : args && typeof args === "object"
        ? args
        : {};
  const next = normalizeGlobalAgentConfig(input);
  // Light validation: env keys must look like shell identifiers.
  for (const key of Object.keys(next.env_vars)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      throw new Error(`invalid env var key: ${key}`);
    }
    if (
      /^(GOOSE_PROVIDER|GOOSE_MODEL|BUZZ_ACP_MODEL|BUZZ_AGENT_MODEL|BUZZ_AGENT_PROVIDER)$/i.test(
        key,
      )
    ) {
      throw new Error(
        `key ${key} must be set via structured provider/model fields, not env_vars`,
      );
    }
  }
  saveGlobalAgentConfigFile(next);
  const saved = loadGlobalAgentConfig();
  // Restart counts: web host leaves agents running; UI only needs honest counts.
  // (Desktop restarts when effective env changes — optional enhancement.)
  return {
    config: saved,
    restarted_count: 0,
    failed_restart_count: 0,
  };
}

/** NIP-44 encrypt/decrypt to self (read-state snapshots). */
function ipcNip44EncryptToSelf(args) {
  const plaintext = args.plaintext ?? args.input?.plaintext;
  if (typeof plaintext !== "string") throw new Error("plaintext required");
  const sk = loadSecretKeyBytes();
  const pk = getPublicKey(sk);
  const conversationKey = nip44.v2.utils.getConversationKey(sk, pk);
  return nip44.v2.encrypt(plaintext, conversationKey);
}

function ipcNip44DecryptFromSelf(args) {
  const ciphertext = args.ciphertext ?? args.input?.ciphertext;
  if (typeof ciphertext !== "string") throw new Error("ciphertext required");
  const sk = loadSecretKeyBytes();
  const pk = getPublicKey(sk);
  const conversationKey = nip44.v2.utils.getConversationKey(sk, pk);
  return nip44.v2.decrypt(ciphertext, conversationKey);
}

async function ipcListArchivedIdentities() {
  // kind:13535 snapshot — if none, empty list
  try {
    const events = await queryRelay([{ kinds: [13535], limit: 1 }]);
    const archived = [];
    if (events[0]) {
      for (const t of events[0].tags || []) {
        if ((t[0] === "p" || t[0] === "archived") && t[1]) {
          archived.push(t[1].toLowerCase());
        }
      }
    }
    return { archived };
  } catch {
    return { archived: [] };
  }
}

// ── Core messaging / membership / observer (batch fill “not implemented”) ───

const HEX64 = /^[0-9a-f]{64}$/i;
/** NIP-44 v2 ciphertext length envelope (matches buzz-core observer). */
const NIP44_MIN_CONTENT_LEN = 132;
const NIP44_MAX_CONTENT_LEN = 87472;
const OBSERVER_MAX_PLAINTEXT_LEN = 65535;

function requireChannelId(args) {
  const channelId = args.channelId || args.channel_id;
  if (!channelId || typeof channelId !== "string") {
    throw new Error("channelId required");
  }
  return channelId;
}

function requireEventId(args, key = "eventId") {
  const eventId = args[key] || args.event_id || args.eventId;
  if (!eventId || !HEX64.test(String(eventId))) {
    throw new Error(`${key} required (64-char hex)`);
  }
  return String(eventId).toLowerCase();
}

function parseCommandResponse(message) {
  if (message == null) throw new Error("empty command response");
  const text = String(message);
  const jsonText = text.startsWith("response:")
    ? text.slice("response:".length)
    : text;
  try {
    return JSON.parse(jsonText);
  } catch (err) {
    throw new Error(
      `expected 'response:' prefix or valid JSON, got: ${text.slice(0, 200)} (${err.message})`,
    );
  }
}

function contentLooksLikeNip44(content) {
  const n = typeof content === "string" ? content.length : 0;
  return n >= NIP44_MIN_CONTENT_LEN && n <= NIP44_MAX_CONTENT_LEN;
}

/**
 * Kind 41010 — open (or surface) a DM. Relay returns
 * `response:{"channel_id":"...","created":bool}` in the OK message.
 */
async function ipcOpenDm(args) {
  const raw =
    args.pubkeys ||
    args.input?.pubkeys ||
    args.participantPubkeys ||
    args.participant_pubkeys ||
    [];
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new Error("open_dm requires at least one pubkey");
  }
  if (raw.length > 8) {
    throw new Error("open_dm accepts at most 8 other participants");
  }
  const tags = [];
  const seen = new Set();
  for (const pk of raw) {
    const hex = String(pk || "").trim().toLowerCase();
    if (!HEX64.test(hex)) throw new Error(`invalid pubkey: ${pk}`);
    if (seen.has(hex)) continue;
    seen.add(hex);
    tags.push(["p", hex]);
  }
  if (tags.length === 0) throw new Error("open_dm requires at least one pubkey");

  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 41010,
      created_at: Math.floor(Date.now() / 1000),
      tags,
      content: "",
    },
    sk,
  );
  const submitResult = await submitEvent(event);
  if (submitResult && submitResult.accepted === false) {
    throw new Error(
      `relay rejected open_dm: ${submitResult.message || "unknown"}`,
    );
  }
  const message =
    (submitResult && submitResult.message) ||
    (typeof submitResult === "string" ? submitResult : "");
  let channelId = null;
  try {
    const ack = parseCommandResponse(message);
    channelId = ack.channel_id || ack.channelId || null;
  } catch (err) {
    // Some relays may only return accepted without body — try membership probe.
    console.warn("[open_dm] parse response failed:", err.message, message);
  }
  if (!channelId) {
    throw new Error(
      `open_dm: relay did not return channel_id (message=${String(message).slice(0, 200)})`,
    );
  }

  pendingOwnedChannelIds.add(channelId);

  // Poll kind:39000 like create_channel — metadata can lag slightly.
  for (let i = 0; i < 12; i++) {
    try {
      const details = await ipcGetChannelDetails(channelId);
      if (details && details.id) {
        details.is_member = true;
        return details;
      }
    } catch {
      /* lag */
    }
    await sleep(200 + i * 80);
  }

  return {
    id: channelId,
    name: "",
    channel_type: "dm",
    visibility: "private",
    description: "",
    topic: null,
    purpose: null,
    member_count: tags.length + 1,
    member_pubkeys: [hostPubkey(), ...tags.map((t) => t[1])],
    last_message_at: null,
    archived_at: null,
    participants: [hostPubkey(), ...tags.map((t) => t[1])],
    participant_pubkeys: [hostPubkey(), ...tags.map((t) => t[1])],
    is_member: true,
    ttl_seconds: null,
    ttl_deadline: null,
  };
}

/** Kind 41012 — hide DM from listing. */
async function ipcHideDm(args) {
  const channelId = requireChannelId(args);
  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 41012,
      created_at: Math.floor(Date.now() / 1000),
      tags: [["h", channelId]],
      content: "",
    },
    sk,
  );
  await submitEvent(event);
  return true;
}

/** Kind 9022 — leave channel. */
async function ipcLeaveChannel(args) {
  const channelId = requireChannelId(args);
  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 9022,
      created_at: Math.floor(Date.now() / 1000),
      tags: [["h", channelId]],
      content: "",
    },
    sk,
  );
  await submitEvent(event);
  pendingOwnedChannelIds.delete(channelId);
  return true;
}

/** Kind 9001 — remove member. */
async function ipcRemoveChannelMember(args) {
  const channelId = requireChannelId(args);
  const pubkey = String(args.pubkey || args.targetPubkey || "").trim().toLowerCase();
  if (!HEX64.test(pubkey)) throw new Error("pubkey required");
  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 9001,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["h", channelId],
        ["p", pubkey],
      ],
      content: "",
    },
    sk,
  );
  await submitEvent(event);
  return true;
}

/** Kind 9000 with role — change member role (admin/member/guest/bot). */
async function ipcChangeChannelMemberRole(args) {
  const channelId = requireChannelId(args);
  const pubkey = String(args.pubkey || args.targetPubkey || "").trim().toLowerCase();
  const role = String(args.role || "").trim();
  if (!HEX64.test(pubkey)) throw new Error("pubkey required");
  if (!["admin", "member", "guest", "bot"].includes(role)) {
    throw new Error(`invalid role: ${role}`);
  }
  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 9000,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["h", channelId],
        ["p", pubkey],
        ["role", role],
      ],
      content: "",
    },
    sk,
  );
  await submitEvent(event);
  return true;
}

/** Kind 7 — NIP-25 reaction (optional NIP-30 custom emoji). */
async function ipcAddReaction(args) {
  const eventId = requireEventId(args);
  const emoji = String(args.emoji || "").trim();
  if (!emoji) throw new Error("emoji required");
  const emojiUrl = args.emojiUrl || args.emoji_url || null;
  const tags = [["e", eventId]];
  let content = emoji;
  if (emojiUrl) {
    // NIP-30: content is :shortcode: and emoji tag carries url.
    const shortcode = emoji.replace(/^:|:$/g, "") || "custom";
    content = `:${shortcode}:`;
    tags.push(["emoji", shortcode, String(emojiUrl)]);
  }
  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 7,
      created_at: Math.floor(Date.now() / 1000),
      tags,
      content,
    },
    sk,
  );
  await submitEvent(event);
  return true;
}

/** Find our kind:7 and delete it (kind 5). */
async function ipcRemoveReaction(args) {
  const eventId = requireEventId(args);
  const emoji = String(args.emoji || "").trim();
  if (!emoji) throw new Error("emoji required");
  const myPk = hostPubkey();
  const reactions = await queryRelay([
    { kinds: [7], "#e": [eventId], authors: [myPk], limit: 50 },
  ]);
  const match = reactions.find((ev) => String(ev.content || "").trim() === emoji);
  if (!match) {
    throw new Error("could not find your reaction event for this emoji");
  }
  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 5,
      created_at: Math.floor(Date.now() / 1000),
      tags: [["e", match.id]],
      content: "",
    },
    sk,
  );
  await submitEvent(event);
  return true;
}

/** Kind 40003 — edit message. */
async function ipcEditMessage(args) {
  const channelId = requireChannelId(args);
  const eventId = requireEventId(args);
  const content = args.content != null ? String(args.content) : "";
  const mediaTags = args.mediaTags || args.media_tags || [];
  const emojiTags = args.emojiTags || args.emoji_tags || [];
  const mentions = args.mentionPubkeys || args.mention_pubkeys || [];
  if (!content.trim() && (!Array.isArray(mediaTags) || mediaTags.length === 0)) {
    throw new Error("edit must have content or attachments");
  }
  const tags = [
    ["h", channelId],
    ["e", eventId],
  ];
  for (const p of mentions) {
    if (p && HEX64.test(String(p))) tags.push(["p", String(p).toLowerCase()]);
  }
  if (Array.isArray(mediaTags)) {
    for (const imeta of mediaTags) {
      if (Array.isArray(imeta) && imeta.length) tags.push(imeta.map(String));
    }
  }
  if (Array.isArray(emojiTags)) {
    for (const et of emojiTags) {
      if (Array.isArray(et) && et.length) tags.push(et.map(String));
    }
  }
  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 40003,
      created_at: Math.floor(Date.now() / 1000),
      tags,
      content,
    },
    sk,
  );
  await submitEvent(event);
  return true;
}

/** Kind 5 — delete message (channel-scoped). */
async function ipcDeleteMessage(args) {
  const channelId = requireChannelId(args);
  const eventId = requireEventId(args);
  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 5,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["h", channelId],
        ["e", eventId],
      ],
      content: "",
    },
    sk,
  );
  await submitEvent(event);
  return true;
}

/** Kind 9002 — archive / unarchive channel. */
async function ipcArchiveChannel(args, archived) {
  const channelId = requireChannelId(args);
  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 9002,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["h", channelId],
        ["archived", archived ? "true" : "false"],
      ],
      content: "",
    },
    sk,
  );
  await submitEvent(event);
  return true;
}

/** Kind 9008 — delete channel. */
async function ipcDeleteChannel(args) {
  const channelId = requireChannelId(args);
  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 9008,
      created_at: Math.floor(Date.now() / 1000),
      tags: [["h", channelId]],
      content: "",
    },
    sk,
  );
  await submitEvent(event);
  return true;
}

/** Kind 9002 — set topic / purpose tags. */
async function ipcSetChannelTopic(args) {
  const channelId = requireChannelId(args);
  const topic = args.topic != null ? String(args.topic) : "";
  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 9002,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["h", channelId],
        ["topic", topic],
      ],
      content: "",
    },
    sk,
  );
  await submitEvent(event);
  return true;
}

async function ipcSetChannelPurpose(args) {
  const channelId = requireChannelId(args);
  const purpose = args.purpose != null ? String(args.purpose) : "";
  const sk = loadSecretKeyBytes();
  const event = finalizeEvent(
    {
      kind: 9002,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["h", channelId],
        ["purpose", purpose],
      ],
      content: "",
    },
    sk,
  );
  await submitEvent(event);
  return true;
}

/**
 * Decrypt kind:24200 observer frame content with host seckey (owner key).
 * Args: { eventJson: string } — full event JSON.
 */
function ipcDecryptObserverEvent(args) {
  const eventJson = args.eventJson || args.event_json;
  if (typeof eventJson !== "string" || !eventJson.trim()) {
    throw new Error("eventJson required");
  }
  let event;
  try {
    event = JSON.parse(eventJson);
  } catch (err) {
    throw new Error(`invalid event: ${err.message}`);
  }
  if (!event || typeof event !== "object") {
    throw new Error("invalid event: not an object");
  }
  if (typeof verifyEvent === "function") {
    try {
      if (!verifyEvent(event)) {
        throw new Error("observer event has invalid ID or signature");
      }
    } catch (err) {
      if (String(err.message || "").includes("invalid ID")) throw err;
      // verifyEvent may throw on malformed — surface clearly
      throw new Error(`observer event verification failed: ${err.message}`);
    }
  }
  if (!contentLooksLikeNip44(event.content)) {
    throw new Error(
      `invalid NIP-44 ciphertext length: ${String(event.content || "").length}`,
    );
  }
  const sk = loadSecretKeyBytes();
  const senderPk = String(event.pubkey || "").toLowerCase();
  if (!HEX64.test(senderPk)) throw new Error("observer event missing pubkey");
  const conversationKey = nip44.v2.utils.getConversationKey(sk, senderPk);
  let plaintext;
  try {
    plaintext = nip44.v2.decrypt(event.content, conversationKey);
  } catch (err) {
    throw new Error(`decrypt observer event failed: ${err.message}`);
  }
  if (plaintext.length > OBSERVER_MAX_PLAINTEXT_LEN) {
    throw new Error(
      `observer plaintext exceeds ${OBSERVER_MAX_PLAINTEXT_LEN} bytes (got ${plaintext.length})`,
    );
  }
  try {
    return JSON.parse(plaintext);
  } catch (err) {
    throw new Error(`observer payload JSON error: ${err.message}`);
  }
}

/**
 * Build signed kind:24200 control frame (owner → agent).
 * Returns event JSON string (Tauri parity).
 */
function ipcBuildObserverControlEvent(args) {
  const agentPubkey = String(
    args.agentPubkey || args.agent_pubkey || "",
  )
    .trim()
    .toLowerCase();
  if (!HEX64.test(agentPubkey)) throw new Error("invalid agent pubkey");
  const payload = args.payload;
  if (payload === undefined) throw new Error("payload required");

  let plaintext = JSON.stringify(payload);
  if (plaintext.length > OBSERVER_MAX_PLAINTEXT_LEN) {
    throw new Error(
      `observer plaintext exceeds ${OBSERVER_MAX_PLAINTEXT_LEN} bytes (got ${plaintext.length})`,
    );
  }
  const sk = loadSecretKeyBytes();
  const conversationKey = nip44.v2.utils.getConversationKey(sk, agentPubkey);
  const encrypted = nip44.v2.encrypt(plaintext, conversationKey);
  plaintext = ""; // drop cleartext reference
  if (!contentLooksLikeNip44(encrypted)) {
    throw new Error("encrypt observer control produced invalid NIP-44 length");
  }

  // Control frames: p + agent both point at agent (desktop build_observer_control_event).
  const event = finalizeEvent(
    {
      kind: 24200,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["p", agentPubkey],
        ["agent", agentPubkey],
        ["frame", "control"],
      ],
      content: encrypted,
    },
    sk,
  );
  return JSON.stringify(event);
}

// ── ACP runtime discovery (Settings → Agents / harness catalog) ─────────────
// Desktop probes PATH for known harness CLIs and returns AcpRuntimeCatalogEntry.
// Web host must do the same on the Fedora machine — not hardcode fake "available".

const HOST_PATH_EXTRA = [
  path.join(process.env.HOME || "/home/lary", ".local/bin"),
  path.join(process.env.HOME || "/home/lary", ".local/share/pnpm"),
  path.join(process.env.HOME || "/home/lary", ".local/share/pnpm/bin"),
  path.join(process.env.HOME || "/home/lary", ".opencode/bin"),
  "/usr/local/bin",
  "/usr/bin",
];

function hostSearchPath() {
  const base = process.env.PATH || "";
  const parts = base.split(path.delimiter).filter(Boolean);
  for (const extra of HOST_PATH_EXTRA) {
    if (!parts.includes(extra)) parts.unshift(extra);
  }
  return parts.join(path.delimiter);
}

function resolveCommandOnPath(command) {
  if (!command || typeof command !== "string") return null;
  const trimmed = command.trim();
  if (!trimmed) return null;
  // Absolute / relative path
  if (trimmed.includes("/") || trimmed.startsWith(".")) {
    try {
      if (fs.existsSync(trimmed) && fs.statSync(trimmed).isFile()) {
        try {
          fs.accessSync(trimmed, fs.constants.X_OK);
          return path.resolve(trimmed);
        } catch {
          return path.resolve(trimmed);
        }
      }
    } catch {
      return null;
    }
  }
  const search = hostSearchPath().split(path.delimiter);
  for (const dir of search) {
    if (!dir) continue;
    const candidate = path.join(dir, trimmed);
    try {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        return candidate;
      }
    } catch {
      /* continue */
    }
  }
  // `command -v` fallback (respects login aliases less, but catches more PATH)
  try {
    const out = execSync(`command -v ${JSON.stringify(trimmed)}`, {
      encoding: "utf8",
      env: { ...process.env, PATH: hostSearchPath() },
      timeout: 2000,
    }).trim();
    if (out && fs.existsSync(out)) return out;
  } catch {
    /* not found */
  }
  return null;
}

/**
 * Known harness catalog (subset of desktop KNOWN_ACP_RUNTIMES + host pi wrapper).
 * availability is computed by probing command names on PATH.
 */
const KNOWN_HOST_ACP_RUNTIMES = [
  {
    id: "buzz-agent",
    label: "Buzz Agent",
    commands: ["buzz-agent", "buzz-acp"],
    // Host ships buzz-acp binary under the repo target dir.
    extraPaths: [
      path.join(__dirname, "target/release/buzz-acp"),
      path.join(__dirname, "target/debug/buzz-acp"),
    ],
    avatar_url: "",
    mcp_command: "buzz-dev-mcp",
    underlying_cli: null,
    model_env_var: "BUZZ_AGENT_MODEL",
    provider_env_var: "BUZZ_AGENT_PROVIDER",
    thinking_env_var: "BUZZ_AGENT_THINKING_EFFORT",
    install_hint: "On this web host, Buzz Agent is the local buzz-acp process.",
    install_instructions_url: "https://github.com/block/buzz",
    can_auto_install: false,
    requires_external_cli: false,
    login_hint: null,
    auth_probe: null,
    source: "builtin",
  },
  {
    id: "goose",
    label: "Goose",
    commands: ["goose"],
    extraPaths: [],
    avatar_url: "",
    mcp_command: null,
    underlying_cli: "goose",
    model_env_var: "GOOSE_MODEL",
    provider_env_var: "GOOSE_PROVIDER",
    thinking_env_var: "GOOSE_THINKING_EFFORT",
    install_hint: "Buzz talks to Goose through the Goose CLI.",
    install_instructions_url:
      "https://goose-docs.ai/docs/getting-started/installation/",
    can_auto_install: false,
    requires_external_cli: true,
    login_hint: null,
    auth_probe: null,
    source: "builtin",
  },
  {
    id: "claude",
    label: "Claude Code",
    commands: ["claude-agent-acp", "claude-code-acp"],
    extraPaths: [],
    avatar_url: "",
    mcp_command: null,
    underlying_cli: "claude",
    model_env_var: null,
    provider_env_var: null,
    thinking_env_var: null,
    install_hint:
      "Buzz talks to Claude Code through an ACP adapter (claude-agent-acp).",
    install_instructions_url: "https://code.claude.com/docs/en/getting-started",
    can_auto_install: false,
    requires_external_cli: true,
    login_hint: "Run the Claude CLI to complete authentication.",
    auth_probe: ["claude", "auth", "status"],
    source: "builtin",
  },
  {
    id: "codex",
    label: "Codex",
    commands: ["codex-acp"],
    extraPaths: [],
    avatar_url: "",
    mcp_command: null,
    underlying_cli: "codex",
    model_env_var: null,
    provider_env_var: null,
    thinking_env_var: null,
    install_hint:
      "Buzz talks to Codex through an ACP adapter (codex-acp).",
    install_instructions_url: "https://developers.openai.com/codex/cli/",
    can_auto_install: false,
    requires_external_cli: true,
    login_hint: "Run `codex login` to authenticate.",
    auth_probe: ["codex", "login", "status"],
    source: "builtin",
  },
  {
    // Host-specific: preferred runtime in web global defaults.
    // Prefer pi-acp-wrapper.js (ACP shim) then `pi` CLI on PATH.
    id: "pi-coding-agent",
    label: "Pi Coding Agent",
    commands: ["pi-coding-agent", "pi"],
    extraPaths: [path.join(__dirname, "pi-acp-wrapper.js")],
    default_args: ["acp"],
    avatar_url: "",
    mcp_command: null,
    underlying_cli: "pi",
    model_env_var: "BUZZ_AGENT_MODEL",
    provider_env_var: "BUZZ_AGENT_PROVIDER",
    thinking_env_var: "BUZZ_AGENT_THINKING_EFFORT",
    install_hint:
      "Install the Pi coding agent CLI, or use the host pi-acp-wrapper.js.",
    install_instructions_url: "https://github.com/badlogic/pi-mono",
    can_auto_install: false,
    requires_external_cli: true,
    login_hint: null,
    auth_probe: null,
    source: "preset",
  },
  // ── Desktop PRESET_HARNESSES (discovery.rs) ──────────────────────────────
  // These are PATH-probed tier-2 entries. Grok Build is `command: grok`, NOT
  // a binary named grok-build (model id grok-build-0.1 is unrelated).
  {
    id: "grok",
    label: "Grok Build",
    commands: ["grok"],
    extraPaths: [
      path.join(process.env.HOME || "/home/lary", ".local/bin/grok"),
      path.join(process.env.HOME || "/home/lary", ".grok/bin/grok"),
    ],
    default_args: ["agent", "--always-approve", "stdio"],
    avatar_url: "",
    mcp_command: null,
    underlying_cli: null,
    model_env_var: null,
    provider_env_var: null,
    thinking_env_var: null,
    install_hint:
      "Buzz talks to Grok Build through its CLI's agent stdio mode.",
    install_instructions_url: "https://build.x.ai/docs",
    can_auto_install: false,
    requires_external_cli: false,
    login_hint: null,
    auth_probe: null,
    source: "preset",
  },
  {
    id: "cursor",
    label: "Cursor",
    commands: ["cursor-agent"],
    extraPaths: [],
    default_args: ["acp"],
    avatar_url: "",
    mcp_command: null,
    underlying_cli: null,
    model_env_var: null,
    provider_env_var: null,
    thinking_env_var: null,
    install_hint:
      "Buzz talks to Cursor through the cursor-agent CLI's ACP mode.",
    install_instructions_url: "https://cursor.com/downloads",
    can_auto_install: false,
    requires_external_cli: false,
    login_hint: null,
    auth_probe: null,
    source: "preset",
  },
  {
    id: "omp",
    label: "Oh My Pi",
    commands: ["omp"],
    extraPaths: [],
    default_args: ["acp"],
    avatar_url: "",
    mcp_command: null,
    underlying_cli: null,
    model_env_var: null,
    provider_env_var: null,
    thinking_env_var: null,
    install_hint: "Buzz talks to Oh My Pi through its CLI's ACP mode (omp acp).",
    install_instructions_url: "https://github.com/can1357/oh-my-pi",
    can_auto_install: false,
    requires_external_cli: false,
    login_hint: null,
    auth_probe: null,
    source: "preset",
  },
  {
    id: "opencode",
    label: "OpenCode",
    commands: ["opencode"],
    extraPaths: [],
    default_args: ["acp"],
    avatar_url: "",
    mcp_command: null,
    underlying_cli: null,
    model_env_var: null,
    provider_env_var: null,
    thinking_env_var: null,
    install_hint:
      "Buzz talks to OpenCode through its CLI's ACP mode (opencode acp).",
    install_instructions_url: "https://opencode.ai/docs",
    can_auto_install: false,
    requires_external_cli: false,
    login_hint: null,
    auth_probe: null,
    source: "preset",
  },
  {
    id: "kimi",
    label: "Kimi Code",
    commands: ["kimi"],
    extraPaths: [],
    default_args: ["acp"],
    avatar_url: "",
    mcp_command: null,
    underlying_cli: null,
    model_env_var: null,
    provider_env_var: null,
    thinking_env_var: null,
    install_hint: "Buzz talks to Kimi Code through its CLI's ACP mode (kimi acp).",
    install_instructions_url: "https://kimi.ai/download",
    can_auto_install: false,
    requires_external_cli: false,
    login_hint: null,
    auth_probe: null,
    source: "preset",
  },
  {
    id: "amp",
    label: "Amp",
    commands: ["amp-acp"],
    extraPaths: [],
    default_args: [],
    avatar_url: "",
    mcp_command: null,
    underlying_cli: "amp",
    model_env_var: null,
    provider_env_var: null,
    thinking_env_var: null,
    install_hint:
      "Buzz talks to the Amp CLI through the amp-acp adapter.",
    install_instructions_url: "https://github.com/tao12345666333/amp-acp",
    can_auto_install: false,
    requires_external_cli: true,
    login_hint: null,
    auth_probe: null,
    source: "preset",
  },
  {
    id: "hermes",
    label: "Hermes Agent",
    commands: ["hermes-acp"],
    extraPaths: [],
    default_args: [],
    avatar_url: "",
    mcp_command: null,
    underlying_cli: null,
    model_env_var: null,
    provider_env_var: null,
    thinking_env_var: null,
    install_hint: "Buzz talks to Hermes Agent through its hermes-acp command.",
    install_instructions_url: "https://hermes-agent.nousresearch.com",
    can_auto_install: false,
    requires_external_cli: false,
    login_hint: null,
    auth_probe: null,
    source: "preset",
  },
  {
    id: "openclaw",
    label: "OpenClaw",
    commands: ["openclaw"],
    extraPaths: [],
    default_args: ["acp"],
    avatar_url: "",
    mcp_command: null,
    underlying_cli: null,
    model_env_var: null,
    provider_env_var: null,
    thinking_env_var: null,
    install_hint:
      "Buzz talks to OpenClaw through its ACP mode (openclaw acp).",
    install_instructions_url:
      "https://docs.openclaw.ai/start/getting-started",
    can_auto_install: false,
    requires_external_cli: false,
    login_hint: null,
    auth_probe: null,
    source: "preset",
  },
];

function probeAuthStatus(probeArgs) {
  if (!probeArgs || !probeArgs.length) {
    return { status: "not_applicable" };
  }
  const bin = resolveCommandOnPath(probeArgs[0]);
  if (!bin) return { status: "unknown" };
  try {
    execSync(
      [bin, ...probeArgs.slice(1)]
        .map((a) => JSON.stringify(a))
        .join(" "),
      {
        encoding: "utf8",
        env: { ...process.env, PATH: hostSearchPath() },
        timeout: 5000,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    return { status: "logged_in" };
  } catch {
    return { status: "logged_out" };
  }
}

function resolveRuntimeBinary(def) {
  for (const extra of def.extraPaths || []) {
    try {
      if (fs.existsSync(extra) && fs.statSync(extra).isFile()) {
        return { command: path.basename(extra), binaryPath: path.resolve(extra) };
      }
    } catch {
      /* continue */
    }
  }
  for (const cmd of def.commands || []) {
    const resolved = resolveCommandOnPath(cmd);
    if (resolved) return { command: cmd, binaryPath: resolved };
  }
  return { command: null, binaryPath: null };
}

function classifyAvailability(def, command, binaryPath, underlyingCliPath) {
  if (command && binaryPath) {
    return "available";
  }
  if (def.requires_external_cli && def.underlying_cli) {
    if (!underlyingCliPath) return "cli_missing";
    // CLI present but ACP adapter/command missing
    return "adapter_missing";
  }
  return "not_installed";
}

/**
 * @returns {Array} RawAcpRuntimeCatalogEntry[] (snake_case, desktop-compatible)
 */
function ipcDiscoverAcpProviders() {
  const nodePath = resolveCommandOnPath("node");
  const entries = [];

  for (const def of KNOWN_HOST_ACP_RUNTIMES) {
    const { command, binaryPath } = resolveRuntimeBinary(def);
    const underlyingCliPath = def.underlying_cli
      ? resolveCommandOnPath(def.underlying_cli)
      : null;

    let availability = classifyAvailability(
      def,
      command,
      binaryPath,
      underlyingCliPath,
    );

    // buzz-agent on this host: treat release binary or running unit as available
    if (def.id === "buzz-agent" && availability !== "available") {
      const release = path.join(__dirname, "target/release/buzz-acp");
      if (fs.existsSync(release)) {
        availability = "available";
      }
    }

    const auth_status =
      availability === "available"
        ? def.auth_probe
          ? probeAuthStatus(def.auth_probe)
          : { status: "not_applicable" }
        : { status: "unknown" };

    // Prefer concrete command name when available; for buzz-acp use full path.
    let resolvedCommand = command;
    let resolvedBinary = binaryPath;
    if (def.id === "buzz-agent" && !resolvedBinary) {
      const release = path.join(__dirname, "target/release/buzz-acp");
      if (fs.existsSync(release)) {
        resolvedCommand = "buzz-acp";
        resolvedBinary = release;
        availability = "available";
      }
    }
    if (def.id === "pi-coding-agent" && !resolvedBinary) {
      const wrapper = path.join(__dirname, "pi-acp-wrapper.js");
      if (fs.existsSync(wrapper)) {
        resolvedCommand = wrapper;
        resolvedBinary = wrapper;
        availability = "available";
      }
    }

    entries.push({
      id: def.id,
      label: def.label,
      avatar_url: def.avatar_url || "",
      availability,
      command: resolvedCommand,
      binary_path: resolvedBinary,
      default_args: Array.isArray(def.default_args) ? def.default_args : [],
      mcp_command: def.mcp_command,
      model_env_var: def.model_env_var,
      provider_env_var: def.provider_env_var,
      thinking_env_var: def.thinking_env_var,
      install_hint: def.install_hint || "",
      install_instructions_url: def.install_instructions_url || "",
      can_auto_install: Boolean(def.can_auto_install),
      requires_external_cli: Boolean(def.requires_external_cli),
      underlying_cli_path: underlyingCliPath,
      node_required: false,
      auth_status,
      login_hint:
        auth_status.status === "logged_in" ||
        auth_status.status === "not_applicable"
          ? null
          : def.login_hint,
      source: def.source || "builtin",
      definition_env: {},
    });
  }

  // Surface node presence for adapters that need npm install (informational).
  if (!nodePath) {
    for (const e of entries) {
      if (
        e.availability === "adapter_missing" ||
        e.availability === "not_installed"
      ) {
        // leave as-is; node is present on this host typically
      }
    }
  }

  return entries;
}

function ipcDiscoverManagedAgentPrereqs(args) {
  const input = args.input || args;
  const acpCommand = String(input.acpCommand || input.acp_command || "buzz-acp").trim();
  const mcpCommand = String(input.mcpCommand || input.mcp_command || "").trim();
  const acpPath = resolveCommandOnPath(acpCommand);
  const mcpPath = mcpCommand ? resolveCommandOnPath(mcpCommand) : null;
  return {
    acp: {
      command: acpCommand,
      resolved_path: acpPath,
      available: Boolean(acpPath),
    },
    mcp: {
      command: mcpCommand || "buzz-dev-mcp",
      resolved_path: mcpPath,
      available: mcpCommand ? Boolean(mcpPath) : true,
    },
  };
}

function ipcDiscoverGitBashPrerequisite() {
  // Linux host — Git Bash is a Windows-only prerequisite; omit card.
  return null;
}

// ── Models / signing (existing) ─────────────────────────────────────────────

async function fetchFedoraModels() {
  try {
    const res = await fetch("http://10.127.127.15:8317/v1/models", {
      headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY || process.env.BUZZ_MODELS_API_KEY || ""}` },
    });
    if (res.ok) {
      const json = await res.json();
      if (Array.isArray(json.data)) {
        return json.data.map((m) => ({
          id: m.id,
          name: m.id,
          description: (m.owned_by ? m.owned_by + " " : "") + m.id,
        }));
      }
    }
  } catch (err) {
    console.error("models fetch failed:", err.message);
  }
  return FALLBACK_MODELS;
}

function createAuthEvent(challenge, relayUrl) {
  if (!challenge) throw new Error("challenge required");
  const relay = (relayUrl && String(relayUrl).trim()) || RELAY_WS;
  const sk = loadSecretKeyBytes();
  return finalizeEvent(
    {
      kind: 22242,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["relay", relay],
        ["challenge", challenge],
      ],
      content: "",
    },
    sk,
  );
}

function signEvent({ kind, content, tags, created_at }) {
  if (typeof kind !== "number") throw new Error("kind required");
  const sk = loadSecretKeyBytes();
  return finalizeEvent(
    {
      kind,
      created_at: created_at ?? Math.floor(Date.now() / 1000),
      tags: Array.isArray(tags) ? tags : [],
      content: typeof content === "string" ? content : "",
    },
    sk,
  );
}

function getServiceStatus() {
  try {
    return execSync("systemctl --user is-active buzz-agent.service", {
      encoding: "utf8",
    }).trim() === "active"
      ? "running"
      : "stopped";
  } catch {
    return "stopped";
  }
}

// ── IPC router ──────────────────────────────────────────────────────────────

async function handleIpc(cmd, args = {}) {
  switch (cmd) {
    case "get_agent_models":
    case "discover_agent_models": {
      const models = await fetchFedoraModels();
      const env = getEnvConfig();
      return {
        agentName: "Fedora-Agent",
        agentVersion: "0.81.1",
        models,
        agentDefaultModel: "grok-4.5",
        selectedModel: env.BUZZ_ACP_MODEL || env.GOOSE_MODEL || "grok-4.5",
        supportsSwitching: true,
      };
    }

    // Remote run destinations — NOT models. Empty = local-only create flow.
    case "discover_backend_providers":
      return [];

    // Settings → Agents: PATH-probe harness CLIs (desktop discover_acp_providers).
    case "discover_acp_providers":
    case "discover_acp_runtimes":
      return ipcDiscoverAcpProviders();

    case "discover_managed_agent_prereqs":
      return ipcDiscoverManagedAgentPrereqs(args);

    case "discover_git_bash_prerequisite":
      // null = hide Windows Git Bash card on Linux web host
      return ipcDiscoverGitBashPrerequisite();

    case "list_personas":
      return ipcListPersonas();

    case "create_persona":
      return ipcCreatePersona(args);

    case "update_persona":
      return ipcUpdatePersona(args);

    case "set_persona_active":
      return ipcSetPersonaActive(args);

    case "nip44_encrypt_to_self":
      return ipcNip44EncryptToSelf(args);

    case "nip44_decrypt_from_self":
      return ipcNip44DecryptFromSelf(args);

    case "create_auth_event": {
      const challenge =
        args.challenge ?? args.input?.challenge ?? args.req?.challenge;
      const relayUrl =
        args.relayUrl ??
        args.relay_url ??
        args.input?.relayUrl ??
        RELAY_WS;
      return JSON.stringify(createAuthEvent(challenge, relayUrl));
    }

    case "sign_event": {
      const kind = args.kind ?? args.input?.kind;
      const content = args.content ?? args.input?.content ?? "";
      const tags = args.tags ?? args.input?.tags ?? [];
      const created_at =
        args.created_at ?? args.createdAt ?? args.input?.created_at;
      return JSON.stringify(signEvent({ kind, content, tags, created_at }));
    }

    case "get_identity":
      return getHostIdentity();

    case "get_nsec":
      // Host-held: BackupStep during onboarding needs the nsec once.
      return getHostNsec();

    case "persist_current_identity": {
      // Desktop persists an ephemeral keyring key. On web:
      // - default: ensure current host key is durable in identity file + env
      // - forceNew / generateNew: mint a fresh host-held keypair
      const forceNew =
        args.forceNew === true ||
        args.generateNew === true ||
        args.rotate === true ||
        (args.input &&
          (args.input.forceNew === true ||
            args.input.generateNew === true ||
            args.input.rotate === true));
      if (forceNew) {
        const display =
          args.displayName ||
          args.display_name ||
          process.env.BUZZ_WEB_DISPLAY_NAME ||
          "fedora";
        const user =
          args.username || process.env.BUZZ_WEB_USERNAME || display;
        generateHostIdentity(display, user);
      } else {
        // Re-persist current material so identity file always matches env.
        // If nothing is installed yet, mint a first host-held key.
        let seckeyHex;
        try {
          seckeyHex = loadSecretKeyHex();
        } catch {
          seckeyHex = null;
        }
        if (!seckeyHex) {
          const display =
            args.displayName ||
            args.display_name ||
            process.env.BUZZ_WEB_DISPLAY_NAME ||
            "fedora";
          const user =
            args.username || process.env.BUZZ_WEB_USERNAME || display;
          generateHostIdentity(display, user);
        } else {
          installHostIdentity({
            seckeyHex,
            displayName:
              process.env.BUZZ_WEB_DISPLAY_NAME ||
              (readIdentityFile() || {}).display_name ||
              "fedora",
            username:
              process.env.BUZZ_WEB_USERNAME ||
              (readIdentityFile() || {}).username ||
              "fedora",
            source: "persist_current_identity",
          });
        }
      }
      return getHostIdentity();
    }

    case "import_identity": {
      const nsec = args.nsec || args.input?.nsec || "";
      importHostIdentityFromNsec(nsec);
      return getHostIdentity();
    }

    case "create_host_identity":
    case "generate_host_identity": {
      const display =
        args.displayName ||
        args.display_name ||
        process.env.BUZZ_WEB_DISPLAY_NAME ||
        "fedora";
      const user = args.username || process.env.BUZZ_WEB_USERNAME || display;
      generateHostIdentity(display, user);
      return getHostIdentity();
    }

    case "get_channels":
    case "list_channels":
      return await ipcGetChannels();

    case "ensure_starter_channels":
      // Create missing open starters (stable UUID v5) + join if not member.
      return await ipcEnsureStarterChannels();

    case "get_channel_details":
      return await ipcGetChannelDetails(
        args.channelId || args.channel_id || args.id,
      );

    case "get_channel_members":
    case "list_channel_members":
      return await ipcGetChannelMembers(
        args.channelId || args.channel_id || args.id,
      );

    case "get_channel_messages_before":
      return await ipcGetChannelMessagesBefore(args);

    case "get_channel_window":
      return await ipcGetChannelWindow(args);

    case "get_event": {
      const eventId = args.eventId || args.event_id || args.id;
      if (!eventId) throw new Error("eventId required");
      const events = await queryRelay([
        { ids: [eventId], limit: 1 },
      ]);
      if (!events[0]) throw new Error("event not found");
      return JSON.stringify(events[0]);
    }

    case "send_channel_message":
      return await ipcSendChannelMessage(args);

    case "create_channel":
      return await ipcCreateChannel(args);

    case "join_channel":
      return await ipcJoinChannel(args);

    case "add_channel_members":
      return await ipcAddChannelMembers(args);

    case "update_channel":
      return await ipcUpdateChannel(args.input || args);

    // ── DMs / membership / messages / reactions (core product path) ──
    case "open_dm":
      return await ipcOpenDm(
        args.input && typeof args.input === "object"
          ? { ...args, ...args.input }
          : args,
      );
    case "hide_dm":
      return await ipcHideDm(args);
    case "leave_channel":
      return await ipcLeaveChannel(args);
    case "remove_channel_member":
      return await ipcRemoveChannelMember(args);
    case "change_channel_member_role":
      return await ipcChangeChannelMemberRole(args);
    case "add_reaction":
      return await ipcAddReaction(args);
    case "remove_reaction":
      return await ipcRemoveReaction(args);
    case "edit_message":
      return await ipcEditMessage(args);
    case "delete_message":
      return await ipcDeleteMessage(args);
    case "archive_channel":
      return await ipcArchiveChannel(args, true);
    case "unarchive_channel":
      return await ipcArchiveChannel(args, false);
    case "delete_channel":
      return await ipcDeleteChannel(args);
    case "set_channel_topic":
      return await ipcSetChannelTopic(args);
    case "set_channel_purpose":
      return await ipcSetChannelPurpose(args);

    // ── Agent observer (ACP activity pane) ──
    case "decrypt_observer_event":
      return ipcDecryptObserverEvent(args);
    case "build_observer_control_event":
      return ipcBuildObserverControlEvent(args);

    case "get_profile":
    case "get_user_profile":
      return await ipcGetProfile(args.pubkey || args.pubKey);

    case "get_users_batch":
      return await ipcGetUsersBatch(args);

    case "list_relay_agents":
      return await ipcListRelayAgents();

    case "list_managed_agents":
    case "get_managed_agents": {
      // Refresh process liveness before listing
      const store = loadManagedAgentsStore();
      let changed = false;
      for (let i = 0; i < store.agents.length; i++) {
        const before = store.agents[i].status;
        store.agents[i] = syncManagedAgentRuntimeStatus(store.agents[i]);
        if (store.agents[i].status !== before) changed = true;
      }
      if (changed) saveManagedAgentsStore(store);
      return ipcListManagedAgents();
    }

    case "create_managed_agent":
      return ipcCreateManagedAgent(args);

    case "update_managed_agent":
      return ipcUpdateManagedAgent(args);

    case "get_global_agent_config":
      return ipcGetGlobalAgentConfig();

    case "set_global_agent_config":
      return ipcSetGlobalAgentConfig(args);

    case "get_agent_config_surface":
      return ipcGetAgentConfigSurface(args);

    case "put_agent_session_config":
      return ipcPutAgentSessionConfig(args);

    case "get_runtime_file_config":
      return ipcGetRuntimeFileConfig(args);

    case "delete_managed_agent":
      return ipcDeleteManagedAgent(args);

    case "start_managed_agent":
      return ipcStartManagedAgent(args);

    case "stop_managed_agent":
      return ipcStopManagedAgent(args);

    case "update_profile":
      return await ipcUpdateProfile(args);

    case "ensure_host_profile":
      return await ensureHostProfilePublished();

    case "list_archived_identities":
      return await ipcListArchivedIdentities();

    case "get_relay_http_url":
      return RELAY_HTTP;

    case "get_relay_ws_url":
    case "get_default_relay_url":
      return RELAY_WS;

    case "get_relay_self": {
      // NIP-11 `self` (hex). Optional; null is valid and must not be [].
      try {
        const res = await fetch(RELAY_HTTP, {
          headers: { Accept: "application/nostr+json" },
        });
        if (!res.ok) return null;
        const doc = await res.json();
        const selfPk =
          (typeof doc.self === "string" && doc.self) ||
          (typeof doc.pubkey === "string" && doc.pubkey) ||
          null;
        if (
          selfPk &&
          /^[0-9a-f]{64}$/i.test(selfPk.trim())
        ) {
          return selfPk.trim().toLowerCase();
        }
      } catch (err) {
        console.warn("get_relay_self failed:", err.message);
      }
      return null;
    }

    case "get_private_key":
    case "get_identity_key":
      // Prefer get_nsec for onboarding backup; raw hex stays host-only.
      throw new Error("use get_nsec for backup; raw hex is not exposed");

    default:
      // undefined = not handled (null is a valid IPC value, e.g. get_relay_self)
      return undefined;
  }
}

// ── HTTP server ─────────────────────────────────────────────────────────────

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 2_000_000) {
        reject(new Error("body too large"));
        req.destroy();
      }
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = req.url || "/";

  if (url === "/api/ipc" && req.method === "POST") {
    try {
      const raw = await readBody(req);
      const { cmd, args } = JSON.parse(raw || "{}");
      if (!cmd || typeof cmd !== "string") {
        sendJson(res, 400, { error: "cmd required" });
        return;
      }
      const result = await handleIpc(cmd, args || {});
      if (result === undefined) {
        sendJson(res, 404, { error: "unknown cmd", cmd });
        return;
      }
      sendJson(res, 200, result);
    } catch (err) {
      console.error("[ipc]", err);
      sendJson(res, 500, {
        error: err instanceof Error ? err.message : String(err),
      });
    }
    return;
  }

  if (url === "/api/status" && req.method === "GET") {
    try {
      const identity = getHostIdentity();
      sendJson(res, 200, {
        ok: true,
        role: "desktop-replacement",
        agent: getServiceStatus(),
        pubkey: identity.pubkey,
        owner_pubkey: identity.owner_pubkey,
        relay: RELAY_HTTP,
      });
    } catch (err) {
      sendJson(res, 500, {
        error: err instanceof Error ? err.message : String(err),
      });
    }
    return;
  }

  if (url === "/api/agents" && req.method === "GET") {
    const env = getEnvConfig();
    let pubkey;
    try {
      pubkey = hostPubkey();
    } catch {
      pubkey = "unknown";
    }
    sendJson(res, 200, [
      {
        id: "fedora-agent-main",
        name: "Fedora-Agent",
        pubkey,
        status: getServiceStatus(),
        model: env.BUZZ_ACP_MODEL || env.GOOSE_MODEL || "grok-4.5",
        provider: env.GOOSE_PROVIDER || "openai",
        owner: env.BUZZ_ACP_AGENT_OWNER || null,
        runtime: "pi-coding-agent",
      },
    ]);
    return;
  }

  if (url === "/api/agents/start" && req.method === "POST") {
    try {
      execSync("systemctl --user start buzz-agent.service");
      sendJson(res, 200, { ok: true, status: "running" });
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err.message });
    }
    return;
  }

  if (url === "/api/agents/stop" && req.method === "POST") {
    try {
      execSync("systemctl --user stop buzz-agent.service");
      sendJson(res, 200, { ok: true, status: "stopped" });
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err.message });
    }
    return;
  }

  if (url === "/api/agents/model" && req.method === "POST") {
    try {
      const raw = await readBody(req);
      const { model } = JSON.parse(raw || "{}");
      if (!model) {
        sendJson(res, 400, { ok: false, error: "invalid payload" });
        return;
      }
      let envText = fs.readFileSync(ENV_PATH, "utf8");
      envText = envText.replace(/BUZZ_ACP_MODEL=.*/g, "BUZZ_ACP_MODEL=" + model);
      envText = envText.replace(/GOOSE_MODEL=.*/g, "GOOSE_MODEL=" + model);
      fs.writeFileSync(ENV_PATH, envText);
      exec("systemctl --user restart buzz-agent.service");
      sendJson(res, 200, { ok: true, model });
    } catch (err) {
      sendJson(res, 500, {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
    return;
  }

  sendJson(res, 404, { error: "not found" });
});

server.listen(PORT, "0.0.0.0", () => {
  try {
    const id = getHostIdentity();
    console.log(
      `Buzz host IPC (desktop-replacement) :${PORT} identity=${id.pubkey.slice(0, 12)}… relay=${RELAY_HTTP}`,
    );
  } catch (err) {
    console.log(`Buzz host IPC :${PORT} (key error: ${err.message})`);
  }
});
