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
const { finalizeEvent, getPublicKey, nip19 } = requireDesktop("nostr-tools");

/** Mirror desktop TIMELINE_KINDS minus huddle (voice out of scope). */
const TIMELINE_KINDS = [9, 40002, 40008, 40099, 43001, 43002, 43003, 43004, 43005, 43006];

/** Channels we just created: membership (kind:39002) may lag; treat as member. */
const pendingOwnedChannelIds = new Set();

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

function buildNip98Auth(method, url, bodyBuf) {
  const sk = loadSecretKeyBytes();
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

async function submitEvent(event) {
  const url = `${RELAY_HTTP}/events`;
  const bodyBuf = Buffer.from(JSON.stringify(event));
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

/**
 * Desktop-style managed agent list for path-3 web.
 * Maps host buzz-acp + systemctl into RawManagedAgent[] (snake_case).
 */
function ipcListManagedAgents() {
  // Fresh onboard: do not invent a managed agent when buzz-agent is stopped/disabled.
  // Set BUZZ_WEB_SHOW_STOPPED_AGENT=1 to surface the systemd unit as a stopped agent.
  const status = getServiceStatus();
  if (status !== "running" && process.env.BUZZ_WEB_SHOW_STOPPED_AGENT !== "1") {
    return [];
  }
  const env = getEnvConfig();
  const agentPk = getAgentPubkey();
  const ownerPk =
    process.env.BUZZ_ACP_AGENT_OWNER ||
    env.BUZZ_ACP_AGENT_OWNER ||
    hostPubkey();
  const now = new Date().toISOString();
  const model = env.BUZZ_ACP_MODEL || env.GOOSE_MODEL || "grok-4.5";
  const running = status === "running";
  return [
    {
      pubkey: agentPk,
      name: "Fedora-Agent",
      persona_id: null,
      team_id: null,
      relay_url: RELAY_WS,
      acp_command: "buzz-acp",
      agent_command: env.BUZZ_ACP_AGENT_COMMAND || "pi-coding-agent",
      agent_command_override: null,
      agent_args: ["acp"],
      mcp_command: "",
      turn_timeout_seconds: 320,
      idle_timeout_seconds: null,
      max_turn_duration_seconds: null,
      parallelism: 1,
      system_prompt: null,
      avatar_url: null,
      model,
      provider: env.GOOSE_PROVIDER || "openai",
      persona_out_of_date: false,
      persona_orphaned: false,
      needs_restart: false,
      env_vars: {},
      status: running ? "running" : "stopped",
      pid: running ? 1 : null,
      created_at: now,
      updated_at: now,
      last_started_at: running ? now : null,
      last_stopped_at: running ? null : now,
      last_exit_code: null,
      last_error: null,
      last_error_code: null,
      log_path: `/tmp/buzz-acp-${agentPk.slice(0, 12)}.log`,
      start_on_app_launch: true,
      auto_restart_on_config_change: true,
      backend: { type: "local" },
      backend_agent_id: null,
      respond_to: env.BUZZ_ACP_RESPOND_TO || "owner-only",
      respond_to_allowlist: ownerPk ? [ownerPk] : [],
    },
  ];
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
    case "discover_agent_models":
    case "discover_backend_providers": {
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
    case "ensure_starter_channels":
      // No fake starter channels — real membership from relay.
      return await ipcGetChannels();

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

    case "get_profile":
    case "get_user_profile":
      return await ipcGetProfile(args.pubkey || args.pubKey);

    case "get_users_batch":
      return await ipcGetUsersBatch(args);

    case "list_relay_agents":
      return await ipcListRelayAgents();

    case "list_managed_agents":
    case "get_managed_agents":
      return ipcListManagedAgents();

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
