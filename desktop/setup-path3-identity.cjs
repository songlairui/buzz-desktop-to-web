const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { generateSecretKey, getPublicKey, finalizeEvent } = require("nostr-tools");

function bytesToHex(b) {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const o = new Uint8Array(hex.length / 2);
  for (let i = 0; i < o.length; i++) o[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return o;
}

async function main() {
  const dir = "/home/lary/.config/buzz-web";
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const idPath = path.join(dir, "desktop-identity.json");

  let human;
  if (fs.existsSync(idPath)) {
    human = JSON.parse(fs.readFileSync(idPath, "utf8"));
    console.log("reuse", human.pubkey);
  } else {
    const sk = generateSecretKey();
    human = {
      role: "fedora-web-desktop",
      created_at: new Date().toISOString(),
      seckey_hex: bytesToHex(sk),
      pubkey: getPublicKey(sk),
      display_name: "Fedora-Desktop",
    };
    fs.writeFileSync(idPath, JSON.stringify(human, null, 2), { mode: 0o600 });
    fs.chmodSync(idPath, 0o600);
    console.log("created", human.pubkey);
  }

  const envText = fs.readFileSync("/home/lary/.config/buzz-agent/env", "utf8");
  const agentSkHex = envText
    .split("\n")
    .find((l) => l.startsWith("BUZZ_PRIVATE_KEY="))
    .split("=")
    .slice(1)
    .join("=")
    .trim();
  const agentSk = hexToBytes(agentSkHex);
  const agentPk = getPublicKey(agentSk);
  const humanSk = hexToBytes(human.seckey_hex);
  console.log("agent", agentPk);
  console.log("human", human.pubkey);

  const conditions = "";
  const preimage = Buffer.from("nostr:agent-auth:" + agentPk + ":" + conditions, "utf8");
  const msg = crypto.createHash("sha256").update(preimage).digest();
  let schnorr;
  try {
    schnorr = require("@noble/curves/secp256k1").schnorr;
  } catch {
    schnorr = require("@noble/secp256k1").schnorr;
  }
  const sig = Buffer.from(schnorr.sign(msg, humanSk)).toString("hex");
  const authTag = ["auth", human.pubkey, conditions, sig];
  console.log("oa_sig_len", sig.length);

  async function nip98(method, url, bodyObj, sk) {
    const body = bodyObj == null ? Buffer.alloc(0) : Buffer.from(JSON.stringify(bodyObj));
    const payload = crypto.createHash("sha256").update(body).digest("hex");
    const authEv = finalizeEvent(
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
    const res = await fetch(url, {
      method,
      headers: {
        "Content-Type": "application/json",
        Authorization: "Nostr " + Buffer.from(JSON.stringify(authEv)).toString("base64"),
      },
      body: body.length ? body : undefined,
    });
    const text = await res.text();
    if (!res.ok) throw new Error(method + " " + url + " " + res.status + " " + text.slice(0, 300));
    return text ? JSON.parse(text) : null;
  }

  const RELAY = "https://buzz.f.mtt.cool";

  try {
    const humanProfile = finalizeEvent(
      {
        kind: 0,
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        content: JSON.stringify({
          name: "fedora-desktop",
          display_name: "Fedora-Desktop",
          about: "Web desktop user on Fedora (path-3)",
        }),
      },
      humanSk,
    );
    await nip98("POST", RELAY + "/events", humanProfile, humanSk);
    console.log("human_profile_ok");
  } catch (e) {
    console.log("human_profile_fail", e.message);
  }

  try {
    const agentProfile = finalizeEvent(
      {
        kind: 0,
        created_at: Math.floor(Date.now() / 1000),
        tags: [authTag],
        content: JSON.stringify({
          name: "Fedora-Agent",
          display_name: "Fedora-Agent",
          about: "Pi Coding Agent on Fedora Host",
        }),
      },
      agentSk,
    );
    await nip98("POST", RELAY + "/events", agentProfile, agentSk);
    console.log("agent_profile_oa_ok");
  } catch (e) {
    console.log("agent_profile_fail", e.message);
  }

  try {
    const ch = await nip98("POST", RELAY + "/query", [{ kinds: [39000], limit: 3 }], humanSk);
    console.log("human_query_ok", Array.isArray(ch) ? ch.length : ch);
  } catch (e) {
    console.log("human_query_fail", e.message);
  }

  fs.writeFileSync(
    path.join(dir, "agent-oa-auth-tag.json"),
    JSON.stringify({ auth_tag: authTag, agent_pubkey: agentPk, owner_pubkey: human.pubkey }, null, 2),
    { mode: 0o600 },
  );
  console.log("done");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
