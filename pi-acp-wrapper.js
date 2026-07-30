#!/usr/bin/env node
/**
 * Minimal ACP server that bridges buzz-acp → local `pi` CLI (-p print mode).
 *
 * Why this exists: stock `pi` speaks RPC / interactive modes, not ACP stdio.
 * buzz-acp expects an ACP agent on stdin/stdout. This shim implements the
 * small ACP surface buzz-acp actually uses (initialize, session/*, prompt)
 * and shells out to `pi -p` for the real model call.
 *
 * Env (inherited from buzz-acp / host daemon):
 *   BUZZ_ACP_MODEL / GOOSE_MODEL / BUZZ_AGENT_MODEL  → --model
 *   OPENAI_BASE_URL / OPENAI_API_KEY                 → passed through to pi
 *   PI_PATH                                         → override pi binary
 *   PI_PROVIDER                                     → optional --provider
 *   PI_PROMPT_TIMEOUT_MS                            → kill hung pi (default 180s)
 */
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const readline = require("readline");

const LOG_PATH =
  process.env.PI_ACP_WRAPPER_LOG ||
  path.join("/tmp", `pi-acp-wrapper-${process.pid}.log`);

function log(...args) {
  const line = `[${new Date().toISOString()}] ${args
    .map((a) => (typeof a === "string" ? a : JSON.stringify(a)))
    .join(" ")}\n`;
  try {
    fs.appendFileSync(LOG_PATH, line);
  } catch {
    /* ignore */
  }
}

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function resolvePiBinary() {
  if (process.env.PI_PATH && fs.existsSync(process.env.PI_PATH)) {
    return process.env.PI_PATH;
  }
  const candidates = [
    path.join(process.env.HOME || "", ".local/share/pnpm/bin/pi"),
    path.join(process.env.HOME || "", ".local/bin/pi"),
    "/usr/local/bin/pi",
  ];
  for (const c of candidates) {
    if (c && fs.existsSync(c)) return c;
  }
  return "pi";
}

function resolveModel() {
  return (
    process.env.BUZZ_ACP_MODEL ||
    process.env.GOOSE_MODEL ||
    process.env.BUZZ_AGENT_MODEL ||
    process.env.PI_MODEL ||
    ""
  );
}

function resolveProvider() {
  // Prefer explicit PI_PROVIDER. Never default to "openai" — that hits
  // api.openai.com. Host's ~/.pi/agent/settings.json uses defaultProvider
  // "cpa" (local proxy). Empty string = do not pass --provider/--model and
  // let pi use its saved defaults (most reliable for this machine).
  return process.env.PI_PROVIDER || process.env.BUZZ_ACP_PI_PROVIDER || "";
}

function extractPromptText(params) {
  if (!params) return "";
  const prompt = params.prompt;
  if (typeof prompt === "string") return prompt;
  if (Array.isArray(prompt)) {
    return prompt
      .map((p) => {
        if (typeof p === "string") return p;
        if (p && typeof p === "object") {
          if (typeof p.text === "string") return p.text;
          if (p.type === "text" && typeof p.text === "string") return p.text;
        }
        return "";
      })
      .filter(Boolean)
      .join("\n");
  }
  return "";
}

function buildPiArgs(promptText) {
  // Match interactive pi defaults unless the host explicitly overrides.
  // Passing bare --model grok-4.5 without provider made pi pick "opencode".
  const args = ["-p", promptText, "--no-session"];
  const provider = resolveProvider();
  let model = resolveModel();

  if (provider && model && !model.includes("/")) {
    args.push("--provider", provider);
    args.push("--model", model);
  } else if (provider && !model) {
    args.push("--provider", provider);
  } else if (model && model.includes("/")) {
    // e.g. cpa/grok-4.5
    args.push("--model", model);
  } else if (model) {
    // Model-only: use provider/id form with host default "cpa" so pi does not
    // invent a broken provider. Override via PI_PROVIDER if needed.
    const fallbackProvider =
      process.env.PI_DEFAULT_PROVIDER || "cpa";
    args.push("--model", `${fallbackProvider}/${model}`);
  }
  // Do NOT pass --offline: it breaks provider auth for cpa/openai proxies.
  return args;
}

function runPiPrompt(promptText, { onChunk }) {
  const timeoutMs = Number(process.env.PI_PROMPT_TIMEOUT_MS || 180_000);
  const piPath = resolvePiBinary();
  const args = buildPiArgs(promptText);

  // Fix PATH so pnpm global bin is reachable (previous typo: pnmp).
  const home = process.env.HOME || "/home/lary";
  const pathExtra = [
    path.join(home, ".local/share/pnpm/bin"),
    path.join(home, ".local/bin"),
    "/usr/local/bin",
  ];
  const pathParts = String(process.env.PATH || "")
    .split(path.delimiter)
    .filter(Boolean);
  for (const extra of pathExtra) {
    if (!pathParts.includes(extra)) pathParts.unshift(extra);
  }

  log("spawn", piPath, args.slice(0, 6).join(" "), `timeout=${timeoutMs}ms`);

  return new Promise((resolve) => {
    let settled = false;
    let stdout = "";
    let stderr = "";

    const child = spawn(piPath, args, {
      env: {
        ...process.env,
        PATH: pathParts.join(path.delimiter),
        // Keep proxy credentials if host injected them.
        OPENAI_BASE_URL: process.env.OPENAI_BASE_URL || process.env.OPENAI_API_BASE,
        OPENAI_API_KEY: process.env.OPENAI_API_KEY,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    const timer = setTimeout(() => {
      if (settled) return;
      log("timeout killing pi");
      try {
        child.kill("SIGTERM");
      } catch {
        /* ignore */
      }
      setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          /* ignore */
        }
      }, 2000);
    }, timeoutMs);

    child.stdout.on("data", (buf) => {
      const text = buf.toString("utf8");
      stdout += text;
      if (text && onChunk) onChunk(text);
    });
    child.stderr.on("data", (buf) => {
      stderr += buf.toString("utf8");
    });

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (stderr.trim()) log("pi stderr:", stderr.trim().slice(0, 800));
      log("pi exit", result);
      resolve(result);
    };

    child.on("error", (err) => {
      finish({
        ok: false,
        text: `[Error spawning pi (${piPath}): ${err.message}]`,
        code: -1,
      });
    });

    child.on("close", (code) => {
      const trimmed = stdout.trim();
      if (code !== 0 && !trimmed) {
        finish({
          ok: false,
          text:
            `[pi exited ${code}]` +
            (stderr.trim() ? `\n${stderr.trim().slice(0, 500)}` : ""),
          code,
        });
        return;
      }
      finish({ ok: true, text: trimmed || "(empty response)", code });
    });
  });
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

// Serialize prompts — pi is not re-entrant in this shim.
let promptChain = Promise.resolve();

log("wrapper start", { pid: process.pid, pi: resolvePiBinary() });

rl.on("line", (line) => {
  if (!line.trim()) return;
  let req;
  try {
    req = JSON.parse(line);
  } catch (err) {
    log("bad json", String(err.message || err));
    return;
  }

  const { id, method, params } = req;

  if (method === "initialize") {
    send({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: 1,
        agentInfo: { name: "pi-coding-agent", version: "0.82.1" },
        agentCapabilities: {
          loadSession: true,
          promptCapabilities: { image: true, embeddedContext: true },
          sessionCapabilities: { list: {}, close: {} },
        },
      },
    });
    return;
  }

  if (method === "session/new" || method === "session/load") {
    send({
      jsonrpc: "2.0",
      id,
      result: { sessionId: `pi-session-${Date.now()}` },
    });
    return;
  }

  if (method === "session/prompt") {
    const promptText = extractPromptText(params) || "Hello";
    promptChain = promptChain
      .then(async () => {
        log("session/prompt", promptText.slice(0, 200));
        const result = await runPiPrompt(promptText, {
          onChunk: (text) => {
            send({
              jsonrpc: "2.0",
              method: "session/update",
              params: {
                update: {
                  sessionUpdate: "agent_message_chunk",
                  content: { type: "text", text },
                },
              },
            });
          },
        });
        if (!result.ok) {
          send({
            jsonrpc: "2.0",
            method: "session/update",
            params: {
              update: {
                sessionUpdate: "agent_message_chunk",
                content: { type: "text", text: result.text },
              },
            },
          });
        }
        if (id !== undefined) {
          send({
            jsonrpc: "2.0",
            id,
            result: { stopReason: "end_turn" },
          });
        }
      })
      .catch((err) => {
        log("prompt chain error", String(err && err.message ? err.message : err));
        if (id !== undefined) {
          send({
            jsonrpc: "2.0",
            id,
            result: { stopReason: "end_turn" },
          });
        }
      });
    return;
  }

  if (method === "session/cancel") {
    // Best-effort: we don't track child pids across cancel in this shim.
    if (id !== undefined) send({ jsonrpc: "2.0", id, result: {} });
    return;
  }

  if (id !== undefined) {
    send({ jsonrpc: "2.0", id, result: {} });
  }
});

rl.on("close", () => {
  log("stdin closed — draining prompt queue");
  // Don't exit until in-flight prompt finishes (parent may close stdin early
  // in tests; buzz-acp keeps the pipe open for the process lifetime).
  promptChain.finally(() => {
    log("exiting after drain");
    process.exit(0);
  });
});
