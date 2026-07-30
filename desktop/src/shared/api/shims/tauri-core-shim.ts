import {
  acknowledgePendingCommunityDeepLink,
  getPendingCommunityDeepLinks,
  ingestWebDeepLinksFromLocation,
  takePendingCommunityDeepLink,
} from "./web-deep-links";

export const isTauri = () => false;

export class Resource {
  rid: number = 0;
  async close() {}
}

export async function addPluginListener<T = unknown>(
  _plugin: string,
  _event: string,
  _cb: (payload: T) => void
) {
  return () => {};
}

export class Channel<T = unknown> {
  id: string;
  onmessage: ((message: T) => void) | null = null;
  constructor(onmessage?: (message: T) => void) {
    this.id = "channel-" + Math.random().toString(36).slice(2);
    if (onmessage) {
      this.onmessage = onmessage;
    }
  }
  send(message: T) {
    if (this.onmessage) {
      this.onmessage(message);
    }
  }
}

/**
 * Path-3: web session = desktop human (BUZZ_WEB_PRIVATE_KEY on host daemon).
 * Agent process remains BUZZ_PRIVATE_KEY.
 *
 * Do NOT auto-stamp onboarding or seed a community — that skipped the full
 * Welcome / connect flow. Session pubkey is cached only after identity resolves.
 */

const FALLBACK_SESSION_PUBKEY =
  "50ed5fefccd9ea7e3c7f22aa31a5a6a38ca0c4697a84c31f6fecc02c88b8043a";

function rememberSessionPubkey(pubkey: string) {
  if (typeof window === "undefined" || !pubkey) return;
  localStorage.setItem("buzz-web-session-pubkey", pubkey);
  // Host already holds the seckey — machine identity onboarding is done.
  // Do NOT seed communities / skip Welcome; only skip "create or enter nsec".
  localStorage.setItem(`buzz-machine-onboarding-complete.v2:${pubkey}`, "true");
}

// Ingest ?connect / /connect / buzz://… query forms once at module load.
if (typeof window !== "undefined") {
  ingestWebDeepLinksFromLocation();
}

/** POST /api/ipc — host daemon. Throws on non-OK so callers don't swallow AUTH failures. */
async function hostIpc<T = unknown>(
  cmd: string,
  args: Record<string, unknown> = {},
): Promise<T> {
  const res = await fetch("/api/ipc", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cmd, args }),
  });
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    const msg =
      data &&
      typeof data === "object" &&
      data !== null &&
      "error" in data &&
      typeof (data as { error: unknown }).error === "string"
        ? (data as { error: string }).error
        : `host ipc ${cmd} failed: HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data as T;
}

const wsSockets = new Map<number, WebSocket>();
let nextWsId = 1;

export async function invoke<T = unknown>(
  cmd: string,
  args: Record<string, unknown> = {}
): Promise<T> {
  console.log("[Web-Shim] invoke:", cmd, args);

  switch (cmd) {
    // AgentDefaultsEditor uses discover_agent_models; get_agent_models is the
    // older per-agent path. Both should hit the host daemon model list.
    //
    // IMPORTANT: discover_backend_providers is a DIFFERENT command — it must
    // return BackendProviderCandidate[] (remote run destinations). Mapping it
    // to the models object made WhereToRunSection call `.find` on a non-array
    // and crash Create Agent ("i.find is not a function").
    case "discover_backend_providers":
      // Web host: no remote backend binaries; local-only create flow.
      return [] as unknown as T;

    case "get_agent_models":
    case "discover_agent_models": {
      try {
        const res = await fetch("/api/ipc", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            cmd: "get_agent_models",
            args,
          }),
        });
        if (res.ok) {
          const data = await res.json();
          if (data && data.models) return data as unknown as T;
        }
      } catch (err) {}
      return {
        agentName: "Fedora-Agent",
        agentVersion: "0.81.1",
        models: [
          { id: "grok-4.5", name: "grok-4.5", description: "xAI Grok 4.5" },
          { id: "claude-sonnet-4-6", name: "claude-sonnet-4-6", description: "Anthropic Claude Sonnet 4.6" }
        ],
        agentDefaultModel: "grok-4.5",
        selectedModel: "grok-4.5",
        supportsSwitching: true
      } as unknown as T;
    }

    case "nip44_encrypt_to_self":
    case "nip44_decrypt_from_self":
      return (await hostIpc(cmd, args)) as T;

    case "create_auth_event": {
      // Host signs with BUZZ_PRIVATE_KEY — never mock. createAuthEvent() JSON.parses the result.
      const data = await hostIpc<string | Record<string, unknown>>(
        "create_auth_event",
        args,
      );
      if (typeof data === "string") {
        // Daemon already returns JSON string of the event (Tauri parity).
        return data as unknown as T;
      }
      if (data && typeof data === "object" && "id" in data && "sig" in data) {
        return JSON.stringify(data) as unknown as T;
      }
      throw new Error("create_auth_event: unexpected host response");
    }

    case "sign_event": {
      const data = await hostIpc<string | Record<string, unknown>>(
        "sign_event",
        args,
      );
      if (typeof data === "string") return data as unknown as T;
      if (data && typeof data === "object") {
        return JSON.stringify(data) as unknown as T;
      }
      throw new Error("sign_event: unexpected host response");
    }

    case "plugin:websocket|connect": {
      const url = (args.url as string) || "wss://buzz.f.mtt.cool";
      const onMessageChannel = args.onMessage as Channel<unknown>;
      const id = nextWsId++;
      try {
        const ws = new WebSocket(url);
        wsSockets.set(id, ws);
        ws.onmessage = (event) => {
          if (onMessageChannel) {
            onMessageChannel.send({ type: "Text", data: event.data });
          }
        };
        ws.onerror = (err) => {
          console.warn("[Web-Shim WS Error]", url, err);
        };
        ws.onclose = () => {
          wsSockets.delete(id);
        };
      } catch (e) {
        console.warn("[Web-Shim WS Connect Exception]", url, e);
      }
      return id as unknown as T;
    }

    case "plugin:websocket|send": {
      const id = (args.id as number) || (args.wsId as number);
      const message = args.message as any;
      const ws = wsSockets.get(id);
      if (ws && ws.readyState === WebSocket.OPEN) {
        const payload =
          typeof message === "string"
            ? message
            : message?.data
            ? message.data
            : JSON.stringify(message);
        ws.send(payload);
      }
      return true as unknown as T;
    }

    case "plugin:websocket|disconnect":
    case "plugin:websocket|disconnect_all": {
      const id = args.id as number;
      if (id && wsSockets.has(id)) {
        wsSockets.get(id)?.close();
        wsSockets.delete(id);
      } else if (cmd === "plugin:websocket|disconnect_all") {
        for (const ws of wsSockets.values()) {
          ws.close();
        }
        wsSockets.clear();
      }
      return true as unknown as T;
    }

    case "get_identity": {
      try {
        const identity = (await hostIpc("get_identity", args)) as {
          pubkey?: string;
          display_name?: string;
          username?: string;
          lost?: boolean;
          locked?: boolean;
        };
        if (identity?.pubkey) rememberSessionPubkey(identity.pubkey);
        return identity as T;
      } catch (err) {
        console.warn("[Web-Shim] get_identity host failed", err);
        const pubkey =
          (typeof localStorage !== "undefined" &&
            localStorage.getItem("buzz-web-session-pubkey")) ||
          FALLBACK_SESSION_PUBKEY;
        rememberSessionPubkey(pubkey);
        return {
          pubkey,
          display_name: "Fedora-Desktop",
          username: "fedora-desktop",
          lost: false,
          locked: false,
        } as unknown as T;
      }
    }

    // Machine onboarding: host holds the seckey and can mint / import / export nsec.
    case "persist_current_identity": {
      // Pass through forceNew when UI requests rotation (lost-identity replace).
      // Default: re-persist / ensure durable host key without rotating.
      const identity = (await hostIpc("persist_current_identity", {
        displayName: "fedora",
        username: "fedora",
        ...args,
      })) as { pubkey?: string };
      if (identity?.pubkey) rememberSessionPubkey(identity.pubkey);
      return identity as T;
    }

    case "import_identity": {
      const identity = (await hostIpc("import_identity", args)) as {
        pubkey?: string;
      };
      if (identity?.pubkey) rememberSessionPubkey(identity.pubkey);
      return identity as T;
    }

    case "get_nsec": {
      // BackupStep — host returns nsec of the currently held human key.
      return (await hostIpc("get_nsec", args)) as T;
    }

    case "get_profile":
    case "get_user_profile":
      return (await hostIpc(cmd, args)) as T;

    case "update_profile":
      // Publish kind:0 on the relay so other clients see display_name.
      return (await hostIpc("update_profile", args)) as T;

    case "get_users_batch":
      return (await hostIpc("get_users_batch", args)) as T;

    case "search_users":
    case "search_messages":
    case "get_presence":
      return (await hostIpc(cmd, args)) as T;

    // Settings → Agents defaults. Must hit host so preferred_runtime (e.g. grok)
    // persists across refresh — never hardcode pi-coding-agent.
    case "get_global_agent_config":
    case "set_global_agent_config":
      return (await hostIpc(cmd, args)) as T;

    // Agent profile config panel — MUST be object with sources.configFilePath.
    // Unknown-cmd fallback returns [] and crashes AgentConfigPanel.
    case "get_agent_config_surface":
      return (await hostIpc(cmd, args)) as T;

    case "put_agent_session_config":
      return (await hostIpc(cmd, args)) as T;

    case "get_runtime_file_config":
      return (await hostIpc(cmd, args)) as T;

    case "get_baked_build_env":
    case "get_baked_build_env_keys":
      return [] as unknown as T;

    case "get_relay_http_url":
      try {
        return (await hostIpc(cmd, args)) as T;
      } catch {
        return "https://buzz.f.mtt.cool" as unknown as T;
      }

    case "get_relay_ws_url":
    case "get_default_relay_url":
      try {
        return (await hostIpc(cmd, args)) as T;
      } catch {
        return "wss://buzz.f.mtt.cool" as unknown as T;
      }

    case "get_media_proxy_port":
      return 0 as unknown as T;

    case "get_pending_community_deep_links":
      return getPendingCommunityDeepLinks() as unknown as T;

    case "take_pending_community_deep_link":
      return takePendingCommunityDeepLink() as unknown as T;

    case "acknowledge_pending_community_deep_link": {
      const id = (args.id as string) || "";
      return acknowledgePendingCommunityDeepLink(id) as unknown as T;
    }

    case "get_legacy_workspace_storage":
    case "get_sprout_community_storage":
    case "get_onboarding_completions":
    case "read_legacy_sprout_community_storage":
    case "read_legacy_sprout_storage":
      // Empty completions so Welcome / machine onboarding can run on a fresh browser.
      return {
        workspaces: null,
        activeWorkspaceId: null,
        onboardingCompletions: [],
      } as unknown as T;

    case "has_keyring_key":
    case "is_keyring_unlocked":
    case "is_unlocked":
      return true as unknown as T;

    case "get_private_key":
    case "get_identity_key":
      // Prefer get_nsec (handled above) for BackupStep; raw hex stays host-only.
      throw new Error("use get_nsec for backup; raw hex is not exposed");

    case "get_primary_community": {
      // No baked-in community — first-run WelcomeSetup / connect URL must add one.
      return null as unknown as T;
    }

    case "get_version":
      return "0.1.0" as unknown as T;

    // ── Real host IPC (Fedora desktop replacement) ──────────────────────────
    case "get_channels":
    case "list_channels":
    case "ensure_starter_channels":
      return (await hostIpc(cmd, args)) as T;

    case "get_channel_details":
      return (await hostIpc("get_channel_details", args)) as T;

    case "get_channel_members":
    case "list_channel_members":
      return (await hostIpc(cmd, args)) as T;

    case "get_channel_messages_before":
      return (await hostIpc("get_channel_messages_before", args)) as T;

    case "get_channel_window":
      return (await hostIpc("get_channel_window", args)) as T;

    case "get_event": {
      const data = await hostIpc<string | Record<string, unknown>>(
        "get_event",
        args,
      );
      // Tauri returns JSON string of the event.
      if (typeof data === "string") return data as unknown as T;
      return JSON.stringify(data) as unknown as T;
    }

    case "send_channel_message":
      return (await hostIpc("send_channel_message", args)) as T;

    case "list_relay_agents":
      return (await hostIpc("list_relay_agents", args)) as T;

    case "list_archived_identities":
      return (await hostIpc("list_archived_identities", args)) as T;

    case "create_channel":
    case "join_channel":
    case "add_channel_members":
    case "update_channel":
    case "open_dm":
    case "hide_dm":
    case "remove_channel_member":
    case "change_channel_member_role":
    case "leave_channel":
    case "add_reaction":
    case "remove_reaction":
    case "edit_message":
    case "delete_message":
    case "archive_channel":
    case "unarchive_channel":
    case "delete_channel":
    case "set_channel_topic":
    case "set_channel_purpose":
      return (await hostIpc(cmd, args)) as T;

    // Agent ACP activity: decrypt live/archived 24200 frames; build control frames.
    case "decrypt_observer_event":
      return (await hostIpc(cmd, args)) as T;

    case "build_observer_control_event": {
      const data = await hostIpc<string | Record<string, unknown>>(cmd, args);
      // Tauri returns JSON string of the signed event.
      if (typeof data === "string") return data as unknown as T;
      if (data && typeof data === "object") {
        return JSON.stringify(data) as unknown as T;
      }
      throw new Error("build_observer_control_event: unexpected host response");
    }

    case "get_canvas":
    case "set_canvas":
    case "get_feed":
      return (await hostIpc(cmd, args)) as T;

    // Workflows / voice out of scope
    case "get_channel_workflows":
    case "get_channels_workflows":
    case "list_workflows":
    case "get_workflow_runs":
    case "get_run_approvals":
      return [] as unknown as T;

    case "list_managed_agents":
    case "get_managed_agents":
    case "create_managed_agent":
    case "update_managed_agent":
    case "delete_managed_agent":
    case "start_managed_agent":
    case "stop_managed_agent":
      // Host file-backed managed agents (snake_case RawManagedAgent).
      return (await hostIpc(cmd, args)) as T;

    case "list_personas":
    case "create_persona":
    case "update_persona":
    case "set_persona_active":
    case "delete_persona":
      return (await hostIpc(cmd, args)) as T;

    case "discover_acp_providers":
    case "discover_acp_runtimes": {
      // Host PATH-probes real CLIs (goose, claude, codex, pi, buzz-acp, …).
      try {
        const catalog = await hostIpc<unknown[]>(cmd, args);
        if (Array.isArray(catalog) && catalog.length > 0) {
          return catalog as T;
        }
      } catch (err) {
        console.warn("[Web-Shim] discover_acp_providers failed", err);
      }
      // Safe empty catalog — never return broken auth_status shapes.
      return [] as unknown as T;
    }

    case "discover_managed_agent_prereqs":
      return (await hostIpc(cmd, args)) as T;

    case "discover_git_bash_prerequisite": {
      try {
        return (await hostIpc(cmd, args)) as T;
      } catch {
        return null as unknown as T;
      }
    }

    case "list_teams":
    case "create_team":
    case "update_team":
    case "delete_team":
      return (await hostIpc(cmd, args)) as T;

    // Not used on web host product path (or no desktop store equivalent yet).
    case "list_projects":
    case "list_community_members":
    case "list_custom_emojis":
      return [] as unknown as T;

    case "resolve_oa_owner":
    case "archive_identity":
    case "unarchive_identity":
    case "get_agent_memory":
      return (await hostIpc(cmd, args)) as T;

    case "discover_acp_auth_methods":
      return { methods: [] } as unknown as T;

    case "relay_requires_membership":
      return false as unknown as T;

    // NIP-11 relay identity. MUST be string|null — never [] (truthy empty array
    // crashes normalizeValidPubkey via .trim on non-string).
    case "get_relay_self":
      return (await hostIpc("get_relay_self", args)) as T;

    // Array-shaped IPC used during app shell boot. Explicit stubs avoid the
    // dangerous `/api/ipc` fallback which returns HTTP 200 + `{}` for unknown
    // cmds (truthy object → `.map is not a function` / wrong shape crashes).
    case "list_channel_templates":
    case "list_audio_output_devices":
    case "reconcile_managed_agent_runtimes":
    case "list_managed_agent_runtimes":
    case "list_save_subscriptions":
      return [] as unknown as T;

    case "get_huddle_state":
      return null as unknown as T;

    case "get_audio_output_device":
    case "get_voice_input_mode":
      return null as unknown as T;

    case "is_shared_identity":
    case "is_auto_update_supported":
    case "observer_archive_default_enabled":
      return false as unknown as T;

    // Web host is bound to the local relay; skip empty-community WelcomeSetup
    // and auto-seed the default relay as first community (non-local hosts only).
    case "auto_connect_default_relay_enabled":
      return true as unknown as T;

    case "apply_workspace":
    case "set_prevent_sleep_active":
      return true as unknown as T;

    case "plugin:updater|check":
    case "plugin:updater|download":
      return null as unknown as T;

    default:
      break;
  }

  try {
    const res = await fetch("/api/ipc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cmd, args }),
    });
    if (res.ok) {
      const data = await res.json();
      // Daemon returns `{}` for unknown cmds with HTTP 200 — treat empty object
      // as "not handled" so callers get the safer default array, not a false shape.
      if (
        data &&
        typeof data === "object" &&
        !Array.isArray(data) &&
        Object.keys(data).length === 0
      ) {
        // fall through to default
      } else {
        return data as T;
      }
    } else {
      // Surface host 4xx/5xx instead of silently returning [] — that turns
      // missing object-shaped IPCs into runtime crashes (e.g. .configFilePath).
      const text = await res.text().catch(() => "");
      let msg = `host ipc ${cmd} failed: HTTP ${res.status}`;
      try {
        const parsed = text ? JSON.parse(text) : null;
        if (
          parsed &&
          typeof parsed === "object" &&
          typeof (parsed as { error?: unknown }).error === "string"
        ) {
          msg = (parsed as { error: string }).error;
        }
      } catch {
        /* ignore */
      }
      console.warn("[Web-Shim] unhandled IPC error", cmd, msg);
    }
  } catch (err) {
    // Ignore fetch errors
  }

  // Last resort: empty array. Prefer explicit case handlers for object shapes.
  console.warn(
    "[Web-Shim] unhandled IPC falling back to []:",
    cmd,
    "(add an explicit host handler if this is an object-shaped command)",
  );
  return [] as unknown as T;
}
