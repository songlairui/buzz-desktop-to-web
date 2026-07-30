/**
 * Browser stand-in for Tauri's deep-link queue (`desktop/src-tauri/src/deep_link.rs`).
 *
 * Custom schemes (`buzz://…`) cannot be handled by a normal HTTPS web app.
 * Instead we accept equivalent HTTPS entry points and feed the same pending
 * queue that `listenForDeepLinks` drains via `take_pending_community_deep_link`.
 *
 * Supported entry forms (any one is enough):
 *   /connect?relay=wss://buzz.f.mtt.cool
 *   /#/connect?relay=wss://…
 *   ?relay=wss://…
 *   ?connect=wss://…   (or full buzz://connect?relay=…)
 *   ?uri=buzz://connect?relay=…
 *   ?buzz=buzz://connect?relay=…
 *   ?join=buzz://join?relay=…&code=…   /  /join?relay=…&code=…
 *   ?add-community=wss://…   /  /add-community?relay=…&name=…
 */

export type PendingCommunityDeepLink = {
  id: string;
  kind: "connect" | "join" | "add-community";
  relayUrl: string;
  code: string | null;
  name: string | null;
  policyReceipt: string | null;
};

const queue: PendingCommunityDeepLink[] = [];
let ingested = false;

function isWsRelay(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "ws:" || u.protocol === "wss:";
  } catch {
    return false;
  }
}

function normalizeRelay(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  if (isWsRelay(trimmed)) return trimmed.replace(/\/$/, "");
  // Allow bare host or https URL → wss
  try {
    if (/^https?:\/\//i.test(trimmed)) {
      const u = new URL(trimmed);
      const scheme = u.protocol === "https:" ? "wss:" : "ws:";
      return `${scheme}//${u.host}`.replace(/\/$/, "");
    }
    if (!trimmed.includes("://")) {
      return `wss://${trimmed.replace(/\/$/, "")}`;
    }
  } catch {
    return null;
  }
  return null;
}

function parseBuzzScheme(raw: string): PendingCommunityDeepLink | null {
  try {
    const url = new URL(raw.trim());
    if (url.protocol !== "buzz:") return null;
    const kind = url.host; // connect | join | add-community
    if (kind !== "connect" && kind !== "join" && kind !== "add-community") {
      return null;
    }
    const relay = url.searchParams.get("relay");
    if (!relay || !isWsRelay(relay)) return null;
    return {
      id: crypto.randomUUID(),
      kind,
      relayUrl: relay.replace(/\/$/, ""),
      code: url.searchParams.get("code"),
      name: url.searchParams.get("name"),
      policyReceipt: url.searchParams.get("policy_receipt"),
    };
  } catch {
    return null;
  }
}

function enqueue(link: PendingCommunityDeepLink) {
  // Deduplicate exact intents (same as Rust FIFO queue).
  const dup = queue.some(
    (q) =>
      q.kind === link.kind &&
      q.relayUrl === link.relayUrl &&
      q.code === link.code &&
      q.name === link.name,
  );
  if (dup) return;
  queue.push(link);
  // Notify listeners registered via the event shim.
  try {
    const eventName =
      link.kind === "join"
        ? "deep-link-join"
        : link.kind === "add-community"
          ? "deep-link-add-community"
          : "deep-link-connect";
    const payload =
      link.kind === "connect"
        ? link.relayUrl
        : link.kind === "join"
          ? {
              relayUrl: link.relayUrl,
              code: link.code ?? "",
              policyReceipt: link.policyReceipt,
            }
          : {
              relayUrl: link.relayUrl,
              name: link.name ?? undefined,
            };
    window.dispatchEvent(
      new CustomEvent(`tauri://${eventName}`, { detail: payload }),
    );
  } catch {
    /* ignore */
  }
}

function tryEnqueueFromSearch(params: URLSearchParams) {
  // Full buzz:// URI in a query bag
  for (const key of ["uri", "buzz", "deeplink", "deep_link", "deep-link"]) {
    const raw = params.get(key);
    if (!raw) continue;
    const parsed = parseBuzzScheme(raw);
    if (parsed) {
      enqueue(parsed);
      return true;
    }
  }

  // ?connect= may be a relay URL or a full buzz://connect…
  const connectRaw = params.get("connect");
  if (connectRaw) {
    const asBuzz = parseBuzzScheme(connectRaw);
    if (asBuzz) {
      enqueue(asBuzz);
      return true;
    }
    const relay = normalizeRelay(connectRaw);
    if (relay) {
      enqueue({
        id: crypto.randomUUID(),
        kind: "connect",
        relayUrl: relay,
        code: null,
        name: null,
        policyReceipt: null,
      });
      return true;
    }
  }

  const joinRaw = params.get("join");
  if (joinRaw) {
    const asBuzz = parseBuzzScheme(joinRaw);
    if (asBuzz) {
      enqueue(asBuzz);
      return true;
    }
  }

  const addRaw = params.get("add-community") || params.get("add_community");
  if (addRaw) {
    const asBuzz = parseBuzzScheme(addRaw);
    if (asBuzz) {
      enqueue(asBuzz);
      return true;
    }
    const relay = normalizeRelay(addRaw);
    if (relay) {
      enqueue({
        id: crypto.randomUUID(),
        kind: "add-community",
        relayUrl: relay,
        code: null,
        name: params.get("name"),
        policyReceipt: null,
      });
      return true;
    }
  }

  // Bare ?relay=wss://… (+ optional code/name)
  const relayParam = params.get("relay");
  if (relayParam) {
    const relay = normalizeRelay(relayParam);
    if (relay) {
      const code = params.get("code");
      const name = params.get("name");
      enqueue({
        id: crypto.randomUUID(),
        kind: code ? "join" : name ? "add-community" : "connect",
        relayUrl: relay,
        code,
        name,
        policyReceipt: params.get("policy_receipt"),
      });
      return true;
    }
  }

  return false;
}

function pathKind(pathname: string): "connect" | "join" | "add-community" | null {
  const p = pathname.replace(/\/+$/, "") || "/";
  if (p === "/connect" || p.endsWith("/connect")) return "connect";
  if (p === "/join" || p.endsWith("/join")) return "join";
  if (p === "/add-community" || p.endsWith("/add-community")) return "add-community";
  return null;
}

/**
 * Parse the current location once and seed the pending queue.
 * Strips consumed query/path so a refresh does not re-fire forever.
 */
export function ingestWebDeepLinksFromLocation() {
  if (typeof window === "undefined" || ingested) return;
  ingested = true;

  try {
    const url = new URL(window.location.href);
    let changed = false;

    // Hash route: #/connect?relay=…
    if (url.hash && url.hash.includes("connect")) {
      try {
        const hashBody = url.hash.replace(/^#/, "");
        const hashUrl = new URL(hashBody, "https://buzz.local");
        if (tryEnqueueFromSearch(hashUrl.searchParams) || pathKind(hashUrl.pathname)) {
          const kind = pathKind(hashUrl.pathname);
          if (kind && hashUrl.searchParams.get("relay")) {
            const relay = normalizeRelay(hashUrl.searchParams.get("relay")!);
            if (relay) {
              enqueue({
                id: crypto.randomUUID(),
                kind,
                relayUrl: relay,
                code: hashUrl.searchParams.get("code"),
                name: hashUrl.searchParams.get("name"),
                policyReceipt: hashUrl.searchParams.get("policy_receipt"),
              });
            }
          }
          url.hash = "";
          changed = true;
        }
      } catch {
        /* ignore malformed hash */
      }
    }

    // Path routes: /connect, /join, /add-community
    const kind = pathKind(url.pathname);
    if (kind) {
      const relay = normalizeRelay(url.searchParams.get("relay") || "");
      if (relay) {
        enqueue({
          id: crypto.randomUUID(),
          kind,
          relayUrl: relay,
          code: url.searchParams.get("code"),
          name: url.searchParams.get("name"),
          policyReceipt: url.searchParams.get("policy_receipt"),
        });
        url.pathname = "/";
        for (const k of [
          "relay",
          "code",
          "name",
          "policy_receipt",
          "connect",
          "join",
          "uri",
          "buzz",
        ]) {
          url.searchParams.delete(k);
        }
        changed = true;
      }
    }

    if (tryEnqueueFromSearch(url.searchParams)) {
      for (const k of [
        "relay",
        "code",
        "name",
        "policy_receipt",
        "connect",
        "join",
        "uri",
        "buzz",
        "deeplink",
        "deep_link",
        "deep-link",
        "add-community",
        "add_community",
      ]) {
        url.searchParams.delete(k);
      }
      changed = true;
    }

    if (changed) {
      const next = `${url.pathname}${url.search}${url.hash}` || "/";
      window.history.replaceState(window.history.state, "", next);
    }
  } catch (err) {
    console.warn("[Web-Shim] deep-link ingest failed", err);
  }
}

export function takePendingCommunityDeepLink(): PendingCommunityDeepLink | null {
  return queue[0] ?? null;
}

export function acknowledgePendingCommunityDeepLink(id: string): boolean {
  const idx = queue.findIndex((q) => q.id === id);
  if (idx < 0) return false;
  queue.splice(idx, 1);
  return true;
}

export function getPendingCommunityDeepLinks(): PendingCommunityDeepLink[] {
  return [...queue];
}

/** Manual enqueue for in-app "paste connect URL" UI. */
export function enqueueCommunityDeepLinkFromUserInput(
  raw: string,
): PendingCommunityDeepLink | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const asBuzz = parseBuzzScheme(trimmed);
  if (asBuzz) {
    enqueue(asBuzz);
    return asBuzz;
  }
  const relay = normalizeRelay(trimmed);
  if (!relay) return null;
  const link: PendingCommunityDeepLink = {
    id: crypto.randomUUID(),
    kind: "connect",
    relayUrl: relay,
    code: null,
    name: null,
    policyReceipt: null,
  };
  enqueue(link);
  return link;
}
