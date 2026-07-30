export type UnlistenFn = () => void;

export async function listen<T = unknown>(
  event: string,
  handler: (event: { event: string; payload: T }) => void
): Promise<UnlistenFn> {
  console.log("[Web-Shim] listen registered:", event);
  const listener = (e: Event) => {
    const custom = e as CustomEvent<T>;
    handler({ event, payload: custom.detail });
  };
  window.addEventListener(`tauri://${event}`, listener);
  return () => {
    window.removeEventListener(`tauri://${event}`, listener);
  };
}

export async function emit<T = unknown>(event: string, payload?: T): Promise<void> {
  console.log("[Web-Shim] emit:", event, payload);
  const custom = new CustomEvent(`tauri://${event}`, { detail: payload });
  window.dispatchEvent(custom);
}
