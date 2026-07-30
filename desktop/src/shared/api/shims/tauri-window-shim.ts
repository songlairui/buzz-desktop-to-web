export enum UserAttentionType {
  Critical = 1,
  Informational = 2,
}

export class Window {
  label: string = "main";

  async setFocus() {}
  async requestUserAttention() {}
  async isMaximized() {
    return false;
  }
  async isMinimized() {
    return false;
  }
  async isFullscreen() {
    return false;
  }
  async startDragging() {}
  async close() {}
  async setBadgeCount(_count?: number) {}
  async setBadgeLabel(_label?: string) {}
  async theme() {
    return "dark";
  }

  async onResized(_cb: () => void): Promise<() => void> {
    return () => {};
  }
  async onFocusChanged(_cb: () => void): Promise<() => void> {
    return () => {};
  }
  async onMoved(_cb: () => void): Promise<() => void> {
    return () => {};
  }
  async onCloseRequested(_cb: () => void): Promise<() => void> {
    return () => {};
  }
  async onThemeChanged(_cb: () => void): Promise<() => void> {
    return () => {};
  }
}

export function getCurrentWindow() {
  return new Window();
}
