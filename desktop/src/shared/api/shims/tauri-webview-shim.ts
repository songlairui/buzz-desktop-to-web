export class Webview {
  async setZoom() {}
  async getZoom() {
    return 1;
  }
}

export function getCurrentWebview() {
  return new Webview();
}
