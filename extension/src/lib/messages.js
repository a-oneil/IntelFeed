// The popup and options pages call the background worker through this.

export async function call(type, payload = {}) {
  const reply = await chrome.runtime.sendMessage({ type, ...payload });
  if (!reply) throw new Error("The extension did not respond. Reload it from your browser's extensions page and try again.");
  if (!reply.ok) {
    const err = new Error(reply.error);
    err.notSignedIn = reply.notSignedIn;
    err.status = reply.status;
    throw err;
  }
  return reply.data;
}
