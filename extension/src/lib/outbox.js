// Sends that couldn't reach the server, kept in chrome.storage.local until it answers again. Pure functions over the queue array, so the tests run them under plain node; background.js does the storage and the sending.

// chrome.storage.local holds 10 MB in all. The queue stays under 8 MB.
export const MAX_ITEMS = 25;
const MAX_BYTES = 8 * 1000 * 1000;
// What "couldn't send" keeps, so a refused page isn't silently lost.
export const MAX_FAILED = 10;

/** Worth keeping to try again: the network failed, or a proxy in front of the server did. */
export function isRetryable(err) {
  if (err instanceof TypeError) return true; // fetch: offline, DNS, connection refused
  return [502, 503, 504].includes(err?.status);
}

/** Approximate stored size of one item. */
const sizeOf = (item) => JSON.stringify(item).length;

/** The page body without its HTML: the server fetches the page itself instead. */
function withoutHtml(body) {
  const { html: _html, ...rest } = body;
  return rest;
}

/** Add a send to the queue. Returns {queue, downgraded} or throws when it is full. A page whose HTML would take the queue over MAX_BYTES is kept as a link (no HTML): the server fetches it later, which loses paywalled or signed-in content but keeps the send. */
export function enqueue(queue, { kind, body, title }, now = Date.now()) {
  if (queue.length >= MAX_ITEMS) {
    throw new Error(`${MAX_ITEMS} pages are already waiting to send. Send or discard them from the toolbar popup first.`);
  }
  const used = queue.reduce((n, item) => n + sizeOf(item), 0);
  let item = { kind, body, title: title || body.title || body.url, url: body.url, queuedAt: now, attempts: 0 };
  let downgraded = false;
  if (used + sizeOf(item) > MAX_BYTES && body.html) {
    item = { ...item, kind: "link", body: withoutHtml(body) };
    downgraded = true;
  }
  if (used + sizeOf(item) > MAX_BYTES) {
    throw new Error("The queue of pages waiting to send is full. Send or discard them from the toolbar popup first.");
  }
  return { queue: [...queue, item], downgraded };
}

/** Keep the newest MAX_FAILED refusals. */
export function addFailed(failed, item, message, now = Date.now()) {
  return [...failed, { title: item.title, url: item.url, message, at: now }].slice(-MAX_FAILED);
}
