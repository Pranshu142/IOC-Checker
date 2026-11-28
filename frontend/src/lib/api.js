export const API = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');

const headers = (key, rpm) => ({ 'Content-Type': 'application/json', 'X-VT-Key': key, ...(rpm ? { 'X-VT-Rpm': String(rpm) } : {}) });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fail(res) {
  const d = await res.json().catch(() => ({}));
  const e = new Error(d.error || 'Request failed (' + res.status + ')');
  e.badKey = !!d.badKey;
  return e;
}

export async function fetchQuota(key) {
  const res = await fetch(API + '/api/quota', { method: 'POST', headers: headers(key), body: '{}' });
  if (!res.ok) throw await fail(res);
  return res.json();
}

// One streaming request: a line per finished indicator, in completion order.
// The server also sends a ping every 15s. If nothing at all arrives for idleMs the
// connection is treated as stalled and an error with .stalled = true is thrown.
export async function streamBatch({ indicators, key, rpm, signal, onResult, idleMs = 90_000 }) {
  const inner = new AbortController();
  const relay = () => inner.abort();
  if (signal) { if (signal.aborted) inner.abort(); else signal.addEventListener('abort', relay); }
  let stalled = false, timer;
  const arm = () => { clearTimeout(timer); timer = setTimeout(() => { stalled = true; inner.abort(); }, idleMs); };
  try {
    arm();
    const res = await fetch(API + '/api/batch', { method: 'POST', signal: inner.signal, headers: headers(key, rpm), body: JSON.stringify({ indicators }) });
    if (!res.ok) throw await fail(res);
    const reader = res.body.getReader(), dec = new TextDecoder();
    let buf = '';
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      arm();
      buf += dec.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
        if (!line) continue;
        const d = JSON.parse(line);
        if (!d.ping) onResult(d);
      }
    }
  } catch (e) {
    if (stalled) { const err = new Error('The connection to the server stalled.'); err.stalled = true; throw err; }
    throw e;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', relay);
  }
}

// Checks every indicator. If the connection drops or stalls, only the unanswered ones are sent again
// (up to 6 tries without progress, waiting longer each time). Calls onResult(indicator, result) once per indicator.
export async function checkAll({ indicators, key, rpm, signal, onResult, idleMs, retryDelayMs = 2000 }) {
  const finished = new Set();
  let attempts = 0, lastError = null;
  while (!signal?.aborted && attempts < 6) {
    const pending = indicators.filter((i) => !finished.has(i));
    if (!pending.length) break;
    const chunk = pending.slice(0, 500), before = finished.size;
    try {
      await streamBatch({ indicators: chunk, key, rpm, signal, idleMs, onResult: (d) => {
        const ind = chunk[d.idx];
        if (ind === undefined || finished.has(ind)) return;
        finished.add(ind);
        onResult(ind, d);
      } });
    } catch (e) {
      if (signal?.aborted || e.badKey) throw e;       // Stop pressed, or the key is bad: do not retry
      lastError = e;
      await sleep(Math.min(15_000, retryDelayMs * 2 ** attempts));   // 2s, 4s, 8s, then 15s
    }
    attempts = finished.size > before ? 0 : attempts + 1;
  }
  return { finished, lastError: indicators.every((i) => finished.has(i)) ? null : lastError };
}

// Free hosting puts the server to sleep when idle, and waking it takes up to a minute or more.
// Polls /api/health until it answers (or maxMs passes). onSlow fires once if it takes longer than 4 seconds.
export async function wakeServer({ signal, onSlow, maxMs = 120_000 }) {
  const start = Date.now();
  const slow = setTimeout(() => onSlow?.(), 4000);
  try {
    while (!signal?.aborted && Date.now() - start < maxMs) {
      try {
        const res = await fetch(API + '/api/health', { signal: AbortSignal.timeout(15_000) });
        if (res.ok) return true;
      } catch { /* not up yet */ }
      await sleep(2500);
    }
    return false;
  } finally { clearTimeout(slow); }
}
