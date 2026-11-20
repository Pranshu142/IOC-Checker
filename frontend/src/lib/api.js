export const API = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');

const headers = (key, rpm) => ({ 'Content-Type': 'application/json', 'X-VT-Key': key, ...(rpm ? { 'X-VT-Rpm': String(rpm) } : {}) });

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

// Streams one NDJSON line per finished indicator, in completion order.
export async function streamBatch({ indicators, key, rpm, signal, onResult }) {
  const res = await fetch(API + '/api/batch', { method: 'POST', signal, headers: headers(key, rpm), body: JSON.stringify({ indicators }) });
  if (!res.ok) throw await fail(res);
  const reader = res.body.getReader(), dec = new TextDecoder();
  let buf = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
      if (line) onResult(JSON.parse(line));
    }
  }
}
