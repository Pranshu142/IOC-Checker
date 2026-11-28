// ---- severity rule (edit here) ----
export const COUNT_SUSPICIOUS = false;
export const severity = (n) => (n <= 0 ? 'Clean' : n <= 5 ? 'Medium' : n <= 10 ? 'High' : 'Critical');

// ---- server result -> table row ----
export function toRow(d) {
  const base = { value: d.value, type: d.type, mal: '', total: '', link: '', cached: !!d.cached };
  switch (d.status) {
    case 'invalid': return { ...base, sev: 'Invalid', note: d.error };
    case 'notfound': return { ...base, mal: 0, total: 0, sev: 'No data', link: d.link };
    case 'ok': return { ...base, mal: d.malicious, total: d.total, link: d.link,
      sev: severity(d.malicious + (COUNT_SUSPICIOUS ? d.suspicious : 0)) };
    default: return { ...base, sev: 'Error', note: d.error || 'Lookup failed' };
  }
}
export const scoreText = (r) => (r && r.total ? `${r.mal} / ${r.total}` : 'No data');

// Splits pasted text into indicators. Spaces around defang brackets ("example [.] com") are closed first.
export function splitIndicators(text) {
  const t = text.replace(/\s*([\[({]\s*(?:[.:/\\]+|dot)\s*[\])}])\s*/gi, '$1');
  return [...new Set(t.split(/[\s,;]+/).filter(Boolean))];
}

// Rough check, only used to find the indicator column in a sheet. The server does the real validation.
export function looksLikeIoc(raw) {
  let s = String(raw ?? '').trim().replace(/\\\./g, '.')
    .replace(/[\[({]\s*(?:\.|dot)\s*[\])}]/gi, '.').replace(/[\[({]\s*([:/\\]+)\s*[\])}]/g, '$1');
  s = s.replace(/^[\s"'<({\[]+/, '').replace(/[\s"'>)}\].,;]+$/, '');
  if (!s || /\s/.test(s)) return false;
  return /^(h[xt*]{2}p\[?s?\]?|meow)[:/\\]+\S+/i.test(s)
    || /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(s)
    || (/^[0-9a-f:]{2,39}$/i.test(s) && (s.match(/:/g) || []).length >= 2)
    || /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(s)
    || /^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z]{2,63}([:/?#]\S*)?$/i.test(s);
}

// ---- API key: this browser tab only ----
export const isKey = (k) => /^[a-f0-9]{64}$/i.test(k);
export const loadKey = () => { try { return sessionStorage.getItem('vt_key') || ''; } catch { return ''; } };
export const saveKey = (k) => { try { k ? sessionStorage.setItem('vt_key', k) : sessionStorage.removeItem('vt_key'); } catch { /* blocked */ } };

// ---- how fast can this key go? Read from VirusTotal's own quota numbers ----
export function planFrom(q) {
  if (!q || !q.known || !q.hourlyAllowed) return { rpm: 4, label: 'Free limit assumed', dailyLeft: null };
  const rpm = Math.max(4, Math.min(600, Math.floor(q.hourlyAllowed / 60)));
  return {
    rpm,
    label: rpm <= 4 ? 'Free key' : 'Premium key',
    dailyLeft: q.dailyAllowed ? Math.max(0, q.dailyAllowed - q.dailyUsed) : null,
  };
}

// ---- 24h result cache in this browser: repeat indicators cost no quota ----
const CK = 'vt_cache_v2', TTL = 24 * 3600_000, MAX = 3000, GOOD = ['Clean', 'Medium', 'High', 'Critical', 'No data'];
let mem = null, dirty = false;
const store = () => { if (!mem) { try { mem = JSON.parse(localStorage.getItem(CK) || '{}'); } catch { mem = {}; } } return mem; };
export function cacheGet(k) { const e = store()[k]; return e && Date.now() - e.t < TTL ? e.r : null; }
export function cacheSet(k, r) { if (GOOD.includes(r.sev)) { store()[k] = { t: Date.now(), r }; dirty = true; } }
export function cacheSave() {
  if (!dirty) return;
  try {
    const keep = Object.entries(store()).filter(([, e]) => Date.now() - e.t < TTL).sort((a, b) => b[1].t - a[1].t).slice(0, MAX);
    mem = Object.fromEntries(keep);
    localStorage.setItem(CK, JSON.stringify(mem));
    dirty = false;
  } catch { /* storage full or blocked */ }
}
