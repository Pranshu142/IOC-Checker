import { useEffect, useRef, useState } from 'react';
import { Header, Composer, Message } from '@/components/chat';
import { fetchQuota, checkAll, wakeServer } from '@/lib/api';
import { readSheet, downloadExcel } from '@/lib/excel';
import { cacheGet, cacheSave, cacheSet, isKey, loadKey, planFrom, saveKey, splitIndicators, toRow } from '@/lib/ioc';

let n = 0;
const uid = () => 'm' + ++n + '-' + Date.now();
const HELP = 'Paste IPs, domains, URLs or hashes (defanged is fine), or attach an .xlsx file with a column of indicators. Any layout works.';
const ASK_KEY = 'Hi, I check IPs, domains, URLs and file hashes on VirusTotal. Paste your own VirusTotal API key below to start. It stays in this browser tab and is only forwarded to VirusTotal.';

// Turns network and gateway failures into something a person can act on.
const friendly = (e) => (e.stalled || /Failed to fetch|NetworkError|Load failed|^Request failed \(5/.test(e.message)
  ? 'The server did not respond. Free hosting sleeps when idle, so wait a minute and run it again.' : e.message);

export default function App() {
  const [key, setKey] = useState(loadKey);
  const [plan, setPlan] = useState(null);
  const [busy, setBusy] = useState(false);
  const [msgs, setMsgs] = useState(() => [{ id: uid(), role: 'assistant', ...(loadKey() ? { text: HELP } : { text: ASK_KEY }) }]);
  const ctl = useRef(null), bottom = useRef(null);

  const add = (m) => setMsgs((x) => [...x, { id: uid(), ...m }]);
  const say = (text, extra) => add({ role: 'assistant', text, ...extra });
  useEffect(() => { bottom.current?.scrollIntoView({ block: 'end' }); }, [msgs.length]);
  useEffect(() => { if (key) loadPlan(key); }, []); // eslint-disable-line

  async function loadPlan(k) {
    try { const p = planFrom(await fetchQuota(k)); setPlan(p); return p; }
    catch (e) { if (e.badKey) return null; const p = planFrom(null); setPlan(p); return p; }
  }
  function forget(message) { saveKey(''); setKey(''); setPlan(null); say(message || 'Paste a VirusTotal API key to continue.'); }

  async function onKey(k) {
    add({ role: 'user', text: 'API key added' });
    if (!isKey(k)) return say('That does not look like a VirusTotal key. It is 64 letters and numbers. Copy it again from your VirusTotal profile.');
    const p = await loadPlan(k);
    if (!p) return say('VirusTotal rejected that key. Check it and paste it again.');
    saveKey(k); setKey(k);
    const daily = p.dailyLeft != null ? `, ${p.dailyLeft} left today` : '';
    say(`${p.label}: ${p.rpm} lookups per minute${daily}. ${HELP}`);
  }

  async function runJob(title, base, items) {
    const id = uid();
    let rpm = (plan || planFrom(null)).rpm;
    const prepared = items.map((it) => {
      const c = cacheGet(it.ind);
      return { ind: it.ind, row: c ? { ...c, cached: true } : null };
    });
    const need = [...new Set(prepared.filter((p) => !p.row).map((p) => p.ind))];
    const job = { title, base, items: prepared, need: need.length, done: 0, rpm, running: need.length > 0, stopped: false, error: null };
    setMsgs((m) => [...m, { id, role: 'assistant', job }]);
    if (!need.length) return say('Nothing new to look up: every row was already checked in the last 24 hours.');

    const patch = (fn) => setMsgs((m) => m.map((x) => (x.id === id ? { ...x, job: fn(x.job) } : x)));
    const ac = new AbortController(); ctl.current = ac;
    setBusy(true);
    if (plan?.dailyLeft != null && need.length > plan.dailyLeft)
      say(`Heads up: this needs ${need.length} lookups and your key has about ${plan.dailyLeft} left today. The rest will fail, and you can still download what finishes.`);

    // Free hosting sleeps when idle: wake the server first, then re-read the key's real speed if that had failed.
    const awake = await wakeServer({ signal: ac.signal, onSlow: () => say('Waking up the server. Free hosting sleeps when idle, so this can take up to a minute.') });
    if (awake && (!plan || plan.label === 'Free limit assumed')) {
      const p = await loadPlan(key);
      if (p) { rpm = p.rpm; patch((j) => ({ ...j, rpm })); }
    }

    let badKey = false, lastErr = null, saved = 0;
    const finished = new Set();
    try {
      lastErr = (await checkAll({ indicators: need, key, rpm, signal: ac.signal, onResult: (ind, d) => {
        finished.add(ind);
        const row = toRow(d);
        cacheSet(ind, row);
        if (++saved % 10 === 0) cacheSave();           // a reload or crash then loses at most 10 results
        patch((j) => ({ ...j, done: j.done + 1, items: j.items.map((it) => (it.ind === ind ? { ...it, row } : it)) }));
        if (d.status === 'badkey') { badKey = true; ac.abort(); }
      } })).lastError;
    } catch (e) {
      if (e.name !== 'AbortError') { badKey = badKey || !!e.badKey; lastErr = e; }
    }
    // Nothing may stay on "Checking": whatever got no answer is resolved here.
    const left = new Set(need.filter((i) => !finished.has(i)));
    const stopped = ac.signal.aborted;
    const leftover = (ind) => ({ value: ind, type: '', mal: '', total: '', link: '', cached: false,
      sev: stopped ? 'Not checked' : 'Error', note: stopped ? undefined : 'No answer from the server. Run it again.' });
    patch((j) => ({ ...j, running: false, stopped: stopped && !badKey,
      error: lastErr ? friendly(lastErr) : left.size && !stopped ? 'Some lookups got no answer from the server and are marked Error.' : null,
      items: j.items.map((it) => (!it.row && left.has(it.ind) ? { ...it, row: leftover(it.ind) } : it)) }));
    cacheSave(); setBusy(false); ctl.current = null;
    if (badKey) forget('VirusTotal rejected your key. Paste a valid one to continue.');
    else loadPlan(key);
  }

  function onText(text) {
    const list = splitIndicators(text).slice(0, 100);
    if (!list.length) return;
    add({ role: 'user', text });
    runJob(list.length === 1 ? list[0] : `${list.length} indicators`, 'vt-chat', list.map((ind) => ({ ind })));
  }

  async function onFile(file) {
    add({ role: 'user', file: file.name });
    let parsed;
    try { parsed = await readSheet(await file.arrayBuffer()); }
    catch { return say('I could not read that file. Save it as .xlsx and try again.'); }
    if (!parsed) return say('I could not find any indicators in that file. Put them in one column of the first sheet and try again.');
    say(`Using column ${parsed.column} of “${parsed.sheet}”: ${parsed.items.length} rows.`);
    runJob(file.name, file.name.replace(/\.[^.]+$/, ''), parsed.items);
  }

  return (
    <div className="flex h-dvh flex-col bg-background">
      <Header plan={plan} hasKey={!!key} busy={busy} onChangeKey={() => forget('Paste your new VirusTotal API key below.')} />
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-6xl space-y-6 px-4 py-6">
          {msgs.map((m) => <Message key={m.id} m={m} onStop={() => ctl.current?.abort()} onDownload={(j) => downloadExcel(j.items, j.base)} />)}
          <div ref={bottom} />
        </div>
      </main>
      <footer className="border-t">
        <div className="mx-auto w-full max-w-6xl px-4 py-3">
          <Composer keyMode={!key} busy={busy} onText={onText} onFile={onFile} onKey={onKey} />
          <p className="mt-2 text-center text-xs text-muted-foreground">Your key stays in this browser tab and is only forwarded to VirusTotal. It is never stored on the server.</p>
        </div>
      </footer>
    </div>
  );
}
