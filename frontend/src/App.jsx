import { useEffect, useRef, useState } from 'react';
import { Header, Composer, Message } from '@/components/chat';
import { fetchQuota, streamBatch } from '@/lib/api';
import { readSheet, downloadExcel, downloadTemplate } from '@/lib/excel';
import { cacheGet, cacheSave, cacheSet, isKey, loadKey, planFrom, saveKey, splitIndicators, toRow } from '@/lib/ioc';

let n = 0;
const uid = () => 'm' + ++n + '-' + Date.now();
const HELP = 'Paste IPs, domains, URLs or hashes (defanged is fine), or attach an .xlsx file with an “indicator” column.';
const ASK_KEY = 'Hi, I check IPs, domains, URLs and file hashes on VirusTotal. Paste your own VirusTotal API key below to start. It stays in this browser tab and is only forwarded to VirusTotal.';

export default function App() {
  const [key, setKey] = useState(loadKey);
  const [plan, setPlan] = useState(null);
  const [busy, setBusy] = useState(false);
  const [msgs, setMsgs] = useState(() => [{ id: uid(), role: 'assistant', ...(loadKey() ? { text: HELP, template: true } : { text: ASK_KEY }) }]);
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
    say(`${p.label}: ${p.rpm} lookups per minute${daily}. ${HELP}`, { template: true });
  }

  async function runJob(title, base, items) {
    const rpm = (plan || planFrom(null)).rpm, id = uid();
    const prepared = items.map((it) => {
      if (it.existing) return { ind: it.ind, row: { value: it.ind, sev: it.existing, mal: '', total: '', link: '' } };
      const c = cacheGet(it.ind);
      return { ind: it.ind, row: c ? { ...c, cached: true } : null };
    });
    const need = [...new Set(prepared.filter((p) => !p.row).map((p) => p.ind))];
    const job = { title, base, items: prepared, need: need.length, done: 0, rpm, running: need.length > 0, stopped: false, error: null };
    setMsgs((m) => [...m, { id, role: 'assistant', job }]);
    if (!need.length) return say('Nothing new to look up: every row was already checked or had a severity.');

    const patch = (fn) => setMsgs((m) => m.map((x) => (x.id === id ? { ...x, job: fn(x.job) } : x)));
    const ac = new AbortController(); ctl.current = ac;
    setBusy(true);
    if (plan?.dailyLeft != null && need.length > plan.dailyLeft)
      say(`Heads up: this needs ${need.length} lookups and your key has about ${plan.dailyLeft} left today. The rest will fail, and you can still download what finishes.`);

    let badKey = false;
    try {
      for (let o = 0; o < need.length && !ac.signal.aborted; o += 500) {
        const chunk = need.slice(o, o + 500);
        await streamBatch({ indicators: chunk, key, rpm, signal: ac.signal, onResult: (d) => {
          const ind = chunk[d.idx], row = toRow(d);
          cacheSet(ind, row);
          patch((j) => ({ ...j, done: j.done + 1, items: j.items.map((it) => (it.ind === ind ? { ...it, row } : it)) }));
          if (d.status === 'badkey') { badKey = true; ac.abort(); }
        } });
      }
      patch((j) => ({ ...j, running: false }));
    } catch (e) {
      if (e.name === 'AbortError') patch((j) => ({ ...j, running: false, stopped: true }));
      else { badKey = badKey || e.badKey; patch((j) => ({ ...j, running: false, error: e.message })); }
    }
    cacheSave(); setBusy(false); ctl.current = null;
    if (badKey) forget('VirusTotal rejected your key. Paste a valid one to continue.');
    else loadPlan(key);
  }

  function onText(text) {
    const list = splitIndicators(text).slice(0, 100);
    if (!list.length) return;
    add({ role: 'user', text });
    runJob(list.length === 1 ? list[0] : `${list.length} indicators`, 'vt-chat', list.map((ind) => ({ ind, existing: '' })));
  }

  async function onFile(file) {
    add({ role: 'user', file: file.name });
    let parsed;
    try { parsed = await readSheet(await file.arrayBuffer()); }
    catch { return say('I could not read that file. Save it as .xlsx and try again.'); }
    if (!parsed || !parsed.items.length) return say('I could not find an “indicator” column with data. The template shows the layout.', { template: true });
    runJob(file.name, file.name.replace(/\.[^.]+$/, ''), parsed.items);
  }

  return (
    <div className="flex h-dvh flex-col bg-background">
      <Header plan={plan} hasKey={!!key} busy={busy} onChangeKey={() => forget('Paste your new VirusTotal API key below.')} />
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-6xl space-y-6 px-4 py-6">
          {msgs.map((m) => <Message key={m.id} m={m} onStop={() => ctl.current?.abort()} onDownload={(j) => downloadExcel(j.items, j.base)} onTemplate={downloadTemplate} />)}
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
