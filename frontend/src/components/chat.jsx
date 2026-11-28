import { useRef, useState } from 'react';
import { ArrowUp, Download, ExternalLink, FileSpreadsheet, KeyRound, Loader2, Moon, Paperclip, Square, Sun } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Progress } from '@/components/ui/progress';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';
import { scoreText } from '@/lib/ioc';
import { useTheme } from '@/lib/theme';

const vtLink = (u) => (typeof u === 'string' && u.startsWith('https://www.virustotal.com/') ? u : null);

// Black and white only: weight and fill carry the severity.
const SEV_STYLE = {
  Critical: 'border-transparent bg-primary text-primary-foreground',
  High: 'border-transparent bg-neutral-600 text-white dark:bg-neutral-400 dark:text-neutral-950',
  Medium: 'border-neutral-900 text-neutral-900 dark:border-neutral-200 dark:text-neutral-200',
  Clean: 'border-transparent bg-neutral-100 text-neutral-600 dark:bg-neutral-800 dark:text-neutral-400',
};

export function SevBadge({ sev }) {
  if (!sev) return <Badge variant="outline" className="text-muted-foreground"><Loader2 className="animate-spin" />Checking</Badge>;
  return <Badge variant="outline" className={cn(SEV_STYLE[sev] || 'border-dashed text-muted-foreground')}>{sev}</Badge>;
}

export function Header({ plan, hasKey, busy, onChangeKey }) {
  const [theme, toggleTheme] = useTheme();
  return (
    <header className="border-b">
      <div className="mx-auto flex h-14 w-full max-w-6xl items-center justify-between px-4">
        <div className="flex items-center gap-2 font-semibold">
          <span className="grid size-7 place-items-center rounded-md bg-primary text-xs text-primary-foreground">VT</span>
          VT Checker
        </div>
        <div className="flex items-center gap-2">
          {hasKey && plan && (
            <Badge variant="outline" className="font-normal text-muted-foreground">
              {plan.label} · {plan.rpm}/min{plan.dailyLeft != null && ` · ${plan.dailyLeft} left today`}
            </Badge>
          )}
          {hasKey && <Button variant="ghost" size="sm" onClick={onChangeKey} disabled={busy}><KeyRound />Change key</Button>}
          <Button variant="ghost" size="icon" onClick={toggleTheme} aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}>
            {theme === 'dark' ? <Sun /> : <Moon />}
          </Button>
        </div>
      </div>
    </header>
  );
}

export function Composer({ keyMode, busy, onText, onFile, onKey }) {
  const [text, setText] = useState('');
  const fileRef = useRef(null);
  const send = () => {
    const t = text.trim();
    if (!t || busy) return;
    keyMode ? onKey(t) : onText(t);
    setText('');
  };
  return (
    <div className="flex items-end gap-2 rounded-2xl border bg-background p-2 shadow-sm focus-within:ring-2 focus-within:ring-ring">
      {keyMode ? (
        <Input
          type="password" autoComplete="off" autoFocus value={text} onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && send()} placeholder="Paste your VirusTotal API key"
          aria-label="VirusTotal API key" className="h-10 border-0 focus-visible:ring-0"
        />
      ) : (
        <>
          <Button variant="ghost" size="icon" onClick={() => fileRef.current.click()} disabled={busy} aria-label="Attach Excel file" title="Attach an .xlsx file">
            <Paperclip />
          </Button>
          <input ref={fileRef} type="file" accept=".xlsx" hidden onChange={(e) => { if (e.target.files[0]) onFile(e.target.files[0]); e.target.value = ''; }} />
          <Textarea
            value={text} onChange={(e) => setText(e.target.value)} disabled={busy}
            onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } }}
            placeholder={busy ? 'Checking…' : 'Paste IPs, domains, URLs or hashes. Defanged is fine.'}
            aria-label="Indicators" rows={1} className="border-0 focus-visible:ring-0"
          />
        </>
      )}
      <Button size="icon" onClick={send} disabled={busy || !text.trim()} aria-label="Send"><ArrowUp /></Button>
    </div>
  );
}

function ResultsTable({ items }) {
  return (
    <div className="max-h-[28rem] overflow-auto rounded-lg border">
      <Table>
        <TableHeader className="sticky top-0 z-10 bg-background">
          <TableRow>
            <TableHead>Indicator</TableHead>
            <TableHead className="w-36">Severity</TableHead>
            <TableHead className="w-28 whitespace-nowrap text-right">VT score</TableHead>
            <TableHead className="w-10" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((it, i) => {
            const r = it.row, link = r && vtLink(r.link);
            return (
              <TableRow key={i}>
                <TableCell className="w-full max-w-0">
                  <div className="truncate font-mono text-xs" title={it.ind}>{it.ind}</div>
                  {r && r.value !== it.ind && <div className="truncate text-xs text-muted-foreground">→ {r.value}</div>}
                  {r?.note && <div className="truncate text-xs text-muted-foreground">{r.note}</div>}
                </TableCell>
                <TableCell><SevBadge sev={r?.sev} /></TableCell>
                <TableCell className="whitespace-nowrap text-right font-mono text-xs">
                  {r ? scoreText(r) : ''}
                  {r?.cached && <div className="font-sans text-[10px] text-muted-foreground">cached</div>}
                </TableCell>
                <TableCell>
                  {link && <a href={link} target="_blank" rel="noopener noreferrer" aria-label="Open on VirusTotal" className="text-muted-foreground hover:text-foreground"><ExternalLink className="size-4" /></a>}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

function JobCard({ job, onStop, onDownload }) {
  const pct = job.need ? Math.round((job.done / job.need) * 100) : 100;
  const left = Math.max(1, Math.ceil((job.need - job.done) / job.rpm));
  const finished = job.items.filter((x) => x.row).length;
  const fromCache = job.items.filter((x) => x.row?.cached).length;
  return (
    <div className="space-y-3">
      {job.need > 0 && (
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>
              {job.running ? `Looking up ${job.done} of ${job.need} new indicators · about ${left} min left at ${job.rpm}/min`
                : job.stopped ? `Stopped at ${job.done} of ${job.need} new lookups` : `Done: ${job.items.length} rows, ${job.done} looked up now`}
              {fromCache > 0 && ` · ${fromCache} from the 24h cache`}
            </span>
            <span>{pct}%</span>
          </div>
          <Progress value={pct} />
        </div>
      )}
      {job.error && <p className="text-sm font-medium">{job.error}</p>}
      <ResultsTable items={job.items} />
      <div className="flex gap-2">
        {job.running && <Button variant="outline" size="sm" onClick={onStop}><Square />Stop</Button>}
        {!job.running && finished > 1 && <Button size="sm" onClick={() => onDownload(job)}><Download />Download Excel</Button>}
      </div>
    </div>
  );
}

export function Message({ m, onStop, onDownload }) {
  if (m.role === 'user') {
    return (
      <div className="flex justify-end">
        <div className="max-w-[85%] whitespace-pre-wrap break-words rounded-2xl rounded-br-sm bg-primary px-4 py-2 text-sm text-primary-foreground">
          {m.file ? <span className="inline-flex items-center gap-2"><FileSpreadsheet className="size-4" />{m.file}</span> : m.text}
        </div>
      </div>
    );
  }
  return (
    <div className="flex gap-3">
      <span className="mt-0.5 grid size-7 shrink-0 place-items-center rounded-full border text-[10px] font-semibold">VT</span>
      <div className="min-w-0 flex-1 space-y-3">
        {m.text && <p className="text-sm leading-relaxed">{m.text}</p>}
        {m.job && <JobCard job={m.job} onStop={onStop} onDownload={onDownload} />}
      </div>
    </div>
  );
}

