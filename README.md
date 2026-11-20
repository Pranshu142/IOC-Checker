# VT Checker v3: React (shadcn) + Java

```
frontend/   React 18 + Vite + Tailwind 4 + shadcn/ui. One chat screen, black and white.
backend/    Java 21, zero dependencies. Virtual-thread lookup engine.
```

## Using it
Paste a VirusTotal key once per tab. Then paste indicators (defanged is fine) or attach an `.xlsx`
with an `indicator` column. Only that column (and `severity`, if present) is read. Rows that
already have a severity are skipped. Results fill in live; **Download Excel** gives a table with
Indicator, Severity (colour-coded) and VT Score.

Severity (VirusTotal malicious count): 0 Clean, 1-5 Medium, 6-10 High, above 10 Critical.

## Why 100 lookups take about 25 minutes on a free key
VirusTotal's free API allows 4 lookups per minute. 100 / 4 = 25 minutes, whatever the code does;
threads cannot raise a quota that VirusTotal enforces per key. What the app does about it:
- reads your key's real quota from VirusTotal and runs at that speed (premium keys run in parallel),
- skips duplicates, invalid values and rows that already have a severity (private IPs are checked too),
- keeps a 24-hour result cache in the browser (and 6 hours on the server), so re-runs cost nothing,
- stops at once when the daily quota is gone instead of waiting on retries.

## Run locally
Terminal 1 (JDK 21+): `cd backend && java src/Main.java`
Terminal 2 (Node 18+): `cd frontend && npm install && npm run dev` -> http://localhost:5173

## Deploy free
Backend: Render web service, Root Directory `backend`, Docker. Env `ALLOWED_ORIGIN` = frontend URL.
Frontend: Vercel, Root Directory `frontend`. Env `VITE_API_URL` = backend URL (no trailing slash).
