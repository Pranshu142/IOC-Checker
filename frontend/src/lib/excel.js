import { looksLikeIoc } from './ioc';

// ExcelJS is large, so it is only loaded when a file is read or written.
const xl = async () => (await import('exceljs')).default;

const NAVY = 'FF1F3864';
const SEV = {                       // light fill + dark text, the standard Excel palette
  clean:    { bg: 'FFC6EFCE', fg: 'FF006100' },
  medium:   { bg: 'FFFFEB9C', fg: 'FF9C5700' },
  high:     { bg: 'FFF8CBAD', fg: 'FF833C0B' },
  critical: { bg: 'FFFFC7CE', fg: 'FF9C0006' },
  other:    { bg: 'FFEDEDED', fg: 'FF595959' },
};
const sevStyle = (s) => SEV[String(s).toLowerCase()] || SEV.other;
const thin = { style: 'thin', color: { argb: 'FFD9D9D9' } };

function save(buffer, filename) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }));
  a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

const HEADER = /^(indicators?|iocs?|ips?|ip addresses?|domains?|urls?|hashes|hash|values?|observables?|artifacts?)$/i;
const colLetter = (n) => { let t = ''; while (n > 0) { const m = (n - 1) % 26; t = String.fromCharCode(65 + m) + t; n = Math.floor((n - 1) / 26); } return t; };

// Picks the column that holds the indicators: the one with the most IOC-looking cells, in any sheet.
// If nothing looks like an IOC but a sheet has a single column, that column is used.
// sheets: [{ name, cols: Map(columnNumber -> [cell texts in row order]) }]
export function pickColumn(sheets) {
  let best = null;
  for (const sh of sheets) {
    for (const [c, texts] of sh.cols) {
      const hits = texts.filter(looksLikeIoc).length;
      if (hits && (!best || hits > best.hits)) best = { sheet: sh.name, c, texts, hits };
    }
  }
  if (!best) {
    const one = sheets.find((sh) => sh.cols.size === 1);
    if (!one) return null;
    const [c, texts] = [...one.cols][0];
    best = { sheet: one.name, c, texts, hits: 0 };
  }
  // A first cell that is a label ("IOC", "Indicators"...) above a column of indicators is skipped.
  const first = best.texts[0];
  const label = best.texts.length > 1 && !looksLikeIoc(first) && (HEADER.test(first) || best.hits >= (best.texts.length - 1) / 2);
  return { sheet: best.sheet, column: colLetter(best.c), items: (label ? best.texts.slice(1) : best.texts).map((ind) => ({ ind })) };
}

// Any layout works: no header or special format is needed. Only the indicator column is used.
export async function readSheet(buffer) {
  const ExcelJS = await xl();
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.load(buffer);
  const sheets = wb.worksheets.map((ws) => {
    const cols = new Map();
    ws.eachRow({ includeEmpty: false }, (row) => {
      row.eachCell({ includeEmpty: false }, (cell, c) => {
        const t = String(cell.text ?? '').trim();
        if (t) { if (!cols.has(c)) cols.set(c, []); cols.get(c).push(t); }
      });
    });
    return { name: ws.name, cols };
  });
  const found = pickColumn(sheets);
  return found && found.items.length ? found : null;
}

// items: [{ ind, row }]  ->  Indicator | Severity, as a real Excel table
export async function downloadExcel(items, name) {
  const ExcelJS = await xl();
  const done = items.filter((it) => it.row);
  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet('Results', { views: [{ state: 'frozen', ySplit: 1 }] });
  ws.addTable({
    name: 'IOCResults', ref: 'A1', headerRow: true, totalsRow: false,
    style: { theme: 'TableStyleLight1', showRowStripes: false },
    columns: [{ name: 'Indicator', filterButton: true }, { name: 'Severity', filterButton: true }],
    rows: done.map((it) => [it.ind, it.row.sev]),
  });
  [64, 20].forEach((w, i) => { ws.getColumn(i + 1).width = w; });

  ws.getRow(1).height = 22;
  for (let c = 1; c <= 2; c++) {
    const h = ws.getCell(1, c);
    h.font = { name: 'Arial', size: 11, bold: true, color: { argb: 'FFFFFFFF' } };
    h.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: NAVY } };
    h.alignment = { vertical: 'middle', horizontal: c === 1 ? 'left' : 'center', indent: c === 1 ? 1 : 0 };
  }
  done.forEach((it, i) => {
    const r = i + 2, s = sevStyle(it.row.sev);
    for (let c = 1; c <= 2; c++) {
      const cell = ws.getCell(r, c);
      cell.font = { name: 'Arial', size: 10 };
      cell.border = { top: thin, bottom: thin, left: thin, right: thin };
      cell.alignment = { vertical: 'middle', horizontal: c === 1 ? 'left' : 'center', indent: c === 1 ? 1 : 0 };
    }
    const sc = ws.getCell(r, 2);
    sc.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: s.bg } };
    sc.font = { name: 'Arial', size: 10, bold: true, color: { argb: s.fg } };
  });
  save(await wb.xlsx.writeBuffer(), name + '-results.xlsx');
}
