import { scoreText } from './ioc';

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

// Reads only the "indicator" column. Every other column, including any severity already in the sheet, is ignored.
export async function readSheet(buffer) {
  const ExcelJS = await xl();
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.load(buffer);
  for (const ws of wb.worksheets) {
    let ci = 0, hr = 0;
    for (let r = 1; r <= Math.min(ws.rowCount, 15) && !ci; r++) {
      ws.getRow(r).eachCell({ includeEmpty: false }, (cell, c) => {
        if (!ci && String(cell.text ?? '').trim().toLowerCase() === 'indicator') { ci = c; hr = r; }
      });
    }
    if (!ci) continue;
    const items = [];
    for (let r = hr + 1; r <= ws.rowCount; r++) {
      const row = ws.getRow(r);
      const ind = String(row.getCell(ci).text ?? '').trim();
      if (ind) items.push({ ind });
    }
    return { items, sheet: ws.name };
  }
  return null;
}

// items: [{ ind, row }]  ->  Indicator | Severity | VT Score, as a real Excel table
export async function downloadExcel(items, name) {
  const ExcelJS = await xl();
  const done = items.filter((it) => it.row);
  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet('Results', { views: [{ state: 'frozen', ySplit: 1 }] });
  ws.addTable({
    name: 'IOCResults', ref: 'A1', headerRow: true, totalsRow: false,
    style: { theme: 'TableStyleLight1', showRowStripes: false },
    columns: [{ name: 'Indicator', filterButton: true }, { name: 'Severity', filterButton: true }, { name: 'VT Score', filterButton: true }],
    rows: done.map((it) => [it.ind, it.row.sev, scoreText(it.row)]),
  });
  [60, 18, 14].forEach((w, i) => { ws.getColumn(i + 1).width = w; });

  ws.getRow(1).height = 22;
  for (let c = 1; c <= 3; c++) {
    const h = ws.getCell(1, c);
    h.font = { name: 'Arial', size: 11, bold: true, color: { argb: 'FFFFFFFF' } };
    h.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: NAVY } };
    h.alignment = { vertical: 'middle', horizontal: c === 1 ? 'left' : 'center', indent: c === 1 ? 1 : 0 };
  }
  done.forEach((it, i) => {
    const r = i + 2, s = sevStyle(it.row.sev);
    for (let c = 1; c <= 3; c++) {
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

export async function downloadTemplate() {
  const ExcelJS = await xl();
  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet('Indicators');
  ws.addTable({
    name: 'Indicators', ref: 'A1', headerRow: true, style: { theme: 'TableStyleLight1', showRowStripes: false },
    columns: [{ name: 'indicator' }, { name: 'severity' }],
    rows: [['8.8.8.8', ''], ['example[.]com', ''], ['hxxps://example[.]org/login', ''], ['44d88612fea8a8f36de82e1278abb02f', '']],
  });
  ws.getColumn(1).width = 60; ws.getColumn(2).width = 16;
  for (let c = 1; c <= 2; c++) {
    const h = ws.getCell(1, c);
    h.font = { name: 'Arial', size: 11, bold: true, color: { argb: 'FFFFFFFF' } };
    h.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: NAVY } };
  }
  save(await wb.xlsx.writeBuffer(), 'vt-template.xlsx');
}
