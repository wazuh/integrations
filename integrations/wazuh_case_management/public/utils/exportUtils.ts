/*
 * Export helpers — no external dependencies.
 *
 * exportCasesToExcel : generates an HTML-table .xls file (Excel opens natively)
 * exportDashboardPdf : triggers window.print() after applying a print-mode class
 */

import { Case } from '../../common/types';

// ─── Excel ────────────────────────────────────────────────────

const EXCEL_COLUMNS: Array<{ header: string; key: keyof Case | string }> = [
  { header: 'Case ID',     key: 'case_id' },
  { header: 'Title',       key: 'title' },
  { header: 'Status',      key: 'status' },
  { header: 'Severity',    key: 'severity' },
  { header: 'Priority',    key: 'priority' },
  { header: 'Category',    key: 'category' },
  { header: 'Assignee',    key: 'assignee' },
  { header: 'Tags',        key: 'tags' },
  { header: 'Created At',  key: 'created_at' },
  { header: 'Updated At',  key: 'updated_at' },
  { header: 'Closed At',   key: 'closed_at' },
  { header: 'Created By',  key: 'created_by' },
];

function cellValue(c: Case, key: string): string {
  const v = (c as any)[key];
  if (v == null) return '';
  if (Array.isArray(v)) return v.join(', ');
  if (typeof v === 'string' && (key.endsWith('_at') || key === 'closed_at')) {
    try { return new Date(v).toLocaleString(); } catch { return v; }
  }
  return String(v);
}

function escape(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

interface ExportRangeMeta {
  label: string;
  from?: string;
  to?: string;
}

export function exportCasesToExcel(
  cases: Case[],
  filename = 'wazuh-cases',
  range?: ExportRangeMeta,
): void {
  const now = new Date().toLocaleString();

  const rangeInfo = range
    ? range.from && range.to
      ? `${escape(range.label)}: ${escape(new Date(range.from).toLocaleString())} → ${escape(new Date(range.to).toLocaleString())}`
      : escape(range.label)
    : 'All time';

  const headerRow = EXCEL_COLUMNS.map(
    (c) => `<th style="background:#006BB4;color:#fff;padding:6px 10px;border:1px solid #ccc;white-space:nowrap">${escape(c.header)}</th>`
  ).join('');

  const dataRows = cases.map((c, i) => {
    const bg = i % 2 === 0 ? '#ffffff' : '#f4f7fb';
    const cells = EXCEL_COLUMNS.map(
      (col) => `<td style="padding:5px 10px;border:1px solid #ddd;background:${bg}">${escape(cellValue(c, col.key))}</td>`
    ).join('');
    return `<tr>${cells}</tr>`;
  }).join('');

  const html = `
<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">
<head>
  <meta charset="UTF-8">
  <!--[if gte mso 9]><xml><x:ExcelWorkbook><x:ExcelWorksheets><x:ExcelWorksheet>
  <x:Name>Cases</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions>
  </x:ExcelWorksheet></x:ExcelWorksheets></x:ExcelWorkbook></xml><![endif]-->
</head>
<body>
  <table style="border-collapse:collapse;font-family:Arial,sans-serif;font-size:12px">
    <tr>
      <td colspan="${EXCEL_COLUMNS.length}" style="padding:10px 10px 4px;font-size:16px;font-weight:bold;color:#006BB4;border:none">
        Wazuh Case Management — Case Report
      </td>
    </tr>
    <tr>
      <td colspan="${EXCEL_COLUMNS.length}" style="padding:2px 10px 2px;font-size:12px;color:#555;border:none">
        Period: ${rangeInfo}
      </td>
    </tr>
    <tr>
      <td colspan="${EXCEL_COLUMNS.length}" style="padding:2px 10px 10px;font-size:11px;color:#888;border:none;border-bottom:2px solid #1D76EE">
        Exported: ${escape(now)} &nbsp;|&nbsp; Total cases: ${cases.length}
      </td>
    </tr>
    <tr><td colspan="${EXCEL_COLUMNS.length}" style="padding:6px;border:none">&nbsp;</td></tr>
    <thead><tr>${headerRow}</tr></thead>
    <tbody>${dataRows}</tbody>
    <tfoot>
      <tr><td colspan="${EXCEL_COLUMNS.length}" style="padding:6px 10px;font-size:11px;color:#888;border-top:2px solid #ccc">
        ${cases.length} case(s) exported — Wazuh Case Management Plugin
      </td></tr>
    </tfoot>
  </table>
</body>
</html>`;

  // Use a data URI so the download works inside OSD's sandboxed context.
  // btoa/unescape handles the UTF-8 → base64 conversion reliably.
  const base64 = btoa(unescape(encodeURIComponent(html)));
  const dataUri = `data:application/vnd.ms-excel;base64,${base64}`;
  const a = document.createElement('a');
  a.href = dataUri;
  a.download = `${filename}-${new Date().toISOString().slice(0, 10)}.xls`;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  setTimeout(() => document.body.removeChild(a), 300);
}

// ─── PDF / Print ──────────────────────────────────────────────

export function exportDashboardPdf(): void {
  // Apply print-mode class so the SCSS @media print rules hide nav/actions
  document.body.classList.add('cm-print-mode');
  window.print();
  // Remove class after the print dialog closes
  const cleanup = () => {
    document.body.classList.remove('cm-print-mode');
    window.removeEventListener('afterprint', cleanup);
  };
  window.addEventListener('afterprint', cleanup);
  // Fallback: remove class after 3 seconds in case afterprint never fires
  setTimeout(() => document.body.classList.remove('cm-print-mode'), 3000);
}
