import { PRODUCTS, SAMPLE_FILES, WEEK, type SampleFile } from './demoData';

export interface NormalizedRow {
  fileId: string;
  source: string;
  line: number;
  date: string;
  sku: string;
  qty: number;
  net: number;
  key: string;
}

export type IssueSeverity = 'excluded' | 'warning';

export interface Issue {
  severity: IssueSeverity;
  source: string;
  fileName: string;
  line: number;
  reason: string;
  detail: string;
}

export interface SummaryLine {
  sku: string;
  name: string;
  qty: number;
  net: number;
}

export interface DemoResult {
  totalRows: number;
  includedRows: number;
  issues: Issue[];
  byProduct: SummaryLine[];
  bySource: { source: string; net: number; rows: number }[];
  totalNet: number;
}

export function parseTable(file: SampleFile): string[][] {
  return file.raw
    .split('\n')
    .map((line) => line.split(file.delimiter).map((cell) => cell.trim()));
}

/** "2026.09.21." → "2026-09-21"; "2026-09-21T09:14:00" → "2026-09-21". */
function normalizeDate(value: string): string {
  const hu = /^(\d{4})\.(\d{2})\.(\d{2})\.?$/.exec(value);
  if (hu) return `${hu[1]}-${hu[2]}-${hu[3]}`;
  return value.slice(0, 10);
}

/** "51 600,00" → 51600; "77400" → 77400. */
function normalizeNumber(value: string): number {
  return Number(value.replace(/\s/g, '').replace(',', '.'));
}

function normalizeFile(file: SampleFile): NormalizedRow[] {
  const [, ...rows] = parseTable(file);
  return rows.map((cells, index) => {
    const line = index + 2;
    if (file.id === 'webshop') {
      const [orderId, date, sku, qty, net] = cells;
      return {
        fileId: file.id,
        source: file.source,
        line,
        date: normalizeDate(date),
        sku,
        qty: normalizeNumber(qty),
        net: normalizeNumber(net),
        key: `${orderId}|${sku}|${qty}`,
      };
    }
    const [date, sku, , qty, net] = cells;
    return {
      fileId: file.id,
      source: file.source,
      line,
      date: normalizeDate(date),
      sku,
      qty: normalizeNumber(qty),
      net: normalizeNumber(net),
      key: `${file.id}|${line}`,
    };
  });
}

export function runDemo(files: readonly SampleFile[] = SAMPLE_FILES): DemoResult {
  const issues: Issue[] = [];
  const included: NormalizedRow[] = [];
  const seenKeys = new Set<string>();
  let totalRows = 0;

  for (const file of files) {
    for (const row of normalizeFile(file)) {
      totalRows += 1;
      const base = { source: file.source, fileName: file.name, line: row.line };

      if (!row.sku) {
        issues.push({ ...base, severity: 'excluded', reason: 'Hiányzó cikkszám', detail: `${row.qty} db, ${formatFt(row.net)}` });
        continue;
      }
      if (!PRODUCTS[row.sku]) {
        issues.push({ ...base, severity: 'excluded', reason: 'Ismeretlen cikkszám', detail: `„${row.sku}” nem szerepel a terméklistában` });
        continue;
      }
      if (row.date < WEEK.start || row.date > WEEK.end) {
        issues.push({ ...base, severity: 'excluded', reason: 'Dátum a héten kívül', detail: `${row.date} – nem ehhez a héthez tartozik` });
        continue;
      }
      if (seenKeys.has(row.key)) {
        issues.push({ ...base, severity: 'excluded', reason: 'Ismétlődő sor', detail: 'Ugyanaz a rendelési tétel kétszer szerepel' });
        continue;
      }
      seenKeys.add(row.key);

      if (row.qty < 0) {
        issues.push({ ...base, severity: 'warning', reason: 'Negatív mennyiség', detail: `${row.qty} db – valószínűleg visszáru, összesítve, de érdemes ellenőrizni` });
      }
      included.push(row);
    }
  }

  const productMap = new Map<string, SummaryLine>();
  const sourceMap = new Map<string, { source: string; net: number; rows: number }>();
  for (const row of included) {
    const product = productMap.get(row.sku) ?? { sku: row.sku, name: PRODUCTS[row.sku].name, qty: 0, net: 0 };
    product.qty += row.qty;
    product.net += row.net;
    productMap.set(row.sku, product);

    const source = sourceMap.get(row.source) ?? { source: row.source, net: 0, rows: 0 };
    source.net += row.net;
    source.rows += 1;
    sourceMap.set(row.source, source);
  }

  const byProduct = [...productMap.values()].sort((a, b) => b.net - a.net);
  return {
    totalRows,
    includedRows: included.length,
    issues,
    byProduct,
    bySource: [...sourceMap.values()],
    totalNet: byProduct.reduce((sum, line) => sum + line.net, 0),
  };
}

const ftFormatter = new Intl.NumberFormat('hu-HU', { maximumFractionDigits: 0 });

export function formatFt(value: number): string {
  return `${ftFormatter.format(value)} Ft`;
}

export function formatNumber(value: number): string {
  return ftFormatter.format(value);
}

export function toCsv(result: DemoResult): string {
  const lines = [
    `Heti összesítő – bemutató mintaadatokkal;${WEEK.label}`,
    '',
    'Cikkszám;Termék;Mennyiség;Nettó összeg (Ft)',
    ...result.byProduct.map((line) => `${line.sku};${line.name};${line.qty};${line.net}`),
    `;Összesen;;${result.totalNet}`,
    '',
    'Eltéréslista',
    'Forrás;Fájl;Sor;Kezelés;Ok;Részletek',
    ...result.issues.map(
      (issue) =>
        `${issue.source};${issue.fileName};${issue.line};${issue.severity === 'excluded' ? 'Kihagyva' : 'Összesítve, ellenőrizendő'};${issue.reason};${issue.detail}`,
    ),
  ];
  return lines.join('\r\n');
}
