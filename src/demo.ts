import { track } from './analytics';
import { SAMPLE_FILES, WEEK } from './demoData';
import { formatFt, formatNumber, parseTable, runDemo, toCsv, type DemoResult } from './demoEngine';
import { escapeHtml, prefersReducedMotion, wait } from './dom';

const STEP_DURATION = 900;

function renderFiles(container: HTMLElement): void {
  container.innerHTML = SAMPLE_FILES.map((file) => {
    const [header, ...rows] = parseTable(file);
    const ext = file.name.split('.').pop() ?? '';
    return `
      <article class="demo-file" data-file="${file.id}">
        <header>
          <span class="file-ext ${ext}">${escapeHtml(ext.toUpperCase())}</span>
          <div>
            <h3>${escapeHtml(file.name)}</h3>
            <p>${escapeHtml(file.source)} · ${rows.length} sor</p>
          </div>
        </header>
        <p class="demo-file-format">${escapeHtml(file.format)}</p>
        <details>
          <summary>Fájl előnézete</summary>
          <div class="table-scroll" tabindex="0" role="region" aria-label="${escapeHtml(file.name)} tartalma">
            <table class="mini-table">
              <thead><tr>${header.map((cell) => `<th scope="col">${escapeHtml(cell)}</th>`).join('')}</tr></thead>
              <tbody>${rows
                .map((row) => `<tr>${row.map((cell) => `<td>${cell ? escapeHtml(cell) : '<span class="empty">üres</span>'}</td>`).join('')}</tr>`)
                .join('')}</tbody>
            </table>
          </div>
        </details>
      </article>`;
  }).join('');
}

function renderResult(result: DemoResult): string {
  const excluded = result.issues.filter((issue) => issue.severity === 'excluded').length;
  const warnings = result.issues.length - excluded;

  return `
    <div class="result-head">
      <div>
        <h3>Heti összesítő</h3>
        <p>Mintahét: ${escapeHtml(WEEK.label)}</p>
      </div>
      <button class="btn btn-secondary btn-sm" type="button" data-demo-download>Összesítő letöltése (CSV)</button>
    </div>

    <dl class="kpis">
      <div><dt>Beolvasott sor</dt><dd>${result.totalRows}</dd></div>
      <div><dt>Összesítésbe került</dt><dd>${result.includedRows}</dd></div>
      <div class="kpi-warn"><dt>Ellenőrzést igényel</dt><dd>${result.issues.length}</dd></div>
      <div><dt>Nettó összesen</dt><dd>${escapeHtml(formatFt(result.totalNet))}</dd></div>
    </dl>

    <div class="result-grid">
      <section aria-labelledby="osszesito-termek">
        <h4 id="osszesito-termek">Termékenként</h4>
        <div class="table-scroll" tabindex="0" role="region" aria-labelledby="osszesito-termek">
          <table class="data-table">
            <thead><tr><th scope="col">Termék</th><th scope="col" class="num">Db</th><th scope="col" class="num">Nettó</th></tr></thead>
            <tbody>
              ${result.byProduct
                .map(
                  (line) => `<tr><td><span class="sku">${escapeHtml(line.sku)}</span> ${escapeHtml(line.name)}</td><td class="num">${formatNumber(line.qty)}</td><td class="num">${escapeHtml(formatFt(line.net))}</td></tr>`,
                )
                .join('')}
            </tbody>
            <tfoot><tr><th scope="row">Összesen</th><td></td><td class="num">${escapeHtml(formatFt(result.totalNet))}</td></tr></tfoot>
          </table>
        </div>
        <h4 class="mt">Forrásonként</h4>
        <ul class="source-bars">
          ${result.bySource
            .map((source) => {
              const width = Math.max(4, Math.round((source.net / result.totalNet) * 100));
              return `<li><span class="source-name">${escapeHtml(source.source)}</span><span class="bar" aria-hidden="true"><span style="width:${width}%"></span></span><span class="source-val">${escapeHtml(formatFt(source.net))}</span></li>`;
            })
            .join('')}
        </ul>
      </section>

      <section aria-labelledby="elteresek">
        <h4 id="elteresek">Eltéréslista</h4>
        <p class="issue-summary">${excluded} sor kimaradt az összesítésből, ${warnings} sor összesítve, de ellenőrizendő.</p>
        <ul class="issues">
          ${result.issues
            .map(
              (issue) => `
            <li class="issue issue-${issue.severity}">
              <span class="issue-tag">${issue.severity === 'excluded' ? 'Kihagyva' : 'Ellenőrizendő'}</span>
              <strong>${escapeHtml(issue.reason)}</strong>
              <span class="issue-where">${escapeHtml(issue.fileName)}, ${issue.line}. sor</span>
              <span class="issue-detail">${escapeHtml(issue.detail)}</span>
            </li>`,
            )
            .join('')}
        </ul>
      </section>
    </div>

    <div class="result-cta">
      <p>Nálad más fájlok és más szabályok vannak? Pont ezt nézzük meg a felmérésnél.</p>
      <a class="btn btn-primary" href="#kapcsolat" data-preselect="riport" data-track-cta="demo-result">Megnézzük, automatizálható-e?</a>
    </div>`;
}

function downloadCsv(result: DemoResult): void {
  const blob = new Blob(['﻿' + toCsv(result)], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'heti_osszesito_minta.csv';
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function initDemo(): void {
  const root = document.querySelector<HTMLElement>('[data-demo]');
  if (!root) return;

  const files = root.querySelector<HTMLElement>('[data-demo-files]')!;
  const steps = [...root.querySelectorAll<HTMLElement>('[data-demo-steps] li')];
  const runButton = root.querySelector<HTMLButtonElement>('[data-demo-run]')!;
  const resetButton = root.querySelector<HTMLButtonElement>('[data-demo-reset]')!;
  const status = root.querySelector<HTMLElement>('[data-demo-status]')!;
  const resultBox = root.querySelector<HTMLElement>('[data-demo-result]')!;
  let lastResult: DemoResult | null = null;

  renderFiles(files);

  const setStep = (active: number): void => {
    steps.forEach((step, index) => {
      step.classList.toggle('is-done', index < active);
      step.classList.toggle('is-active', index === active);
      if (index === active) step.setAttribute('aria-current', 'step');
      else step.removeAttribute('aria-current');
    });
  };

  const reset = (): void => {
    setStep(-1);
    resultBox.hidden = true;
    resultBox.innerHTML = '';
    resetButton.hidden = true;
    runButton.hidden = false;
    runButton.disabled = false;
    root.classList.remove('is-running', 'is-finished');
    files.querySelectorAll('.demo-file').forEach((file) => file.classList.remove('is-read'));
    status.textContent = '';
  };

  runButton.addEventListener('click', async () => {
    track('demo_start');
    runButton.disabled = true;
    root.classList.add('is-running');
    const delay = prefersReducedMotion() ? 150 : STEP_DURATION;

    setStep(0);
    status.textContent = 'Mintafájlok beolvasása…';
    for (const file of files.querySelectorAll('.demo-file')) {
      await wait(delay / 3);
      file.classList.add('is-read');
    }

    setStep(1);
    status.textContent = 'Adatok ellenőrzése…';
    lastResult = runDemo();
    await wait(delay);

    setStep(2);
    status.textContent = 'Összesítő készítése…';
    await wait(delay * 0.7);

    setStep(3);
    resultBox.innerHTML = renderResult(lastResult);
    resultBox.hidden = false;
    runButton.hidden = true;
    resetButton.hidden = false;
    root.classList.remove('is-running');
    root.classList.add('is-finished');
    status.textContent = `Kész. ${lastResult.includedRows} sor került az összesítésbe, ${lastResult.issues.length} sor az eltéréslistára.`;
    resultBox.focus({ preventScroll: true });
    resultBox.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
    track('demo_complete');
  });

  resetButton.addEventListener('click', () => {
    reset();
    runButton.focus();
  });

  resultBox.addEventListener('click', (event) => {
    const target = event.target as HTMLElement;
    if (target.closest('[data-demo-download]') && lastResult) {
      downloadCsv(lastResult);
      track('demo_download');
    }
  });
}
