import { track } from './analytics';
import { escapeHtml } from './dom';
import { TASK_EXAMPLES } from './tasks';

type PickerTask = keyof typeof TASK_EXAMPLES;

function isPickerTask(value: string | undefined): value is PickerTask {
  return !!value && value in TASK_EXAMPLES;
}

export function initTaskPicker(): void {
  const picker = document.querySelector<HTMLElement>('[data-task-picker]');
  const detail = document.querySelector<HTMLElement>('[data-task-detail]');
  if (!picker || !detail) return;

  const cards = [...picker.querySelectorAll<HTMLButtonElement>('[data-task]')];

  const select = (task: PickerTask): void => {
    cards.forEach((card) => card.setAttribute('aria-pressed', String(card.dataset.task === task)));
    const example = TASK_EXAMPLES[task];
    detail.innerHTML = `
      <h3>${escapeHtml(example.title)}</h3>
      <div class="task-compare">
        <div><p class="compare-label">Most</p><p>${escapeHtml(example.before)}</p></div>
        <div class="compare-arrow" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6" /></svg></div>
        <div><p class="compare-label compare-label-after">Automatizálva</p><p>${escapeHtml(example.after)}</p></div>
      </div>
      <div class="task-detail-actions">
        <a class="btn btn-primary" href="#kapcsolat" data-preselect="${task}" data-track-cta="task-picker">Ezzel a feladattal jelentkezem</a>
        ${example.secondary ? `<a class="text-link" href="${escapeHtml(example.secondary.href)}" data-track-cta="task-picker-demo">${escapeHtml(example.secondary.label)}</a>` : ''}
      </div>`;
    detail.hidden = false;
    detail.classList.remove('is-entering');
    void detail.offsetWidth;
    detail.classList.add('is-entering');
    track('task_type_select', { task_type: task, where: 'picker' });
  };

  cards.forEach((card) => {
    card.addEventListener('click', () => {
      if (isPickerTask(card.dataset.task)) select(card.dataset.task);
    });
  });
}
