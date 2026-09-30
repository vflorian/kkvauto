import { track } from './analytics';
import { TASK_OPTIONS, isTaskId, taskLabel, type TaskId } from './tasks';

const ENDPOINT = import.meta.env.VITE_CONTACT_ENDPOINT?.trim() ?? '';
const PRIVACY_URL = import.meta.env.VITE_PRIVACY_URL?.trim() ?? '';
const REQUEST_TIMEOUT_MS = 15000;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

type FieldName = 'name' | 'email' | 'description';

export interface ContactPayload {
  name: string;
  email: string;
  company: string;
  taskType: TaskId | '';
  taskTypeLabel: string;
  description: string;
  tools: string;
  page: string;
  submittedAt: string;
}

let selectElement: HTMLSelectElement | null = null;

/** Preselects the task type in the contact form (used by CTAs across the page). */
export function preselectTask(task: TaskId): void {
  if (!selectElement) return;
  selectElement.value = task;
  track('task_type_preselect', { task_type: task });
}

function validate(form: HTMLFormElement): Partial<Record<FieldName, string>> {
  const data = new FormData(form);
  const errors: Partial<Record<FieldName, string>> = {};
  const name = String(data.get('name') ?? '').trim();
  const email = String(data.get('email') ?? '').trim();
  const description = String(data.get('description') ?? '').trim();

  if (!name) errors.name = 'Kérlek, add meg a neved.';
  if (!email) errors.email = 'Kérlek, add meg az e-mail-címed.';
  else if (!EMAIL_PATTERN.test(email)) errors.email = 'Ez nem tűnik érvényes e-mail-címnek.';
  if (!description) errors.description = 'Írd le röviden a feladatot.';
  else if (description.length < 20) errors.description = 'Írj egy kicsit többet: legalább 20 karakter kell, hogy értsem a feladatot.';

  return errors;
}

function showErrors(form: HTMLFormElement, errors: Partial<Record<FieldName, string>>): void {
  (['name', 'email', 'description'] as const).forEach((field) => {
    const input = form.elements.namedItem(field) as HTMLInputElement | HTMLTextAreaElement;
    const message = form.querySelector<HTMLElement>(`[data-error-for="${field}"]`);
    const error = errors[field];
    input.setAttribute('aria-invalid', error ? 'true' : 'false');
    if (message) message.textContent = error ?? '';
  });
}

async function send(payload: ContactPayload): Promise<void> {
  if (!ENDPOINT) {
    throw new Error('VITE_CONTACT_ENDPOINT is not configured');
  }
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`Contact endpoint responded with ${response.status}`);
    }
  } finally {
    window.clearTimeout(timer);
  }
}

export function initContactForm(): void {
  const form = document.querySelector<HTMLFormElement>('[data-contact-form]');
  const success = document.querySelector<HTMLElement>('[data-form-success]');
  if (!form || !success) return;

  selectElement = form.querySelector<HTMLSelectElement>('[data-task-select]');
  if (selectElement) {
    for (const option of TASK_OPTIONS) {
      selectElement.add(new Option(option.label, option.id));
    }
    selectElement.addEventListener('change', () => {
      if (selectElement?.value) track('task_type_select', { task_type: selectElement.value, where: 'form' });
    });
  }

  if (PRIVACY_URL) {
    const note = form.querySelector<HTMLElement>('[data-privacy-note]');
    if (note) {
      note.innerHTML = 'Az adataidat a megkeresésed megválaszolásához használom. Részletek az <a></a>.';
      const link = note.querySelector('a')!;
      link.href = PRIVACY_URL;
      link.textContent = 'adatkezelési tájékoztatóban';
      note.hidden = false;
    }
    const footerItem = document.querySelector<HTMLElement>('[data-privacy-footer]');
    if (footerItem) {
      const link = document.createElement('a');
      link.href = PRIVACY_URL;
      link.textContent = 'Adatkezelési tájékoztató';
      footerItem.append(link);
      footerItem.hidden = false;
    }
  }

  const status = form.querySelector<HTMLElement>('[data-form-status]')!;
  const submit = form.querySelector<HTMLButtonElement>('[data-submit]')!;
  const submitLabel = form.querySelector<HTMLElement>('[data-submit-label]')!;
  let attempted = false;
  let sending = false;

  form.addEventListener('input', () => {
    if (attempted) showErrors(form, validate(form));
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (sending) return;
    attempted = true;
    status.textContent = '';
    status.className = 'form-status';

    const errors = validate(form);
    showErrors(form, errors);
    const firstInvalid = (['name', 'email', 'description'] as const).find((field) => errors[field]);
    if (firstInvalid) {
      (form.elements.namedItem(firstInvalid) as HTMLElement).focus();
      status.textContent = 'Néhány mező hiányos. Javítsd, és küldd el újra.';
      status.classList.add('is-error');
      track('contact_form_invalid', { fields: Object.keys(errors).join(',') });
      return;
    }

    const data = new FormData(form);
    // Honeypot: real visitors never see or fill this field.
    if (String(data.get('website') ?? '').trim()) {
      status.textContent = 'Az üzenetet nem sikerült elküldeni.';
      status.classList.add('is-error');
      return;
    }

    const rawTask = String(data.get('taskType') ?? '');
    const taskType: TaskId | '' = isTaskId(rawTask) ? rawTask : '';
    const payload: ContactPayload = {
      name: String(data.get('name')).trim(),
      email: String(data.get('email')).trim(),
      company: String(data.get('company') ?? '').trim(),
      taskType,
      taskTypeLabel: taskType ? taskLabel(taskType) : '',
      description: String(data.get('description')).trim(),
      tools: String(data.get('tools') ?? '').trim(),
      page: window.location.href,
      submittedAt: new Date().toISOString(),
    };

    sending = true;
    submit.disabled = true;
    form.setAttribute('aria-busy', 'true');
    form.classList.add('is-sending');
    submitLabel.textContent = 'Küldés folyamatban…';
    status.textContent = 'Küldés folyamatban…';

    try {
      await send(payload);
      track('contact_form_success', { task_type: taskType || 'nincs_megadva' });
      form.reset();
      attempted = false;
      showErrors(form, {});
      status.textContent = '';
      form.hidden = true;
      success.hidden = false;
      success.focus();
    } catch (error) {
      console.error('[kapcsolat] Sikertelen küldés:', error);
      status.textContent = ENDPOINT
        ? 'Az üzenetet nem sikerült elküldeni. Ellenőrizd az internetkapcsolatot, és próbáld újra pár perc múlva.'
        : 'Az üzenetküldés jelenleg nem érhető el. Kérlek, próbáld újra később.';
      status.classList.add('is-error');
      track('contact_form_error', { task_type: taskType || 'nincs_megadva', reason: ENDPOINT ? 'request_failed' : 'not_configured' });
    } finally {
      sending = false;
      submit.disabled = false;
      form.removeAttribute('aria-busy');
      form.classList.remove('is-sending');
      submitLabel.textContent = 'Elküldöm a feladatot';
    }
  });

  success.querySelector<HTMLButtonElement>('[data-form-again]')?.addEventListener('click', () => {
    success.hidden = true;
    form.hidden = false;
    (form.elements.namedItem('name') as HTMLInputElement).focus();
  });
}
