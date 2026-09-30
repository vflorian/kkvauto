import './style.css';
import { track } from './analytics';
import { initContactForm, preselectTask } from './contactForm';
import { initDemo } from './demo';
import { initNav } from './nav';
import { initTaskPicker } from './taskPicker';
import { isTaskId } from './tasks';

initNav();
initTaskPicker();
initDemo();
initContactForm();

document.querySelectorAll('[data-year]').forEach((element) => {
  element.textContent = String(new Date().getFullYear());
});

// Delegated handlers so dynamically rendered CTAs work too.
document.addEventListener('click', (event) => {
  const target = (event.target as HTMLElement).closest<HTMLElement>('a, button');
  if (!target) return;

  const preselect = target.dataset.preselect;
  if (preselect && isTaskId(preselect)) preselectTask(preselect);

  if (target.dataset.trackCta) {
    track('cta_click', { location: target.dataset.trackCta, label: target.textContent?.trim() ?? '' });
  }
  if (target.dataset.trackOutbound) {
    track('outbound_click', { target: target.dataset.trackOutbound });
  }
});

// Reveal-on-scroll for cards; content stays visible without JS or with reduced motion.
if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches && 'IntersectionObserver' in window) {
  const revealables = document.querySelectorAll<HTMLElement>('.solution, .steps li, .cost, .product-features li, .task-card, .also-card');
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      }
    },
    { rootMargin: '0px 0px -8% 0px' },
  );
  revealables.forEach((element) => {
    element.classList.add('reveal');
    observer.observe(element);
  });
}
