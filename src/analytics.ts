/**
 * Minimal, provider-agnostic event tracking.
 *
 * The project has no analytics provider configured yet. Events are pushed to
 * `window.dataLayer` (Google Tag Manager / GA4 compatible) and forwarded to
 * Plausible when its script is present, so connecting either later requires no
 * code change. A DOM event (`kkvauto:track`) is also dispatched for debugging.
 */

type EventProps = Record<string, string | number | boolean>;

declare global {
  interface Window {
    dataLayer?: unknown[];
    plausible?: (event: string, options?: { props?: EventProps }) => void;
  }
}

export function track(event: string, props: EventProps = {}): void {
  try {
    window.dataLayer = window.dataLayer ?? [];
    window.dataLayer.push({ event, ...props });
    window.plausible?.(event, { props });
    window.dispatchEvent(new CustomEvent('kkvauto:track', { detail: { event, props } }));
  } catch {
    // Tracking must never break the page.
  }
}
