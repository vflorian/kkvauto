/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Public HTTPS endpoint that receives contact form submissions as JSON (POST). */
  readonly VITE_CONTACT_ENDPOINT?: string;
  /** URL of the privacy notice (adatkezelési tájékoztató). */
  readonly VITE_PRIVACY_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
