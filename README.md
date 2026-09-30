# kkvauto.hu

A KKVauto magyar nyelvű, egyoldalas ügyfélszerző weboldala.

Technológia: [Vite](https://vite.dev) + TypeScript, keretrendszer nélkül. A kimenet statikus (`dist/`),
bármilyen statikus tárhelyre feltölthető.

## Parancsok

```bash
npm install
npm run dev        # helyi fejlesztői előnézet: http://localhost:5173
npm run build      # típusellenőrzés + éles build a dist/ mappába
npm run preview    # a buildelt oldal előnézete: http://localhost:4173
npm run lint       # ESLint
npm run typecheck  # TypeScript
npm run check      # lint + typecheck + build
```

## Konfiguráció

Másold a `.env.example` fájlt `.env` néven, és töltsd ki (build előtt kell megadni):

| Változó | Leírás |
| --- | --- |
| `VITE_CONTACT_ENDPOINT` | Nyilvános HTTPS-végpont, amely az űrlapot JSON-ként (POST) fogadja és elmenti. Csak 2xx válasz esetén jelenik meg a sikeres küldés. Titkos kulcs nem kerülhet ide. |
| `VITE_PRIVACY_URL` | Az adatkezelési tájékoztató címe. Ha megadod, megjelenik az űrlapnál és a láblécben. |

Ha `VITE_CONTACT_ENDPOINT` nincs megadva, az űrlap hibaüzenetet ad, és **nem** mutat sikeres beküldést.

### Az űrlap által küldött adat

```json
{
  "name": "…", "email": "…", "company": "…",
  "taskType": "riport | integracio | adminisztracio | alkalmazas | gepkolcsonzo | egyeb | ''",
  "taskTypeLabel": "Riportok és adatfeldolgozás",
  "description": "…", "tools": "…",
  "page": "https://kkvauto.hu/#kapcsolat",
  "submittedAt": "2026-09-30T12:00:00.000Z"
}
```

## Mérés

Nincs beépített analitikai szolgáltató. A `src/analytics.ts` az eseményeket a `window.dataLayer`-be
(Google Tag Manager / GA4) és – ha be van töltve – a Plausible-nek küldi, így a szolgáltató
bekötése kódmódosítás nélkül működik. Események:

| Esemény | Paraméterek |
| --- | --- |
| `cta_click` | `location`, `label` |
| `task_type_select` | `task_type`, `where` (`picker` / `form`) |
| `task_type_preselect` | `task_type` |
| `demo_start`, `demo_complete`, `demo_download` | – |
| `outbound_click` | `target` |
| `contact_form_invalid` | `fields` |
| `contact_form_success` | `task_type` |
| `contact_form_error` | `task_type`, `reason` |

## Fájlok

- `index.html` – az oldal teljes tartalma és a SEO/megosztási metaadatok
- `src/` – interakciók: menü, feladatválasztó, bemutató, űrlap, mérés
- `src/demoData.ts` – a bemutató szintetikus mintaadatai
- `scripts/og-image.html` – a `public/og-image.png` megosztási kép forrása
