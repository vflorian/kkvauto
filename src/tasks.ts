export type TaskId =
  | 'riport'
  | 'integracio'
  | 'adminisztracio'
  | 'alkalmazas'
  | 'gepkolcsonzo'
  | 'egyeb';

interface TaskOption {
  id: TaskId;
  /** Label shown in the contact form select and sent with the submission. */
  label: string;
}

export const TASK_OPTIONS: readonly TaskOption[] = [
  { id: 'riport', label: 'Riportok és adatfeldolgozás' },
  { id: 'integracio', label: 'Rendszerek összekötése' },
  { id: 'adminisztracio', label: 'Adminisztrációs folyamat automatizálása' },
  { id: 'alkalmazas', label: 'Egyedi üzleti alkalmazás' },
  { id: 'gepkolcsonzo', label: 'Gépkölcsönző Cloud bemutató' },
  { id: 'egyeb', label: 'Egyéb, még nem tudom' },
];

export function isTaskId(value: string): value is TaskId {
  return TASK_OPTIONS.some((option) => option.id === value);
}

export function taskLabel(id: TaskId): string {
  return TASK_OPTIONS.find((option) => option.id === id)?.label ?? id;
}

/** Examples shown by the "Mi viszi el az idődet?" picker. */
export const TASK_EXAMPLES: Record<
  'riport' | 'integracio' | 'adminisztracio' | 'alkalmazas',
  { title: string; before: string; after: string; secondary?: { label: string; href: string } }
> = {
  riport: {
    title: 'Példa: heti értékesítési riport három forrásból',
    before:
      'Hétfőnként letöltöd a két üzlet és a webshop exportját, egy táblába másolod őket, kijavítod a dátum- és számformátumokat, és kézzel keresed az elütéseket.',
    after:
      'Az automatizálás beolvassa a fájlokat, egységesíti és ellenőrzi az adatokat, elkészíti az összesítőt, a problémás sorokat pedig külön listán adja át.',
    secondary: { label: 'Kipróbálom a bemutatóban', href: '#bemutato' },
  },
  integracio: {
    title: 'Példa: webshoprendelések átvezetése',
    before:
      'A webshopba beérkező rendeléseket egyenként rögzíted a számlázó- vagy készletkezelő programban, és közben figyelsz, hogy semmi ne maradjon ki.',
    after:
      'A rendelések rögzített szabályok szerint kerülnek át a másik rendszerbe – API-n, fájlexporttal vagy RPA-val, attól függően, mit tesznek lehetővé a programok. Minden átadás naplózva van.',
  },
  adminisztracio: {
    title: 'Példa: dokumentumbekérés ajánlatkéréshez',
    before:
      'Az ajánlatkérések e-mailben érkeznek, és táblázatban követed, kitől melyik dokumentum hiányzik még. Az emlékeztetőket kézzel írod meg.',
    after:
      'A megkeresések egy listába kerülnek, látszik, mi hiányzik még, és a beállított ütemezés szerint automatikusan kimennek az emlékeztetők.',
  },
  alkalmazas: {
    title: 'Példa: nyilvántartás táblázatok helyett',
    before:
      'A nyilvántartás több táblázatban él, egyszerre többen szerkesztik, és nehéz követni, ki mit módosított és melyik a legfrissebb változat.',
    after:
      'Egy egyszerű webes alkalmazásban egy helyen vannak az adatok, jogosultságokkal, keresővel és a módosítások előzményeivel – a te folyamatodra szabva.',
  },
};
