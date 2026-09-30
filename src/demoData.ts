/**
 * Synthetic sample data for the "Heti riport több táblázatból" demo.
 * Every product, amount and file is invented for illustration only.
 */

export const WEEK = { start: '2026-09-21', end: '2026-09-27', label: '2026. szeptember 21–27.' };

export const PRODUCTS: Record<string, { name: string; price: number }> = {
  'A-100': { name: 'Másolópapír A4, karton', price: 12900 },
  'A-210': { name: 'Toner, fekete', price: 18500 },
  'B-310': { name: 'Iratrendező', price: 1450 },
  'B-420': { name: 'Jegyzetfüzet A5', price: 890 },
  'C-510': { name: 'Asztali lámpa', price: 9900 },
};

export interface SampleFile {
  id: string;
  name: string;
  source: string;
  format: string;
  /** Raw text exactly as it would arrive in the file (xlsx shown as tab-separated). */
  raw: string;
  delimiter: string;
}

export const SAMPLE_FILES: readonly SampleFile[] = [
  {
    id: 'buda',
    name: 'ertekesites_buda.xlsx',
    source: 'Budai üzlet',
    format: 'Excel-munkalap, ISO dátum',
    delimiter: '\t',
    raw: [
      'Dátum\tCikkszám\tTermék\tDb\tNettó (Ft)',
      '2026-09-21\tA-100\tMásolópapír A4, karton\t6\t77400',
      '2026-09-21\tB-310\tIratrendező\t20\t29000',
      '2026-09-22\tA-210\tToner, fekete\t2\t37000',
      '2026-09-23\t\tIratrendező\t8\t11600',
      '2026-09-24\tC-510\tAsztali lámpa\t1\t9900',
      '2026-09-19\tA-100\tMásolópapír A4, karton\t3\t38700',
      '2026-09-25\tB-420\tJegyzetfüzet A5\t30\t26700',
    ].join('\n'),
  },
  {
    id: 'pest',
    name: 'ertekesites_pest.csv',
    source: 'Pesti üzlet',
    format: 'CSV pontosvesszővel, magyar dátum- és számformátum',
    delimiter: ';',
    raw: [
      'Nap;Cikkszám;Megnevezés;Mennyiség;Nettó összeg',
      '2026.09.21.;A-100;Másolópapír A4, karton;4;51 600,00',
      '2026.09.22.;B-420;Jegyzetfüzet A5;12;10 680,00',
      '2026.09.23.;A-210;Toner, fekete;-2;-37 000,00',
      '2026.09.24.;B-4200;Jegyzetfüzet A5;10;8 900,00',
      '2026.09.25.;C-510;Asztali lámpa;3;29 700,00',
      '2026.09.26.;B-310;Iratrendező;15;21 750,00',
    ].join('\n'),
  },
  {
    id: 'webshop',
    name: 'webshop_export.csv',
    source: 'Webshop',
    format: 'CSV vesszővel, angol oszlopnevek',
    delimiter: ',',
    raw: [
      'order_id,order_date,sku,qty,net_huf',
      'W-1041,2026-09-21T09:14:00,A-210,1,18500',
      'W-1042,2026-09-22T13:02:00,B-420,25,22250',
      'W-1043,2026-09-23T18:45:00,A-100,5,64500',
      'W-1043,2026-09-23T18:45:00,A-100,5,64500',
      'W-1044,2026-09-25T07:30:00,C-510,2,19800',
      'W-1045,2026-09-27T21:11:00,B-310,10,14500',
    ].join('\n'),
  },
];
