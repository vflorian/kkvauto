# CapScope – helyi pcap/pcapng elemző

Önálló, helyben futó elemző `.pcap` és `.pcapng` fájlokhoz, mobilhálózati és IoT
hibakereséshez (jelzésforgalom, ügyféloldali adatforgalom, roaming, kapcsolatfelépítési
hibák), de általános hálózati hibakereséshez is használható.

* Böngészős felület, csak `127.0.0.1`-en; nincs CDN, telemetria vagy külső szolgáltatás.
* A capture, az index, a csomagtartalom és az exportok a gépen maradnak.
* Dekódolás, display filter és reassembly: **TShark**. Indexelés, korreláció, szabályok, export: **Python**.
* A felület magyar, a protokollnevek és mezők eredeti formában, az incidens-összefoglaló angol.

## Architektúra röviden

```
Böngésző (vanilla JS, szigorú CSP)  ──HTTP, 127.0.0.1──►  FastAPI (api.py)
                                                           │
             ┌─────────────────────────────────────────────┼──────────────────────────┐
             ▼                                             ▼                          ▼
  indexer.py: egyetlen TShark-menet          service.py: display filter (tshark -Y),   export.py / incident.py
  (-T fields, ~70 mező) + saját              mezőfa (PDML), hex (fájl-offsetről),      pcapng-export eredeti
  pcap/pcapng blokkbejáró (capfile.py)       stream követés (-z follow,…,yaml)         hivatkozással, CSV/JSON,
  → kötegelt SQLite írás                                                               angol riport, maszkolás
             │
             ▼
  analyzers/*  (egymástól független modulok, automatikusan felderítve)
     stats  → idővonal, protokollhierarchia, top talkers
     flows  → TCP/UDP flow-k, kézfogás, RST, újraküldés, TLS, ICMP
     dns    → DNS kérés–válasz párosítás
     gtpc   → GTPv1-C/GTPv2-C tranzakciók, session-életciklus, F-TEID-ek
     gtpu   → GTP-U → session hozzárendelés (fogadó F-TEID + időablak)
```

**Miért így.** FastAPI + SQLite, ahogy a feladat javasolta. Capture-önként külön
SQLite-index készül (`<adat>/captures/<id>/index.sqlite`). Így a törlés és az
újraindexelés egyetlen fájlművelet, több capture később `ATTACH`-csal kapcsolható össze,
és a képernyőnkénti lekérdezés indexelt (keyset-lapozás `frame_no` szerint). A
blokkbejáró saját, kb. 300 soros Python-kód. Nem dekódol, csak a rekord- és
blokkfejléceket olvassa, és ezt adja minden csomaghoz:

* fájl-offset (gyors hex nézet, izolált dekódolás, veszteségmentes export),
* pcapng-szekció és interfész,
* nyers időbélyeg és felbontás,
* ISB drop-számlálók,
* beágyazott dekriptálási titkok (DSB) jelenléte,
* SHA-256, csonkolás felismerése.

Minden csomagnál megmarad: capture-azonosító (= az index adatbázisa), szekció,
interfész, eredeti csomagszám (`frame_no`, PRIMARY KEY), időbélyeg egész
nanoszekundumban (`ts_ns`; µs/ns felbontásnál veszteségmentes) és fájl-offset. Az
alapnézet UTC. A `captures.display_offset_ns` oszlop a későbbi megjelenítési eltoláshoz
van fenntartva.

### Repószerkezet

```
capscope/
  start.ps1                 Windows-indító (venv, függőségek, TShark-keresés, indítás)
  requirements*.txt, pyproject.toml
  capscope/
    __main__.py             python -m capscope  (--port, --data, --no-browser, --check)
    config.py               beállítások, korlátok (környezeti változókkal felülírhatók)
    tshark.py               TShark keresése, verzió, mezőlista, biztonságos indítás, szűrő-validálás
    capfile.py              pcap/pcapng blokkbejáró + veszteségmentes pcapng-író
    db.py                   SQLite séma (katalógus + capture-index), kötegelt írás
    indexer.py              egymenetes indexelés, megszakítás, részleges index kezelése
    jobs.py                 háttérfeladatok: haladás, megszakítás
    service.py              capture-regisztráció, szűrés, mezőfa/hex, stream követés
    export.py               pcapng/CSV/JSON export, DSB-kezelés
    incident.py             incidens-gyűjtés és angol riport (sablon)
    masking.py              azonosítómaszkolás és hatókör
    tempfiles.py            ellenőrzött ideiglenes könyvtárak
    synth.py                szintetikus capture-generátor (tesztek, benchmark, demo)
    analyzers/              base.py + stats, flows, dns, gtpc, gtpu
    static/                 index.html, app.js, app.css (külső erőforrás nélkül)
  tests/                    pytest: valódi pcap/pcapng fájlok TShark-kal
  bench/bench_large.py      reprodukálható nagyfájlos mérés
```

## Indítás Windows 11-en

Előfeltételek:

1. **Python 3.10 vagy újabb.** Például: `winget install Python.Python.3.12`.
2. **Wireshark a TShark komponenssel.** A telepítő alapból felteszi, helye általában
   `C:\Program Files\Wireshark\tshark.exe`. Élő capture-höz kellene az Npcap, fájlok
   elemzéséhez nem kell.

A `capscope` mappában, PowerShellben:

```powershell
.\start.ps1
```

Ha a végrehajtási házirend tiltja a szkriptet:

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

Első indításkor a szkript létrehoz egy `.venv` környezetet, és telepíti a `fastapi` és
`uvicorn` csomagot. Ehhez egyszer kell internet, vagy offline wheel-csomag (lásd lent).
Ezután kiírja a token-es helyi címet, és megnyitja a böngészőt:

```
A felület (csak erről a gépről érhető el):
  http://127.0.0.1:8765/?token=…
```

Paraméterek: `-Port 8770`, `-Data D:\capscope-data` (adatkönyvtár, alapból
`%USERPROFILE%\.capscope`), `-TShark "D:\Wireshark\tshark.exe"`, `-NoBrowser`.

### TShark-ellenőrzés

```powershell
.\start.ps1 -Check
```

Kiírja a TShark útvonalát és verzióját, a mezők számát, és lefordít egy próba display
filtert (`dns && gtpv2`). A TShark keresési sorrendje: `-TShark` paraméter →
`CAPSCOPE_TSHARK` környezeti változó → `PATH` → `%ProgramFiles%\Wireshark\tshark.exe`.

### Offline telepítés

Internettel rendelkező gépen:

```powershell
pip download -r requirements.txt -d wheels
```

A célgépen:

```powershell
.venv\Scripts\python.exe -m pip install --no-index --find-links wheels -r requirements.txt
```

## Végigkövethető vizsgálati példa

1. Demo capture készítése: S11 és S1-U, valamint egy GTPv1 roaming (Gp) szakasz,
   benne DNS, TLS, elutasított és megválaszolatlan Create Session:

   ```powershell
   .venv\Scripts\python.exe -m capscope.synth demo $env:USERPROFILE\capscope-demo.pcapng
   ```

2. A felső mezőbe beírod az útvonalat (vagy **Tallózás…**), majd **Megnyitás és
   indexelés**. A haladás és a **Megszakítás** gomb a fejléc alatt látszik.
3. **Áttekintés**:
   * 31 csomag, 8,275 s, egy interfész (`s11-s1u`), a drop oszlopban „Nincs adat”.
   * Az idővonal egy oszlopára kattintva a Csomagok nézet arra az időablakra szűrve nyílik meg.
4. **SIM és session**, keresés erre: `216305555555555`.
   * A Create Session Request háromszor ment el (#23, #24, #25), az állapot „válasz nélkül”.
   * A Tranzakciók nézetben: „A válasz nem látszik a vizsgált capture-ben.”, állapota
     *nem eldönthető*, mert a capture vége a 30 s-os válaszablakon belül van.
5. **SIM és session**, keresés erre: `0x000a0001` (TEID):
   * Session #1 (S11): felépítés #1–#4, bontás #30–#31.
   * A C-plane és U-plane F-TEID-ek külön táblában vannak.
   * Uplink: 10.0.2.1 → 10.0.1.2, downlink fordítva. Mellettük a belső IP-párok
     (100.64.0.10 → 8.8.8.8 stb.), állapotuk *következtetett* (`GTPU-FTEID` szabály).
6. **Tranzakciók és flow-k → Tranzakciók**:
   * GTPv2 Create Session elutasítás: cause `78 Missing or unknown APN`.
   * DNS NXDOMAIN.
   * Megválaszolatlan DNS (#15, ismétlés #16).
   * A `#…` linkek a kérésre, illetve a válaszra ugranak.
7. **Flow-k**:
   * A tunnelezett TCP 443-as flow: teljes kézfogás, TLS ClientHello
     (SNI `www.example.com`), ServerHello, `handshake_failure` alert, RST.
   * A **Követés** gomb mutatja a stream tartalmát.
8. **Csomagok**:
   * Szűrő: `gtpv2.cause > 63 || dns.flags.rcode != 0`.
   * A hibás szűrő (pl. `dns.qry.nme == 1`) magyar magyarázatot és a TShark eredeti
     üzenetét adja.
   * Egy csomagra kattintva megnyílik a mezőfa és a hex nézet. A „Kontextus” és az
     „Izolált” mód közti különbségből látszik, mi múlik a dekódolási előzményeken.
   * **Szűrt lista exportja (pcapng)**: minden csomag kommentje
     `capscope-ref file=… sha256=… frame=N section=… iface=…`.
9. Bármely nézetben a **+ incidens** gombbal veszel fel elemeket. Az **Incidens** nézetben:
   * **Maszkolt riport készítése**: angol Markdown, JSON és CSV, UTC-idővonallal,
     csomaghivatkozásokkal és vizsgálati korlátokkal.
   * Külön blokkban: **Nyers capture-export** (maszkolatlan).

## Állapotok, szabályok, bizonyíték

| Állapot | Jelentés |
|---|---|
| megfigyelt (observed) | közvetlenül látszik a capture-ben |
| következtetett (inferred) | megnevezett korrelációs szabályból következik |
| nem eldönthető (undetermined) | a capture alapján nem dönthető el, pl. több jelölt, vagy a capture/index a válaszablakon belül ér véget |

Minden tranzakció, megállapítás és GTP-U hozzárendelés mellett ott van a szabály
azonosítója és a kapcsolódó csomagszámok.

* **DNS-párosítás.** Kulcs: L4, DNS ID, kliens ip:port, szerver ip:port. Feltétel:
  ellenirány és azonos qname, 5 s-os ablakon belül.
  * Ismételt kérés: ugyanaz a kulcs válasz előtt; egy tranzakcióként, külön listázva jelenik meg.
  * Kérés nélküli válasz: `orphan_response`.
* **GTP-C párosítás.** Kulcs: verzió, sequence, kérő ip:port, válaszoló ip, párosított
  üzenettípus, 30 s-os ablakon belül.
* **GTP-C session.** A header TEID = 0-val érkező Create Session / Create PDP Context
  nyitja.
  * A további üzeneteket a *fogadó* C-plane F-TEID-je köti a sessionhöz: cél-IP és
    header TEID.
  * Ha a session létrehozása nem látszik, a session `unknown_start` állapotú, és ez
    megállapításként is megjelenik.
* **GTP-U hozzárendelés (`GTPU-FTEID`).** A külső cél-IP (fogadó végpont) és a TEID
  egyezzen meg egy, ugyanannak a sessionnek jelzett user-plane F-TEID-del, a csomag ideje
  pedig essen az F-TEID érvényességi ablakába:
  * az ablak a jelzéstől a cseréig, felszabadításig vagy bontásig tart, ±2 s-os,
    jelölt peremmel;
  * az irány az F-TEID interfésztípusából adódik (uplink/downlink).

  Kiegészítő ellenőrzés a belső IP és a kiosztott cím egyezése. Eltérésnél az állapot
  *nem eldönthető*. Nincs hozzárendelés:
  * ha a TEID csak más végponton ismert, vagy csak az IP egyezik (`GTPU-NOMATCH`, a
    megjegyzés megnevezi a másik végpontot);
  * több érvényes jelöltnél (`GTPU-FTEID-AMBIGUOUS`, a jelöltek listájával).

  C-plane TEID-et soha nem használ user-plane hozzárendeléshez.

## Szűrés és dekódolási előzmények

A display filter (`tshark -Y`) csak azt dönti el, mely csomagok kerülnek a listába. A
dekódolás ettől függetlenül a teljes capture-ön, sorrendben fut:

* **TCP-reassembly, IP-defragmentálás, kérés–válasz állapot:** a szűrőnek nem megfelelő
  korábbi csomagokból is felépül.
* **„két menetes (-2)” opció:** a szűrő a későbbi csomagokra mutató mezőket is látja.
* **Részletes nézet:**
  * „Kontextus” módban az 1…N. csomagot dekódolja (`-c N`);
  * „Izolált” módban csak az adott csomagot;
  * felsorolja az előzmény-csomagokat (`tcp.segment`, `ip.fragment` …), és jelzi, ha
    ezek nincsenek a szűrt listában.
* **Export:** a „reassembly-előzmények is” opció ezeket is beteszi.

## Biztonság és adatkezelés

* **Hálózat és hozzáférés:**
  * A szerver csak `127.0.0.1`-hez kötődik, ez nem konfigurálható.
  * Indításkor véletlen token keletkezik, amely HttpOnly, SameSite=Strict cookie-ba kerül.
  * Host-fejléc allow-list véd a DNS rebinding ellen.
  * Állapotváltoztató kéréshez `X-CapScope` fejléc kell.
  * Szigorú CSP: csak `'self'`.
* **Fájlhozzáférés.** Csak a felhasználó által megnyitott, pcap/pcapng fejlécű,
  capture-kiterjesztésű fájlok érhetők el. Minden további művelet capture-azonosítón
  keresztül megy. Ha a fájl az indexelés óta megváltozott, a csomagtartalom és az export
  tiltott, amíg újra nem indexeled.
* **TShark-hívás.** Mindig argumentumlistával és shell nélkül, `-n` kapcsolóval, így
  nincs névfeloldás és nincs kimenő DNS. A stderr külön szálban gyűlik.
* **Ideiglenes fájlok.**
  * Csak `<adat>/tmp` alá kerülnek, és a `with` blokk végén törlődnek (kivételnél és
    megszakításnál is).
  * A félkész exportok `.part` kiterjesztésűek, kilépéskor törlődnek.
  * Indításkor a régi maradványok takarítása is lefut.
* **Megszakított import.** Az import közben leállt alkalmazás indexét a következő
  indítás `interrupted` (részleges) állapotúra állítja. Böngészhető marad, és
  újraindexelhető.
* **Maszkolás.**
  * Hatálya: a szöveges exportok (riport, CSV, JSON), mezőszinten és szabad szövegben is
    (ismert azonosítók, 14–16 jegyű számsorok).
  * Választható: IMSI, MSISDN, IMEI, UE IP vagy minden IP.
  * A hatókör minden exportba beleíródik.
  * A **nyers capture-export soha nem maszkolt**, és a felület külön blokkban,
    `_RAW` fájlnévvel kezeli.
* **Dekriptálási titkok (DSB).** A pcapng-be ágyazott Decryption Secrets Block
  alapértelmezésben kimarad az exportból. Megtartása csak a `TITKOKKAL` szó beírásával
  lehetséges; ilyenkor a fájlnév `_RAW_WITH_SECRETS`, és az exportlista piros jelzést
  mutat.

## Tesztek

```powershell
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m pytest -q
```

A tesztek valódi `.pcap` és `.pcapng` fájlokat generálnak (`capscope/synth.py`), és
TShark-kal indexelik őket. Ezeket fedik le:

* pcap µs/ns, pcapng több interfész eltérő időfelbontással, több szekció, ISB drop,
  csonka fájl, snaplen-csonkolás, felhasználói csomagkorlát;
* érvényes és hibás display filterek;
* DNS-párosítás: válasz, válasz nélkül, ismétlés, azonos ID más porton, kérés nélküli
  válasz, capture vége az ablakon belül;
* azonos TEID két tunnelvégponton két külön sessionként, ismeretlen végpont, belső
  IP-eltérés, kétértelmű jelölt, C/U-plane szétválasztás, bontás utáni forgalom;
* megszakított import, majd újrahasználat és újraindexelés; újraindítás utáni
  helyreállítás;
* export eredeti csomaghivatkozással (pcap- és pcapng-forrásból), változatlan bájtokkal
  és időbélyeggel, reassembly-előzményekkel; DSB csak megerősítéssel;
* maszkolt és maszkolatlan riport, illetve CSV/JSON;
* API-biztonság (token, Host, CSRF-fejléc, nem capture fájl);
* a teljes függőleges szelet HTTP-n keresztül.

## Nagyfájlos mérés

```powershell
.venv\Scripts\python.exe bench\bench_large.py --packets 2000000 --out bench\out
```

Determinisztikus (seedelt) szintetikus pcapng-t generál: GTP-C, GTP-U belső TCP-vel,
DNS, TCP SYN, két interfész. Friss adatkönyvtárral indexeli, majd méri:

* az indexelési időt;
* a memóriacsúcsot (a Python-folyamat és a TShark-gyerekfolyamat RSS-e, 100 ms-os
  mintavétellel);
* négy display filter hideg futási idejét;
* a böngésző által kért lapozó lekérdezéseket.

Az eredmény a `bench/out/result.json` fájlba kerül.

### Mért eredmények (2026-11-09)

**Platform:**

* Linux x86_64 konténer (`Linux-6.18.44-…-x86_64-with-glibc2.39`), 4 vCPU, 15,7 GiB RAM;
* Python 3.13.18, **TShark 4.2.2** (`/usr/bin/tshark`, Ubuntu-csomag 4.2.2-1.1build3).

**Windows 11-en még nem mértem.** A számok a fenti Linux-gépre vonatkoznak.

| Mérés | 200 000 csomag | 2 000 000 csomag |
|---|---|---|
| Tesztfájl mérete (pcapng) | 72,6 MiB | **724,0 MiB** (759 211 620 B) |
| Indexelési idő (TShark-menet + elemzők + SQLite) | 14,9 s (13 450 cs./s) | **168,9 s** (11 839 cs./s) |
| Memóriacsúcs – Python-folyamat (RSS) | 237 MiB | **590 MiB** |
| Memóriacsúcs – TShark gyerekfolyamat (RSS) | 308 MiB | **1 811 MiB** |
| Memóriacsúcs – összesen | 499 MiB | **2 185 MiB** |
| Index-adatbázis mérete | 75,8 MiB | 764,7 MiB |
| Display filter, hideg futás (`dns.qry.name == "h4242.example.com"`) | 7,0 s | **61,2 s** (220 találat) |
| Display filter (`gtpv2.message_type == 32`) | 6,9 s | 60,3 s (3 064 találat) |
| Display filter (`tcp.flags.syn == 1 && !gtp`) | 6,9 s | 61,8 s (231 014 találat) |
| Display filter (`gtp.teid == 0x00300005`) | 6,6 s | 61,7 s (1 093 találat) |
| Ugyanaz a szűrő újra (cache-ből) | < 0,1 s | < 0,1 s |
| Csomaglista-oldal (100 sor): első / közép / szűrt közép / időablak | 9 / 17 / 9 / 7 ms | 8 / 128 / 25 / 7 ms |
| Áttekintés-API | 60 ms | 509 ms |

**Értelmezés:**

* A TShark egyedül, ugyanazzal a ~70 mezővel 200k csomagon 9,8 s alatt fut le
  (`-e frame.number`-rel 6,5 s). Az indexelés idejének nagyobb része tehát a TShark
  dekódolása; a Python-feldolgozás vele párhuzamosan, csővezetéken fut.
* A Python-oldali memóriát főleg a memóriában tartott flow-tábla adja. Ennek felső
  korlátja 200 000 aktív flow, a régebbieket UPSERT-tel írja lemezre. A csomaglista
  soha nincs memóriában.
* A TShark memóriája a csomagszámmal nő (lásd az ismert korlátokat).
* A display filter mindig teljes TShark-menet, ezért ideje a fájlmérettel arányos.

## Új elemzőmodul hozzáadása

Hozz létre egy fájlt az `capscope/analyzers/` alatt:

```python
from .base import Analyzer, OBSERVED

class SipAnalyzer(Analyzer):
    name, title, order = "sip", "SIP", 60
    triggers = frozenset({"sip"})                 # csak ezekre a rétegekre hívódik
    fields = ("sip.Method", "sip.Status-Code", "sip.Call-ID")
    schema = "CREATE TABLE IF NOT EXISTS sip_calls(...);"
    def on_packet(self, pkt): ...                 # pkt.get(), pkt.all(), pkt.endpoints_of("sip")
    def finish(self, cut): ...                    # cut.is_cut → a vágás közeli eredmény nem eldönthető

ANALYZER = SipAnalyzer
```

A modult a program automatikusan felderíti. A mezői bekerülnek az egyetlen
TShark-menetbe; ha egy mező az adott TShark-verzióban nem létezik, kimarad, és erről
figyelmeztetés jelenik meg. A megállapításokat a `self.ctx.finding(...)` hívással
rögzíted: állapot, szabály, csomagok, angol cím.

## Ismert korlátok

* **TShark-memória.** A TShark egymenetes módban is csomagonként tart állapotot
  (frame-adatok, konverzációk), ezért a memóriája a csomagszámmal nő. A Python-oldal
  korlátos; a számokat lásd a mérésnél. Nagyon nagy fájlokhoz az `editcap -c`
  darabolás javasolt.
* **Időbélyegek.** ns-ra kerekítve tárolódnak. µs- és ns-felbontásnál ez
  veszteségmentes, ps-felbontásnál nem. Az export viszont mindig a nyers egységeket
  másolja.
* **GTPv2 bearer contextek.** Ha több bearer context és eltérő számú F-TEID van egy
  üzenetben, az EBI-hozzárendelés üresen marad. Ez a session-hozzárendelést nem
  érinti, csak az EBI oszlopot.
* **GTPv1 user plane.** A GSN Address #1 a control plane-hez, a #2 a user plane-hez
  tartozik (TS 29.060). Ha csak egy cím van, mindkettőre azt használja.
* **Időablakok.** Rögzítettek: DNS 5 s, GTP-C 30 s, GTP-U perem ±2 s. Csak
  `config.py`-ban vagy környezeti változóval állíthatók.
* **Elemzés hatóköre.**
  * Csak a capture-pontban látható forgalmat elemzi.
  * Roaming-felismerés (HPLMN/VPLMN összevetés), PFCP/N3, Diameter, S1AP/NGAP,
    SIP/IMS még nincs.
  * Dekriptálás nincs: DSB-t és kulcsfájlt nem használ.
* **Több capture.** Az időbeli igazítás és a megjelenítési időeltolás még nincs kész.
  Az adatszerkezet fel van készítve rá: capture-azonosító minden hivatkozásban és
  `display_offset_ns`.
* **Gzip-pel tömörített capture.** Indexelhető, de nincs fájl-offset. Emiatt a hex nézet
  nem érhető el, az export pedig TShark-kal készül, és az eredeti csomagszámokat egy
  külön `.refs.json` fájl rögzíti.
* **Natív fájlválasztó.** Külön Tk-folyamatban fut. Ha nem érhető el, írd be az
  útvonalat.
* **Stream követés és kontextusos mezőfa.** Mindkettő TShark-menetet futtat a fájlon,
  időkorláttal (300 s, illetve 120 s); a stream megjelenítése 2 MB-ig tart. Nagy fájl
  végén lévő csomagnál használd az „Izolált” módot.
* **TShark-profil.** A felhasználó alap Wireshark-profiljának beállításai (pl.
  Decode As) érvényesülnek a dekódolásban.
