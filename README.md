# nessus_cli.py – CLI för Nessus Professional REST-API (v2.1.0)

Kräver Python 3.6+ och `requests` 2.20+ (anpassat för systempaketen i t.ex. SLES 15: Python 3.6.15, requests 2.25.1, urllib3 1.25). `cryptography` är valfritt (ger subject/issuer/giltighet för overifierade cert i `--check-connection`).
Utan argument skrivs hjälpen ut.

> `settings.json`, `reports/` och exporterade rapporter (`*.nessus`, `*.csv`, `*.pdf`, `*.html`, `*.db`) ignoreras av `.gitignore` och ska aldrig checkas in.

## Kom igång
```bash
cp settings.example.json settings.json
chmod 600 settings.json                  # skriptet varnar om filen är läsbar för andra
./nessus_cli.py --encode-secret          # frågar dolt, skriver ut base64-värdet
#   → klistra in i auth.password / auth.secret_key / export.db_password
./nessus_cli.py --check-connection
```

## Hemligheter i settings.json
`auth.password`, `auth.secret_key` och `export.db_password` **ska** vara base64-kodade. Ogiltig base64 ger ett tydligt fel.
Base64 är **obfuskering, inte kryptering** – det skyddar mot att någon läser lösenordet över axeln, inte mot den som kan läsa filen. Filrättigheter (600) är det egentliga skyddet.
Miljövariabler (`NESSUS_URL`, `NESSUS_ACCESS_KEY`, `NESSUS_SECRET_KEY`, `NESSUS_USERNAME`, `NESSUS_PASSWORD`) går före filen och anges i **klartext**.

`--encode-secret` kan även läsa från stdin: `echo -n 'hemligt' | ./nessus_cli.py -B` (värde som argument hamnar i shell-historiken).

## Autentisering
| `auth.method` | Headers | Kommentar |
|---|---|---|
| `session` (default) | `X-Cookie: token=…` + `X-API-Token` | Rekommenderas för Pro. `X-API-Token` läses ur `/nessus6.js`; misslyckas det, sätt `auth.api_token` manuellt. |
| `api_keys` | `X-ApiKeys` | Fungerar för läsning/export. I Nessus Pro kan skapa/starta scan ge **HTTP 412 "API is not available"**. |

### X-API-Token (session-auth)
Inloggningen (`POST /session`) ger en session-token som skickas som `X-Cookie: token=…`. Nessus Pro kräver dessutom headern `X-API-Token` för de flesta anrop. Det är ett fast UUID som finns inbakat i webbgränssnittets JavaScript och som webbläsaren skickar med varje anrop.
Skriptet letar i `/nessus6.js` och i alla `<script src>` som startsidan laddar. Hittar det inget fortsätter det utan token och skriver en varning.

Hämta tokenet manuellt:
- **Webbläsare:** logga in i Nessus → DevTools (F12) → Network → välj ett anrop till t.ex. `/scans` → Request Headers → `X-API-Token`.
- **curl:** `curl -sk https://<nessus>:8834/nessus6.js | grep -oE '.{0,80}(getApiToken|X-API-Token).{0,200}' | head`

Lägg värdet i `auth.api_token` (klartext, det är ingen hemlighet per användare). Tokenet ändras normalt bara när Nessus uppgraderas.

## Åtgärder (exakt en per körning)
| Kort | Lång | Argument |
|---|---|---|
| `-C` | `--check-connection` | – DNS, TCP, TLS/cert, tjänstestatus, inloggning, licens, användarroll, läsrätt |
| `-I` | `--server-info` | – |
| `-L` | `--list-scans` | – (filtrera med `-g`) |
| `-F` | `--list-folders` | – |
| `-T` | `--list-templates` | – |
| `-P` | `--list-policies` | – |
| `-R` | `--list-report-templates` | – |
| `-H` | `--list-history` | SCAN |
| `-Q` | `--status` | SCAN |
| `-N` | `--create-scan` | NAMN |
| `-S` | `--launch` | SCAN |
| `-Z` / `-U` / `-K` | `--pause` / `--resume` / `--stop` | SCAN |
| `-E` | `--export` | SCAN |
| `-O` | `--export-formats` | SCAN |
| `-X` | `--delete` | SCAN |
| `-B` | `--encode-secret` | [VÄRDE] |

SCAN = scan-id eller exakt namn (skiftlägesokänsligt).
Namn söks i alla mappar utom papperskorgen. Finns samma namn i flera mappar avbryts körningen med en lista över id och mappar. Välj då med `-g/--folder` (t.ex. `-Q DMZ -g "Kund X"`) eller ange id. Scans i papperskorgen nås med `-g Trash` eller id.

## Parametrar
| Kort | Lång | Används med |
|---|---|---|
| `-t` | `--targets` | `-N` (kommaseparerat) |
| `-i` | `--targets-file` | `-N` (# = kommentar) |
| `-m` | `--template` | `-N` (basic, advanced, discovery …) |
| `-c` | `--policy` | `-N` (egen policy, istället för `-m`) |
| `-g` | `--folder` | `-N`, `-L` |
| `-n` | `--description` | `-N` |
| `-l` | `--launch-now` | `-N` |
| `-a` | `--alt-targets` | `-S` |
| `-w` | `--wait` | `-N`, `-S` |
| `-f` | `--format` | `-E`; med `-N`/`-S`: vänta och exportera när scannen är klar |
| `-j` | `--history-id` | `-E` (`latest` default, `all`, eller ID) |
| `-o` | `--out` | `-E`, `-N`, `-S` |
| `-e` | `--report-template` | `-E`, `-N`/`-S` med `-f` – rapportmall för html/pdf, id eller namn |
| `-s` | `--settings` | alla (default `./settings.json` / `$NESSUS_SETTINGS`) |
| `-k` | `--insecure` | alla – ingen TLS-verifiering |
| `-r` | `--raw` | listor/status – rå JSON |
| `-y` | `--yes` | `-X` |
| `-d` | `--debug` | alla |
| `-V` | `--version` | |

## Exempel
```bash
./nessus_cli.py -L -g "My Scans"
./nessus_cli.py -N "Kund X DMZ" -t 10.0.0.0/24,web01 -m basic -l -f csv pdf -o ./reports
./nessus_cli.py -N "Kund X AD" -i mal.txt -c "Min policy"
./nessus_cli.py -S "Kund X DMZ" -a 10.0.0.5 -w
./nessus_cli.py -E 42 -f csv html nessus -j all
./nessus_cli.py -Q 42 -d 2> debug.log
```

## --debug
Skriver till stderr: skriptets/Pythons/requests/OpenSSL-versioner, proxy- och CA-miljövariabler, filrättigheter på settings, effektiva inställningar efter base64-avkodning, varje HTTP-anrop (metod, URL, params, headers, body), svar (status, svarstid, headers, body), urllib3-anslutningsloggar, mall/scan/mapp-uppslag, valda history_id, exporttider, sha256 på nedladdade filer och full stacktrace vid oväntade fel.
Hemligheter (lösenord, nycklar, session-token, X-API-Token) maskas alltid, så loggen kan delas.

## Exportformat
| Format | Kommentar |
|---|---|
| `nessus` | XML v2 – bäst för vidare parsning/SIEM |
| `csv` | Extra kolumnval via `export.extra.csv` |
| `html`, `pdf` | Rapportmall: `-e/--report-template`, annars `export.template_id`, annars `export.chapters`. PDF krävde Java på servern i äldre versioner. |
| `db` | Krypterad, kräver `export.db_password` (base64) |
| `json` | Lokalt: rådata från `GET /scans/{id}` |

Filnamn: `<scannamn>_<scanid>_h<historyid>_<tidsstämpel>.<ext>`.

## Rapportmallar
```bash
./nessus_cli.py -R                                      # lista (Std = export.template_id i settings)
./nessus_cli.py -E 42 -f pdf -e "Detailed Vulnerabilities By Host"
./nessus_cli.py -E 42 -f pdf html -e 17
./nessus_cli.py -S "Kund X DMZ" -f pdf -e "QiSec Kundrapport" -o ./reports
```
- `-e` och `export.template_id` tar både id och namn (skiftlägesokänsligt). Namn som finns flera gånger ger fel med id-lista.
- Mallen gäller bara `html`/`pdf`. Används `-e` med enbart andra format skriver skriptet en varning.
- Ett felaktigt mallnamn stoppar körningen innan någon export startas.
- `GET /reports/custom/templates` finns i nyare Nessus (8.x/10.x). I äldre versioner används `export.chapters`.

## Returkoder
0 = OK, 1 = fel (även fel i `--check-connection`), 2 = ingen åtgärd angiven / scan ej `completed`, 130 = avbruten.

## Ändringar v2.0
- Optioner istället för underkommandon; alla har `-X` och `--xxx`
- `--check-connection`, `--list-scans`, `--encode-secret`
- Base64 för hemligheter i settings.json
- `--debug` med full diagnostik (ersätter `-v`)
- Default `auth.method` är nu `session`
- `-e/--report-template` (id eller namn), tydligare `-R`, mallnamn tillåtet i `export.template_id` (v2.1.0)
- Kompatibel med Python 3.6 (SLES 15, RHEL 8 m.fl.) (v2.0.3)
- Scannamn avgörs med `-g/--folder` vid dubbletter, papperskorgen exkluderas (v2.0.2)
- X-API-Token söks även i andra JS-filer och saknad token stoppar inte längre körningen (v2.0.1)
- Fix: `REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE` i miljön skrev över `verify_ssl`/`ca_bundle`

## Licens
MIT – se [LICENSE](LICENSE). Programvaran levereras i befintligt skick, utan garantier.
