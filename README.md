# nessus_cli.py – CLI for the Nessus Professional REST API (v2.2.0)

Requires Python 3.6+ and `requests` 2.20+ (designed to work with the system packages on e.g. SLES 15: Python 3.6.15, requests 2.25.1, urllib3 1.25). `cryptography` is optional (adds subject/issuer/validity for unverified certificates in `--check-connection`).
Running without arguments prints the help.

> `settings.json`, `reports/` and exported reports (`*.nessus`, `*.csv`, `*.pdf`, `*.html`, `*.db`) are excluded by `.gitignore` and must never be committed.

## Getting started
```bash
cp settings.example.json settings.json
chmod 600 settings.json                  # the script warns if the file is readable by others
./nessus_cli.py --encode-secret          # prompts hidden, prints the base64 value
#   → paste into auth.password / auth.secret_key / export.db_password
./nessus_cli.py --check-connection
```

## Secrets in settings.json
`auth.password`, `auth.secret_key` and `export.db_password` **must** be base64-encoded. Invalid base64 gives a clear error.
Base64 is **obfuscation, not encryption** – it protects against someone reading the password over your shoulder, not against anyone who can read the file. File permissions (600) are the real protection.
Environment variables (`NESSUS_URL`, `NESSUS_ACCESS_KEY`, `NESSUS_SECRET_KEY`, `NESSUS_USERNAME`, `NESSUS_PASSWORD`) take precedence over the file and are given in **plain text**.

`--encode-secret` can also read from stdin: `echo -n 'secret' | ./nessus_cli.py -B` (a value given as an argument ends up in the shell history).

## Authentication
| `auth.method` | Headers | Comment |
|---|---|---|
| `session` (default) | `X-Cookie: token=…` + `X-API-Token` | Recommended for Pro. `X-API-Token` is read from the web UI JavaScript; if that fails, set `auth.api_token` manually. |
| `api_keys` | `X-ApiKeys` | Works for listing/export. In Nessus Pro, create/launch scan may return **HTTP 412 "API is not available"**. |

### X-API-Token (session auth)
Logging in (`POST /session`) returns a session token that is sent as `X-Cookie: token=…`. Nessus Pro also requires the `X-API-Token` header for most calls. It is a fixed UUID embedded in the web UI JavaScript, which the browser sends with every call.
The script searches `/nessus6.js` and every `<script src>` loaded by the start page. If nothing is found it continues without the token and prints a warning.

Getting the token manually:
- **Browser:** log in to Nessus → DevTools (F12) → Network → select a call to e.g. `/scans` → Request Headers → `X-API-Token`.
- **curl:** `curl -sk https://<nessus>:8834/nessus6.js | grep -oE '.{0,80}(getApiToken|X-API-Token).{0,200}' | head`

Put the value in `auth.api_token` (plain text; it is not a per-user secret). The token normally only changes when Nessus is upgraded.

## Actions (exactly one per run)
| Short | Long | Argument |
|---|---|---|
| `-C` | `--check-connection` | – DNS, TCP, TLS/certificate, service status, login, license, user role, read access |
| `-I` | `--server-info` | – |
| `-L` | `--list-scans` | – (filter with `-g`) |
| `-F` | `--list-folders` | – |
| `-T` | `--list-templates` | – |
| `-P` | `--list-policies` | – |
| `-R` | `--list-report-templates` | – |
| `-H` | `--list-history` | SCAN |
| `-Q` | `--status` | SCAN |
| `-N` | `--create-scan` | NAME |
| `-S` | `--launch` | SCAN |
| `-Z` / `-U` / `-K` | `--pause` / `--resume` / `--stop` | SCAN |
| `-E` | `--export` | SCAN |
| `-O` | `--export-formats` | SCAN |
| `-X` | `--delete` | SCAN |
| `-B` | `--encode-secret` | [VALUE] |

SCAN = scan id or exact name (case-insensitive).
Names are searched in all folders except the trash. If the same name exists in several folders, the run stops with a list of ids and folders. Pick one with `-g/--folder` (e.g. `-Q DMZ -g "Customer X"`) or give the id. Scans in the trash are reached with `-g Trash` or by id.

## Parameters
| Short | Long | Used with |
|---|---|---|
| `-t` | `--targets` | `-N` (comma-separated) |
| `-i` | `--targets-file` | `-N` (# = comment) |
| `-m` | `--template` | `-N` (basic, advanced, discovery …) |
| `-c` | `--policy` | `-N` (custom policy, instead of `-m`) |
| `-g` | `--folder` | `-N`, `-L`, and to pick a scan by name |
| `-n` | `--description` | `-N` |
| `-l` | `--launch-now` | `-N` |
| `-a` | `--alt-targets` | `-S` |
| `-w` | `--wait` | `-N`, `-S` |
| `-f` | `--format` | `-E`; with `-N`/`-S`: wait and export when the scan has finished |
| `-j` | `--history-id` | `-E` (`latest` default, `all`, or an ID) |
| `-o` | `--out` | `-E`, `-N`, `-S` |
| `-e` | `--report-template` | `-E`, `-N`/`-S` with `-f` – report template for html/pdf, id or name |
| `-s` | `--settings` | all (default `./settings.json` / `$NESSUS_SETTINGS`) |
| `-k` | `--insecure` | all – no TLS verification |
| `-r` | `--raw` | lists/status – raw JSON |
| `-y` | `--yes` | `-X` |
| `-d` | `--debug` | all |
| `-V` | `--version` | |

## Examples
```bash
./nessus_cli.py -L -g "My Scans"
./nessus_cli.py -N "Customer X DMZ" -t 10.0.0.0/24,web01 -m basic -l -f csv pdf -o ./reports
./nessus_cli.py -N "Customer X AD" -i targets.txt -c "My policy"
./nessus_cli.py -S "Customer X DMZ" -a 10.0.0.5 -w
./nessus_cli.py -E 42 -f csv html nessus -j all
./nessus_cli.py -Q 42 -d 2> debug.log
```

## --debug
Writes to stderr: script/Python/requests/OpenSSL versions, proxy and CA environment variables, settings file permissions, effective settings after base64 decoding, every HTTP call (method, URL, params, headers, body), responses (status, response time, headers, body), urllib3 connection logs, template/scan/folder lookups, selected history_id, export times, sha256 of downloaded files and a full stack trace on unexpected errors.
Secrets (passwords, keys, session token, X-API-Token) are always masked, so the log can be shared.

## Export formats
| Format | Comment |
|---|---|
| `nessus` | XML v2 – best for further parsing/SIEM |
| `csv` | Extra column selection via `export.extra.csv` |
| `html`, `pdf` | Report template: `-e/--report-template`, otherwise `export.template_id`, otherwise `export.chapters`. PDF required Java on the server in older versions. |
| `db` | Encrypted, requires `export.db_password` (base64) |
| `json` | Local: raw data from `GET /scans/{id}` |

File names: `<scanname>_<scanid>_h<historyid>_<timestamp>.<ext>`.

## Report templates
```bash
./nessus_cli.py -R                                      # list (Def = export.template_id in settings)
./nessus_cli.py -E 42 -f pdf -e "Detailed Vulnerabilities By Host"
./nessus_cli.py -E 42 -f pdf html -e 17
./nessus_cli.py -S "Customer X DMZ" -f pdf -e "My Company Report" -o ./reports
```
- `-e` and `export.template_id` accept both id and name (case-insensitive). A name that exists more than once gives an error with the list of ids.
- The template only applies to `html`/`pdf`. If `-e` is used with other formats only, the script prints a warning.
- An invalid template name stops the run before any export starts.
- `GET /reports/custom/templates` exists in newer Nessus versions (8.x/10.x). Older versions use `export.chapters`.

## Exit codes
0 = OK, 1 = error (including failures in `--check-connection`), 2 = no action given / scan not `completed`, 130 = interrupted.

## Changes
- All output, help texts, comments and docs in English (v2.2.0)
- `-e/--report-template` (id or name), clearer `-R`, template name allowed in `export.template_id` (v2.1.0)
- Compatible with Python 3.6 (SLES 15, RHEL 8 etc.) (v2.0.3)
- Duplicate scan names resolved with `-g/--folder`, trash excluded (v2.0.2)
- X-API-Token also searched for in other JS files; a missing token no longer stops the run (v2.0.1)
- v2.0.0: options instead of subcommands, all with `-X` and `--xxx`; `--check-connection`, `--list-scans`, `--encode-secret`; base64 for secrets in settings.json; `--debug` with full diagnostics (replaces `-v`); default `auth.method` is now `session`; fix: `REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE` in the environment overrode `verify_ssl`/`ca_bundle`

## License
MIT – see [LICENSE](LICENSE). The software is provided as is, without warranty.
