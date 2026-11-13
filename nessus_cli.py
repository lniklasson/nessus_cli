#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# Namn:         nessus_cli.py
# Beskrivning:  All-round CLI för Nessus Professional REST-API
# Författare:   Lars Niklasson
# Version:      2.1.0
# Senast ändrad: 2026-11-12
# Kräver:       Python 3.6+, requests 2.20+ (cryptography valfritt)
# Testad mot:   Nessus Professional 10.12
# Repo:         https://github.com/lniklasson/nessus_cli
# Licens:       MIT (se LICENSE)
#
# Ändringslogg:
#   2.1.0  2026-11-12  -e/--report-template (id eller namn), tydligare -R,
#                      mallnamn tillåtet i export.template_id
#   2.0.3              Kompatibel med Python 3.6 (SLES 15, RHEL 8 m.fl.)
#   2.0.2              Scannamn avgörs med -g/--folder vid dubbletter,
#                      papperskorgen exkluderas vid namnuppslag
#   2.0.1              X-API-Token söks även i andra JS-filer; saknad token
#                      stoppar inte längre körningen
#   2.0.0              Optioner istället för underkommandon (-X/--xxx),
#                      --check-connection, --list-scans, --encode-secret,
#                      base64 för hemligheter, --debug (ersätter -v),
#                      default auth.method = session.
#                      Fix: REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE skrev över
#                      verify_ssl/ca_bundle
# =============================================================================
"""
nessus_cli.py - All-round CLI för Nessus Professional REST-API.

Alla inställningar läses från settings.json (se settings.example.json).
Fälten auth.password, auth.secret_key och export.db_password ska vara base64-kodade
(skapa värdet med: nessus_cli.py --encode-secret).
Miljövariabler går före filen och anges i KLARTEXT:
    NESSUS_URL, NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY, NESSUS_USERNAME, NESSUS_PASSWORD

Exempel:
    nessus_cli.py --check-connection
    nessus_cli.py --list-scans --folder "My Scans"
    nessus_cli.py --create-scan "Kund X DMZ" --targets 10.0.0.0/24,web01 --template basic --launch-now --format csv pdf
    nessus_cli.py --launch "Kund X DMZ" --wait
    nessus_cli.py --export 42 --format csv html nessus --history-id all --out ./reports
    nessus_cli.py --status 42 --debug

Kräver: Python 3.6+, requests 2.20+ (cryptography valfritt, ger mer cert-info i --check-connection)
"""

import argparse
import base64
import binascii
import getpass
import hashlib
import json
import logging
import os
import platform
import re
import socket
import ssl
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse

try:
    import requests
    import urllib3
except ImportError:  # pragma: no cover
    sys.exit("Modulen 'requests' saknas: pip install requests")

__version__ = "2.1.0"

if sys.version_info < (3, 6):  # pragma: no cover
    sys.exit("nessus_cli.py kräver Python 3.6 eller senare")

RUNNING_STATES = {"running", "pending", "processing", "resuming", "pausing", "stopping", "publishing"}
EXPORT_FORMATS = ("nessus", "csv", "html", "pdf", "db", "json")
FILE_EXT = {f: f for f in EXPORT_FORMATS}
DEFAULT_CHAPTERS = "vuln_hosts_summary;vuln_by_host;remediations"

# Fält i settings.json som lagras base64-kodade
B64_FIELDS = (("auth", "password"), ("auth", "secret_key"), ("export", "db_password"))
# Nycklar vars värden alltid maskas i debug-utskrifter
SECRET_KEYS = {"password", "secret_key", "access_key", "db_password", "api_token", "token"}

DEFAULT_SETTINGS = {
    "url": "https://localhost:8834",
    "verify_ssl": True,
    "ca_bundle": None,
    "timeout": 60,
    "auth": {
        "method": "session",
        "access_key": "",
        "secret_key": "",
        "username": "",
        "password": "",
        "use_api_token": None,
        "api_token": None,
    },
    "scan_defaults": {
        "template": "basic",
        "folder": "My Scans",
        "poll_interval": 30,
        "max_wait_minutes": 720,
    },
    "export": {
        "output_dir": "./reports",
        "default_formats": ["csv", "html"],
        "chapters": DEFAULT_CHAPTERS,
        "template_id": None,
        "db_password": "",
        "poll_interval": 3,
        "timeout_seconds": 900,
        "extra": {},
    },
}


# --------------------------------------------------------------------------- #
# Loggning / hjälpfunktioner
# --------------------------------------------------------------------------- #
class NessusError(Exception):
    pass


DEBUG = False


def log(msg: str, err: bool = False) -> None:
    print(msg, file=sys.stderr if err else sys.stdout, flush=True)


def debug(msg: str) -> None:
    if DEBUG:
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        for line in str(msg).splitlines() or [""]:
            print(f"[debug {ts}] {line}", file=sys.stderr, flush=True)


def mask(value, keep: int = 4) -> str:
    if value in (None, ""):
        return "(tom)"
    s = str(value)
    return s[:keep] + "…" + f"({len(s)} tecken)" if len(s) > keep else "****"


def redact(obj):
    if isinstance(obj, dict):
        return {k: (mask(v) if k.lower() in SECRET_KEYS and v else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def redact_headers(headers) -> dict:
    out = {}
    for k, v in dict(headers).items():
        kl = k.lower()
        if kl == "x-apikeys":
            v = re.sub(r"(accessKey=)([^;]+)", lambda m: m.group(1) + mask(m.group(2)), v)
            v = re.sub(r"(secretKey=)([^;]+)", lambda m: m.group(1) + "****", v)
        elif kl in ("x-cookie", "cookie", "set-cookie"):
            v = re.sub(r"(token=)([^;\s]+)", lambda m: m.group(1) + mask(m.group(2)), v)
        elif kl in ("x-api-token", "authorization"):
            v = mask(v, 8)
        out[k] = v
    return out


def pretty(obj) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False, default=str)


def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def b64decode_field(value: str, field: str) -> str:
    if not value:
        return value
    try:
        return base64.b64decode(value.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError) as e:
        raise NessusError(f"'{field}' i settings.json är inte giltig base64 ({e}). "
                          f"Skapa värdet med: nessus_cli.py --encode-secret") from e


def load_settings(path: str) -> dict:
    p = Path(path)
    debug(f"Läser settings: {p.resolve()}")
    if not p.is_file():
        raise NessusError(f"Hittar inte settings-filen: {p.resolve()} (utgå från settings.example.json)")
    if os.name == "posix":
        mode = p.stat().st_mode
        debug(f"Filrättigheter: {stat.filemode(mode)} ägare uid={p.stat().st_uid}")
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            log(f"VARNING: {p} är läsbar för andra än ägaren. Kör: chmod 600 {p}", err=True)
    try:
        user = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise NessusError(f"Ogiltig JSON i {p}: {e}") from e
    cfg = deep_merge(DEFAULT_SETTINGS, user)

    for sect, key in B64_FIELDS:
        cfg[sect][key] = b64decode_field(cfg[sect].get(key) or "", f"{sect}.{key}")

    env_map = {
        "NESSUS_URL": ("url",),
        "NESSUS_ACCESS_KEY": ("auth", "access_key"),
        "NESSUS_SECRET_KEY": ("auth", "secret_key"),
        "NESSUS_USERNAME": ("auth", "username"),
        "NESSUS_PASSWORD": ("auth", "password"),
    }
    for env, keys in env_map.items():
        val = os.environ.get(env)
        if val:
            debug(f"Miljövariabel {env} åsidosätter {'.'.join(keys)}")
            tgt = cfg
            for k in keys[:-1]:
                tgt = tgt[k]
            tgt[keys[-1]] = val
    debug("Effektiva inställningar (hemligheter maskade, efter base64-avkodning):\n" + pretty(redact(cfg)))
    return cfg


def fmt_ts(epoch) -> str:
    try:
        return datetime.fromtimestamp(int(epoch)).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OSError):
        return "-"


def safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "scan"


def print_table(rows: List[dict], cols: List[Tuple[str, str]]) -> None:
    if not rows:
        log("(inga träffar)")
        return
    widths = {k: max(len(h), *(len(str(r.get(k, ""))) for r in rows)) for k, h in cols}
    log("  ".join(h.ljust(widths[k]) for k, h in cols))
    log("  ".join("-" * widths[k] for k, _ in cols))
    for r in rows:
        log("  ".join(str(r.get(k, "")).ljust(widths[k]) for k, _ in cols))


def parse_targets(targets: Optional[str], targets_file: Optional[str]) -> List[str]:
    items = []
    if targets:
        items += [t.strip() for t in re.split(r"[,\s]+", targets) if t.strip()]
    if targets_file:
        for line in Path(targets_file).read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                items += [t.strip() for t in re.split(r"[,\s]+", line) if t.strip()]
    debug(f"Mål ({len(items)} st): {items}")
    return items


def debug_environment(argv) -> None:
    if not DEBUG:
        return
    debug(f"nessus_cli {__version__}  argv={argv}")
    debug(f"Python {sys.version.split()[0]} ({sys.executable})  plattform: {platform.platform()}")
    debug(f"requests {requests.__version__}  urllib3 {urllib3.__version__}  {ssl.OPENSSL_VERSION}")
    debug(f"requests CA-bundle (default): {requests.certs.where()}")
    for v in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy",
              "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NESSUS_SETTINGS"):
        if os.environ.get(v):
            debug(f"env {v}={os.environ[v]}")
    for v in ("NESSUS_URL", "NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY", "NESSUS_USERNAME", "NESSUS_PASSWORD"):
        if os.environ.get(v):
            debug(f"env {v}={mask(os.environ[v]) if 'KEY' in v or 'PASS' in v else os.environ[v]}")
    # urllib3 loggar anslutningar/återanvändning/retries
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG,
                        format="[debug %(asctime)s] %(name)s: %(message)s", datefmt="%H:%M:%S")


# --------------------------------------------------------------------------- #
# API-klient
# --------------------------------------------------------------------------- #
class NessusClient:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.url = cfg["url"].rstrip("/")
        self.timeout = cfg.get("timeout", 60)
        self.auth = cfg["auth"]
        self.s = requests.Session()
        self.verify = cfg.get("ca_bundle") or cfg.get("verify_ssl", True)
        self.s.verify = self.verify
        if self.verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.s.headers.update({"Accept": "application/json", "User-Agent": f"nessus_cli/{__version__}"})
        self._session_token = None  # type: Optional[str]
        self.api_token_source = None  # type: Optional[str]
        self.api_token_missing = False
        self.scan_folder = None   # sätts från -g/--folder, används för att avgöra scannamn
        self.report_template_ref = None  # sätts från -e/--report-template
        self._rt_cache = {}
        debug(f"Klient: url={self.url} verify={self.verify} timeout={self.timeout}s "
              f"proxies={requests.utils.get_environ_proxies(self.url) or 'inga'}")

    # ---- transport --------------------------------------------------------
    def _req(self, method: str, path: str, **kw) -> requests.Response:
        kw.setdefault("timeout", self.timeout)
        # verify skickas per anrop: annars skriver REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE över session.verify
        kw.setdefault("verify", self.verify)
        url = self.url + path
        if DEBUG:
            hdrs = dict(self.s.headers)
            hdrs.update(kw.get("headers") or {})
            debug(f">>> {method} {url}")
            if kw.get("params"):
                debug(f">>> params: {kw['params']}")
            debug(">>> headers: " + pretty(redact_headers(hdrs)))
            if kw.get("json") is not None:
                debug(">>> body: " + pretty(redact(kw["json"])))
        t0 = time.perf_counter()
        try:
            r = self.s.request(method, url, **kw)
        except requests.exceptions.SSLError as e:
            raise NessusError(f"TLS-fel mot {self.url}: {e}\n"
                              "Tips: sätt 'ca_bundle' till Nessus CA-cert, eller 'verify_ssl': false (labb). "
                              "Kör --check-connection för detaljer.") from e
        except requests.exceptions.ConnectionError as e:
            raise NessusError(f"Kan inte ansluta till {self.url}: {e}") from e
        except requests.exceptions.Timeout as e:
            raise NessusError(f"Timeout ({kw['timeout']}s) mot {url}") from e
        if DEBUG:
            ms = (time.perf_counter() - t0) * 1000
            debug(f"<<< HTTP {r.status_code} {r.reason}  ({ms:.0f} ms, HTTP/{r.raw.version / 10 if r.raw.version else '?'})")
            debug("<<< headers: " + pretty(redact_headers(r.headers)))
            self._debug_body(r, kw.get("stream", False))
        if r.status_code >= 400:
            try:
                msg = r.json().get("error", r.text)
            except ValueError:
                msg = r.text.strip()[:500]
            hint = ""
            if r.status_code == 412 or "API is not available" in str(msg):
                hint = ("\nTips: Nessus Professional blockerar vissa anrop (t.ex. skapa/starta scan) via API-nycklar. "
                        "Prova auth.method = \"session\" (användarnamn/lösenord + X-API-Token).")
            elif r.status_code == 401:
                hint = "\nTips: kontrollera nycklar/lösenord i settings.json (base64-kodade?)."
            elif r.status_code == 403:
                hint = "\nTips: användaren saknar behörighet för anropet."
            raise NessusError(f"{method} {path} -> HTTP {r.status_code}: {msg}{hint}")
        return r

    @staticmethod
    def _debug_body(r: requests.Response, streamed: bool) -> None:
        if streamed:
            debug(f"<<< body: (strömmas till fil, Content-Length={r.headers.get('Content-Length', '?')})")
            return
        ctype = r.headers.get("Content-Type", "")
        if not r.content:
            debug("<<< body: (tom)")
        elif "json" in ctype:
            try:
                debug("<<< body: " + pretty(redact(r.json())))
            except ValueError:
                debug("<<< body (ogiltig JSON): " + r.text[:4000])
        elif "javascript" in ctype:
            debug(f"<<< body: (javascript, {len(r.content):,} byte – visas inte, innehåller X-API-Token)")
        elif ctype.startswith("text"):
            txt = r.text
            debug(f"<<< body ({len(txt):,} tecken{', visar 2000 första' if len(txt) > 2000 else ''}): {txt[:2000]}")
        else:
            debug(f"<<< body: (binär {ctype}, {len(r.content):,} byte)")

    def get(self, path, **kw):
        r = self._req("GET", path, **kw)
        return r.json() if r.content else {}

    def post(self, path, **kw):
        r = self._req("POST", path, **kw)
        return r.json() if r.content else {}

    def delete(self, path, **kw):
        r = self._req("DELETE", path, **kw)
        return r.json() if r.content else {}

    # ---- autentisering ----------------------------------------------------
    @property
    def auth_method(self) -> str:
        return (self.auth.get("method") or "session").lower()

    def login(self) -> None:
        method = self.auth_method
        debug(f"Autentisering: metod={method}")
        if method == "api_keys":
            ak, sk = self.auth.get("access_key"), self.auth.get("secret_key")
            if not ak or not sk:
                raise NessusError("auth.access_key/secret_key saknas i settings.json")
            self.s.headers["X-ApiKeys"] = f"accessKey={ak}; secretKey={sk}"
        elif method == "session":
            u, p = self.auth.get("username"), self.auth.get("password")
            if not u or not p:
                raise NessusError("auth.username/password saknas i settings.json")
            data = self.post("/session", json={"username": u, "password": p})
            self._session_token = data.get("token")
            if not self._session_token:
                raise NessusError("Inloggningen gav ingen session-token")
            self.s.headers["X-Cookie"] = f"token={self._session_token}"
            debug(f"Session-token erhållen: {mask(self._session_token)}")
        else:
            raise NessusError(f"Okänd auth.method: {method} (använd 'api_keys' eller 'session')")

        use_tok = self.auth.get("use_api_token")
        if use_tok is None:
            use_tok = method == "session"
        if use_tok:
            self.api_token_source = "settings" if self.auth.get("api_token") else None
            tok = self.auth.get("api_token") or self.fetch_api_token()
            if tok:
                self.s.headers["X-API-Token"] = tok
                debug(f"X-API-Token satt: {mask(tok, 8)} (källa: {self.api_token_source})")
            else:
                self.api_token_missing = True
                log("VARNING: hittade ingen X-API-Token i webbgränssnittets JavaScript. Fortsätter utan – "
                    "läsning/export fungerar oftast, men skapa/starta scan kan ge HTTP 412. "
                    "Sätt auth.api_token manuellt vid behov (kör med --debug för detaljer).", err=True)

    TOKEN_ANCHORS = ("getApiToken", "X-API-Token", "x-api-token", "apiToken", "api_token")
    UUID_RE = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")

    def _token_from_js(self, js: str, src: str) -> Optional[str]:
        for anchor in self.TOKEN_ANCHORS:
            for m in re.finditer(re.escape(anchor), js):
                window = js[max(0, m.start() - 300):m.end() + 600]
                u = self.UUID_RE.search(window)
                debug(f"{src}: '{anchor}' på pos {m.start()} -> {'UUID hittad' if u else 'ingen UUID i närheten'}")
                if u:
                    return u.group(0)
        return None

    def _js_candidates(self) -> List[str]:
        """Skriptfiler som webbgränssnittet laddar: nessus6.js först, sedan <script src> från startsidan."""
        paths = ["/nessus6.js"]
        try:
            html = self._req("GET", "/", headers={"Accept": "text/html"}).text
            for src in re.findall(r"<script[^>]+src=[\"']([^\"']+\.js)[^\"']*[\"']", html, re.I):
                if src.startswith("http"):
                    src = urlparse(src).path
                src = "/" + src.lstrip("./").lstrip("/")
                if src not in paths:
                    paths.append(src)
        except NessusError as e:
            debug(f"Kunde inte läsa startsidan för skriptlista: {e}")
        debug(f"JS-filer att söka X-API-Token i: {paths}")
        return paths

    def fetch_api_token(self) -> Optional[str]:
        """Hämtar X-API-Token ur webbgränssnittets JavaScript (behövs för session-auth i Pro).
        Returnerar None om den inte hittas (anroparen fortsätter utan)."""
        for path in self._js_candidates():
            try:
                r = self._req("GET", path, headers={"Accept": "*/*"})
            except NessusError as e:
                debug(f"{path}: {e}")
                continue
            ctype = r.headers.get("Content-Type", "")
            debug(f"{path}: {len(r.text):,} tecken, Content-Type={ctype}")
            if "html" in ctype:
                debug(f"{path}: fick HTML istället för JS (servern startar/uppdaterar plugins?)")
                continue
            tok = self._token_from_js(r.text, path)
            if tok:
                self.api_token_source = path
                return tok
        return None

    def logout(self) -> None:
        if self._session_token:
            try:
                self._req("DELETE", "/session")
                debug("Utloggad (DELETE /session)")
            except NessusError as e:
                debug(f"Utloggning misslyckades: {e}")
            self._session_token = None

    # ---- uppslag ----------------------------------------------------------
    def server_properties(self):
        return self.get("/server/properties")

    def server_status(self):
        return self.get("/server/status")

    def session_info(self):
        return self.get("/session")

    def folders(self) -> List[dict]:
        return self.get("/folders").get("folders") or []

    def scans(self, folder_id: Optional[int] = None) -> dict:
        params = {"folder_id": folder_id} if folder_id is not None else None
        return self.get("/scans", params=params)

    def scan_details(self, scan_id: int, history_id: Optional[int] = None) -> dict:
        params = {"history_id": history_id} if history_id else None
        return self.get(f"/scans/{scan_id}", params=params)

    def templates(self) -> List[dict]:
        return self.get("/editor/scan/templates").get("templates") or []

    def policies(self) -> List[dict]:
        return self.get("/policies").get("policies") or []

    def report_templates(self) -> List[dict]:
        """Rapportmallar för html/pdf (GET /reports/custom/templates, Nessus 8.x+/10.x)."""
        data = self.get("/reports/custom/templates")
        if isinstance(data, dict):
            data = data.get("templates", data.get("reports", []))
        return data if isinstance(data, list) else []

    def resolve_report_template(self, ref) -> int:
        """Rapportmall på id eller namn (skiftlägesokänsligt). Cachas per körning."""
        key = str(ref).strip()
        if key in self._rt_cache:
            return self._rt_cache[key]
        try:
            tpls = self.report_templates()
        except NessusError as e:
            if key.isdigit():
                debug(f"Kunde inte lista rapportmallar ({e}) – använder id {key} som det är")
                return int(key)
            raise NessusError(f"Kan inte slå upp rapportmallen '{key}': {e}") from e
        if key.isdigit():
            hits = [t for t in tpls if str(t.get("id")) == key]
            if not hits and tpls:
                raise NessusError(f"Ingen rapportmall med id {key}. Lista med -R/--list-report-templates")
            tid = int(key)
        else:
            hits = [t for t in tpls if str(t.get("name", "")).lower() == key.lower()]
            if not hits:
                names = ", ".join(sorted(str(t.get("name")) for t in tpls)) or "(inga)"
                raise NessusError(f"Ingen rapportmall som heter '{key}'. Tillgängliga: {names}")
            if len(hits) > 1:
                raise NessusError(f"Flera rapportmallar heter '{key}' (id: "
                                  f"{', '.join(str(h.get('id')) for h in hits)}) – ange id")
            tid = int(hits[0]["id"])
        debug(f"Rapportmall '{key}' -> id {tid}" + (f" ({hits[0].get('name')})" if hits else ""))
        self._rt_cache[key] = tid
        return tid

    def effective_report_template(self) -> Optional[int]:
        """-e/--report-template går före export.template_id i settings (båda kan vara id eller namn)."""
        ref = self.report_template_ref or self.cfg["export"].get("template_id")
        return self.resolve_report_template(ref) if ref not in (None, "") else None

    def resolve_folder(self, ref) -> Optional[int]:
        if ref in (None, ""):
            return None
        if str(ref).isdigit():
            return int(ref)
        for f in self.folders():
            if f.get("name", "").lower() == str(ref).lower():
                debug(f"Mapp '{ref}' -> id {f['id']}")
                return f["id"]
        raise NessusError(f"Hittar ingen mapp som heter '{ref}'")

    def resolve_scan(self, ref: str) -> dict:
        """Slår upp scan på id eller namn. Namn söks i alla mappar utom papperskorgen,
        eller bara i --folder om den är angiven. Flera träffar ger fel med id och mapp."""
        data = self.scans()
        all_scans = data.get("scans") or []
        folders = {f["id"]: f for f in data.get("folders") or []}
        fname = lambda s: folders.get(s.get("folder_id"), {}).get("name", s.get("folder_id"))
        if str(ref).isdigit():
            for s in all_scans:
                if s["id"] == int(ref):
                    debug(f"Scan id {ref} -> '{s.get('name')}' i mapp '{fname(s)}'")
                    return s
            raise NessusError(f"Ingen scan med id {ref}")

        if self.scan_folder not in (None, ""):
            fid = self.resolve_folder(self.scan_folder)
            pool = [s for s in all_scans if s.get("folder_id") == fid]
            where = f"i mappen '{self.scan_folder}'"
        else:
            trash = {fid for fid, f in folders.items() if f.get("type") == "trash"}
            pool = [s for s in all_scans if s.get("folder_id") not in trash]
            where = "(papperskorgen exkluderad)"
        hits = [s for s in pool if s.get("name", "").lower() == str(ref).lower()]
        if not hits:
            raise NessusError(f"Ingen scan med namnet '{ref}' {where}")
        if len(hits) > 1:
            lst = ", ".join(f"id {h['id']} ({fname(h)})" for h in hits)
            raise NessusError(f"Flera scans heter '{ref}': {lst}. Ange id, eller mapp med -g/--folder")
        debug(f"Scan '{ref}' -> id {hits[0]['id']} i mapp '{fname(hits[0])}'")
        return hits[0]

    def resolve_template(self, ref: str) -> dict:
        tpls = self.templates()
        for t in tpls:
            if ref.lower() in (str(t.get("uuid", "")).lower(), str(t.get("name", "")).lower(),
                               str(t.get("title", "")).lower()):
                debug(f"Mall '{ref}' -> {t.get('name')} / {t.get('uuid')}")
                return t
        names = ", ".join(sorted(t.get("name", "") for t in tpls))
        raise NessusError(f"Okänd mall '{ref}'. Tillgängliga: {names}")

    def resolve_policy(self, ref: str) -> dict:
        for p in self.policies():
            if str(p.get("id")) == str(ref) or p.get("name", "").lower() == str(ref).lower():
                debug(f"Policy '{ref}' -> id {p['id']} template_uuid {p.get('template_uuid')}")
                return p
        raise NessusError(f"Ingen policy '{ref}'")

    # ---- scan-hantering ---------------------------------------------------
    def create_scan(self, name, targets, template=None, policy=None, folder=None, description="") -> dict:
        settings = {"name": name, "description": description, "text_targets": ",".join(targets),
                    "enabled": False, "launch": "ON_DEMAND"}
        if policy:
            pol = self.resolve_policy(policy)
            uuid = pol["template_uuid"]
            settings["policy_id"] = pol["id"]
        else:
            uuid = self.resolve_template(template or self.cfg["scan_defaults"]["template"])["uuid"]
        fid = self.resolve_folder(folder if folder is not None else self.cfg["scan_defaults"].get("folder"))
        if fid is not None:
            settings["folder_id"] = fid
        data = self.post("/scans", json={"uuid": uuid, "settings": settings})
        return data.get("scan", data)

    def launch(self, scan_id: int, alt_targets=None) -> Optional[str]:
        body = {"alt_targets": alt_targets} if alt_targets else None
        return self.post(f"/scans/{scan_id}/launch", json=body).get("scan_uuid")

    def control(self, scan_id: int, action: str) -> None:
        self.post(f"/scans/{scan_id}/{action}")

    def delete_scan(self, scan_id: int) -> None:
        self.delete(f"/scans/{scan_id}")

    def wait_for_scan(self, scan_id: int, scan_uuid: Optional[str] = None) -> dict:
        d = self.cfg["scan_defaults"]
        interval = int(d.get("poll_interval", 30))
        deadline = time.time() + int(d.get("max_wait_minutes", 720)) * 60
        debug(f"Väntar på scan {scan_id} (uuid {scan_uuid}), poll var {interval}s")
        last = None
        time.sleep(min(5, interval))
        while True:
            det = self.scan_details(scan_id)
            hist = self._find_history(det, scan_uuid)
            status = (hist or {}).get("status") or det.get("info", {}).get("status")
            if status != last:
                log(f"[{datetime.now():%H:%M:%S}] scan {scan_id}: {status}")
                last = status
            if status not in RUNNING_STATES:
                return hist or {"status": status}
            if time.time() > deadline:
                raise NessusError(f"Timeout i väntan på scan {scan_id} (status {status})")
            time.sleep(interval)

    @staticmethod
    def _find_history(details: dict, scan_uuid: Optional[str]) -> Optional[dict]:
        hist = details.get("history") or []
        if scan_uuid:
            for h in hist:
                if h.get("uuid") == scan_uuid:
                    return h
        return max(hist, key=lambda h: h.get("creation_date", 0)) if hist else None

    def history(self, scan_id: int) -> List[dict]:
        hist = self.scan_details(scan_id).get("history") or []
        return sorted(hist, key=lambda h: h.get("creation_date", 0), reverse=True)

    def pick_history(self, scan_id: int, which: str) -> list:
        if which not in ("latest", "all"):
            if not str(which).isdigit():
                raise NessusError(f"--history-id måste vara 'latest', 'all' eller ett heltal, inte '{which}'")
            return [int(which)]
        done = [h for h in self.history(scan_id) if h.get("status") in ("completed", "imported", "canceled", "aborted")]
        if not done:
            log(f"Scan {scan_id}: ingen avslutad körning i historiken – exporterar utan history_id", err=True)
            return [None]
        completed = [h for h in done if h.get("status") in ("completed", "imported")] or done
        picked = [completed[0]["history_id"]] if which == "latest" else [h["history_id"] for h in completed]
        debug(f"Valda history_id ({which}): {picked}")
        return picked

    # ---- export -----------------------------------------------------------
    def export_formats(self, scan_id: int):
        return self.get(f"/scans/{scan_id}/export/formats")

    def export(self, scan_id: int, fmt: str, history_id, out_dir: Path, scan_name: str) -> Path:
        ecfg = self.cfg["export"]
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hpart = f"_h{history_id}" if history_id else ""
        target = out_dir / f"{safe_name(scan_name)}_{scan_id}{hpart}_{stamp}.{FILE_EXT[fmt]}"

        if fmt == "json":
            data = self.scan_details(scan_id, history_id)
            target.write_text(pretty(data), encoding="utf-8")
            return target

        body = {"format": fmt}
        if fmt in ("html", "pdf"):
            tid = self.effective_report_template()
            if tid is not None:
                body["template_id"] = tid
            else:
                body["chapters"] = ecfg.get("chapters") or DEFAULT_CHAPTERS
        if fmt == "db":
            if not ecfg.get("db_password"):
                raise NessusError("Format 'db' kräver export.db_password (base64) i settings.json")
            body["password"] = ecfg["db_password"]
        body.update((ecfg.get("extra") or {}).get(fmt, {}))

        params = {"history_id": history_id} if history_id else None
        res = self.post(f"/scans/{scan_id}/export", json=body, params=params)
        file_id = res.get("file")
        if file_id is None:
            raise NessusError(f"Export-anropet returnerade inget fil-id: {res}")

        interval = float(ecfg.get("poll_interval", 3))
        deadline = time.time() + int(ecfg.get("timeout_seconds", 900))
        t0 = time.time()
        while True:
            st = self.get(f"/scans/{scan_id}/export/{file_id}/status").get("status")
            if st == "ready":
                debug(f"Export {fmt} file={file_id} klar efter {time.time() - t0:.1f}s")
                break
            if st == "error":
                raise NessusError(f"Nessus kunde inte generera {fmt}-rapporten (file {file_id})")
            if time.time() > deadline:
                raise NessusError(f"Timeout vid generering av {fmt}-rapport")
            time.sleep(interval)

        r = self._req("GET", f"/scans/{scan_id}/export/{file_id}/download",
                      headers={"Accept": "*/*"}, stream=True, timeout=max(self.timeout, 300))
        with open(target, "wb") as fh:
            for chunk in r.iter_content(chunk_size=1 << 16):
                fh.write(chunk)
        debug(f"Sparad: {target.resolve()} ({target.stat().st_size:,} byte, "
              f"sha256 {hashlib.sha256(target.read_bytes()).hexdigest()})")
        return target


# --------------------------------------------------------------------------- #
# --check-connection
# --------------------------------------------------------------------------- #
class Checker:
    def __init__(self):
        self.fail = 0
        self.warn = 0

    def ok(self, name, detail=""):
        log(f"[ OK ] {name}{': ' + detail if detail else ''}")

    def warning(self, name, detail=""):
        self.warn += 1
        log(f"[VARN] {name}{': ' + detail if detail else ''}")

    def error(self, name, detail=""):
        self.fail += 1
        log(f"[ FEL] {name}{': ' + detail if detail else ''}")


def _cert_details(der: bytes) -> str:
    fp = hashlib.sha256(der).hexdigest().upper()
    fp = ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))
    try:
        from cryptography import x509
        c = x509.load_der_x509_certificate(der)
        nva = getattr(c, "not_valid_after_utc", None) or c.not_valid_after.replace(tzinfo=timezone.utc)
        return (f"subject={c.subject.rfc4514_string()} issuer={c.issuer.rfc4514_string()} "
                f"giltigt till {nva:%Y-%m-%d} sha256={fp}")
    except Exception:  # cryptography saknas eller kan inte tolka
        return f"sha256={fp}"


def check_connection(cfg: dict) -> int:
    chk = Checker()
    u = urlparse(cfg["url"])
    host, scheme = u.hostname, (u.scheme or "https").lower()
    port = u.port or (443 if scheme == "https" else 80)
    timeout = min(int(cfg.get("timeout", 60)), 15)
    log(f"Kontrollerar anslutning till {cfg['url']}  (auth: {cfg['auth'].get('method')})\n")

    if not host:
        chk.error("URL", f"kan inte tolka '{cfg['url']}'")
        return 1
    if scheme != "https":
        chk.warning("URL", "http:// används – Nessus kör normalt endast https på 8834")

    proxies = requests.utils.get_environ_proxies(cfg["url"])
    if proxies:
        chk.warning("Proxy", f"requests kommer gå via {proxies} – nät/TLS-testerna nedan går direkt")

    # 1. DNS
    try:
        addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
        chk.ok("DNS", f"{host} -> {', '.join(addrs)}")
    except socket.gaierror as e:
        chk.error("DNS", f"{host}: {e}")
        return 1

    # 2. TCP
    try:
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout):
            chk.ok("TCP", f"{host}:{port} öppen ({(time.perf_counter() - t0) * 1000:.0f} ms)")
    except OSError as e:
        chk.error("TCP", f"{host}:{port}: {e}")
        return 1

    # 3. TLS
    if scheme == "https":
        verify, ca = cfg.get("verify_ssl", True), cfg.get("ca_bundle")
        der = None
        if verify or ca:
            cafile = ca or os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE") or requests.certs.where()
            debug(f"TLS-kontroll med CA-fil: {cafile}")
            ctx = ssl.create_default_context(cafile=cafile)
            try:
                with socket.create_connection((host, port), timeout=timeout) as raw, \
                        ctx.wrap_socket(raw, server_hostname=host) as tls:
                    pc = tls.getpeercert()
                    der = tls.getpeercert(binary_form=True)
                    days = (ssl.cert_time_to_seconds(pc["notAfter"]) - time.time()) / 86400
                    chk.ok("TLS-handskakning", f"{tls.version()} {tls.cipher()[0]}")
                    chk.ok("Certifikat verifierat", _cert_details(der) + f" CA={cafile}")
                    if days < 0:
                        chk.error("Certifikatets giltighet", "utgånget")
                    elif days < 30:
                        chk.warning("Certifikatets giltighet", f"går ut om {days:.0f} dagar")
            except (ssl.SSLError, ssl.CertificateError, OSError) as e:
                # 3.7+: SSLCertVerificationError (har verify_message); 3.6: SSLError/CertificateError
                verify_fail = isinstance(e, ssl.CertificateError) or "CERTIFICATE_VERIFY_FAILED" in str(e) \
                    or hasattr(e, "verify_message")
                if verify_fail:
                    reason = getattr(e, "verify_message", None) or str(e)
                    chk.error("Certifikatverifiering", f"{reason} – tips: ca_bundle = Nessus CA "
                              "(Linux: /opt/nessus/com/nessus/CA/cacert.pem, "
                              "Windows: C:\\ProgramData\\Tenable\\Nessus\\nessus\\CA\\cacert.pem)")
                else:
                    chk.error("TLS-handskakning", str(e))
        if der is None:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            try:
                with socket.create_connection((host, port), timeout=timeout) as raw, \
                        ctx.wrap_socket(raw, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
                    chk.ok("TLS (overifierad)", f"{tls.version()} {tls.cipher()[0]}")
                    log(f"       Servercert: {_cert_details(der)}")
                    if not (verify or ca):
                        chk.warning("TLS-verifiering", "avstängd i settings (verify_ssl=false)")
            except (ssl.SSLError, OSError) as e:
                chk.error("TLS-handskakning", str(e))
                return 1

    client = NessusClient(cfg)
    # 4. Oautentiserat API-anrop
    try:
        st = client.server_status()
        s = st.get("status")
        (chk.ok if s == "ready" else chk.warning)("Nessus-tjänst", f"status={s} progress={st.get('progress')}")
    except NessusError as e:
        chk.error("Nessus-tjänst (GET /server/status)", str(e))
        return 1

    # 5. Autentisering
    try:
        client.login()
        chk.ok("Autentisering", client.auth_method)
        if "X-API-Token" in client.s.headers:
            chk.ok("X-API-Token", f"hittad (källa: {client.api_token_source})")
        elif client.api_token_missing:
            chk.warning("X-API-Token", "hittades inte – skapa/starta scan kan ge HTTP 412. "
                        "Sätt auth.api_token manuellt (se README, 'X-API-Token')")
    except NessusError as e:
        chk.error("Autentisering", str(e))
        return 1

    try:
        # 6. Serverinfo
        try:
            p = client.server_properties()
            lic = p.get("license") or {}
            chk.ok("Server", f"{p.get('nessus_type')} {p.get('server_version') or p.get('nessus_ui_version')}")
            exp = lic.get("expiration_date")
            if exp:
                days = (int(exp) - time.time()) / 86400
                (chk.ok if days > 30 else chk.warning if days > 0 else chk.error)(
                    "Licens", f"{lic.get('type', '-')} utgår {fmt_ts(exp)} ({days:.0f} dagar)")
            if p.get("nessus_type") and "Professional" not in p["nessus_type"]:
                chk.warning("Produkt", "skriptet är byggt för Nessus Professional")
        except NessusError as e:
            chk.error("GET /server/properties", str(e))

        # 7. Användare
        try:
            si = client.session_info()
            perm = si.get("permissions")
            role = {128: "System Administrator", 64: "Administrator", 32: "Standard", 16: "Basic"}.get(perm, perm)
            chk.ok("Användare", f"{si.get('username')} ({role})")
        except NessusError as e:
            chk.warning("GET /session", str(e))

        # 8. Läsrättighet scans
        try:
            d = client.scans()
            chk.ok("Läsa scans", f"{len(d.get('scans') or [])} scans i {len(d.get('folders') or [])} mappar")
        except NessusError as e:
            chk.error("GET /scans", str(e))

        if client.auth_method == "api_keys":
            chk.warning("API-nycklar", "i Nessus Pro kan skapa/starta scan ge HTTP 412 – överväg auth.method=session")
    finally:
        client.logout()

    log(f"\nResultat: {chk.fail} fel, {chk.warn} varningar")
    return 1 if chk.fail else 0


# --------------------------------------------------------------------------- #
# Åtgärder
# --------------------------------------------------------------------------- #
def act_server_info(c, a):
    props, st = c.server_properties(), c.server_status()
    if a.raw:
        log(pretty({"properties": props, "status": st}))
        return
    lic = props.get("license") or {}
    log(f"URL:         {c.url}")
    log(f"Produkt:     {props.get('nessus_type')} {props.get('server_version') or props.get('nessus_ui_version')}")
    log(f"UI-version:  {props.get('nessus_ui_version')}")
    log(f"Plugin-set:  {props.get('plugin_set') or (props.get('feed_info') or {}).get('plugin_set', '-')}")
    log(f"Licens:      {lic.get('type', '-')}  utgår {fmt_ts(lic.get('expiration_date'))}")
    log(f"Status:      {st.get('status')}")


def act_list_folders(c, a):
    f = c.folders()
    log(pretty(f)) if a.raw else print_table(f, [("id", "ID"), ("name", "Namn"), ("type", "Typ")])


def act_list_scans(c, a):
    fid = c.resolve_folder(a.folder) if a.folder else None
    data = c.scans(fid)
    scans = data.get("scans") or []
    if a.raw:
        log(pretty(scans))
        return
    fnames = {f["id"]: f["name"] for f in data.get("folders") or []}
    rows = [{"id": s["id"], "name": s.get("name"), "status": s.get("status"),
             "folder": fnames.get(s.get("folder_id"), s.get("folder_id")),
             "modified": fmt_ts(s.get("last_modification_date"))}
            for s in sorted(scans, key=lambda s: s.get("last_modification_date") or 0, reverse=True)]
    print_table(rows, [("id", "ID"), ("name", "Namn"), ("status", "Status"), ("folder", "Mapp"), ("modified", "Ändrad")])


def act_list_templates(c, a):
    t = c.templates()
    if a.raw:
        log(pretty(t))
        return
    rows = [{"name": x.get("name"), "title": x.get("title"), "uuid": x.get("uuid"),
             "sub": "ja" if x.get("subscription_only") else ""} for x in t]
    print_table(sorted(rows, key=lambda r: r["name"] or ""),
                [("name", "Namn"), ("title", "Titel"), ("uuid", "UUID"), ("sub", "Kräver abonnemang")])


def act_list_policies(c, a):
    p = c.policies()
    if a.raw:
        log(pretty(p))
        return
    rows = [{"id": x.get("id"), "name": x.get("name"), "template_uuid": x.get("template_uuid"),
             "modified": fmt_ts(x.get("last_modification_date"))} for x in p]
    print_table(rows, [("id", "ID"), ("name", "Namn"), ("template_uuid", "Mall-UUID"), ("modified", "Ändrad")])


def act_list_report_templates(c, a):
    items = c.report_templates()
    if a.raw:
        log(pretty(items))
        return
    default_ref = c.cfg["export"].get("template_id")
    default_id = None
    if default_ref not in (None, ""):
        try:
            default_id = c.resolve_report_template(default_ref)
        except NessusError as e:
            log(f"VARNING: export.template_id i settings: {e}", err=True)
    extra = [k for k in ("type", "owner", "format", "formats", "description", "templateDescription")
             if any(k in t for t in items)]
    rows = []
    for t in sorted(items, key=lambda t: (str(t.get("type", "")), str(t.get("name", "")).lower())):
        r = {"default": "*" if default_id is not None and str(t.get("id")) == str(default_id) else "",
             "id": t.get("id"), "name": t.get("name")}
        for k in extra:
            v = t.get(k, "")
            r[k] = ",".join(map(str, v)) if isinstance(v, list) else str(v)[:60]
        rows.append(r)
    print_table(rows, [("default", "Std"), ("id", "ID"), ("name", "Namn")] + [(k, k.capitalize()) for k in extra])
    if items:
        log("\nAnvänd med: -E SCAN -f pdf -e <ID|namn>   (Std = export.template_id i settings)")


def act_status(c, a):
    s = c.resolve_scan(a.status)
    det = c.scan_details(s["id"])
    if a.raw:
        log(pretty(det))
        return
    info = det.get("info", {})
    log(f"Scan:        {info.get('name')} (id {s['id']})")
    log(f"Status:      {info.get('status')}")
    log(f"Mål:         {info.get('targets')}")
    log(f"Policy:      {info.get('policy')}")
    log(f"Start/Slut:  {fmt_ts(info.get('scan_start'))} / {fmt_ts(info.get('scan_end'))}")
    log(f"Hosts:       {info.get('hostcount', len(det.get('hosts') or []))}")
    sev = {4: 0, 3: 0, 2: 0, 1: 0, 0: 0}
    for v in det.get("vulnerabilities") or []:
        sev[v.get("severity", 0)] = sev.get(v.get("severity", 0), 0) + (v.get("count") or 1)
    log(f"Fynd:        Critical {sev[4]}  High {sev[3]}  Medium {sev[2]}  Low {sev[1]}  Info {sev[0]}")


def act_list_history(c, a):
    s = c.resolve_scan(a.list_history)
    h = c.history(s["id"])
    if a.raw:
        log(pretty(h))
        return
    rows = [{"history_id": x.get("history_id"), "status": x.get("status"), "created": fmt_ts(x.get("creation_date")),
             "modified": fmt_ts(x.get("last_modification_date")), "uuid": x.get("uuid")} for x in h]
    print_table(rows, [("history_id", "History-ID"), ("status", "Status"), ("created", "Skapad"),
                       ("modified", "Ändrad"), ("uuid", "Scan-UUID")])


def _do_exports(c, scan: dict, formats, which: str, out) -> int:
    out_dir = Path(out or c.cfg["export"]["output_dir"])
    errors = 0
    if c.report_template_ref and not set(formats) & {"html", "pdf"}:
        log("VARNING: -e/--report-template används bara för html/pdf och ignoreras för "
            f"{', '.join(formats)}", err=True)
    elif set(formats) & {"html", "pdf"}:
        tid = c.effective_report_template()  # slå upp tidigt så ett felaktigt namn stoppar innan export
        log(f"Rapportmall för html/pdf: {('id ' + str(tid)) if tid is not None else 'ingen (chapters: ' + str(c.cfg['export'].get('chapters')) + ')'}")
    for hid in c.pick_history(scan["id"], which):
        for fmt in formats:
            try:
                log(f"Exporterar {fmt} för '{scan['name']}' (id {scan['id']}, history {hid or '-'}) ...")
                p = c.export(scan["id"], fmt, hid, out_dir, scan["name"])
                log(f"  -> {p} ({p.stat().st_size:,} byte)")
            except NessusError as e:
                errors += 1
                log(f"  FEL: {e}", err=True)
    return errors


def act_export(c, a):
    scan = c.resolve_scan(a.export)
    formats = a.format or c.cfg["export"]["default_formats"]
    return 1 if _do_exports(c, scan, formats, a.history_id, a.out) else 0


def act_export_formats(c, a):
    log(pretty(c.export_formats(c.resolve_scan(a.export_formats)["id"])))


def _launch_flow(c, scan: dict, a) -> int:
    alt = parse_targets(a.alt_targets, None) or None
    scan_uuid = c.launch(scan["id"], alt)
    log(f"Startade '{scan['name']}' (id {scan['id']}), scan_uuid {scan_uuid}")
    if not (a.wait or a.format):
        return 0
    hist = c.wait_for_scan(scan["id"], scan_uuid)
    log(f"Scan avslutad med status: {hist.get('status')}")
    if a.format:
        hid = hist.get("history_id")
        return 1 if _do_exports(c, scan, a.format, str(hid) if hid else "latest", a.out) else 0
    return 0 if hist.get("status") == "completed" else 2


def act_launch(c, a):
    return _launch_flow(c, c.resolve_scan(a.launch), a)


def act_create_scan(c, a):
    targets = parse_targets(a.targets, a.targets_file)
    if not targets:
        raise NessusError("--create-scan kräver --targets och/eller --targets-file")
    if a.template and a.policy:
        raise NessusError("Ange antingen --template eller --policy, inte båda")
    scan = c.create_scan(a.create_scan, targets, template=a.template, policy=a.policy,
                         folder=a.folder, description=a.description or "")
    log(f"Skapade scan '{scan.get('name', a.create_scan)}' med id {scan.get('id')}")
    if a.launch_now or a.wait or a.format:
        return _launch_flow(c, {"id": scan["id"], "name": scan.get("name", a.create_scan)}, a)
    return 0


def _control(action, attr):
    def f(c, a):
        s = c.resolve_scan(getattr(a, attr))
        c.control(s["id"], action)
        log(f"{action} skickat till '{s['name']}' (id {s['id']})")
    return f


def act_delete(c, a):
    s = c.resolve_scan(a.delete)
    if not a.yes:
        ans = input(f"Ta bort scan '{s['name']}' (id {s['id']}) inklusive historik? [j/N] ")
        if ans.strip().lower() not in ("y", "j", "yes", "ja"):
            log("Avbrutet.")
            return 0
    c.delete_scan(s["id"])
    log(f"Tog bort scan {s['id']}")


def act_encode_secret(value: str) -> int:
    if not value:
        if not sys.stdin.isatty():
            value = sys.stdin.readline().rstrip("\n")
        else:
            value = getpass.getpass("Hemlighet att koda: ")
            if value != getpass.getpass("Upprepa: "):
                log("FEL: värdena matchar inte", err=True)
                return 1
    log(base64.b64encode(value.encode("utf-8")).decode("ascii"))
    return 0


# (dest, kort, lång, metavar|None, hjälptext, funktion)
ACTIONS = [
    ("check_connection", "-C", "--check-connection", None, "testa DNS, TCP, TLS/cert, tjänst, inloggning och rättigheter", None),
    ("server_info", "-I", "--server-info", None, "visa serverinfo, version och licens", act_server_info),
    ("list_scans", "-L", "--list-scans", None, "lista scans (filtrera med --folder)", act_list_scans),
    ("list_folders", "-F", "--list-folders", None, "lista mappar", act_list_folders),
    ("list_templates", "-T", "--list-templates", None, "lista scanmallar (för --template)", act_list_templates),
    ("list_policies", "-P", "--list-policies", None, "lista egna policys (för --policy)", act_list_policies),
    ("list_report_templates", "-R", "--list-report-templates", None,
     "lista rapportmallar för html/pdf (används med -e/--report-template)", act_list_report_templates),
    ("list_history", "-H", "--list-history", "SCAN", "lista körningar (history_id) för en scan", act_list_history),
    ("status", "-Q", "--status", "SCAN", "status och fyndsammanfattning för en scan", act_status),
    ("create_scan", "-N", "--create-scan", "NAMN", "skapa ny scan (kräver --targets/--targets-file)", act_create_scan),
    ("launch", "-S", "--launch", "SCAN", "starta en befintlig scan", act_launch),
    ("pause", "-Z", "--pause", "SCAN", "pausa en körande scan", _control("pause", "pause")),
    ("resume", "-U", "--resume", "SCAN", "återuppta en pausad scan", _control("resume", "resume")),
    ("stop", "-K", "--stop", "SCAN", "stoppa en körande scan", _control("stop", "stop")),
    ("export", "-E", "--export", "SCAN", "skapa och ladda ner rapporter (--format, --history-id, --out)", act_export),
    ("export_formats", "-O", "--export-formats", "SCAN", "visa exportformat/kapitel som servern stödjer", act_export_formats),
    ("delete", "-X", "--delete", "SCAN", "ta bort en scan (bekräfta eller --yes)", act_delete),
    ("encode_secret", "-B", "--encode-secret", "VÄRDE",
     "base64-koda ett lösenord/secret för settings.json (utan värde: fråga dolt)", None),
]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nessus_cli.py",
        description="All-round CLI för Nessus Professional REST-API. Ange exakt en ÅTGÄRD. "
                    "SCAN = scan-id eller exakt scannamn.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)

    act = p.add_argument_group("Åtgärder (välj en)")
    mx = act.add_mutually_exclusive_group()
    for dest, short, long_, metavar, help_, _ in ACTIONS:
        if dest == "encode_secret":
            mx.add_argument(short, long_, dest=dest, nargs="?", const="", default=None, metavar=metavar, help=help_)
        elif metavar:
            mx.add_argument(short, long_, dest=dest, metavar=metavar, help=help_)
        else:
            mx.add_argument(short, long_, dest=dest, action="store_true", help=help_)

    g = p.add_argument_group("Scanparametrar (--create-scan / --launch)")
    g.add_argument("-t", "--targets", metavar="MÅL", help="kommaseparerade mål (IP, CIDR, intervall, hostnamn)")
    g.add_argument("-i", "--targets-file", metavar="FIL", help="fil med mål, ett eller flera per rad (# = kommentar)")
    g.add_argument("-m", "--template", metavar="MALL", help="mallnamn/titel/uuid, t.ex. basic, advanced, discovery")
    g.add_argument("-c", "--policy", metavar="POLICY", help="namn eller id på egen policy (istället för --template)")
    g.add_argument("-g", "--folder", metavar="MAPP", help="mappnamn eller id: mål för --create-scan, filter för --list-scans, "
                        "och avgör vilken scan som avses när samma namn finns i flera mappar")
    g.add_argument("-n", "--description", metavar="TEXT", help="beskrivning av scannen")
    g.add_argument("-l", "--launch-now", action="store_true", help="starta direkt efter --create-scan")
    g.add_argument("-a", "--alt-targets", metavar="MÅL", help="kör --launch mot andra mål än de sparade")
    g.add_argument("-w", "--wait", action="store_true", help="vänta tills scannen är klar")

    e = p.add_argument_group("Export (--export, eller efter --launch/--create-scan)")
    e.add_argument("-f", "--format", nargs="+", choices=EXPORT_FORMATS, metavar="FMT",
                   help=f"ett eller flera av: {', '.join(EXPORT_FORMATS)}. Med --launch/--create-scan: "
                        "vänta och exportera när scannen är klar")
    e.add_argument("-j", "--history-id", default="latest", metavar="ID",
                   help="'latest' (default), 'all' eller ett specifikt history_id")
    e.add_argument("-o", "--out", metavar="KATALOG", help="utkatalog (default export.output_dir)")
    e.add_argument("-e", "--report-template", metavar="MALL",
                   help="rapportmall för html/pdf: id eller namn (se -R). Går före export.template_id")

    o = p.add_argument_group("Allmänt")
    o.add_argument("-s", "--settings", metavar="FIL", default=os.environ.get("NESSUS_SETTINGS", "settings.json"),
                   help="settings-fil (default ./settings.json eller $NESSUS_SETTINGS)")
    o.add_argument("-k", "--insecure", action="store_true", help="hoppa över TLS-verifiering (labb)")
    o.add_argument("-r", "--raw", action="store_true", help="skriv rå JSON från API:t istället för tabeller")
    o.add_argument("-y", "--yes", action="store_true", help="fråga inte om bekräftelse (--delete)")
    o.add_argument("-d", "--debug", action="store_true",
                   help="all diagnostik: miljö, settings, alla HTTP-anrop med headers/body och svarstider "
                        "(hemligheter maskas)")
    o.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None) -> int:
    global DEBUG
    argv = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    if not argv:
        parser.print_help()
        return 0
    a = parser.parse_args(argv)
    DEBUG = a.debug
    debug_environment(argv)

    chosen = [x for x in ACTIONS if getattr(a, x[0]) not in (None, False)]
    if not chosen:
        parser.print_usage(sys.stderr)
        log("FEL: ange en åtgärd, t.ex. --list-scans eller --check-connection (se --help)", err=True)
        return 2
    dest, func = chosen[0][0], chosen[0][5]
    debug(f"Åtgärd: {dest}")

    if dest == "encode_secret":
        return act_encode_secret(a.encode_secret)

    client = None
    t0 = time.perf_counter()
    try:
        cfg = load_settings(a.settings)
        if a.insecure:
            cfg["verify_ssl"], cfg["ca_bundle"] = False, None
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        if dest == "check_connection":
            return check_connection(cfg)
        client = NessusClient(cfg)
        client.scan_folder = a.folder
        client.report_template_ref = a.report_template
        client.login()
        return func(client, a) or 0
    except NessusError as e:
        log(f"FEL: {e}", err=True)
        return 1
    except BrokenPipeError:  # t.ex. utdata pipad till head
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0
    except KeyboardInterrupt:
        log("\nAvbrutet av användaren (en startad scan fortsätter på servern).", err=True)
        return 130
    except Exception as e:
        log(f"Oväntat fel: {type(e).__name__}: {e}", err=True)
        if DEBUG:
            import traceback
            traceback.print_exc()
        else:
            log("Kör om med --debug för fullständig stacktrace.", err=True)
        return 1
    finally:
        if client:
            client.logout()
        debug(f"Total körtid: {time.perf_counter() - t0:.2f}s")


if __name__ == "__main__":
    sys.exit(main())
