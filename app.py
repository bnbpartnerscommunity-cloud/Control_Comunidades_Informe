# app.py
# -*- coding: utf-8 -*-
"""
Control Comunidades • Sheets (Service Account) + Drive (OAuth Mi Unidad)
- Usuarios/roles/comunidades en Google Sheets
- Fotos privadas en Drive (Mi Unidad) usando OAuth conectado SOLO por admin
- Informe Draft/Final
- Exporta PDF visual (3 columnas: categoría/instalación/tarea | estado+obs | foto)
- Guarda PDF final en Drive y registra el file_id en Sheets
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
import streamlit as st

# PDF
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet

# Crypto (token OAuth cifrado en Sheets)
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Google Auth for Service Account -> access token (Sheets)
from google.oauth2.service_account import Credentials as SACredentials


# -------------------------
# Config / Secrets
# -------------------------
st.set_page_config(page_title="Control Comunidades", page_icon="🛡️", layout="wide")

REQUIRED_SECRETS = [
    "GCP_SERVICE_ACCOUNT",
    "SHEET_ID",
    "APP_PEPPER",
    "BOOTSTRAP_ADMIN_EMAILS",
    "OAUTH_CLIENT_ID",
    "OAUTH_CLIENT_SECRET",
    "OAUTH_REDIRECT_URI",
]
missing = [k for k in REQUIRED_SECRETS if k not in st.secrets]
if missing:
    st.error(f"Faltan secrets: {', '.join(missing)}")
    st.stop()

SHEET_ID = st.secrets["SHEET_ID"]
APP_PEPPER = st.secrets["APP_PEPPER"]
BOOTSTRAP_ADMIN_EMAILS = set(
    x.strip().lower()
    for x in st.secrets["BOOTSTRAP_ADMIN_EMAILS"].split(",")
    if x.strip()
)

OAUTH_CLIENT_ID = st.secrets["OAUTH_CLIENT_ID"]
OAUTH_CLIENT_SECRET = st.secrets["OAUTH_CLIENT_SECRET"]
OAUTH_REDIRECT_URI = st.secrets["OAUTH_REDIRECT_URI"].rstrip("/")  # canonical
DRIVE_REPORTS_FOLDER_ID = st.secrets.get("DRIVE_REPORTS_FOLDER_ID", "").strip()  # optional; empty = raíz Mi unidad

INVITE_EXPIRY_HOURS = int(st.secrets.get("INVITE_EXPIRY_HOURS", "48"))

# scopes
SHEETS_SCOPE = "https://www.googleapis.com/auth/spreadsheets"
DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file"

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"


# -------------------------
# Schema (tabs/headers)
# -------------------------
TABS_HEADERS: Dict[str, List[str]] = {
    "AppConfig": ["key", "value"],
    "Users": ["email", "display_name", "is_admin", "active", "created_at"],
    "Invites": ["invite_code", "email", "created_by", "created_at", "expires_at", "used_at", "used_by"],
    "Communities": ["community_id", "name", "active", "created_at"],
    "Installations": ["installation_id", "community_id", "category", "name", "active", "created_at"],
    "Tasks": ["task_id", "community_id", "installation_id", "task", "active", "created_at"],
    "UserCommunityAccess": ["email", "community_id", "role", "can_create_reports", "can_view_summary", "active", "created_at"],
    "Reports": [
        "report_id", "community_id", "community_name",
        "status", "created_by_email", "created_at", "updated_at",
        "drive_pdf_file_id", "drive_pdf_filename",
    ],
    "ReportItems": [
        "report_id", "community_id",
        "installation_id", "installation_name", "category",
        "task_id", "task",
        "status", "note",
        "photo_drive_file_id", "photo_sha1",
        "updated_at",
    ],
}

CATEGORY_ORDER = ["Críticos", "Infraestructura", "Espacio Común", "Accesos", "Higiene", "Comunes", "Infra"]


# -------------------------
# Utils
# -------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()

def parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

def norm_email(s: str) -> str:
    return (s or "").strip().lower()

def is_bootstrap_admin(email: str) -> bool:
    return norm_email(email) in BOOTSTRAP_ADMIN_EMAILS


# -------------------------
# Backoff for HTTP
# -------------------------
def _sleep_backoff(attempt: int) -> None:
    base = 0.7 * (2 ** (attempt - 1))
    jitter = secrets.randbelow(250) / 1000.0
    time.sleep(min(base + jitter, 10.0))

def request_with_backoff(
    method: str,
    url: str,
    *,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    json_body: Any = None,
    data: Any = None,
    timeout: int = 60,
    max_attempts: int = 8,
) -> requests.Response:
    for attempt in range(1, max_attempts + 1):
        resp = requests.request(
            method,
            url,
            headers=headers,
            params=params,
            json=json_body,
            data=data,
            timeout=timeout,
        )
        if resp.status_code in (429, 500, 502, 503, 504):
            _sleep_backoff(attempt)
            continue
        return resp
    return resp


# -------------------------
# Sheets (Service Account) via REST
# -------------------------
@st.cache_resource(show_spinner=False)
def _sa_creds() -> SACredentials:
    # Expect GCP_SERVICE_ACCOUNT as JSON string in secrets
    sa_raw = st.secrets["GCP_SERVICE_ACCOUNT"]
    if isinstance(sa_raw, str):
        info = json.loads(sa_raw)
    else:
        info = dict(sa_raw)
    return SACredentials.from_service_account_info(info, scopes=[SHEETS_SCOPE])

@st.cache_data(ttl=45 * 60, show_spinner=False)
def _sa_access_token() -> str:
    creds = _sa_creds()
    # google-auth refresh mechanism
    from google.auth.transport.requests import Request as GARequest
    creds.refresh(GARequest())
    return creds.token

def sheets_api_headers() -> dict:
    return {"Authorization": f"Bearer {_sa_access_token()}"}

def sheets_url(path: str) -> str:
    return f"https://sheets.googleapis.com/v4/spreadsheets/{SHEET_ID}{path}"

def sheets_get_meta() -> dict:
    resp = request_with_backoff("GET", sheets_url(""), headers=sheets_api_headers(), params={"fields": "sheets(properties(title))"})
    if resp.status_code >= 400:
        raise RuntimeError(f"Google Sheets meta error {resp.status_code}: {resp.text}")
    return resp.json()

def sheets_batch_update(body: dict) -> dict:
    resp = request_with_backoff("POST", sheets_url(":batchUpdate"), headers={**sheets_api_headers(), "Content-Type": "application/json"}, json_body=body)
    if resp.status_code >= 400:
        raise RuntimeError(f"Google Sheets batchUpdate error {resp.status_code}: {resp.text}")
    return resp.json()

def sheets_values_get(a1: str) -> List[List[str]]:
    enc = requests.utils.quote(a1, safe="!:'(),-._~")
    resp = request_with_backoff("GET", sheets_url(f"/values/{enc}"), headers=sheets_api_headers())
    if resp.status_code >= 400:
        raise RuntimeError(f"Google Sheets values.get error {resp.status_code}: {resp.text}")
    return resp.json().get("values", [])

def sheets_values_update(a1: str, values: List[List[Any]]) -> None:
    enc = requests.utils.quote(a1, safe="!:'(),-._~")
    body = {"range": a1, "majorDimension": "ROWS", "values": values}
    resp = request_with_backoff(
        "PUT",
        sheets_url(f"/values/{enc}"),
        headers={**sheets_api_headers(), "Content-Type": "application/json"},
        params={"valueInputOption": "RAW"},
        json_body=body,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"Google Sheets values.update error {resp.status_code}: {resp.text}")

def sheets_values_append(tab: str, values: List[List[Any]]) -> None:
    a1 = f"{tab}!A1"
    enc = requests.utils.quote(a1, safe="!:'(),-._~")
    body = {"range": a1, "majorDimension": "ROWS", "values": values}
    resp = request_with_backoff(
        "POST",
        sheets_url(f"/values/{enc}:append"),
        headers={**sheets_api_headers(), "Content-Type": "application/json"},
        params={"valueInputOption": "RAW", "insertDataOption": "INSERT_ROWS"},
        json_body=body,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"Google Sheets values.append error {resp.status_code}: {resp.text}")

def ensure_tabs_and_headers(force_reset: bool = False) -> None:
    meta = sheets_get_meta()
    existing = set(s["properties"]["title"] for s in meta.get("sheets", []))

    requests_list = []

    # create missing tabs
    for tab, headers in TABS_HEADERS.items():
        if tab not in existing:
            requests_list.append({"addSheet": {"properties": {"title": tab}}})

    if requests_list:
        sheets_batch_update({"requests": requests_list})
        st.cache_data.clear()

    # ensure headers (and optional reset)
    for tab, headers in TABS_HEADERS.items():
        if force_reset:
            # Clear entire sheet then write header
            sheets_values_update(f"{tab}!A1:Z", [])
            sheets_values_update(f"{tab}!A1:{chr(64+len(headers))}1", [headers])
        else:
            row1 = sheets_values_get(f"{tab}!A1:Z1")
            if not row1 or row1[0] != headers:
                # overwrite header only (keeps data, but mismatch can break logic; for testing, overwrite)
                sheets_values_update(f"{tab}!A1:{chr(64+len(headers))}1", [headers])


def read_table(tab: str) -> Tuple[List[str], List[Dict[str, str]]]:
    values = sheets_values_get(f"{tab}!A1:Z")
    if not values:
        return TABS_HEADERS[tab], []
    headers = values[0]
    rows = []
    for r in values[1:]:
        row = {headers[i]: (r[i] if i < len(r) else "") for i in range(len(headers))}
        rows.append(row)
    return headers, rows

def write_table(tab: str, headers: List[str], rows: List[Dict[str, Any]]) -> None:
    out = [headers]
    for row in rows:
        out.append([row.get(h, "") for h in headers])
    sheets_values_update(f"{tab}!A1:{chr(64+len(headers))}{len(out)}", out)


# -------------------------
# Crypto for storing OAuth token in Sheets (AppConfig)
# -------------------------
def _derive_fernet_key(pepper: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend(),
    )
    key = kdf.derive(pepper.encode("utf-8"))
    return base64.urlsafe_b64encode(key)

def encrypt_text(plain: str) -> str:
    salt = secrets.token_bytes(16)
    fkey = _derive_fernet_key(APP_PEPPER, salt)
    f = Fernet(fkey)
    ct = f.encrypt(plain.encode("utf-8"))
    payload = {"salt": base64.b64encode(salt).decode("utf-8"), "ct": ct.decode("utf-8")}
    return json.dumps(payload)

def decrypt_text(cipher_json: str) -> str:
    payload = json.loads(cipher_json)
    salt = base64.b64decode(payload["salt"])
    ct = payload["ct"].encode("utf-8")
    fkey = _derive_fernet_key(APP_PEPPER, salt)
    f = Fernet(fkey)
    pt = f.decrypt(ct)
    return pt.decode("utf-8")


# -------------------------
# AppConfig helpers
# -------------------------
def appconfig_get(key: str) -> Optional[str]:
    _, rows = read_table("AppConfig")
    for r in rows:
        if r.get("key") == key:
            return r.get("value") or ""
    return None

def appconfig_set(key: str, value: str) -> None:
    headers, rows = read_table("AppConfig")
    found = False
    for r in rows:
        if r.get("key") == key:
            r["value"] = value
            found = True
            break
    if not found:
        rows.append({"key": key, "value": value})
    write_table("AppConfig", headers, rows)


# -------------------------
# OAuth Drive (Mi unidad) – token stored encrypted in Sheets
# -------------------------
def build_oauth_auth_url(state: str) -> str:
    params = {
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": DRIVE_SCOPE,
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    return requests.Request("GET", GOOGLE_AUTH_URL, params=params).prepare().url

def exchange_code_for_token(code: str) -> dict:
    data = {
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "grant_type": "authorization_code",
        "code": code,
    }
    resp = request_with_backoff("POST", GOOGLE_TOKEN_URL, data=data, timeout=30)
    if resp.status_code >= 400:
        raise RuntimeError(f"OAuth token exchange error {resp.status_code}: {resp.text}")
    return resp.json()

def refresh_access_token(refresh_token: str) -> dict:
    data = {
        "client_id": OAUTH_CLIENT_ID,
        "client_secret": OAUTH_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    resp = request_with_backoff("POST", GOOGLE_TOKEN_URL, data=data, timeout=30)
    if resp.status_code >= 400:
        raise RuntimeError(f"OAuth refresh error {resp.status_code}: {resp.text}")
    return resp.json()

def get_drive_token() -> Optional[dict]:
    enc = appconfig_get("DRIVE_OAUTH_TOKEN")
    if not enc:
        return None
    raw = decrypt_text(enc)
    return json.loads(raw)

def save_drive_token(token: dict) -> None:
    enc = encrypt_text(json.dumps(token))
    appconfig_set("DRIVE_OAUTH_TOKEN", enc)

def ensure_valid_access_token(token: dict) -> dict:
    # token fields: access_token, refresh_token, expires_in, created_at
    now = int(time.time())
    created_at = int(token.get("created_at", now))
    expires_in = int(token.get("expires_in", 0))
    if token.get("access_token") and (now < created_at + expires_in - 60):
        return token

    rt = token.get("refresh_token")
    if not rt:
        return {}
    refreshed = refresh_access_token(rt)
    token["access_token"] = refreshed["access_token"]
    token["expires_in"] = refreshed.get("expires_in", 3600)
    token["created_at"] = int(time.time())
    save_drive_token(token)
    return token

def drive_headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}

def drive_files_create(access_token: str, metadata: dict, media: Optional[bytes] = None, mime: Optional[str] = None) -> dict:
    if media is None:
        resp = request_with_backoff(
            "POST",
            "https://www.googleapis.com/drive/v3/files",
            headers={**drive_headers(access_token), "Content-Type": "application/json"},
            params={"fields": "id,name,webViewLink"},
            json_body=metadata,
            timeout=60,
        )
        if resp.status_code >= 400:
            raise RuntimeError(f"Drive create error {resp.status_code}: {resp.text}")
        return resp.json()

    boundary = "===============" + secrets.token_hex(12)
    delimiter = f"\r\n--{boundary}\r\n"
    close_delim = f"\r\n--{boundary}--\r\n"

    body = (
        delimiter
        + "Content-Type: application/json; charset=UTF-8\r\n\r\n"
        + json.dumps(metadata)
        + delimiter
        + f"Content-Type: {mime or 'application/octet-stream'}\r\n\r\n"
    ).encode("utf-8") + media + close_delim.encode("utf-8")

    headers = {
        **drive_headers(access_token),
        "Content-Type": f"multipart/related; boundary={boundary}",
    }
    resp = request_with_backoff(
        "POST",
        "https://www.googleapis.com/upload/drive/v3/files",
        headers=headers,
        params={"uploadType": "multipart", "fields": "id,name,webViewLink"},
        data=body,
        timeout=60,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"Drive upload error {resp.status_code}: {resp.text}")
    return resp.json()

def drive_files_get_media(access_token: str, file_id: str) -> bytes:
    resp = request_with_backoff(
        "GET",
        f"https://www.googleapis.com/drive/v3/files/{file_id}",
        headers=drive_headers(access_token),
        params={"alt": "media"},
        timeout=60,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"Drive download error {resp.status_code}: {resp.text}")
    return resp.content

def drive_find_folder(access_token: str, parent_id: str, name: str) -> Optional[str]:
    safe_name = (name or "").replace("'", "\\'")
    q = (
        "mimeType='application/vnd.google-apps.folder' and "
        f"name='{safe_name}' and trashed=false and "
        f"'{parent_id}' in parents"
    )
    resp = request_with_backoff(
        "GET",
        "https://www.googleapis.com/drive/v3/files",
        headers=drive_headers(access_token),
        params={"q": q, "fields": "files(id,name)"},
        timeout=60,
    )
    if resp.status_code >= 400:
        raise RuntimeError(f"Drive list error {resp.status_code}: {resp.text}")
    files = resp.json().get("files", [])
    return files[0]["id"] if files else None

def drive_ensure_folder(access_token: str, parent_id: str, name: str) -> str:
    fid = drive_find_folder(access_token, parent_id, name)
    if fid:
        return fid
    meta = {
        "name": name,
        "mimeType": "application/vnd.google-apps.folder",
        "parents": [parent_id] if parent_id else [],
    }
    created = drive_files_create(access_token, meta)
    return created["id"]


# -------------------------
# Auth (simple): email + invite code
# -------------------------
def user_get(email: str) -> Optional[dict]:
    _, users = read_table("Users")
    em = norm_email(email)
    for u in users:
        if norm_email(u.get("email", "")) == em and u.get("active", "true").lower() == "true":
            return u
    return None

def user_is_admin(email: str) -> bool:
    u = user_get(email)
    if u and u.get("is_admin", "").lower() == "true":
        return True
    return is_bootstrap_admin(email)

def ensure_bootstrap_users() -> None:
    headers, users = read_table("Users")
    existing = {norm_email(u.get("email", "")) for u in users}
    for em in BOOTSTRAP_ADMIN_EMAILS:
        if em not in existing:
            users.append({
                "email": em,
                "display_name": em.split("@")[0],
                "is_admin": "true",
                "active": "true",
                "created_at": iso(now_utc()),
            })
    write_table("Users", headers, users)

def invite_create(target_email: str, created_by: str) -> str:
    code = secrets.token_urlsafe(10).replace("-", "").replace("_", "")[:12]
    created_at = now_utc()
    expires_at = created_at + timedelta(hours=INVITE_EXPIRY_HOURS)
    _, inv = read_table("Invites")
    inv.append({
        "invite_code": code,
        "email": norm_email(target_email),
        "created_by": norm_email(created_by),
        "created_at": iso(created_at),
        "expires_at": iso(expires_at),
        "used_at": "",
        "used_by": "",
    })
    write_table("Invites", TABS_HEADERS["Invites"], inv)
    return code

def invite_use(email: str, code: str) -> bool:
    headers, inv = read_table("Invites")
    em = norm_email(email)
    code = (code or "").strip()
    now = now_utc()
    changed = False
    ok = False
    for r in inv:
        if r.get("invite_code") == code and norm_email(r.get("email", "")) == em:
            # verify unused + not expired
            if r.get("used_at"):
                break
            exp = r.get("expires_at") or ""
            if exp:
                if now > parse_iso(exp):
                    break
            r["used_at"] = iso(now)
            r["used_by"] = em
            changed = True
            ok = True
            break
    if changed:
        write_table("Invites", headers, inv)
    return ok

def ensure_user_exists(email: str, display_name: str = "") -> None:
    headers, users = read_table("Users")
    em = norm_email(email)
    for u in users:
        if norm_email(u.get("email", "")) == em:
            # reactivate if needed
            if u.get("active", "true").lower() != "true":
                u["active"] = "true"
                write_table("Users", headers, users)
            return
    users.append({
        "email": em,
        "display_name": display_name or em.split("@")[0],
        "is_admin": "false",
        "active": "true",
        "created_at": iso(now_utc()),
    })
    write_table("Users", headers, users)


# -------------------------
# Access / communities
# -------------------------
def list_communities(active_only: bool = True) -> List[dict]:
    _, comms = read_table("Communities")
    if active_only:
        return [c for c in comms if c.get("active", "true").lower() == "true"]
    return comms

def community_create(name: str) -> str:
    cid = "C_" + secrets.token_hex(6)
    headers, comms = read_table("Communities")
    comms.append({
        "community_id": cid,
        "name": name.strip(),
        "active": "true",
        "created_at": iso(now_utc()),
    })
    write_table("Communities", headers, comms)
    return cid

def community_delete(cid: str) -> None:
    # Hard delete test-mode: deletes related rows (Sheets). Does NOT delete Drive assets.
    # Communities
    h, comms = read_table("Communities")
    comms = [c for c in comms if c.get("community_id") != cid]
    write_table("Communities", h, comms)

    # Installations
    h, inst = read_table("Installations")
    inst = [i for i in inst if i.get("community_id") != cid]
    write_table("Installations", h, inst)

    # Tasks
    h, tsk = read_table("Tasks")
    tsk = [t for t in tsk if t.get("community_id") != cid]
    write_table("Tasks", h, tsk)

    # Reports & ReportItems
    h, reports = read_table("Reports")
    report_ids = {r.get("report_id") for r in reports if r.get("community_id") == cid}
    reports = [r for r in reports if r.get("community_id") != cid]
    write_table("Reports", h, reports)

    h, items = read_table("ReportItems")
    items = [x for x in items if x.get("community_id") != cid and x.get("report_id") not in report_ids]
    write_table("ReportItems", h, items)

    # Access
    h, acc = read_table("UserCommunityAccess")
    acc = [a for a in acc if a.get("community_id") != cid]
    write_table("UserCommunityAccess", h, acc)

def access_list_for_user(email: str) -> List[dict]:
    _, acc = read_table("UserCommunityAccess")
    em = norm_email(email)
    rows = [a for a in acc if norm_email(a.get("email", "")) == em and a.get("active", "true").lower() == "true"]
    return rows

def user_allowed_communities(email: str) -> List[str]:
    if user_is_admin(email):
        return [c["community_id"] for c in list_communities(active_only=True)]
    return [a["community_id"] for a in access_list_for_user(email)]

def set_user_access(email: str, community_id: str, role: str, can_create_reports: bool, can_view_summary: bool, active: bool = True) -> None:
    headers, acc = read_table("UserCommunityAccess")
    em = norm_email(email)
    found = False
    for a in acc:
        if norm_email(a.get("email", "")) == em and a.get("community_id") == community_id:
            a["role"] = role
            a["can_create_reports"] = "true" if can_create_reports else "false"
            a["can_view_summary"] = "true" if can_view_summary else "false"
            a["active"] = "true" if active else "false"
            a["created_at"] = a.get("created_at") or iso(now_utc())
            found = True
            break
    if not found:
        acc.append({
            "email": em,
            "community_id": community_id,
            "role": role,
            "can_create_reports": "true" if can_create_reports else "false",
            "can_view_summary": "true" if can_view_summary else "false",
            "active": "true" if active else "false",
            "created_at": iso(now_utc()),
        })
    write_table("UserCommunityAccess", headers, acc)


# -------------------------
# Installations + Tasks (admin configured per community)
# -------------------------
def installations_for_community(cid: str) -> List[dict]:
    _, inst = read_table("Installations")
    return [i for i in inst if i.get("community_id") == cid and i.get("active", "true").lower() == "true"]

def tasks_for_community(cid: str) -> List[dict]:
    _, tsk = read_table("Tasks")
    return [t for t in tsk if t.get("community_id") == cid and t.get("active", "true").lower() == "true"]

def installation_add(cid: str, category: str, name: str) -> str:
    iid = "I_" + secrets.token_hex(6)
    headers, inst = read_table("Installations")
    inst.append({
        "installation_id": iid,
        "community_id": cid,
        "category": category.strip(),
        "name": name.strip(),
        "active": "true",
        "created_at": iso(now_utc()),
    })
    write_table("Installations", headers, inst)
    return iid

def installation_deactivate(iid: str) -> None:
    headers, inst = read_table("Installations")
    for i in inst:
        if i.get("installation_id") == iid:
            i["active"] = "false"
            break
    write_table("Installations", headers, inst)

def task_add(cid: str, installation_id: str, task: str) -> str:
    tid = "T_" + secrets.token_hex(6)
    headers, tsk = read_table("Tasks")
    tsk.append({
        "task_id": tid,
        "community_id": cid,
        "installation_id": installation_id,
        "task": task.strip(),
        "active": "true",
        "created_at": iso(now_utc()),
    })
    write_table("Tasks", headers, tsk)
    return tid

def task_deactivate(tid: str) -> None:
    headers, tsk = read_table("Tasks")
    for t in tsk:
        if t.get("task_id") == tid:
            t["active"] = "false"
            break
    write_table("Tasks", headers, tsk)


# -------------------------
# Reports
# -------------------------
def reports_for_community(cid: str) -> List[dict]:
    _, reps = read_table("Reports")
    reps = [r for r in reps if r.get("community_id") == cid]
    reps.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return reps

def report_get(report_id: str) -> Optional[dict]:
    _, reps = read_table("Reports")
    for r in reps:
        if r.get("report_id") == report_id:
            return r
    return None

def report_create(cid: str, cname: str, created_by: str) -> str:
    rid = "R_" + datetime.utcnow().strftime("%Y%m%d_%H%M%S") + "_" + secrets.token_hex(3)
    headers, reps = read_table("Reports")
    reps.append({
        "report_id": rid,
        "community_id": cid,
        "community_name": cname,
        "status": "Draft",
        "created_by_email": norm_email(created_by),
        "created_at": iso(now_utc()),
        "updated_at": iso(now_utc()),
        "drive_pdf_file_id": "",
        "drive_pdf_filename": "",
    })
    write_table("Reports", headers, reps)

    # seed ReportItems from configured installations + tasks
    inst = installations_for_community(cid)
    tsk = tasks_for_community(cid)
    inst_by_id = {i["installation_id"]: i for i in inst}
    tasks_by_inst: Dict[str, List[dict]] = {}
    for t in tsk:
        tasks_by_inst.setdefault(t["installation_id"], []).append(t)

    # Create items rows
    headers_i, items = read_table("ReportItems")
    for i in inst:
        its = tasks_by_inst.get(i["installation_id"], [])
        if not its:
            # allow 1 default task row if none configured
            items.append({
                "report_id": rid,
                "community_id": cid,
                "installation_id": i["installation_id"],
                "installation_name": i["name"],
                "category": i["category"] or "",
                "task_id": "",
                "task": "",
                "status": "pending",
                "note": "",
                "photo_drive_file_id": "",
                "photo_sha1": "",
                "updated_at": iso(now_utc()),
            })
        else:
            for t in its:
                items.append({
                    "report_id": rid,
                    "community_id": cid,
                    "installation_id": i["installation_id"],
                    "installation_name": i["name"],
                    "category": i["category"] or "",
                    "task_id": t["task_id"],
                    "task": t["task"],
                    "status": "pending",
                    "note": "",
                    "photo_drive_file_id": "",
                    "photo_sha1": "",
                    "updated_at": iso(now_utc()),
                })
    write_table("ReportItems", headers_i, items)
    return rid

def report_set_status(report_id: str, status: str) -> None:
    headers, reps = read_table("Reports")
    for r in reps:
        if r.get("report_id") == report_id:
            r["status"] = status
            r["updated_at"] = iso(now_utc())
            break
    write_table("Reports", headers, reps)

def report_set_pdf(report_id: str, file_id: str, filename: str) -> None:
    headers, reps = read_table("Reports")
    for r in reps:
        if r.get("report_id") == report_id:
            r["drive_pdf_file_id"] = file_id
            r["drive_pdf_filename"] = filename
            r["updated_at"] = iso(now_utc())
            break
    write_table("Reports", headers, reps)

def reportitems_for_report(report_id: str) -> List[dict]:
    _, items = read_table("ReportItems")
    rows = [x for x in items if x.get("report_id") == report_id]
    # stable order: category -> installation -> task
    def keyf(x: dict) -> tuple:
        cat = x.get("category", "")
        inst = x.get("installation_name", "")
        task = x.get("task", "")
        return (cat, inst, task)
    rows.sort(key=keyf)
    return rows

def reportitem_update(report_id: str, installation_id: str, task_id: str, status: str, note: str,
                      photo_drive_file_id: str = "", photo_sha1: str = "") -> None:
    headers, items = read_table("ReportItems")
    changed = False
    for x in items:
        if x.get("report_id") == report_id and x.get("installation_id") == installation_id and (x.get("task_id") or "") == (task_id or ""):
            x["status"] = status
            x["note"] = note
            if photo_drive_file_id:
                x["photo_drive_file_id"] = photo_drive_file_id
            if photo_sha1:
                x["photo_sha1"] = photo_sha1
            x["updated_at"] = iso(now_utc())
            changed = True
            break
    if changed:
        write_table("ReportItems", headers, items)


# -------------------------
# Drive storage structure (private): Root/Communities/<cid>/Reports/<rid>/(photos,pdfs)
# -------------------------
def get_drive_access_token_or_raise() -> str:
    token = get_drive_token()
    if not token:
        raise RuntimeError("Drive no está conectado. Conecta Drive desde Admin (bnbpartnerscommunity).")
    token = ensure_valid_access_token(token)
    access = token.get("access_token")
    if not access:
        raise RuntimeError("Token Drive inválido. Re-conecta Drive desde Admin.")
    return access

def drive_root_folder(access_token: str) -> str:
    # If DRIVE_REPORTS_FOLDER_ID provided, use it; else use "root"
    return DRIVE_REPORTS_FOLDER_ID if DRIVE_REPORTS_FOLDER_ID else "root"

def drive_paths_for_report(access_token: str, community_id: str, report_id: str) -> Tuple[str, str]:
    root = drive_root_folder(access_token)
    comms = drive_ensure_folder(access_token, root, "Communities")
    cfold = drive_ensure_folder(access_token, comms, community_id)
    reps = drive_ensure_folder(access_token, cfold, "Reports")
    rfold = drive_ensure_folder(access_token, reps, report_id)
    photos = drive_ensure_folder(access_token, rfold, "photos")
    pdfs = drive_ensure_folder(access_token, rfold, "pdfs")
    return photos, pdfs

def upload_photo_private(access_token: str, photos_folder_id: str, filename: str, mime: str, data: bytes) -> str:
    meta = {"name": filename, "parents": [photos_folder_id]}
    created = drive_files_create(access_token, meta, media=data, mime=mime)
    return created["id"]

def upload_pdf_private(access_token: str, pdfs_folder_id: str, filename: str, data: bytes) -> str:
    meta = {"name": filename, "parents": [pdfs_folder_id]}
    created = drive_files_create(access_token, meta, media=data, mime="application/pdf")
    return created["id"]


# -------------------------
# PDF export (3 columns visual)
# -------------------------
def status_badge(status: str) -> str:
    s = (status or "").lower()
    if s == "ok":
        return "OK"
    if s == "fail":
        return "FALLA"
    return "PEND."

def status_color_bg(status: str):
    s = (status or "").lower()
    if s == "fail":
        return colors.Color(1, 0.9, 0.9)  # soft red
    if s == "ok":
        return colors.Color(0.92, 0.98, 0.92)  # soft green
    return colors.whitesmoke

def build_pdf_bytes(
    *,
    community_name: str,
    report_id: str,
    created_by: str,
    created_at_iso: str,
    items: List[dict],
    drive_access_token: str,
) -> bytes:
    # counts
    okc = sum(1 for i in items if (i.get("status") or "").lower() == "ok")
    failc = sum(1 for i in items if (i.get("status") or "").lower() == "fail")
    pendc = sum(1 for i in items if (i.get("status") or "").lower() == "pending")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title=f"Informe {community_name} {report_id}",
        author="Control Comunidades",
    )

    styles = getSampleStyleSheet()
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    normal = styles["BodyText"]

    story = []
    story.append(Paragraph(f"🛡️ <b>Informe de Inspección</b> — {community_name}", h1))
    story.append(Paragraph(f"<b>ID:</b> {report_id} &nbsp;&nbsp; <b>Creado por:</b> {created_by} &nbsp;&nbsp; <b>Fecha:</b> {created_at_iso}", normal))
    story.append(Spacer(1, 6 * mm))

    # summary cards (simple table)
    summary = [
        ["Sistemas OK", str(okc), "Fallas", str(failc), "Pend.", str(pendc)]
    ]
    t = Table(summary, colWidths=[30*mm, 15*mm, 25*mm, 15*mm, 18*mm, 15*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (1,0), colors.Color(0.92, 0.98, 0.92)),
        ("BACKGROUND", (2,0), (3,0), colors.Color(1, 0.9, 0.9)),
        ("BACKGROUND", (4,0), (5,0), colors.whitesmoke),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("ALIGN", (1,0), (1,0), "CENTER"),
        ("ALIGN", (3,0), (3,0), "CENTER"),
        ("ALIGN", (5,0), (5,0), "CENTER"),
        ("BOX", (0,0), (-1,0), 0.6, colors.lightgrey),
        ("INNERGRID", (0,0), (-1,0), 0.6, colors.lightgrey),
        ("VALIGN", (0,0), (-1,0), "MIDDLE"),
    ]))
    story.append(t)
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("Checklist Técnico (Categoría / Instalación / Tarea)", h2))
    story.append(Spacer(1, 3 * mm))

    # group by category
    def cat_rank(cat: str) -> int:
        if cat in CATEGORY_ORDER:
            return CATEGORY_ORDER.index(cat)
        return 999

    items_sorted = sorted(items, key=lambda x: (cat_rank(x.get("category","")), x.get("category",""), x.get("installation_name",""), x.get("task","")))

    # build rows for table 3 columns
    data_rows = []
    # header row
    data_rows.append(["Categoría / Instalación / Tarea", "Estado y observación", "Foto"])

    # photo sizing
    max_w = 55 * mm
    max_h = 32 * mm

    for it in items_sorted:
        cat = it.get("category", "")
        inst = it.get("installation_name", "")
        task = it.get("task", "") or "(Sin tarea)"
        status = it.get("status", "pending")
        note = it.get("note", "") or ""
        badge = status_badge(status)

        left_txt = f"<b>{cat}</b><br/>{inst}<br/><font size=9>{task}</font>"
        mid_txt = f"<b>{badge}</b><br/><font size=9>{note or 'Sin observaciones.'}</font>"

        # photo cell
        img_flow = ""
        pid = it.get("photo_drive_file_id", "")
        if pid:
            try:
                img_bytes = drive_files_get_media(drive_access_token, pid)
                img_buf = io.BytesIO(img_bytes)
                rlimg = RLImage(img_buf)
                rlimg._restrictSize(max_w, max_h)
                img_flow = rlimg
            except Exception:
                img_flow = Paragraph("<font size=8 color='grey'>(Foto no disponible)</font>", normal)
        else:
            img_flow = Paragraph("<font size=8 color='grey'>(Sin foto)</font>", normal)

        data_rows.append([Paragraph(left_txt, normal), Paragraph(mid_txt, normal), img_flow])

    table = Table(
        data_rows,
        colWidths=[80*mm, 60*mm, 55*mm],
        repeatRows=1
    )
    # style with soft-red background for FAIL rows
    ts = [
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("BACKGROUND", (0,0), (-1,0), colors.Color(0.95,0.95,0.98)),
        ("BOX", (0,0), (-1,-1), 0.6, colors.lightgrey),
        ("INNERGRID", (0,0), (-1,-1), 0.4, colors.lightgrey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("ALIGN", (2,1), (2,-1), "CENTER"),
    ]

    # row backgrounds by status
    for row_idx in range(1, len(data_rows)):
        stval = (items_sorted[row_idx-1].get("status") or "pending").lower()
        bg = status_color_bg(stval)
        ts.append(("BACKGROUND", (0,row_idx), (-1,row_idx), bg))

    table.setStyle(TableStyle(ts))
    story.append(table)
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph("<font size=8 color='grey'>Documento generado por Control Comunidades • PDF privado en Drive (Mi unidad).</font>", normal))

    doc.build(story)
    return buf.getvalue()


# -------------------------
# UI pieces
# -------------------------
def ui_drive_connect_admin(current_user: str) -> None:
    st.subheader("🔌 Conectar Drive (Mi unidad) — Solo Admin")
    if not user_is_admin(current_user) or not is_bootstrap_admin(current_user):
        st.info("Solo admins bootstrap pueden conectar Drive (bnbpartnerscommunity, etc.).")
        return

    token = get_drive_token()
    if token:
        token2 = ensure_valid_access_token(token)
        if token2.get("access_token"):
            st.success("Drive ya está conectado ✅")
        else:
            st.warning("Hay token guardado pero inválido. Re-conecta.")
    else:
        st.warning("Drive NO está conectado aún.")

    q = st.query_params
    code = q.get("code")
    if code:
        try:
            tok = exchange_code_for_token(code)
            tok["created_at"] = int(time.time())
            save_drive_token(tok)
            st.success("Conexión Drive exitosa ✅ (token cifrado guardado en Sheets/AppConfig)")
            st.query_params.clear()
            st.rerun()
        except Exception as e:
            st.error("Error al conectar Drive.")
            st.exception(e)
            return

    st.caption("Inicia sesión con bnbpartnerscommunity y autoriza. Esto habilita subir fotos y PDFs a Mi unidad de esa cuenta.")
    state = secrets.token_urlsafe(16)
    st.link_button("Conectar Drive con bnbpartnerscommunity", build_oauth_auth_url(state))


def ui_access_gate() -> Tuple[str, bool]:
    st.title("🛡️ Control Comunidades — Acceso")

    with st.expander("¿Qué debo ingresar?", expanded=True):
        st.write(
            "- **Email**: tu correo (cualquiera). \n"
            "- Si eres **usuario nuevo**, debes tener un **código de invitación** (lo crea un admin).\n"
            "- Si ya estás registrado, entras solo con tu email.\n"
        )

    email = st.text_input("Tu email", placeholder="tu.nombre@empresa.com").strip()
    invite_code = st.text_input("Código de invitación (solo si eres nuevo)", placeholder="Ej: AbC123...").strip()

    login = st.button("Entrar", type="primary", use_container_width=True)
    if not login:
        return "", False

    if not email or "@" not in email:
        st.error("Ingresa un email válido.")
        return "", False

    em = norm_email(email)

    # bootstrap always allowed and created
    if is_bootstrap_admin(em):
        ensure_user_exists(em, display_name=em.split("@")[0])
        st.session_state["user_email"] = em
        return em, True

    # existing user?
    u = user_get(em)
    if u:
        st.session_state["user_email"] = em
        return em, True

    # new user: must have valid invite
    if not invite_code:
        st.error("Usuario nuevo: necesitas un código de invitación.")
        return "", False

    if not invite_use(em, invite_code):
        st.error("Código inválido / expirado / ya usado.")
        return "", False

    ensure_user_exists(em, display_name=em.split("@")[0])
    st.session_state["user_email"] = em
    st.success("Registro exitoso ✅")
    return em, True


def ui_admin_users(current_user: str) -> None:
    st.header("👤 Módulo Usuarios (Admin)")

    # Create invite (and user)
    st.subheader("Invitar / registrar usuario")
    with st.form("invite_form", clear_on_submit=True):
        target = st.text_input("Email del usuario", placeholder="usuario@dominio.com")
        display_name = st.text_input("Nombre (opcional)", placeholder="Juan Pérez")
        make_admin = st.checkbox("Marcar como administrador", value=False)
        create = st.form_submit_button("Crear invitación", type="primary")
        if create:
            if not target or "@" not in target:
                st.error("Email inválido.")
            else:
                tgt = norm_email(target)
                # create invite
                code = invite_create(tgt, current_user)
                ensure_user_exists(tgt, display_name=display_name.strip() if display_name else "")
                # set admin flag if requested
                if make_admin:
                    h, users = read_table("Users")
                    for u in users:
                        if norm_email(u.get("email","")) == tgt:
                            u["is_admin"] = "true"
                            break
                    write_table("Users", h, users)
                st.success("Invitación creada ✅ Copia el código y envíaselo al usuario.")
                st.code(code)

    st.divider()

    # Assign access
    st.subheader("Asignar comunidades y permisos")
    _, users = read_table("Users")
    users = [u for u in users if u.get("active", "true").lower() == "true"]
    user_emails = [u["email"] for u in users]
    pick = st.selectbox("Selecciona usuario", options=user_emails)

    is_admin_flag = (norm_email(pick) in BOOTSTRAP_ADMIN_EMAILS) or (user_get(pick) and user_get(pick).get("is_admin","").lower()=="true")
    st.caption(f"Admin: {'sí' if is_admin_flag else 'no'}")

    comms = list_communities(active_only=True)
    comm_options = {f"{c['name']} ({c['community_id']})": c["community_id"] for c in comms}
    selected = st.multiselect("Comunidades asignadas", options=list(comm_options.keys()))

    if is_admin_flag:
        st.info("Usuario admin: permisos completos (crear informes + ver resumen).")
        role = "admin"
        can_create = True
        can_view = True
    else:
        role = st.selectbox("Rol (informativo)", options=["Supervisor", "Mantenedor", "Analista Interno", "Conserje", "Viewer"], index=0)
        can_create = st.checkbox("Permiso: crear informes (Módulo Informes)", value=True)
        can_view = st.checkbox("Permiso: ver resumen (Módulo Resumen)", value=True)

    if st.button("Guardar asignaciones", type="primary"):
        # deactivate all user access first (non-admin) then set selected active
        # (admins can also be restricted by selection if you want; here we set selected too)
        h, acc = read_table("UserCommunityAccess")
        for a in acc:
            if norm_email(a.get("email","")) == norm_email(pick):
                a["active"] = "false"
        write_table("UserCommunityAccess", h, acc)

        for label in selected:
            cid = comm_options[label]
            set_user_access(pick, cid, role, can_create, can_view, active=True)
        st.success("Permisos guardados ✅")
        st.rerun()

    st.divider()

    # Delete user (hard)
    st.subheader("🗑️ Eliminar usuario definitivamente")
    non_bootstrap = [u for u in users if norm_email(u["email"]) not in BOOTSTRAP_ADMIN_EMAILS]
    if not non_bootstrap:
        st.info("No hay usuarios eliminables (solo bootstrap).")
    else:
        tgt = st.selectbox("Usuario a eliminar", options=[u["email"] for u in non_bootstrap])
        confirm = st.text_input("Escribe ELIMINAR para confirmar", key="del_user_confirm")
        if st.button("Eliminar usuario", type="primary"):
            if confirm.strip().upper() != "ELIMINAR":
                st.error("Debes escribir ELIMINAR.")
            else:
                # Users
                h, users2 = read_table("Users")
                users2 = [u for u in users2 if norm_email(u.get("email","")) != norm_email(tgt)]
                write_table("Users", h, users2)
                # Access
                h, acc2 = read_table("UserCommunityAccess")
                acc2 = [a for a in acc2 if norm_email(a.get("email","")) != norm_email(tgt)]
                write_table("UserCommunityAccess", h, acc2)
                # Invites
                h, inv = read_table("Invites")
                inv = [i for i in inv if norm_email(i.get("email","")) != norm_email(tgt)]
                write_table("Invites", h, inv)
                st.success("Usuario eliminado ✅")
                st.rerun()


def ui_admin_communities(current_user: str) -> None:
    st.header("🏢 Módulo Comunidades (Admin)")

    st.subheader("Crear comunidad")
    with st.form("new_comm", clear_on_submit=True):
        name = st.text_input("Nombre de la comunidad", placeholder="Edificio A / Comunidad X")
        create = st.form_submit_button("Crear", type="primary")
        if create:
            if not name.strip():
                st.error("Nombre requerido.")
            else:
                cid = community_create(name.strip())
                st.success(f"Comunidad creada ✅ ({cid})")
                st.rerun()

    st.divider()

    comms = list_communities(active_only=False)
    if not comms:
        st.info("No hay comunidades aún.")
        return

    opt = {f"{c['name']} ({c['community_id']})": c["community_id"] for c in comms}
    pick_label = st.selectbox("Selecciona comunidad", options=list(opt.keys()))
    cid = opt[pick_label]
    cobj = next(c for c in comms if c["community_id"] == cid)
    st.caption(f"Activo: {cobj.get('active','true')} • Creado: {cobj.get('created_at','')}")

    # Installations manager
    st.subheader("Instalaciones")
    inst = installations_for_community(cid)
    if inst:
        for i in inst:
            with st.container(border=True):
                c1, c2, c3 = st.columns([2, 2, 1])
                c1.write(f"**{i['name']}**")
                c2.write(i.get("category",""))
                if c3.button("Desactivar", key=f"deact_inst_{i['installation_id']}"):
                    installation_deactivate(i["installation_id"])
                    st.rerun()
    else:
        st.info("Sin instalaciones activas.")

    with st.form("add_inst", clear_on_submit=True):
        cat = st.selectbox("Tipo/Categoría", options=["Críticos","Infraestructura","Espacio Común","Accesos","Higiene","Comunes","Infra"])
        name = st.text_input("Nombre instalación", placeholder="Sala de Bombas / Ascensores / Piscina ...")
        add = st.form_submit_button("Agregar instalación", type="primary")
        if add:
            if not name.strip():
                st.error("Nombre requerido.")
            else:
                installation_add(cid, cat, name.strip())
                st.success("Instalación agregada ✅")
                st.rerun()

    st.divider()

    # Tasks manager
    st.subheader("Tareas por instalación")
    inst2 = installations_for_community(cid)
    if not inst2:
        st.warning("Agrega instalaciones primero.")
    else:
        inst_map = {f"{i['name']} ({i['installation_id']})": i["installation_id"] for i in inst2}
        pick_inst = st.selectbox("Instalación", options=list(inst_map.keys()))
        iid = inst_map[pick_inst]

        tsk = [t for t in tasks_for_community(cid) if t.get("installation_id") == iid]
        if tsk:
            for t in tsk:
                with st.container(border=True):
                    c1, c2 = st.columns([5,1])
                    c1.write(t.get("task",""))
                    if c2.button("Desactivar", key=f"deact_task_{t['task_id']}"):
                        task_deactivate(t["task_id"])
                        st.rerun()
        else:
            st.info("Sin tareas activas para esta instalación.")

        with st.form("add_task", clear_on_submit=True):
            task = st.text_input("Nueva tarea", placeholder="Ej: Revisar presión / Alternancia / Fugas ...")
            addt = st.form_submit_button("Agregar tarea", type="primary")
            if addt:
                if not task.strip():
                    st.error("Tarea requerida.")
                else:
                    task_add(cid, iid, task.strip())
                    st.success("Tarea agregada ✅")
                    st.rerun()

    st.divider()

    # Hard delete community
    with st.expander("🗑️ Eliminar comunidad definitivamente"):
        st.warning("Esto borra datos en Sheets (comunidad+instalaciones+tareas+reportes). No borra archivos en Drive.")
        confirm = st.text_input("Escribe ELIMINAR para confirmar", key=f"del_comm_confirm_{cid}")
        if st.button("Eliminar comunidad", type="primary"):
            if confirm.strip().upper() != "ELIMINAR":
                st.error("Debes escribir ELIMINAR.")
            else:
                community_delete(cid)
                st.success("Comunidad eliminada ✅")
                st.rerun()


def ui_reports(current_user: str) -> None:
    st.header("🧾 Módulo Informes")

    allowed = user_allowed_communities(current_user)
    if not allowed:
        st.warning("No tienes comunidades asignadas.")
        return

    comms = [c for c in list_communities(active_only=True) if c["community_id"] in allowed]
    opt = {f"{c['name']} ({c['community_id']})": c["community_id"] for c in comms}
    pick_label = st.selectbox("Elige comunidad", options=list(opt.keys()))
    cid = opt[pick_label]
    cname = next(c["name"] for c in comms if c["community_id"] == cid)

    # permission to create?
    can_create = user_is_admin(current_user)
    if not can_create:
        for a in access_list_for_user(current_user):
            if a.get("community_id") == cid and a.get("can_create_reports","false").lower() == "true":
                can_create = True
                break
    if not can_create:
        st.error("No tienes permiso para crear/editar informes en esta comunidad.")
        return

    st.subheader("Crear nuevo / Continuar Draft")
    reps = reports_for_community(cid)
    last_draft = next((r for r in reps if (r.get("status") or "") == "Draft"), None)

    c1, c2 = st.columns(2)
    with c1:
        if st.button("➕ Crear nuevo informe", type="primary"):
            rid = report_create(cid, cname, current_user)
            st.session_state["active_report_id"] = rid
            st.success(f"Informe creado: {rid}")
            st.rerun()

    with c2:
        if last_draft:
            if st.button(f"📝 Continuar Draft ({last_draft['report_id']})"):
                st.session_state["active_report_id"] = last_draft["report_id"]
                st.rerun()
        else:
            st.info("No hay Draft existente.")

    rid = st.session_state.get("active_report_id", "")
    if not rid:
        st.stop()

    rep = report_get(rid)
    if not rep or rep.get("community_id") != cid:
        st.warning("Informe activo no corresponde a esta comunidad. Selecciona nuevamente.")
        st.session_state["active_report_id"] = ""
        st.stop()

    st.divider()
    st.subheader(f"Informe: {rid} — Estado: {rep.get('status','Draft')}")

    # If Final: do not allow edits, only download
    if rep.get("status") == "Final":
        st.info("Este informe está FINAL. Puedes descargarlo desde Resumen.")
        st.stop()

    # Drive token needed only when uploading photos / generating final pdf
    drive_ready = True
    try:
        drive_access = get_drive_access_token_or_raise()
    except Exception:
        drive_ready = False
        drive_access = ""

    if not drive_ready:
        st.warning("Drive NO está conectado. Las fotos y el PDF final requieren que el admin conecte Drive.")
        st.caption("Un admin bootstrap debe ir a Admin → Conectar Drive, iniciar sesión con bnbpartnerscommunity y autorizar.")

    items = reportitems_for_report(rid)

    # Summary cards (header)
    okc = sum(1 for i in items if (i.get("status") or "").lower() == "ok")
    failc = sum(1 for i in items if (i.get("status") or "").lower() == "fail")
    pendc = sum(1 for i in items if (i.get("status") or "").lower() == "pending")
    st.markdown(
        f"""
        <div style="display:flex; gap:12px; flex-wrap:wrap;">
          <div style="padding:10px 14px; border-radius:14px; background:#ecfdf5; border:1px solid #bbf7d0;">
            <div style="font-size:11px; opacity:0.7;">SISTEMAS OK</div>
            <div style="font-size:22px; font-weight:800; color:#16a34a;">{okc}</div>
          </div>
          <div style="padding:10px 14px; border-radius:14px; background:#fef2f2; border:1px solid #fecaca;">
            <div style="font-size:11px; opacity:0.7;">FALLAS</div>
            <div style="font-size:22px; font-weight:800; color:#dc2626;">{failc}</div>
          </div>
          <div style="padding:10px 14px; border-radius:14px; background:#f8fafc; border:1px solid #e2e8f0;">
            <div style="font-size:11px; opacity:0.7;">PENDIENTES</div>
            <div style="font-size:22px; font-weight:800; color:#334155;">{pendc}</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.write("")
    st.caption("Completa estado/observación. Si subes foto, se guarda privada en Drive (Mi unidad de bnbpartnerscommunity).")

    # Render checklist grouped
    last_cat = None
    for it in items:
        cat = it.get("category", "") or "Sin categoría"
        if cat != last_cat:
            st.markdown(f"### {cat}")
            last_cat = cat

        with st.container(border=True):
            colA, colB, colC = st.columns([2.2, 2.4, 1.6], gap="large")
            with colA:
                st.markdown(f"**{it.get('installation_name','')}**")
                st.caption(it.get("task","") or "(Sin tarea)")
            with colB:
                status = st.radio(
                    "Estado",
                    options=["pending", "ok", "fail"],
                    index=["pending","ok","fail"].index((it.get("status") or "pending").lower()),
                    horizontal=True,
                    label_visibility="collapsed",
                    key=f"st_{rid}_{it['installation_id']}_{it.get('task_id','')}",
                )
                note = st.text_input(
                    "Observación",
                    value=it.get("note",""),
                    placeholder="Observación breve…",
                    label_visibility="collapsed",
                    key=f"nt_{rid}_{it['installation_id']}_{it.get('task_id','')}",
                )

                # persist status/note
                if status != it.get("status") or note != it.get("note",""):
                    reportitem_update(
                        rid,
                        it["installation_id"],
                        it.get("task_id",""),
                        status=status,
                        note=note,
                    )

            with colC:
                # soft fail background hint
                if status == "fail":
                    st.markdown("<div style='padding:6px 10px; border-radius:10px; background:#fef2f2; border:1px solid #fecaca; color:#991b1b; font-weight:700;'>🔴 FALLA</div>", unsafe_allow_html=True)
                elif status == "ok":
                    st.markdown("<div style='padding:6px 10px; border-radius:10px; background:#ecfdf5; border:1px solid #bbf7d0; color:#166534; font-weight:700;'>🟢 OK</div>", unsafe_allow_html=True)
                else:
                    st.markdown("<div style='padding:6px 10px; border-radius:10px; background:#f8fafc; border:1px solid #e2e8f0; color:#334155; font-weight:700;'>⚪ PEND.</div>", unsafe_allow_html=True)

                up = st.file_uploader(
                    "Foto (opcional)",
                    type=["jpg","jpeg","png"],
                    key=f"ph_{rid}_{it['installation_id']}_{it.get('task_id','')}",
                    label_visibility="collapsed",
                )
                if up is not None:
                    file_bytes = up.getvalue()
                    sha1 = hashlib.sha1(file_bytes).hexdigest()

                    # avoid re-upload on rerun
                    hk = f"last_photo_hash_{rid}_{it['installation_id']}_{it.get('task_id','')}"
                    if st.session_state.get(hk) != sha1:
                        if not drive_ready:
                            st.error("Drive no conectado: no se puede guardar foto.")
                        else:
                            try:
                                photos_folder, _ = drive_paths_for_report(drive_access, cid, rid)
                                ext = (up.type.split("/")[-1] if up.type and "/" in up.type else "jpg")
                                fname = f"{rid}__{it['installation_id']}__{it.get('task_id','noTask')}.{ext}"
                                with st.spinner("Subiendo foto..."):
                                    fid = upload_photo_private(drive_access, photos_folder, fname, up.type or "image/jpeg", file_bytes)
                                reportitem_update(
                                    rid,
                                    it["installation_id"],
                                    it.get("task_id",""),
                                    status=status,
                                    note=note,
                                    photo_drive_file_id=fid,
                                    photo_sha1=sha1,
                                )
                                st.session_state[hk] = sha1
                                st.success("Foto guardada ✅")
                            except Exception as e:
                                st.error("Error subiendo foto.")
                                st.exception(e)

                # show photo status (no link)
                if it.get("photo_drive_file_id"):
                    st.caption("📷 Foto vinculada (privada).")

    st.divider()

    # Status control at bottom (Draft/Final) + Finalize => generate PDF & upload to Drive
    st.subheader("Estado del informe")
    current = rep.get("status","Draft")
    new_status = st.radio("Guardar como", options=["Draft","Final"], index=0 if current=="Draft" else 1, horizontal=True)

    col1, col2, col3 = st.columns([1.2, 1.2, 2])
    with col1:
        if st.button("Guardar estado", type="secondary"):
            report_set_status(rid, new_status)
            st.success("Estado guardado ✅")
            st.rerun()

    with col2:
        if new_status == "Final":
            if st.button("✅ Finalizar y generar PDF", type="primary", disabled=not drive_ready):
                try:
                    report_set_status(rid, "Final")  # lock
                    rep2 = report_get(rid) or rep
                    # re-read items to include latest
                    items2 = reportitems_for_report(rid)

                    # build pdf bytes (downloads photos internally)
                    pdf_bytes = build_pdf_bytes(
                        community_name=cname,
                        report_id=rid,
                        created_by=rep2.get("created_by_email",""),
                        created_at_iso=rep2.get("created_at",""),
                        items=items2,
                        drive_access_token=drive_access,
                    )

                    # upload pdf to drive
                    _, pdfs_folder = drive_paths_for_report(drive_access, cid, rid)
                    pdf_name = f"{cname}__{rid}.pdf".replace("/", "-")
                    with st.spinner("Subiendo PDF a Drive..."):
                        pdf_file_id = upload_pdf_private(drive_access, pdfs_folder, pdf_name, pdf_bytes)

                    report_set_pdf(rid, pdf_file_id, pdf_name)
                    st.success("Informe FINAL y PDF guardado ✅")
                    st.info("Puedes descargarlo desde el Módulo Resumen.")
                    st.rerun()
                except Exception as e:
                    st.error("Error generando/subiendo PDF.")
                    st.exception(e)
                    # roll back to draft to avoid lock in test
                    report_set_status(rid, "Draft")

    with col3:
        st.caption("Nota: al finalizar, se bloquea edición y el PDF queda guardado en Drive (privado).")


def ui_summary(current_user: str) -> None:
    st.header("📊 Módulo Resumen")

    # determine which reports user can view
    allowed = user_allowed_communities(current_user)
    if not allowed:
        st.warning("No tienes comunidades asignadas.")
        return

    can_view = user_is_admin(current_user)
    if not can_view:
        # if any access row with can_view_summary true
        rows = access_list_for_user(current_user)
        can_view = any(r.get("can_view_summary","false").lower()=="true" for r in rows)

    if not can_view:
        st.error("No tienes permiso para ver el resumen.")
        return

    _, reps = read_table("Reports")
    reps = [r for r in reps if r.get("community_id") in allowed] if not user_is_admin(current_user) else reps

    # filters
    comms = list_communities(active_only=True)
    comm_map = {c["community_id"]: c["name"] for c in comms}
    reps = [r for r in reps if r.get("community_id") in comm_map]  # remove deleted comms

    colF1, colF2, colF3 = st.columns(3)
    with colF1:
        comm_opts = ["(Todas)"] + sorted({comm_map[r["community_id"]] for r in reps})
        f_comm = st.selectbox("Comunidad", options=comm_opts)
    with colF2:
        f_user = st.text_input("Filtrar por usuario (email contiene)", placeholder="ej: juan")
    with colF3:
        f_status = st.selectbox("Estado", options=["(Todos)", "Final", "Draft"])

    # apply filters
    if f_comm != "(Todas)":
        cidset = {cid for cid, name in comm_map.items() if name == f_comm}
        reps = [r for r in reps if r.get("community_id") in cidset]
    if f_user.strip():
        reps = [r for r in reps if f_user.strip().lower() in (r.get("created_by_email","").lower())]
    if f_status != "(Todos)":
        reps = [r for r in reps if (r.get("status","") == f_status)]

    # sort recent
    reps.sort(key=lambda x: x.get("created_at",""), reverse=True)

    if not reps:
        st.info("No hay informes con esos filtros.")
        return

    # drive token needed to download PDFs
    drive_ready = True
    try:
        drive_access = get_drive_access_token_or_raise()
    except Exception:
        drive_ready = False
        drive_access = ""

    st.caption("Tabla de informes. Descarga disponible solo para informes FINAL con PDF guardado.")
    for r in reps[:200]:
        cname = comm_map.get(r["community_id"], r.get("community_name",""))
        with st.container(border=True):
            c1, c2, c3, c4 = st.columns([2.4, 2.2, 1.2, 1.6], gap="medium")
            c1.write(f"**{cname}**")
            c2.write(f"{r.get('created_at','')}\n\n{r.get('created_by_email','')}")
            c3.write(f"**{r.get('status','')}**")
            pdf_id = r.get("drive_pdf_file_id","")
            if not pdf_id or r.get("status") != "Final":
                c4.caption("Sin PDF")
            else:
                if not drive_ready:
                    c4.caption("Drive no conectado")
                else:
                    if c4.button("⬇️ Descargar PDF", key=f"dl_{r['report_id']}"):
                        try:
                            pdf_bytes = drive_files_get_media(drive_access, pdf_id)
                            st.download_button(
                                "Descargar ahora",
                                data=pdf_bytes,
                                file_name=r.get("drive_pdf_filename") or f"{r['report_id']}.pdf",
                                mime="application/pdf",
                                key=f"dlbtn_{r['report_id']}",
                                use_container_width=True,
                            )
                        except Exception as e:
                            st.error("Error descargando PDF.")
                            st.exception(e)


# -------------------------
# Main
# -------------------------
def main():
    # Ensure base schema (test-mode). If you're changing schemas often, set force_reset=True.
    ensure_tabs_and_headers(force_reset=False)
    ensure_bootstrap_users()

    # Gate
    if "user_email" not in st.session_state:
        user, ok = ui_access_gate()
        if not ok:
            st.stop()
        st.rerun()

    current_user = st.session_state["user_email"]

    # Top bar
    st.sidebar.markdown("## 🛡️ Control Comunidades")
    st.sidebar.write(f"**Usuario:** {current_user}")
    if st.sidebar.button("Cerrar sesión"):
        st.session_state.clear()
        st.rerun()

    # Modules per role
    is_admin = user_is_admin(current_user)

    modules = []
    if is_admin:
        modules = ["Admin • Usuarios", "Admin • Comunidades", "Admin • Drive", "Informes", "Resumen"]
    else:
        # based on access flags (can_create_reports / can_view_summary)
        rows = access_list_for_user(current_user)
        can_create = any(r.get("can_create_reports","false").lower()=="true" for r in rows)
        can_view = any(r.get("can_view_summary","false").lower()=="true" for r in rows)
        modules = []
        if can_create:
            modules.append("Informes")
        if can_view:
            modules.append("Resumen")
        if not modules:
            modules = ["Resumen"]  # conservative fallback

    pick = st.sidebar.radio("Módulo", options=modules)

    if pick == "Admin • Usuarios":
        ui_admin_users(current_user)
    elif pick == "Admin • Comunidades":
        ui_admin_communities(current_user)
    elif pick == "Admin • Drive":
        ui_drive_connect_admin(current_user)
    elif pick == "Informes":
        ui_reports(current_user)
    elif pick == "Resumen":
        ui_summary(current_user)

    st.sidebar.markdown("---")
    st.sidebar.caption("Sheets: Service Account • Drive: OAuth (Mi unidad) • Fotos/PDF privados")

if __name__ == "__main__":
    main()
