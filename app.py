import re
import hmac
import base64
import hashlib
import secrets
import time
import requests
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, date
from typing import Dict, List, Optional, Tuple

import streamlit as st
from google.oauth2.service_account import Credentials
from google.auth.transport.requests import AuthorizedSession

# =========================
# App Config
# =========================
st.set_page_config(page_title="Control Comunidades", page_icon="🛡️", layout="wide")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ROLES = ["admin", "supervisor", "conserje", "viewer"]

# =========================
# Sheets schema
# =========================
REQUIRED_TABS = [
    "Users",
    "Invites",
    "Communities",
    "UserCommunityAccess",
    "Installations",
    "Checklists",
]

USERS_HEADERS = [
    "user_id", "email", "full_name", "is_admin", "is_active",
    "password_hash", "created_at", "last_login_at"
]
INVITES_HEADERS = [
    "email", "invite_code_hash", "expires_at", "used_at",
    "created_by", "created_at"
]
COMM_HEADERS = [
    "community_id", "community_name", "is_active", "created_at"
]
ACCESS_HEADERS = [
    "email", "community_id", "role", "is_active"
]
INSTALL_HEADERS = [
    "installation_id", "community_id", "category", "installation_name", "is_active", "created_at"
]
# ✅ agregamos 2 columnas para fotos persistentes
CHECK_HEADERS = [
    "check_id", "community_id", "check_date", "report_state",
    "installation_id", "category", "installation_name",
    "status", "note",
    "photo_file_id", "photo_web_view_link",
    "updated_at", "updated_by"
]

CATEGORIES_DEFAULT = ["Críticos", "Accesos", "Higiene", "Comunes", "Infra"]

DEFAULT_INSTALLATIONS = [
    ("Críticos", "Sala de Bombas"),
    ("Críticos", "Sala de Calderas"),
    ("Críticos", "Generador"),
    ("Críticos", "PEAS (Presurización)"),
    ("Críticos", "Ascensores"),
    ("Accesos", "Portones"),
    ("Accesos", "Control Biométrico"),
    ("Higiene", "Sala de Basura"),
    ("Higiene", "Ductos"),
    ("Comunes", "Piscina"),
    ("Comunes", "Quincho / Eventos"),
    ("Comunes", "Gym / Sauna"),
    ("Infra", "Pasillos"),
    ("Infra", "Subterráneo"),
    ("Infra", "Jardines"),
]

# =========================
# Helpers
# =========================
def norm_email(email: str) -> str:
    return (email or "").strip().lower()

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def parse_iso(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

def safe_bool_str(v: str, default_true: bool = True) -> str:
    if v is None or v == "":
        return "TRUE" if default_true else "FALSE"
    return "TRUE" if str(v).strip().upper() == "TRUE" else "FALSE"

def sanitize_name_for_folder(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"[\\/:*?\"<>|]+", "_", s)
    s = re.sub(r"\s+", " ", s)
    return s[:120].strip() or "SinNombre"

# =========================
# Secrets
# =========================
SHEET_ID = st.secrets["SHEET_ID"]
APP_PEPPER = str(st.secrets.get("APP_PEPPER", "CHANGE_ME"))
BOOTSTRAP_ADMIN_EMAILS = [
    x.strip().lower()
    for x in str(st.secrets.get("BOOTSTRAP_ADMIN_EMAILS", "")).split(",")
    if x.strip()
]
INVITE_EXPIRY_HOURS = int(str(st.secrets.get("INVITE_EXPIRY_HOURS", "48")))
BOOTSTRAP_SETUP_TOKEN = str(st.secrets.get("BOOTSTRAP_SETUP_TOKEN", ""))

# ✅ Drive root folder for photos
FOTOS_ROOT_FOLDER_ID = str(st.secrets.get("FOTOS_ROOT_FOLDER_ID", "")).strip()

# =========================
# Google Auth (AuthorizedSession)
# =========================
@st.cache_resource
def get_creds():
    info = {
        "type": st.secrets["GCP_TYPE"],
        "project_id": st.secrets["GCP_PROJECT_ID"],
        "private_key_id": st.secrets["GCP_PRIVATE_KEY_ID"],
        "private_key": st.secrets["GCP_PRIVATE_KEY"],
        "client_email": st.secrets["GCP_CLIENT_EMAIL"],
        "client_id": st.secrets["GCP_CLIENT_ID"],
        "auth_uri": st.secrets.get("GCP_AUTH_URI", "https://accounts.google.com/o/oauth2/auth"),
        "token_uri": st.secrets.get("GCP_TOKEN_URI", "https://oauth2.googleapis.com/token"),
        "auth_provider_x509_cert_url": st.secrets.get(
            "GCP_AUTH_PROVIDER_X509_CERT_URL",
            "https://www.googleapis.com/oauth2/v1/certs",
        ),
        "client_x509_cert_url": st.secrets["GCP_CLIENT_X509_CERT_URL"],
    }
    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ]
    return Credentials.from_service_account_info(info, scopes=scopes)

@st.cache_resource
def authed_session() -> AuthorizedSession:
    return AuthorizedSession(get_creds())

# =========================
# Sheets API (retry/backoff + cache)
# =========================
def _gs_url(path: str) -> str:
    return "https://sheets.googleapis.com" + path

def _request_with_backoff(method: str, url: str, *, params=None, json_body=None, timeout=30) -> dict:
    sess = authed_session()
    max_attempts = 6
    base_sleep = 0.8

    for attempt in range(1, max_attempts + 1):
        resp = sess.request(method, url, params=params, json=json_body, timeout=timeout)

        if resp.status_code == 429:
            sleep_s = (base_sleep * (2 ** (attempt - 1))) + (secrets.randbelow(250) / 1000.0)
            time.sleep(min(sleep_s, 8.0))
            continue

        if resp.status_code >= 400:
            raise RuntimeError(f"API error {resp.status_code}: {resp.text}")

        return resp.json() if resp.text else {}

    raise RuntimeError("API request failed after retries (429).")

@st.cache_data(ttl=12, show_spinner=False)
def sheets_get_cached(spreadsheet_id: str) -> dict:
    return _request_with_backoff("GET", _gs_url(f"/v4/spreadsheets/{spreadsheet_id}"))

@st.cache_data(ttl=12, show_spinner=False)
def sheets_values_get_cached(range_a1: str) -> List[List[str]]:
    enc = requests.utils.quote(range_a1, safe="")
    data = _request_with_backoff("GET", _gs_url(f"/v4/spreadsheets/{SHEET_ID}/values/{enc}"))
    return data.get("values", [])

@st.cache_data(ttl=12, show_spinner=False)
def sheets_batch_get_cached(ranges: Tuple[str, ...]) -> Dict[str, List[List[str]]]:
    params = [("ranges", r) for r in ranges]
    data = _request_with_backoff(
        "GET",
        _gs_url(f"/v4/spreadsheets/{SHEET_ID}/values:batchGet"),
        params=params,
    )
    out = {}
    for vr in data.get("valueRanges", []):
        out[vr.get("range", "")] = vr.get("values", [])
    return out

def _invalidate_cache():
    st.cache_data.clear()

def sheets_values_update(range_a1: str, values: List[List[str]]):
    enc = requests.utils.quote(range_a1, safe="")
    _request_with_backoff(
        "PUT",
        _gs_url(f"/v4/spreadsheets/{SHEET_ID}/values/{enc}"),
        params={"valueInputOption": "RAW"},
        json_body={"range": range_a1, "majorDimension": "ROWS", "values": values},
    )
    _invalidate_cache()

def sheets_values_append(range_a1: str, values: List[List[str]]):
    enc = requests.utils.quote(range_a1, safe="")
    _request_with_backoff(
        "POST",
        _gs_url(f"/v4/spreadsheets/{SHEET_ID}/values/{enc}:append"),
        params={"valueInputOption": "RAW", "insertDataOption": "INSERT_ROWS"},
        json_body={"range": range_a1, "majorDimension": "ROWS", "values": values},
    )
    _invalidate_cache()

def sheets_batch_update(reqs: List[dict]):
    _request_with_backoff(
        "POST",
        _gs_url(f"/v4/spreadsheets/{SHEET_ID}:batchUpdate"),
        json_body={"requests": reqs},
    )
    _invalidate_cache()

# =========================
# Drive API (v3) helpers
# =========================
def _drive_url(path: str) -> str:
    return "https://www.googleapis.com/drive/v3" + path

def drive_request(method: str, path: str, *, params=None, json_body=None, timeout=30) -> dict:
    return _request_with_backoff(method, _drive_url(path), params=params, json_body=json_body, timeout=timeout)

@st.cache_data(ttl=120, show_spinner=False)
def drive_find_folder_id(parent_id: str, name: str) -> Optional[str]:
    # Search folder by name under parent
    q = (
        f"mimeType='application/vnd.google-apps.folder' and "
        f"name='{name.replace(\"'\", \"\\'\")}' and "
        f"'{parent_id}' in parents and trashed=false"
    )
    data = drive_request("GET", "/files", params={"q": q, "fields": "files(id,name)"})
    files = data.get("files", [])
    return files[0]["id"] if files else None

def drive_create_folder(parent_id: str, name: str) -> str:
    body = {
        "name": name,
        "mimeType": "application/vnd.google-apps.folder",
        "parents": [parent_id],
    }
    data = drive_request("POST", "/files", params={"fields": "id"}, json_body=body)
    st.cache_data.clear()
    return data["id"]

def drive_get_or_create_folder(parent_id: str, name: str) -> str:
    name = sanitize_name_for_folder(name)
    fid = drive_find_folder_id(parent_id, name)
    if fid:
        return fid
    return drive_create_folder(parent_id, name)

def drive_upload_image_bytes(parent_folder_id: str, filename: str, content_type: str, file_bytes: bytes) -> Tuple[str, str]:
    """
    Upload using multipart/related (metadata + media) to Drive.
    Returns (file_id, webViewLink)
    """
    sess = authed_session()
    metadata = {
        "name": filename,
        "parents": [parent_folder_id],
    }

    boundary = "===============" + secrets.token_hex(12)
    delimiter = f"\r\n--{boundary}\r\n"
    close_delim = f"\r\n--{boundary}--\r\n"

    multipart_body = (
        delimiter
        + "Content-Type: application/json; charset=UTF-8\r\n\r\n"
        + requests.utils.json.dumps(metadata)
        + delimiter
        + f"Content-Type: {content_type}\r\n\r\n"
    ).encode("utf-8") + file_bytes + close_delim.encode("utf-8")

    headers = {"Content-Type": f"multipart/related; boundary={boundary}"}
    url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,webViewLink"

    max_attempts = 6
    base_sleep = 0.8
    for attempt in range(1, max_attempts + 1):
        resp = sess.request("POST", url, data=multipart_body, headers=headers, timeout=60)
        if resp.status_code == 429:
            time.sleep(min((base_sleep * (2 ** (attempt - 1))) + (secrets.randbelow(250) / 1000.0), 8.0))
            continue
        if resp.status_code >= 400:
            raise RuntimeError(f"Drive upload error {resp.status_code}: {resp.text}")
        data = resp.json()
        st.cache_data.clear()
        return data["id"], data.get("webViewLink", "")

    raise RuntimeError("Drive upload failed after retries (429).")

# =========================
# Password & invite hashing
# =========================
def pbkdf2_hash_password(password: str, pepper: str, iterations: int = 210_000) -> str:
    salt = secrets.token_bytes(16)
    pw = (password + pepper).encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", pw, salt, iterations, dklen=32)
    return "pbkdf2_sha256$%d$%s$%s" % (
        iterations,
        base64.urlsafe_b64encode(salt).decode("utf-8"),
        base64.urlsafe_b64encode(dk).decode("utf-8"),
    )

def pbkdf2_verify_password(password: str, stored: str, pepper: str) -> bool:
    try:
        algo, it_s, salt_b64, hash_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(it_s)
        salt = base64.urlsafe_b64decode(salt_b64.encode("utf-8"))
        expected = base64.urlsafe_b64decode(hash_b64.encode("utf-8"))
        pw = (password + pepper).encode("utf-8")
        dk = hashlib.pbkdf2_hmac("sha256", pw, salt, iterations, dklen=32)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

def hash_invite_code(code: str, pepper: str) -> str:
    h = hashlib.sha256((code + pepper).encode("utf-8")).hexdigest()
    return f"sha256${h}"

def verify_invite_code(code: str, stored: str, pepper: str) -> bool:
    try:
        algo, hexhash = stored.split("$", 1)
        if algo != "sha256":
            return False
        h = hashlib.sha256((code + pepper).encode("utf-8")).hexdigest()
        return hmac.compare_digest(h, hexhash)
    except Exception:
        return False

# =========================
# Table utilities
# =========================
def ensure_sheet_tabs_and_headers():
    meta = sheets_get_cached(SHEET_ID)
    existing = {s["properties"]["title"] for s in meta.get("sheets", [])}

    reqs = []
    for title in REQUIRED_TABS:
        if title not in existing:
            reqs.append({"addSheet": {"properties": {"title": title}}})
    if reqs:
        sheets_batch_update(reqs)

    ranges = (
        "Users!A1:Z1",
        "Invites!A1:Z1",
        "Communities!A1:Z1",
        "UserCommunityAccess!A1:Z1",
        "Installations!A1:Z1",
        "Checklists!A1:Z1",
    )
    got = sheets_batch_get_cached(ranges)

    def ensure_headers(range_key: str, tab: str, headers: List[str]):
        vals = got.get(range_key, [])
        if not vals or not vals[0]:
            sheets_values_update(f"{tab}!A1", [headers])
            return
        current = [str(x).strip() for x in vals[0]]
        # Only ensure prefix matches; if sheet has fewer columns, update header row.
        if current[: len(headers)] != headers:
            sheets_values_update(f"{tab}!A1", [headers])

    ensure_headers("Users!A1:Z1", "Users", USERS_HEADERS)
    ensure_headers("Invites!A1:Z1", "Invites", INVITES_HEADERS)
    ensure_headers("Communities!A1:Z1", "Communities", COMM_HEADERS)
    ensure_headers("UserCommunityAccess!A1:Z1", "UserCommunityAccess", ACCESS_HEADERS)
    ensure_headers("Installations!A1:Z1", "Installations", INSTALL_HEADERS)
    ensure_headers("Checklists!A1:Z1", "Checklists", CHECK_HEADERS)

def read_table(tab: str) -> Tuple[List[str], List[Dict[str, str]]]:
    values = sheets_values_get_cached(f"{tab}!A1:Z")
    if not values:
        return [], []
    headers = [str(x).strip() for x in values[0]]
    rows: List[Dict[str, str]] = []
    for r in values[1:]:
        d: Dict[str, str] = {}
        for i, h in enumerate(headers):
            d[h] = str(r[i]).strip() if i < len(r) and r[i] is not None else ""
        if any(v != "" for v in d.values()):
            rows.append(d)
    return headers, rows

def write_table(tab: str, headers: List[str], rows: List[Dict[str, str]]):
    out: List[List[str]] = [headers]
    for d in rows:
        out.append([d.get(h, "") for h in headers])
    sheets_values_update(f"{tab}!A1", out)

# =========================
# Users / auth
# =========================
def bootstrap_admin_users():
    _, users = read_table("Users")
    changed = False
    existing_map = {norm_email(u.get("email", "")): u for u in users if u.get("email")}

    for em in BOOTSTRAP_ADMIN_EMAILS:
        if em not in existing_map:
            users.append({
                "user_id": f"USR-{secrets.token_hex(4)}",
                "email": em,
                "full_name": "Admin",
                "is_admin": "TRUE",
                "is_active": "TRUE",
                "password_hash": "",
                "created_at": iso(now_utc()),
                "last_login_at": "",
            })
            changed = True
        else:
            u = existing_map[em]
            if u.get("is_admin", "").upper() != "TRUE":
                u["is_admin"] = "TRUE"; changed = True
            if u.get("is_active", "").upper() != "TRUE":
                u["is_active"] = "TRUE"; changed = True

    if changed:
        write_table("Users", USERS_HEADERS, users)

def get_user_by_email(email: str) -> Optional[Dict[str, str]]:
    _, users = read_table("Users")
    em = norm_email(email)
    for u in users:
        if norm_email(u.get("email", "")) == em:
            return u
    return None

def upsert_user(user: Dict[str, str]):
    _, users = read_table("Users")
    em = norm_email(user.get("email", ""))
    found = False
    for i, u in enumerate(users):
        if norm_email(u.get("email", "")) == em:
            users[i] = {**u, **user}
            found = True
            break
    if not found:
        users.append(user)
    write_table("Users", USERS_HEADERS, users)

def generate_invite(email: str, created_by: str) -> str:
    code = "".join(str(secrets.randbelow(10)) for _ in range(6))
    expires = now_utc() + timedelta(hours=INVITE_EXPIRY_HOURS)

    invite_row = {
        "email": norm_email(email),
        "invite_code_hash": hash_invite_code(code, APP_PEPPER),
        "expires_at": iso(expires),
        "used_at": "",
        "created_by": norm_email(created_by),
        "created_at": iso(now_utc()),
    }
    sheets_values_append("Invites!A1", [[invite_row.get(h, "") for h in INVITES_HEADERS]])
    return code

def find_valid_invite(email: str, code: str) -> Optional[Dict[str, str]]:
    _, invites = read_table("Invites")
    em = norm_email(email)
    for inv in reversed(invites):
        if norm_email(inv.get("email", "")) != em:
            continue
        if inv.get("used_at"):
            continue
        exp = parse_iso(inv.get("expires_at", ""))
        if not exp or now_utc() > exp:
            continue
        if verify_invite_code(code, inv.get("invite_code_hash", ""), APP_PEPPER):
            return inv
    return None

def mark_invite_used(invite: Dict[str, str]):
    _, invites = read_table("Invites")
    em = norm_email(invite.get("email", ""))
    ca = invite.get("created_at", "")
    for i, inv in enumerate(invites):
        if norm_email(inv.get("email", "")) == em and inv.get("created_at", "") == ca:
            invites[i]["used_at"] = iso(now_utc())
            break
    write_table("Invites", INVITES_HEADERS, invites)

@dataclass
class AuthUser:
    email: str
    full_name: str
    is_admin: bool

def set_auth(user: AuthUser):
    st.session_state["auth"] = {"email": user.email, "full_name": user.full_name, "is_admin": user.is_admin}

def get_auth() -> Optional[AuthUser]:
    d = st.session_state.get("auth")
    if not d:
        return None
    return AuthUser(email=d["email"], full_name=d.get("full_name", ""), is_admin=bool(d.get("is_admin")))

def clear_auth():
    st.session_state.pop("auth", None)
    st.session_state.pop("selected_community_id", None)

# =========================
# Communities / Access
# =========================
def list_communities(include_inactive: bool = False) -> List[Dict[str, str]]:
    _, comms = read_table("Communities")
    out = []
    for c in comms:
        active = safe_bool_str(c.get("is_active", ""), default_true=True)
        if include_inactive or active == "TRUE":
            if c.get("community_id"):
                c2 = dict(c)
                c2["is_active"] = active
                out.append(c2)
    return out

def create_community(name: str) -> Dict[str, str]:
    name = name.strip()
    _, comms = read_table("Communities")
    existing_ids = [c.get("community_id", "") for c in comms if c.get("community_id", "").startswith("COM-")]
    nums = []
    for cid in existing_ids:
        try:
            nums.append(int(cid.split("-")[1]))
        except Exception:
            pass
    next_n = (max(nums) + 1) if nums else 1
    cid = f"COM-{next_n:04d}"
    row = {"community_id": cid, "community_name": name, "is_active": "TRUE", "created_at": iso(now_utc())}
    sheets_values_append("Communities!A1", [[row.get(h, "") for h in COMM_HEADERS]])
    return row

def set_community_active(community_id: str, active: bool):
    _, comms = read_table("Communities")
    for i, c in enumerate(comms):
        if c.get("community_id") == community_id:
            comms[i]["is_active"] = "TRUE" if active else "FALSE"
            break
    write_table("Communities", COMM_HEADERS, comms)

def list_user_access(email: str, include_inactive: bool = False) -> List[Dict[str, str]]:
    _, rows = read_table("UserCommunityAccess")
    em = norm_email(email)
    out = []
    for r in rows:
        if norm_email(r.get("email", "")) != em:
            continue
        active = safe_bool_str(r.get("is_active", ""), default_true=True)
        if include_inactive or active == "TRUE":
            r2 = dict(r)
            r2["is_active"] = active
            out.append(r2)
    return out

def grant_access(email: str, community_id: str, role: str):
    _, rows = read_table("UserCommunityAccess")
    em = norm_email(email)
    role = role.strip().lower()
    if role not in ROLES:
        role = "viewer"

    found = False
    for i, r in enumerate(rows):
        if norm_email(r.get("email", "")) == em and r.get("community_id", "") == community_id:
            rows[i]["role"] = role
            rows[i]["is_active"] = "TRUE"
            found = True
            break

    if not found:
        rows.append({"email": em, "community_id": community_id, "role": role, "is_active": "TRUE"})

    write_table("UserCommunityAccess", ACCESS_HEADERS, rows)

def revoke_access(email: str, community_id: str):
    _, rows = read_table("UserCommunityAccess")
    em = norm_email(email)
    for i, r in enumerate(rows):
        if norm_email(r.get("email", "")) == em and r.get("community_id", "") == community_id:
            rows[i]["is_active"] = "FALSE"
            break
    write_table("UserCommunityAccess", ACCESS_HEADERS, rows)

# =========================
# Installations
# =========================
def list_installations(community_id: str, include_inactive: bool = False) -> List[Dict[str, str]]:
    _, rows = read_table("Installations")
    out = []
    for r in rows:
        if r.get("community_id") != community_id:
            continue
        active = safe_bool_str(r.get("is_active", ""), default_true=True)
        if include_inactive or active == "TRUE":
            r2 = dict(r)
            r2["is_active"] = active
            out.append(r2)
    out.sort(key=lambda x: (x.get("category", ""), x.get("installation_name", "")))
    return out

def add_installation(community_id: str, category: str, name: str) -> Dict[str, str]:
    category = category.strip()
    name = name.strip()
    installation_id = f"INS-{secrets.token_hex(4)}"
    row = {
        "installation_id": installation_id,
        "community_id": community_id,
        "category": category,
        "installation_name": name,
        "is_active": "TRUE",
        "created_at": iso(now_utc()),
    }
    sheets_values_append("Installations!A1", [[row.get(h, "") for h in INSTALL_HEADERS]])
    return row

def set_installation_active(installation_id: str, active: bool):
    _, rows = read_table("Installations")
    for i, r in enumerate(rows):
        if r.get("installation_id") == installation_id:
            rows[i]["is_active"] = "TRUE" if active else "FALSE"
            break
    write_table("Installations", INSTALL_HEADERS, rows)

def seed_default_installations_if_empty(community_id: str):
    current = list_installations(community_id, include_inactive=True)
    if current:
        return
    for cat, name in DEFAULT_INSTALLATIONS:
        add_installation(community_id, cat, name)

# =========================
# Checklist persistence (+ photos)
# =========================
def upsert_check_row(
    community_id: str,
    check_date: str,
    report_state: str,
    inst: Dict[str, str],
    status: str,
    note: str,
    updated_by: str,
    photo_file_id: str = "",
    photo_web_view_link: str = "",
):
    """
    Upsert by (community_id, check_date, report_state, installation_id)
    """
    _, rows = read_table("Checklists")
    key_inst = inst["installation_id"]

    status = status.strip().lower()
    if status not in ["pending", "ok", "fail"]:
        status = "pending"

    report_state = (report_state or "Draft").strip()
    if report_state not in ["Draft", "Final"]:
        report_state = "Draft"

    found = False
    for i, r in enumerate(rows):
        if (
            r.get("community_id") == community_id
            and r.get("check_date") == check_date
            and r.get("report_state") == report_state
            and r.get("installation_id") == key_inst
        ):
            rows[i]["status"] = status
            rows[i]["note"] = note
            # si viene foto nueva, actualiza; si viene vacío, conserva lo anterior
            if photo_file_id != "":
                rows[i]["photo_file_id"] = photo_file_id
                rows[i]["photo_web_view_link"] = photo_web_view_link
            rows[i]["updated_at"] = iso(now_utc())
            rows[i]["updated_by"] = norm_email(updated_by)
            found = True
            break

    if not found:
        row = {
            "check_id": f"CHK-{secrets.token_hex(4)}",
            "community_id": community_id,
            "check_date": check_date,
            "report_state": report_state,
            "installation_id": key_inst,
            "category": inst.get("category", ""),
            "installation_name": inst.get("installation_name", ""),
            "status": status,
            "note": note,
            "photo_file_id": photo_file_id,
            "photo_web_view_link": photo_web_view_link,
            "updated_at": iso(now_utc()),
            "updated_by": norm_email(updated_by),
        }
        rows.append(row)

    write_table("Checklists", CHECK_HEADERS, rows)

def clear_photo_link(community_id: str, check_date: str, report_state: str, installation_id: str, updated_by: str):
    _, rows = read_table("Checklists")
    for i, r in enumerate(rows):
        if (
            r.get("community_id") == community_id
            and r.get("check_date") == check_date
            and r.get("report_state") == report_state
            and r.get("installation_id") == installation_id
        ):
            rows[i]["photo_file_id"] = ""
            rows[i]["photo_web_view_link"] = ""
            rows[i]["updated_at"] = iso(now_utc())
            rows[i]["updated_by"] = norm_email(updated_by)
            break
    write_table("Checklists", CHECK_HEADERS, rows)

def get_check_rows_map(community_id: str, check_date: str, report_state: str) -> Dict[str, Dict[str, str]]:
    _, rows = read_table("Checklists")
    out = {}
    for r in rows:
        if (
            r.get("community_id") == community_id
            and r.get("check_date") == check_date
            and r.get("report_state") == report_state
            and r.get("installation_id")
        ):
            out[r["installation_id"]] = r
    return out

# =========================
# Drive folder routing
# =========================
def ensure_drive_root_ready():
    if not FOTOS_ROOT_FOLDER_ID:
        st.error("Falta FOTOS_ROOT_FOLDER_ID en secrets.toml.")
        st.stop()

def get_community_folder_id(community_id: str, community_name: str) -> str:
    ensure_drive_root_ready()
    folder_name = f"{community_id}__{sanitize_name_for_folder(community_name)}"
    return drive_get_or_create_folder(FOTOS_ROOT_FOLDER_ID, folder_name)

def get_report_folder_id(comm_folder_id: str, check_date: str, report_state: str) -> str:
    folder_name = f"{check_date}__{report_state}"
    return drive_get_or_create_folder(comm_folder_id, folder_name)

def get_installation_folder_id(report_folder_id: str, installation_id: str, installation_name: str) -> str:
    folder_name = f"{installation_id}__{sanitize_name_for_folder(installation_name)}"
    return drive_get_or_create_folder(report_folder_id, folder_name)

# =========================
# Boot
# =========================
if "boot_ok" not in st.session_state:
    try:
        ensure_sheet_tabs_and_headers()
        bootstrap_admin_users()
        st.session_state["boot_ok"] = True
    except Exception as e:
        st.error("No pude inicializar la estructura del Google Sheet.")
        st.exception(e)
        st.stop()

auth = get_auth()

# =========================
# UI - Login
# =========================
st.title("🛡️ Control Comunidades")

if not auth:
    st.info(
        "Formas de ingreso:\n"
        "• **Ingreso con contraseña**\n"
        "• **Primer acceso con código** (admin lo genera)\n"
        "• **Activación inicial** (solo admins bootstrap con token secreto)"
    )

    with st.expander("🧰 Activación inicial (solo admins bootstrap)"):
        b_email = st.text_input("Email admin bootstrap", placeholder="bnbpartnerscommunity@gmail.com")
        b_token = st.text_input("Token secreto", type="password", placeholder="(definido en Secrets)")
        b_pass1 = st.text_input("Nueva contraseña", type="password", key="bpass1")
        b_pass2 = st.text_input("Repetir contraseña", type="password", key="bpass2")

        if st.button("Activar admin"):
            em = norm_email(b_email)
            if em not in BOOTSTRAP_ADMIN_EMAILS:
                st.error("Ese correo no está autorizado como admin bootstrap.")
            elif not BOOTSTRAP_SETUP_TOKEN:
                st.error("Falta BOOTSTRAP_SETUP_TOKEN en Secrets.")
            elif b_token != BOOTSTRAP_SETUP_TOKEN:
                st.error("Token secreto incorrecto.")
            elif b_pass1 != b_pass2:
                st.error("Las contraseñas no coinciden.")
            elif len(b_pass1) < 8 or not any(c.isdigit() for c in b_pass1) or not any(c.isalpha() for c in b_pass1):
                st.error("Contraseña débil: mínimo 8, al menos 1 letra y 1 número.")
            else:
                u = get_user_by_email(em)
                if not u:
                    st.error("Usuario bootstrap no existe en Users.")
                else:
                    u["password_hash"] = pbkdf2_hash_password(b_pass1, APP_PEPPER)
                    u["last_login_at"] = iso(now_utc())
                    upsert_user(u)
                    st.success("Admin activado. Ahora puedes ingresar con contraseña.")

    c1, c2 = st.columns([1.05, 1], gap="large")

    with c1:
        st.subheader("Ingreso con contraseña")
        email = st.text_input("Email", key="login_email", placeholder="usuario@empresa.com")
        password = st.text_input("Contraseña", type="password", key="login_password")

        if st.button("Ingresar", use_container_width=True):
            em = norm_email(email)
            if not EMAIL_RE.match(em):
                st.error("Email inválido.")
            else:
                u = get_user_by_email(em)
                if not u or (safe_bool_str(u.get("is_active", ""), True) != "TRUE"):
                    st.error("Usuario no existe o está inactivo.")
                else:
                    stored = u.get("password_hash", "")
                    if not stored:
                        st.error("Este usuario no tiene contraseña aún. Debe ingresar con código.")
                    elif pbkdf2_verify_password(password, stored, APP_PEPPER):
                        u["last_login_at"] = iso(now_utc())
                        upsert_user(u)
                        set_auth(AuthUser(
                            email=em,
                            full_name=u.get("full_name", "") or em,
                            is_admin=(safe_bool_str(u.get("is_admin", ""), False) == "TRUE")
                        ))
                        st.rerun()
                    else:
                        st.error("Contraseña incorrecta.")

    with c2:
        st.subheader("Primer acceso con código")
        st.caption(f"Código temporal con vigencia de {INVITE_EXPIRY_HOURS} horas.")
        email2 = st.text_input("Email", key="invite_email", placeholder="usuario@empresa.com")
        code = st.text_input("Código (6 dígitos)", key="invite_code", max_chars=6)

        if st.button("Validar código", use_container_width=True):
            em = norm_email(email2)
            if not EMAIL_RE.match(em):
                st.error("Email inválido.")
            elif not code or len(code.strip()) != 6:
                st.error("Código inválido. Debe tener 6 dígitos.")
            else:
                u = get_user_by_email(em)
                if not u or (safe_bool_str(u.get("is_active", ""), True) != "TRUE"):
                    st.error("Usuario no existe o está inactivo.")
                else:
                    inv = find_valid_invite(em, code.strip())
                    if not inv:
                        st.error("Código incorrecto, vencido o ya usado.")
                    else:
                        st.session_state["pending_set_password_email"] = em
                        st.session_state["pending_invite_created_at"] = inv.get("created_at", "")
                        st.success("Código validado. Ahora define tu contraseña abajo.")
                        st.rerun()

    pending_email = st.session_state.get("pending_set_password_email")
    if pending_email:
        st.divider()
        st.subheader("✅ Definir contraseña (primer acceso)")
        p1 = st.text_input("Nueva contraseña", type="password", key="new_pass_1")
        p2 = st.text_input("Repetir contraseña", type="password", key="new_pass_2")

        def strong_enough(p: str) -> bool:
            return len(p) >= 8 and any(ch.isdigit() for ch in p) and any(ch.isalpha() for ch in p)

        if st.button("Guardar contraseña", use_container_width=True):
            if p1 != p2:
                st.error("Las contraseñas no coinciden.")
            elif not strong_enough(p1):
                st.error("Contraseña débil. Mínimo 8, al menos 1 letra y 1 número.")
            else:
                _, invites = read_table("Invites")
                created_at = st.session_state.get("pending_invite_created_at", "")
                inv_row = None
                for inv in reversed(invites):
                    if norm_email(inv.get("email", "")) == pending_email and inv.get("created_at", "") == created_at:
                        inv_row = inv
                        break
                if inv_row:
                    mark_invite_used(inv_row)

                u = get_user_by_email(pending_email)
                u["password_hash"] = pbkdf2_hash_password(p1, APP_PEPPER)
                u["last_login_at"] = iso(now_utc())
                upsert_user(u)

                st.session_state.pop("pending_set_password_email", None)
                st.session_state.pop("pending_invite_created_at", None)

                set_auth(AuthUser(
                    email=pending_email,
                    full_name=u.get("full_name", "") or pending_email,
                    is_admin=(safe_bool_str(u.get("is_admin", ""), False) == "TRUE")
                ))
                st.success("Contraseña guardada. Sesión iniciada.")
                st.rerun()

    st.stop()

# =========================
# MAIN
# =========================
st.sidebar.success(f"Conectado como: {auth.full_name} ({auth.email})")
if st.sidebar.button("Cerrar sesión"):
    clear_auth()
    st.rerun()

access = list_user_access(auth.email, include_inactive=False)
comm_map = {c["community_id"]: c for c in list_communities(include_inactive=False)}

allowed = []
for a in access:
    cid = a.get("community_id", "")
    if cid in comm_map:
        allowed.append({
            "community_id": cid,
            "community_name": comm_map[cid].get("community_name", cid),
            "role": (a.get("role", "") or "viewer").lower()
        })

if auth.is_admin:
    for cid, c in comm_map.items():
        if not any(x["community_id"] == cid for x in allowed):
            allowed.append({"community_id": cid, "community_name": c.get("community_name", cid), "role": "admin"})

allowed.sort(key=lambda x: x["community_name"])

tab_ops, tab_master, tab_admin = st.tabs(
    ["🧾 Operación (Checklist)", "🧱 Datos Maestros (Instalaciones)", "🧑‍💼 Administración"]
)

# =========================
# Operación (Checklist + Fotos)
# =========================
with tab_ops:
    st.header("🧾 Checklist por comunidad")

    if not allowed:
        st.warning("No tienes comunidades asignadas. Pide al admin que te otorgue acceso.")
    else:
        labels = [f"{x['community_name']} ({x['community_id']}) — rol: {x['role']}" for x in allowed]
        idx = 0
        current = st.session_state.get("selected_community_id")
        if current:
            for i, x in enumerate(allowed):
                if x["community_id"] == current:
                    idx = i
                    break

        sel = st.selectbox("Selecciona comunidad", options=list(range(len(allowed))), format_func=lambda i: labels[i], index=idx)
        community_id = allowed[sel]["community_id"]
        community_name = allowed[sel]["community_name"]
        st.session_state["selected_community_id"] = community_id

        # report date + state
        ctop1, ctop2 = st.columns([1, 1])
        with ctop1:
            check_date = st.date_input("Fecha del checklist", value=date.today())
        with ctop2:
            report_state = st.selectbox("Estado del informe", options=["Draft", "Final"], index=0)

        check_date_str = check_date.isoformat()

        inst_all = list_installations(community_id, include_inactive=True)
        if not inst_all:
            if st.button("Precargar instalaciones sugeridas (opcional)"):
                seed_default_installations_if_empty(community_id)
                st.success("Instalaciones precargadas.")
                st.rerun()

        inst = list_installations(community_id, include_inactive=False)
        if not inst:
            st.warning("Esta comunidad aún no tiene instalaciones activas. Ve a 'Datos Maestros'.")
        else:
            existing_map = get_check_rows_map(community_id, check_date_str, report_state)

            ok_n = sum(1 for i in inst if existing_map.get(i["installation_id"], {}).get("status") == "ok")
            fail_n = sum(1 for i in inst if existing_map.get(i["installation_id"], {}).get("status") == "fail")
            pend_n = len(inst) - ok_n - fail_n

            st.markdown(
                f"""
                <div style="display:flex; gap:12px; flex-wrap:wrap; margin-bottom:10px;">
                  <div style="padding:12px 14px; border-radius:14px; border:1px solid #e2e8f0; min-width:160px;">
                    <div style="font-size:12px; opacity:0.7;">OK</div>
                    <div style="font-size:22px; font-weight:800; color:#16a34a;">{ok_n}</div>
                  </div>
                  <div style="padding:12px 14px; border-radius:14px; border:1px solid #e2e8f0; min-width:160px;">
                    <div style="font-size:12px; opacity:0.7;">FALLAS</div>
                    <div style="font-size:22px; font-weight:800; color:#dc2626;">{fail_n}</div>
                  </div>
                  <div style="padding:12px 14px; border-radius:14px; border:1px solid #e2e8f0; min-width:160px;">
                    <div style="font-size:12px; opacity:0.7;">PENDIENTES</div>
                    <div style="font-size:22px; font-weight:800; color:#64748b;">{pend_n}</div>
                  </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            if not FOTOS_ROOT_FOLDER_ID:
                st.warning("⚠️ Aún no está configurado FOTOS_ROOT_FOLDER_ID en secrets, las fotos no podrán subirse.")

            cats = sorted(
                set([x.get("category", "") for x in inst]),
                key=lambda s: (CATEGORIES_DEFAULT.index(s) if s in CATEGORIES_DEFAULT else 999, s)
            )

            for cat in cats:
                st.subheader(cat)
                rows_cat = [x for x in inst if x.get("category") == cat]

                for item in rows_cat:
                    iid = item["installation_id"]
                    saved = existing_map.get(iid, {})
                    cur_status = (saved.get("status") or "pending").lower()
                    cur_note = saved.get("note") or ""
                    photo_link = saved.get("photo_web_view_link") or ""
                    photo_file_id = saved.get("photo_file_id") or ""

                    bg = "#fee2e2" if cur_status == "fail" else "#ffffff"

                    with st.container(border=True):
                        st.markdown(
                            f"<div style='padding:8px 10px; border-radius:10px; background:{bg};'>"
                            f"<div style='font-weight:800; font-size:16px;'>{item['installation_name']}</div>"
                            f"</div>",
                            unsafe_allow_html=True
                        )

                        colA, colB, colC = st.columns([1.2, 2.6, 2.2], gap="medium")

                        with colA:
                            status = st.radio(
                                "Estado",
                                options=["pending", "ok", "fail"],
                                index=["pending", "ok", "fail"].index(cur_status if cur_status in ["pending", "ok", "fail"] else "pending"),
                                format_func=lambda v: {"pending": "Pendiente", "ok": "OK", "fail": "Falla"}[v],
                                key=f"st_{community_id}_{check_date_str}_{report_state}_{iid}",
                                horizontal=True,
                                label_visibility="collapsed"
                            )

                        with colB:
                            note = st.text_input(
                                "Observación",
                                value=cur_note,
                                placeholder="Observación breve…",
                                key=f"nt_{community_id}_{check_date_str}_{report_state}_{iid}",
                                label_visibility="collapsed"
                            )

                        with colC:
                            st.caption("📷 Registro visual (Drive)")
                            up = st.file_uploader(
                                "Subir foto",
                                type=["jpg", "jpeg", "png"],
                                key=f"ph_{community_id}_{check_date_str}_{report_state}_{iid}",
                                label_visibility="collapsed"
                            )

                            if photo_link:
                                st.markdown(f"✅ Foto guardada: [Abrir en Drive]({photo_link})")
                                if st.button("Quitar vínculo (no borra en Drive)", key=f"rm_{community_id}_{check_date_str}_{report_state}_{iid}"):
                                    clear_photo_link(community_id, check_date_str, report_state, iid, auth.email)
                                    st.rerun()
                            else:
                                st.write("Sin foto vinculada.")

                            if up is not None and FOTOS_ROOT_FOLDER_ID:
                                if st.button("Subir a Drive y vincular", key=f"upl_{community_id}_{check_date_str}_{report_state}_{iid}"):
                                    try:
                                        comm_folder = get_community_folder_id(community_id, community_name)
                                        rep_folder = get_report_folder_id(comm_folder, check_date_str, report_state)
                                        ins_folder = get_installation_folder_id(rep_folder, iid, item["installation_name"])

                                        ext = up.type.split("/")[-1] if up.type and "/" in up.type else "jpg"
                                        filename = f"{check_date_str}__{report_state}__{iid}.{ext}"

                                        file_id, web_view = drive_upload_image_bytes(
                                            parent_folder_id=ins_folder,
                                            filename=filename,
                                            content_type=up.type or "image/jpeg",
                                            file_bytes=up.getvalue(),
                                        )

                                        # upsert with photo fields
                                        upsert_check_row(
                                            community_id=community_id,
                                            check_date=check_date_str,
                                            report_state=report_state,
                                            inst=item,
                                            status=status,
                                            note=note,
                                            updated_by=auth.email,
                                            photo_file_id=file_id,
                                            photo_web_view_link=web_view,
                                        )
                                        st.success("Foto subida y vinculada ✅")
                                        st.rerun()
                                    except Exception as e:
                                        st.error("No pude subir la foto a Drive.")
                                        st.exception(e)

                        # Persist status + note (sin tocar foto si no hay cambio)
                        upsert_check_row(
                            community_id=community_id,
                            check_date=check_date_str,
                            report_state=report_state,
                            inst=item,
                            status=status,
                            note=note,
                            updated_by=auth.email,
                            photo_file_id="",           # vacío => no sobrescribe
                            photo_web_view_link="",     # vacío => no sobrescribe
                        )

# =========================
# Datos Maestros
# =========================
with tab_master:
    st.header("🧱 Datos Maestros – Instalaciones por comunidad")

    if not allowed:
        st.warning("No tienes comunidades asignadas.")
    else:
        labels = [f"{x['community_name']} ({x['community_id']})" for x in allowed]
        sel = st.selectbox("Comunidad", options=list(range(len(allowed))), format_func=lambda i: labels[i], index=0, key="master_comm")
        community_id = allowed[sel]["community_id"]

        st.subheader("Instalaciones activas")
        inst = list_installations(community_id, include_inactive=False)
        if inst:
            st.dataframe(
                [{"ID": x["installation_id"], "Categoría": x["category"], "Instalación": x["installation_name"]} for x in inst],
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No hay instalaciones activas para esta comunidad.")

        with st.expander("➕ Agregar instalación"):
            cat = st.selectbox("Categoría", options=CATEGORIES_DEFAULT + ["Otra"], index=0)
            cat_other = ""
            if cat == "Otra":
                cat_other = st.text_input("Nombre categoría", placeholder="Ej: Seguridad")
            name = st.text_input("Nombre instalación", placeholder="Ej: Bombas de agua / Portón norte")
            if st.button("Agregar"):
                category = cat_other.strip() if cat == "Otra" else cat
                if not category:
                    st.error("Indica una categoría.")
                elif not name.strip():
                    st.error("Indica el nombre de la instalación.")
                else:
                    add_installation(community_id, category, name.strip())
                    st.success("Instalación agregada.")
                    st.rerun()

        with st.expander("🗑️ Desactivar/activar instalaciones"):
            inst_all = list_installations(community_id, include_inactive=True)
            if not inst_all:
                st.write("No hay instalaciones.")
            else:
                for x in inst_all:
                    active = (x["is_active"] == "TRUE")
                    col1, col2, col3 = st.columns([4, 2, 2])
                    with col1:
                        st.write(f"**{x['installation_name']}** — {x['category']}  \n`{x['installation_id']}`")
                    with col2:
                        st.write("Activa ✅" if active else "Inactiva ⛔")
                    with col3:
                        if active:
                            if st.button("Desactivar", key=f"deact_{x['installation_id']}"):
                                set_installation_active(x["installation_id"], False)
                                st.rerun()
                        else:
                            if st.button("Activar", key=f"act_{x['installation_id']}"):
                                set_installation_active(x["installation_id"], True)
                                st.rerun()

        st.caption("Recomendación: no borrar, solo desactivar (mantiene historial).")

# =========================
# Administración
# =========================
with tab_admin:
    st.header("🧑‍💼 Administración")

    if not auth.is_admin:
        st.info("Esta sección es solo para admins.")
    else:
        t_users, t_comms, t_access = st.tabs(["👤 Usuarios", "🏢 Comunidades", "🔐 Accesos"])

        with t_users:
            st.subheader("Usuarios")
            _, users = read_table("Users")
            users = sorted(users, key=lambda u: u.get("email", ""))
            show = []
            for u in users:
                show.append({
                    "Email": u.get("email", ""),
                    "Nombre": u.get("full_name", ""),
                    "Admin global": (safe_bool_str(u.get("is_admin", ""), False) == "TRUE"),
                    "Activo": (safe_bool_str(u.get("is_active", ""), True) == "TRUE"),
                    "Último login": u.get("last_login_at", ""),
                })
            st.dataframe(show, use_container_width=True, hide_index=True)

            st.markdown("#### Crear/actualizar usuario + generar código")
            email = st.text_input("Email del usuario", key="admin_new_user_email", placeholder="persona@empresa.com")
            full_name = st.text_input("Nombre completo", key="admin_new_user_name", placeholder="Juan Pérez")
            is_admin_flag = st.checkbox("¿Es admin global?", value=False)

            comms = list_communities(include_inactive=False)
            comm_choices = {f"{c['community_name']} ({c['community_id']})": c["community_id"] for c in comms}
            selected_comm_labels = st.multiselect("Asignar a comunidades", options=list(comm_choices.keys()))
            role = st.selectbox("Rol", options=ROLES, index=1)

            if st.button("Crear/actualizar + generar código"):
                em = norm_email(email)
                if not EMAIL_RE.match(em):
                    st.error("Email inválido.")
                elif not full_name.strip():
                    st.error("Indica nombre completo.")
                else:
                    existing = get_user_by_email(em)
                    if not existing:
                        u = {
                            "user_id": f"USR-{secrets.token_hex(4)}",
                            "email": em,
                            "full_name": full_name.strip(),
                            "is_admin": "TRUE" if is_admin_flag else "FALSE",
                            "is_active": "TRUE",
                            "password_hash": "",
                            "created_at": iso(now_utc()),
                            "last_login_at": "",
                        }
                    else:
                        u = existing
                        u["full_name"] = full_name.strip()
                        u["is_admin"] = "TRUE" if is_admin_flag else "FALSE"
                        u["is_active"] = "TRUE"

                    upsert_user(u)

                    for lbl in selected_comm_labels:
                        cid = comm_choices[lbl]
                        grant_access(em, cid, role)

                    code = generate_invite(em, auth.email)
                    st.success("Usuario listo. Copia el código y envíaselo.")
                    st.code(f"Código para {em}: {code}", language="text")

        with t_comms:
            st.subheader("Comunidades")
            name = st.text_input("Nueva comunidad", placeholder="Ej: Edificio A - Los Castaños")
            if st.button("Crear comunidad"):
                if not name.strip():
                    st.error("Indica un nombre.")
                else:
                    row = create_community(name.strip())
                    st.success(f"Comunidad creada: {row['community_name']} ({row['community_id']})")
                    st.rerun()

            st.markdown("#### Todas las comunidades")
            comms_all = list_communities(include_inactive=True)
            if not comms_all:
                st.write("No hay comunidades.")
            else:
                for c in comms_all:
                    active = (c["is_active"] == "TRUE")
                    col1, col2, col3 = st.columns([5, 2, 2])
                    with col1:
                        st.write(f"**{c['community_name']}**  \n`{c['community_id']}`")
                    with col2:
                        st.write("Activa ✅" if active else "Inactiva ⛔")
                    with col3:
                        if active:
                            if st.button("Eliminar (desactivar)", key=f"del_{c['community_id']}"):
                                set_community_active(c["community_id"], False)
                                st.rerun()
                        else:
                            if st.button("Reactivar", key=f"rea_{c['community_id']}"):
                                set_community_active(c["community_id"], True)
                                st.rerun()

            st.caption("Se recomienda desactivar en vez de borrar, para mantener histórico.")

        with t_access:
            st.subheader("Accesos")
            _, users = read_table("Users")
            users_active = [u for u in users if safe_bool_str(u.get("is_active", ""), True) == "TRUE" and u.get("email")]
            users_active = sorted(users_active, key=lambda u: u.get("email", ""))
            user_emails = [u["email"] for u in users_active]

            comms = list_communities(include_inactive=False)
            comm_choices = {f"{c['community_name']} ({c['community_id']})": c["community_id"] for c in comms}

            if not user_emails:
                st.warning("No hay usuarios activos.")
            else:
                target = st.selectbox("Usuario", options=user_emails)
                st.markdown("##### Accesos actuales del usuario")
                cur = list_user_access(target, include_inactive=True)
                if cur:
                    st.dataframe(cur, use_container_width=True, hide_index=True)
                else:
                    st.write("Sin accesos.")

                st.markdown("##### Otorgar / revocar")
                if not comm_choices:
                    st.warning("Crea al menos una comunidad activa.")
                else:
                    comm_label = st.selectbox("Comunidad", options=list(comm_choices.keys()))
                    role = st.selectbox("Rol", options=ROLES, index=1, key="role_access")

                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("Guardar acceso"):
                            grant_access(target, comm_choices[comm_label], role)
                            st.success("Acceso actualizado.")
                            st.rerun()
                    with col2:
                        if st.button("Revocar acceso"):
                            revoke_access(target, comm_choices[comm_label])
                            st.success("Acceso revocado.")
                            st.rerun()

st.caption("Fotos persistentes en Drive ✅  •  Próximo paso: export PDF/Word con tabla por áreas + fotos.")


