import re
import hmac
import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import streamlit as st
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build

# ---------------------------
# Config UI
# ---------------------------
st.set_page_config(page_title="Control Edificio Pro – Acceso", page_icon="🛡️", layout="wide")

REQUIRED_TABS = ["Users", "Invites", "Communities", "UserCommunityAccess"]

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

ROLES = ["admin", "supervisor", "conserje", "viewer"]
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


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


# ---------------------------
# Secrets
# ---------------------------
SHEET_ID = st.secrets["SHEET_ID"]
APP_PEPPER = str(st.secrets.get("APP_PEPPER", "CHANGE_ME"))
BOOTSTRAP_ADMIN_EMAILS = [
    x.strip().lower()
    for x in str(st.secrets.get("BOOTSTRAP_ADMIN_EMAILS", "")).split(",")
    if x.strip()
]
INVITE_EXPIRY_HOURS = int(str(st.secrets.get("INVITE_EXPIRY_HOURS", "48")))


# ---------------------------
# Google API clients (MODO B)
# ---------------------------
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
        "auth_provider_x509_cert_url": st.secrets.get("GCP_AUTH_PROVIDER_X509_CERT_URL", "https://www.googleapis.com/oauth2/v1/certs"),
        "client_x509_cert_url": st.secrets["GCP_CLIENT_X509_CERT_URL"],
    }
    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ]
    return Credentials.from_service_account_info(info, scopes=scopes)


@st.cache_resource
def sheets_service():
    return build("sheets", "v4", credentials=get_creds())


# ---------------------------
# Hashing (stdlib)
# ---------------------------
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


# ---------------------------
# Sheets helpers
# ---------------------------
def sheets_get(spreadsheet_id: str):
    return sheets_service().spreadsheets().get(spreadsheetId=spreadsheet_id).execute()


def sheets_values_get(range_a1: str) -> List[List[str]]:
    resp = sheets_service().spreadsheets().values().get(
        spreadsheetId=SHEET_ID,
        range=range_a1,
        valueRenderOption="UNFORMATTED_VALUE",
    ).execute()
    return resp.get("values", [])


def sheets_values_update(range_a1: str, values: List[List[str]]):
    sheets_service().spreadsheets().values().update(
        spreadsheetId=SHEET_ID,
        range=range_a1,
        valueInputOption="RAW",
        body={"values": values},
    ).execute()


def sheets_values_append(range_a1: str, values: List[List[str]]):
    sheets_service().spreadsheets().values().append(
        spreadsheetId=SHEET_ID,
        range=range_a1,
        valueInputOption="RAW",
        insertDataOption="INSERT_ROWS",
        body={"values": values},
    ).execute()


def ensure_sheet_tabs_and_headers():
    meta = sheets_get(SHEET_ID)
    existing = {s["properties"]["title"] for s in meta.get("sheets", [])}

    requests = []
    for title in REQUIRED_TABS:
        if title not in existing:
            requests.append({"addSheet": {"properties": {"title": title}}})

    if requests:
        sheets_service().spreadsheets().batchUpdate(
            spreadsheetId=SHEET_ID, body={"requests": requests}
        ).execute()

    def ensure_headers(tab: str, headers: List[str]):
        vals = sheets_values_get(f"{tab}!A1:Z1")
        if not vals or not vals[0]:
            sheets_values_update(f"{tab}!A1", [headers])
            return
        current = [str(x).strip() for x in vals[0]]
        if current[: len(headers)] != headers:
            sheets_values_update(f"{tab}!A1", [headers])

    ensure_headers("Users", USERS_HEADERS)
    ensure_headers("Invites", INVITES_HEADERS)
    ensure_headers("Communities", COMM_HEADERS)
    ensure_headers("UserCommunityAccess", ACCESS_HEADERS)


def read_table(tab: str) -> Tuple[List[str], List[Dict[str, str]]]:
    values = sheets_values_get(f"{tab}!A1:Z")
    if not values:
        return [], []
    headers = [str(x).strip() for x in values[0]]
    rows = []
    for r in values[1:]:
        d = {}
        for i, h in enumerate(headers):
            d[h] = str(r[i]).strip() if i < len(r) and r[i] is not None else ""
        rows.append(d)
    return headers, rows


def write_table(tab: str, headers: List[str], rows: List[Dict[str, str]]):
    out = [headers]
    for d in rows:
        out.append([d.get(h, "") for h in headers])
    sheets_values_update(f"{tab}!A1", out)


# ---------------------------
# Domain logic
# ---------------------------
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


def list_communities() -> List[Dict[str, str]]:
    _, comms = read_table("Communities")
    out = []
    for c in comms:
        if (c.get("is_active", "").upper() or "TRUE") == "TRUE" and c.get("community_id"):
            out.append(c)
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


def list_user_access(email: str) -> List[Dict[str, str]]:
    _, rows = read_table("UserCommunityAccess")
    em = norm_email(email)
    out = []
    for r in rows:
        if norm_email(r.get("email", "")) == em and (r.get("is_active", "").upper() or "TRUE") == "TRUE":
            out.append(r)
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


# ---------------------------
# Session Auth
# ---------------------------
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


# ---------------------------
# Boot
# ---------------------------
ensure_sheet_tabs_and_headers()
bootstrap_admin_users()

auth = get_auth()

st.title("🛡️ Control Edificio Pro — Acceso")

# ---------------------------
# Login UI
# ---------------------------
if not auth:
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
                if not u or (u.get("is_active", "").upper() != "TRUE"):
                    st.error("Usuario no existe o está inactivo.")
                else:
                    stored = u.get("password_hash", "")
                    if not stored:
                        st.error("Este usuario no tiene contraseña aún. Debe ingresar con código inicial.")
                    elif pbkdf2_verify_password(password, stored, APP_PEPPER):
                        u["last_login_at"] = iso(now_utc())
                        upsert_user(u)
                        set_auth(AuthUser(email=em, full_name=u.get("full_name", "") or em, is_admin=(u.get("is_admin", "").upper() == "TRUE")))
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
                if not u or (u.get("is_active", "").upper() != "TRUE"):
                    st.error("Usuario no existe o está inactivo.")
                else:
                    inv = find_valid_invite(em, code.strip())
                    if not inv:
                        st.error("Código incorrecto, vencido o ya usado.")
                    else:
                        st.session_state["pending_set_password_email"] = em
                        st.session_state["pending_invite_created_at"] = inv.get("created_at", "")
                        st.success("Código validado. Ahora define tu contraseña.")
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
                st.error("Contraseña débil. Mínimo 8 caracteres, al menos 1 letra y 1 número.")
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

                set_auth(AuthUser(email=pending_email, full_name=u.get("full_name", "") or pending_email, is_admin=(u.get("is_admin", "").upper() == "TRUE")))
                st.success("Contraseña guardada. Sesión iniciada.")
                st.rerun()

    st.stop()


# ---------------------------
# Main after login
# ---------------------------
st.sidebar.success(f"Conectado como: {auth.full_name} ({auth.email})")
if st.sidebar.button("Cerrar sesión"):
    clear_auth()
    st.rerun()

access = list_user_access(auth.email)
comm_map = {c["community_id"]: c for c in list_communities()}

allowed = []
for a in access:
    cid = a.get("community_id", "")
    if cid in comm_map:
        allowed.append({"community_id": cid, "community_name": comm_map[cid].get("community_name", cid), "role": (a.get("role", "") or "viewer").lower()})

if auth.is_admin:
    for cid, c in comm_map.items():
        if not any(x["community_id"] == cid for x in allowed):
            allowed.append({"community_id": cid, "community_name": c.get("community_name", cid), "role": "admin"})

allowed = sorted(allowed, key=lambda x: x["community_name"])

st.subheader("🏢 Comunidades disponibles")
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
    st.session_state["selected_community_id"] = allowed[sel]["community_id"]
    st.info("Próximo paso: módulo de Reportes (Draft/Final) + Checklist + Drive fotos.")

# ---------------------------
# Admin Panel
# ---------------------------
if auth.is_admin:
    st.divider()
    st.header("🧑‍💼 Panel Admin")

    tab_u, tab_c, tab_a = st.tabs(["👤 Usuarios", "🏢 Comunidades", "🔐 Accesos"])

    with tab_c:
        st.subheader("Crear comunidad")
        name = st.text_input("Nombre de la comunidad", placeholder="Ej: Edificio A - Los Castaños")
        if st.button("Crear comunidad"):
            if not name.strip():
                st.error("Indica un nombre.")
            else:
                row = create_community(name.strip())
                st.success(f"Comunidad creada: {row['community_name']} ({row['community_id']})")
                st.rerun()

        st.markdown("#### Comunidades actuales")
        comms = list_communities()
        if not comms:
            st.write("No hay comunidades aún.")
        else:
            st.dataframe(comms, use_container_width=True)

    with tab_u:
        st.subheader(f"Crear usuario + generar código ({INVITE_EXPIRY_HOURS}h)")
        email = st.text_input("Email del usuario", key="admin_new_user_email", placeholder="persona@empresa.com")
        full_name = st.text_input("Nombre completo", key="admin_new_user_name", placeholder="Juan Pérez")
        is_admin_flag = st.checkbox("¿Es admin global?", value=False)

        comms = list_communities()
        comm_choices = {f"{c['community_name']} ({c['community_id']})": c["community_id"] for c in comms}
        selected_comm_labels = st.multiselect("Asignar a comunidades", options=list(comm_choices.keys()))
        role = st.selectbox("Rol en esas comunidades", options=ROLES, index=1)

        if st.button("Crear / actualizar usuario + generar código"):
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
                st.success("Usuario listo. Copia el código y envíaselo por WhatsApp/correo.")
                st.code(f"Código para {em}: {code}", language="text")

    with tab_a:
        st.subheader("Administrar accesos por comunidad")
        _, users = read_table("Users")
        users_active = [u for u in users if u.get("is_active", "").upper() == "TRUE" and u.get("email")]
        users_active = sorted(users_active, key=lambda u: u.get("email", ""))
        user_emails = [u["email"] for u in users_active]

        if not user_emails:
            st.warning("No hay usuarios activos.")
        else:
            target = st.selectbox("Usuario", options=user_emails)
            st.markdown("##### Accesos actuales")
            current_access = list_user_access(target)
            if current_access:
                st.dataframe(current_access, use_container_width=True)
            else:
                st.write("Sin accesos asignados.")

            st.markdown("##### Otorgar o actualizar acceso")
            comms = list_communities()
            comm_choices = {f"{c['community_name']} ({c['community_id']})": c["community_id"] for c in comms}
            comm_label = st.selectbox("Comunidad", options=list(comm_choices.keys()))
            role = st.selectbox("Rol", options=ROLES, index=1)

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

st.caption("MVP listo: autenticación + panel admin + comunidades (persistente en Sheets). Próximo: Reportes (draft/final) + checklist + Drive fotos.")

