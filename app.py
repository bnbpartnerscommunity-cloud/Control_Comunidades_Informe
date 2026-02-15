import streamlit as st
from datetime import datetime
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build

st.set_page_config(page_title="Control Comunidades", layout="wide")

SHEET_ID = st.secrets["SHEET_ID"]

# =========================
# CREDENCIALES (MODO B)
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
        "auth_uri": st.secrets["GCP_AUTH_URI"],
        "token_uri": st.secrets["GCP_TOKEN_URI"],
        "auth_provider_x509_cert_url": st.secrets["GCP_AUTH_PROVIDER_X509_CERT_URL"],
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


# =========================
# CREAR TABS SI NO EXISTEN
# =========================
def ensure_sheet_tabs_and_headers():
    service = sheets_service()

    meta = service.spreadsheets().get(
        spreadsheetId=SHEET_ID
    ).execute()

    existing_tabs = [s["properties"]["title"] for s in meta["sheets"]]

    required_tabs = {
        "Users": ["user_id", "email", "full_name", "is_admin", "is_active", "password_hash", "created_at"],
        "Invites": ["email", "invite_code_hash", "expires_at", "used_at", "created_by", "created_at"],
        "Communities": ["community_id", "community_name", "is_active", "created_at"],
        "UserCommunityAccess": ["email", "community_id", "role", "is_active"],
    }

    requests = []

    for tab_name in required_tabs:
        if tab_name not in existing_tabs:
            requests.append({
                "addSheet": {
                    "properties": {"title": tab_name}
                }
            })

    if requests:
        service.spreadsheets().batchUpdate(
            spreadsheetId=SHEET_ID,
            body={"requests": requests}
        ).execute()

    # Escribir headers si están vacíos
    for tab_name, headers in required_tabs.items():
        service.spreadsheets().values().update(
            spreadsheetId=SHEET_ID,
            range=f"{tab_name}!A1",
            valueInputOption="RAW",
            body={"values": [headers]}
        ).execute()


# =========================
# UI
# =========================
st.title("🔐 Control Comunidades - Test Conexión")

if st.button("Verificar conexión y crear estructura"):
    ensure_sheet_tabs_and_headers()
    st.success("✅ Conexión exitosa y estructura verificada.")

st.write("Sheet ID:", SHEET_ID)
st.write("Service Account:", st.secrets["GCP_CLIENT_EMAIL"])

