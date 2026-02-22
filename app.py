
import io
import time
import streamlit as st

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
from google.auth.transport.requests import Request

st.set_page_config(page_title="Drive OAuth Test (robusto)", layout="wide")

# Google a veces devuelve scopes extra (openid + userinfo.email) aunque pidas solo drive.file
# (por consentimiento previo o normalización). Para evitar el error "Scope has changed",
# pedimos exactamente el set que Google está devolviendo en tu caso.
OAUTH_SCOPES = [
    "https://www.googleapis.com/auth/drive.file",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
]

def _redirect_uri() -> str:
    return st.secrets["OAUTH_REDIRECT_URI"].strip().rstrip("/")

def _client_config() -> dict:
    redirect_uri = _redirect_uri()
    return {
        "web": {
            "client_id": st.secrets["OAUTH_CLIENT_ID"],
            "client_secret": st.secrets["OAUTH_CLIENT_SECRET"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [redirect_uri],
        }
    }

def get_flow(state=None) -> Flow:
    return Flow.from_client_config(
        _client_config(),
        scopes=OAUTH_SCOPES,
        redirect_uri=_redirect_uri(),
        state=state,
    )

def _clean_query_params():
    try:
        st.query_params.clear()
    except Exception:
        pass

def logout():
    st.session_state.pop("oauth_token", None)
    st.session_state.pop("oauth_state", None)
    _clean_query_params()

def get_authorize_url() -> str:
    flow = get_flow()
    # Quitamos include_granted_scopes para evitar que Google "una" scopes previos.
    auth_url, state = flow.authorization_url(
        access_type="offline",
        prompt="consent",
    )
    st.session_state["oauth_state"] = state
    return auth_url

def handle_oauth_callback() -> bool:
    qp = st.query_params
    code = qp.get("code")
    if isinstance(code, list):
        code = code[0] if code else None
    if not code:
        return False

    state = st.session_state.get("oauth_state")
    flow = get_flow(state=state)

    try:
        flow.fetch_token(code=code)
    except Exception as e:
        st.error("Falló el intercambio del código por tokens (OAuth).")
        st.info(
            "Siguientes pasos (en orden):\n"
            "1) Presiona '🧹 Reset OAuth' y vuelve a 'Conectar con Google'.\n"
            "2) Si sigue: revoca el acceso previo en tu cuenta Google:\n"
            "   Cuenta Google → Seguridad → Acceso de terceros → elimina la app / 'controlcomunidadesinforme'.\n"
            "   Luego vuelve a conectar.\n"
            "3) Verifica Redirect URI EXACTO en Google Cloud:\n"
            f"   {_redirect_uri()}\n"
            "4) Si Streamlit redacta detalles, revisa Manage app → Logs."
        )
        st.exception(e)
        _clean_query_params()
        return False

    creds = flow.credentials
    st.session_state["oauth_token"] = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "scopes": creds.scopes,
    }
    _clean_query_params()
    return True

def get_drive_service():
    tok = st.session_state.get("oauth_token")
    if not tok:
        return None

    creds = Credentials(
        token=tok.get("token"),
        refresh_token=tok.get("refresh_token"),
        token_uri=tok.get("token_uri", "https://oauth2.googleapis.com/token"),
        client_id=st.secrets["OAUTH_CLIENT_ID"],
        client_secret=st.secrets["OAUTH_CLIENT_SECRET"],
        scopes=tok.get("scopes", OAUTH_SCOPES),
    )

    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        st.session_state["oauth_token"]["token"] = creds.token

    return build("drive", "v3", credentials=creds, cache_discovery=False)

def drive_get_folder_meta(drive, folder_id):
    return drive.files().get(fileId=folder_id, fields="id,name,mimeType").execute()

def drive_upload_bytes(drive, folder_id, filename, content_bytes):
    media = MediaIoBaseUpload(io.BytesIO(content_bytes), mimetype="application/pdf", resumable=False)
    body = {"name": filename, "parents": [folder_id]}
    return drive.files().create(body=body, media_body=media, fields="id,name").execute()

def drive_download_bytes(drive, file_id):
    request = drive.files().get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    return fh.getvalue()

def main():
    st.title("🔐 Drive OAuth Test (robusto)")
    st.caption("Evita el error 'Scope has changed' alineando scopes con lo que Google devuelve.")

    if st.button("🧹 Reset OAuth"):
        logout()
        st.rerun()

    if handle_oauth_callback():
        st.success("OAuth completado ✅")

    drive = get_drive_service()

    with st.sidebar:
        st.header("Conexión Google Drive")
        if drive is None:
            st.warning("No conectado.")
            st.link_button("Conectar con Google", get_authorize_url())
            st.caption(f"Redirect URI esperado: {_redirect_uri()}")
            st.caption("Scopes solicitados: " + ", ".join(OAUTH_SCOPES))
        else:
            st.success("Conectado ✅")
            try:
                about = drive.about().get(fields="user").execute()
                st.write("Usuario:", about.get("user", {}))
            except Exception:
                st.info("Conectado, pero no se pudo leer 'about.user'.")
            if st.button("Desconectar"):
                logout()
                st.rerun()

    folder_id = st.secrets.get("DRIVE_REPORTS_FOLDER_ID", "").strip()
    if not folder_id:
        st.error("Falta DRIVE_REPORTS_FOLDER_ID en Secrets.")
        st.stop()

    if drive is None:
        st.stop()

    try:
        meta = drive_get_folder_meta(drive, folder_id)
        st.success(f"Carpeta accesible ✅ {meta.get('name')}")
    except Exception as e:
        st.error("No se pudo acceder a la carpeta. Revisa ID y permisos de tu cuenta usuaria.")
        st.exception(e)
        st.stop()

    st.header("Subir PDF de prueba")
    uploaded = st.file_uploader("Selecciona un PDF", type=["pdf"])
    if uploaded and st.button("⬆️ Subir a Drive", type="primary"):
        try:
            content = uploaded.read()
            filename = f"TEST-{int(time.time())}-{uploaded.name}"
            created = drive_upload_bytes(drive, folder_id, filename, content)
            st.success(f"Subido ✅ {created['name']}")
            st.code(created["id"])
            st.session_state["last_file_id"] = created["id"]
        except Exception as e:
            st.error("Error al subir archivo.")
            st.exception(e)

    st.divider()
    st.header("Descargar último archivo subido")
    file_id = st.text_input("File ID", value=st.session_state.get("last_file_id", ""))
    if file_id and st.button("⬇️ Descargar"):
        try:
            data = drive_download_bytes(drive, file_id)
            st.download_button("Descargar PDF", data=data, file_name=f"{file_id}.pdf", mime="application/pdf")
        except Exception as e:
            st.error("Error al descargar archivo.")
            st.exception(e)

if __name__ == "__main__":
    main()
