
import io
import time
import streamlit as st

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
from google.auth.transport.requests import Request
from googleapiclient.errors import HttpError

st.set_page_config(page_title="Control Comunidades - Drive OAuth (drive.file)", layout="wide")

# Scope drive.file: the app can access files/folders it creates OR the user explicitly opens with the app.
OAUTH_SCOPES = [
    "https://www.googleapis.com/auth/drive.file",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
]

def _redirect_uri() -> str:
    return st.secrets["OAUTH_REDIRECT_URI"].strip().rstrip("/")

def _client_config() -> dict:
    return {
        "web": {
            "client_id": st.secrets["OAUTH_CLIENT_ID"],
            "client_secret": st.secrets["OAUTH_CLIENT_SECRET"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [_redirect_uri()],
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
    st.session_state.pop("active_folder_id", None)
    _clean_query_params()

def get_authorize_url() -> str:
    flow = get_flow()
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

    flow = get_flow(state=st.session_state.get("oauth_state"))

    try:
        flow.fetch_token(code=code)
    except Exception as e:
        st.error("Falló el intercambio del código por tokens (OAuth).")
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

# ---- Drive helpers
def drive_get_folder_meta(drive, folder_id):
    return drive.files().get(fileId=folder_id, fields="id,name,mimeType").execute()

def drive_create_folder(drive, name: str, parent_id=None):
    body = {"name": name, "mimeType": "application/vnd.google-apps.folder"}
    if parent_id:
        body["parents"] = [parent_id]
    return drive.files().create(body=body, fields="id,name").execute()

def drive_list_app_folders(drive, limit=20):
    q = "mimeType='application/vnd.google-apps.folder' and trashed=false"
    res = drive.files().list(q=q, pageSize=limit, fields="files(id,name,createdTime)").execute()
    return res.get("files", [])

def drive_upload_pdf(drive, folder_id, filename, content_bytes):
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
    st.title("📁 Control Comunidades - Drive OAuth (drive.file)")
    st.caption(
        "Con scope **drive.file**, Google solo permite acceder a carpetas/archivos que la app **crea** "
        "o que el usuario **abre explícitamente** con la app. Por eso una carpeta por ID puede dar 404."
    )

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
            st.caption(f"Redirect URI: {_redirect_uri()}")
        else:
            about = drive.about().get(fields="user").execute()
            st.success("Conectado ✅")
            st.write("Usuario:", about.get("user", {}))
            if st.button("Desconectar"):
                logout()
                st.rerun()

    if drive is None:
        st.stop()

    configured_id = st.secrets.get("DRIVE_REPORTS_FOLDER_ID", "").strip()
    active_id = st.session_state.get("active_folder_id") or configured_id

    st.subheader("📌 Carpeta destino")
    st.write("ID configurado en Secrets:", configured_id or "— (vacío)")
    st.write("ID activo (sesión):", active_id or "—")

    folder_ok = False
    if active_id:
        try:
            meta = drive_get_folder_meta(drive, active_id)
            if meta.get("mimeType") == "application/vnd.google-apps.folder":
                st.success(f"Carpeta accesible ✅ {meta.get('name')}")
                folder_ok = True
            else:
                st.warning(f"El ID existe pero no es carpeta (mimeType={meta.get('mimeType')}).")
        except HttpError as e:
            st.error("No se pudo acceder a la carpeta por ID (404 con drive.file es común).")
            st.exception(e)

    st.divider()
    st.subheader("✅ Solución práctica con drive.file: crear la carpeta con la app")
    st.write(
        "Si creas la carpeta desde aquí, la app tendrá permiso garantizado para escribir dentro "
        "(porque la carpeta será creada por la app bajo tu cuenta)."
    )

    colA, colB = st.columns([2, 1])
    with colA:
        new_name = st.text_input("Nombre de carpeta a crear", value="Control Comunidades - Informes")
    with colB:
        if st.button("➕ Crear carpeta", type="primary"):
            try:
                created = drive_create_folder(drive, new_name)
                st.session_state["active_folder_id"] = created["id"]
                st.success(f"Creada ✅ {created['name']}")
                st.code(created["id"])
                st.info("Copia este ID a Secrets como DRIVE_REPORTS_FOLDER_ID para dejarlo fijo.")
                st.rerun()
            except Exception as e:
                st.error("No pude crear la carpeta.")
                st.exception(e)

    st.divider()
    st.subheader("📂 Carpetas visibles para la app (drive.file)")
    try:
        folders = drive_list_app_folders(drive, limit=50)
        if folders:
            st.write(f"Encontré {len(folders)} carpeta(s) accesible(s) por la app:")
            st.json(folders)
            pick = st.selectbox(
                "Elegir una carpeta como destino (solo para esta sesión)",
                options=["—"] + [f"{f['name']}  ({f['id']})" for f in folders],
                index=0
            )
            if pick != "—":
                chosen_id = pick.split("(")[-1].replace(")", "").strip()
                st.session_state["active_folder_id"] = chosen_id
                st.success("Carpeta destino cambiada para esta sesión ✅")
        else:
            st.info("Aún no hay carpetas accesibles por la app. Crea una arriba para empezar.")
    except Exception as e:
        st.error("No pude listar carpetas.")
        st.exception(e)

    st.divider()
    st.subheader("⬆️ Subir PDF de prueba")

    final_folder_id = st.session_state.get("active_folder_id") or configured_id
    if not final_folder_id:
        st.warning("Primero crea/selecciona una carpeta accesible (arriba).")
        st.stop()

    uploaded = st.file_uploader("Selecciona un PDF", type=["pdf"])
    if uploaded and st.button("Subir a Drive"):
        try:
            content = uploaded.read()
            filename = f"TEST-{int(time.time())}-{uploaded.name}"
            created = drive_upload_pdf(drive, final_folder_id, filename, content)
            st.success(f"Subido ✅ {created['name']}")
            st.code(created["id"])
            st.session_state["last_file_id"] = created["id"]
        except Exception as e:
            st.error("Falló la subida.")
            st.exception(e)

    st.divider()
    st.subheader("⬇️ Descargar último archivo subido")
    file_id = st.text_input("File ID", value=st.session_state.get("last_file_id", ""))
    if file_id and st.button("Descargar"):
        try:
            data = drive_download_bytes(drive, file_id)
            st.download_button("Descargar PDF", data=data, file_name=f"{file_id}.pdf", mime="application/pdf")
        except Exception as e:
            st.error("Falló la descarga.")
            st.exception(e)

if __name__ == "__main__":
    main()
