
import io
import time
import streamlit as st

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload

st.set_page_config(page_title="Control Comunidades - Drive (Service Account)", layout="wide")

# ==========
# CONFIG
# ==========
DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive.file"]


# ==========
# DRIVE (Service Account) — NO replace() needed if GCP_PRIVATE_KEY is multiline in Secrets
# ==========
@st.cache_resource(show_spinner=False)
def get_drive_service():
    """
    Builds a Google Drive API client using a Service Account.

    Requirements in Streamlit Secrets:
      - GCP_TYPE = "service_account"
      - GCP_PROJECT_ID
      - GCP_CLIENT_EMAIL
      - GCP_PRIVATE_KEY   (MULTILINE REAL, inside triple quotes)
      - DRIVE_REPORTS_FOLDER_ID
    """
    info = {
        "type": st.secrets.get("GCP_TYPE", "service_account"),
        "project_id": st.secrets["GCP_PROJECT_ID"],
        "private_key": st.secrets["GCP_PRIVATE_KEY"],  # <-- multiline key
        "client_email": st.secrets["GCP_CLIENT_EMAIL"],
        "token_uri": "https://oauth2.googleapis.com/token",
    }

    creds = service_account.Credentials.from_service_account_info(info, scopes=DRIVE_SCOPES)
    return build("drive", "v3", credentials=creds, cache_discovery=False)


def drive_get_folder_meta(drive, folder_id: str):
    return drive.files().get(fileId=folder_id, fields="id,name,mimeType").execute()


def drive_upload_bytes(drive, folder_id: str, filename: str, content_bytes: bytes, mime_type: str = "application/pdf"):
    media = MediaIoBaseUpload(io.BytesIO(content_bytes), mimetype=mime_type, resumable=False)
    body = {"name": filename, "parents": [folder_id]}
    created = drive.files().create(body=body, media_body=media, fields="id,name").execute()
    return created  # dict with id/name


def drive_download_bytes(drive, file_id: str) -> bytes:
    request = drive.files().get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    return fh.getvalue()


def main():
    st.title("🗂️ Control Comunidades - Drive (Service Account)")
    st.caption("App mínima para validar Drive con Service Account y la carpeta destino (Fase 1).")

    # Sidebar diagnostics
    with st.sidebar:
        st.subheader("Diagnóstico Drive")
        folder_id = st.secrets.get("DRIVE_REPORTS_FOLDER_ID", "").strip()
        if not folder_id:
            st.error("Falta DRIVE_REPORTS_FOLDER_ID en Secrets.")
            st.stop()

        try:
            drive = get_drive_service()
            about = drive.about().get(fields="user").execute()
            st.success("Drive autenticado ✅")
            st.write("Identidad:", about.get("user", {}))

            meta = drive_get_folder_meta(drive, folder_id)
            if meta.get("mimeType") != "application/vnd.google-apps.folder":
                st.warning(f"El ID configurado existe, pero no parece ser carpeta. mimeType={meta.get('mimeType')}")
            st.success(f"Carpeta accesible ✅ {meta.get('name')}")

        except Exception as e:
            st.error("Drive no accesible. Revisa Secrets y el sharing de la carpeta con el service account.")
            st.exception(e)
            st.stop()

    st.divider()

    st.header("Subir un PDF de prueba a la carpeta configurada")
    uploaded = st.file_uploader("Selecciona un PDF", type=["pdf"])
    col1, col2 = st.columns([1, 1])

    if uploaded:
        with col1:
            st.write("Archivo:", uploaded.name)
            st.write("Tamaño (bytes):", uploaded.size)

        with col2:
            if st.button("⬆️ Subir a Drive", type="primary"):
                try:
                    content = uploaded.read()
                    ts = time.strftime("%Y%m%d-%H%M%S")
                    safe_name = f"TEST-{ts}-{uploaded.name}"
                    created = drive_upload_bytes(
                        drive=get_drive_service(),
                        folder_id=st.secrets["DRIVE_REPORTS_FOLDER_ID"],
                        filename=safe_name,
                        content_bytes=content,
                        mime_type="application/pdf",
                    )
                    st.success(f"Subido ✅ {created['name']}")
                    st.code(created["id"])
                    st.session_state["last_file_id"] = created["id"]
                except Exception as e:
                    st.error("Falló la subida.")
                    st.exception(e)

    st.divider()

    st.header("Descargar último archivo subido (por File ID)")
    file_id = st.text_input("File ID", value=st.session_state.get("last_file_id", ""))
    if file_id and st.button("⬇️ Descargar desde Drive"):
        try:
            data = drive_download_bytes(get_drive_service(), file_id)
            st.download_button(
                "Descargar PDF",
                data=data,
                file_name=f"{file_id}.pdf",
                mime="application/pdf",
            )
        except Exception as e:
            st.error("Falló la descarga.")
            st.exception(e)

    st.info(
        "Cuando esto funcione OK, integra estas funciones (get_drive_service / upload / download) en tu app principal "
        "y mantén el RBAC en tu capa de app (Admin/Supervisor/Viewer)."
    )


if __name__ == "__main__":
    main()
