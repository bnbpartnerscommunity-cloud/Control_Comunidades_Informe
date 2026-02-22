
import streamlit as st
from google.oauth2 import service_account
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

st.set_page_config(page_title="Control Comunidades - Drive Test", layout="wide")

DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive.file"]

def get_drive_service_and_creds():
    pk = st.secrets.get("GCP_PRIVATE_KEY", "")
    # Convert literal \n to real newlines if needed
    pk = pk.replace("\\n", "\n")

    info = {
        "type": st.secrets.get("GCP_TYPE", "service_account"),
        "project_id": st.secrets["GCP_PROJECT_ID"],
        "private_key": pk,
        "client_email": st.secrets["GCP_CLIENT_EMAIL"],
        "token_uri": "https://oauth2.googleapis.com/token",
    }

    creds = service_account.Credentials.from_service_account_info(
        info,
        scopes=DRIVE_SCOPES
    )

    drive = build("drive", "v3", credentials=creds, cache_discovery=False)
    return drive, creds

def drive_identity_smoke_test(drive_service, creds):
    creds.refresh(Request())
    return drive_service.about().get(fields="user").execute()

def test_folder_access(drive_service):
    folder_id = st.secrets["DRIVE_REPORTS_FOLDER_ID"]
    return drive_service.files().get(
        fileId=folder_id,
        fields="id,name,mimeType"
    ).execute()

def list_accessible_folders(drive_service, limit=20):
    q = "mimeType='application/vnd.google-apps.folder' and trashed=false"
    res = drive_service.files().list(
        q=q,
        pageSize=limit,
        fields="files(id,name,parents)"
    ).execute()
    return res.get("files", [])

def main():
    st.title("🗂️ Drive Service Account Test (Folders Listing)")

    with st.sidebar:
        st.header("Diagnóstico Drive")

        try:
            drive, creds = get_drive_service_and_creds()

            about = drive_identity_smoke_test(drive, creds)
            st.success("Drive autenticado ✅")
            st.write("Identidad:", about.get("user", {}))

            # List folders visible to the service account
            try:
                folders = list_accessible_folders(drive, limit=50)
                st.write("Carpetas visibles para el Service Account:", folders)
            except Exception as list_error:
                st.error("No se pudo listar carpetas visibles para el Service Account.")
                st.exception(list_error)

            # Also try to access the configured folder id
            try:
                folder = test_folder_access(drive)
                st.success(f"Carpeta configurada accesible ✅ {folder['name']}")
            except Exception as folder_error:
                st.error("No se pudo acceder a la carpeta configurada (por ID).")
                st.exception(folder_error)

        except Exception as e:
            st.error("Drive auth falló (identidad/credenciales).")
            st.exception(e)

    st.info("Tip: Busca en la lista el nombre/ID de tu carpeta objetivo y usa ese ID en DRIVE_REPORTS_FOLDER_ID.")

if __name__ == "__main__":
    main()
