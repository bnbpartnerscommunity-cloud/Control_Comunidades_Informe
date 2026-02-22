
import streamlit as st
from google.oauth2 import service_account
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

st.set_page_config(page_title="Control Comunidades - Drive Test", layout="wide")

DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive.file"]

def get_drive_service_and_creds():
    pk = st.secrets.get("GCP_PRIVATE_KEY", "")
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


def main():
    st.title("🗂️ Drive Service Account Test")

    with st.sidebar:
        st.header("Diagnóstico Drive")

        try:
            drive, creds = get_drive_service_and_creds()
            about = drive_identity_smoke_test(drive, creds)
            st.success(f"Drive autenticado ✅")
            st.write("Identidad:", about.get("user", {}))

            try:
                folder = test_folder_access(drive)
                st.success(f"Carpeta accesible ✅ {folder['name']}")
            except Exception as folder_error:
                st.error("No se pudo acceder a la carpeta.")
                st.exception(folder_error)

        except Exception as e:
            st.error("Drive auth falló (identidad/credenciales).")
            st.exception(e)

if __name__ == "__main__":
    main()
