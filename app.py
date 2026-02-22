from google.auth.transport.requests import Request

def drive_identity_smoke_test(drive_service, creds):
    # 1) fuerza refresh del token (si esto falla, la key/SA está mal)
    creds.refresh(Request())
    # 2) llamada que SIEMPRE requiere auth y no depende de carpeta
    about = drive_service.about().get(fields="user").execute()
    return about

try:
    drive, creds = get_drive_service_and_creds()  # te dejo abajo esta función
    about = drive_identity_smoke_test(drive, creds)
    st.success(f"Drive autenticado ✅ (service account): {about.get('user', {})}")
except Exception as e:
    st.error("Drive auth falló (no es carpeta, es identidad/credenciales).")
    st.exception(e)
