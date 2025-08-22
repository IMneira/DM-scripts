
import os
import time
import pwd
from diagnostics.allowed_users import users as allowed_users

def archivos_editados_ultimas_2h_no_permitidos(directorio):
	ahora = time.time()
	tiempo = 60 * 60 * 2  # 2 horas
	archivos_recientes = []
	for root, dirs, files in os.walk(directorio):
		for nombre in files:
			ruta = os.path.join(root, nombre)
			try:
				mtime = os.path.getmtime(ruta)
				if ahora - mtime <= tiempo:
					# Obtener el usuario propietario del archivo
					uid = os.stat(ruta).st_uid
					usuario = pwd.getpwuid(uid).pw_name
					if usuario not in allowed_users:
						archivos_recientes.append((ruta, time.ctime(mtime), usuario))
			except Exception:
				continue
	return archivos_recientes

if __name__ == "__main__":
	directorio = "/"  # Directorio raíz para un servidor Debian
	archivos = archivos_editados_ultimas_2h_no_permitidos(directorio)
	if archivos:
		print("Archivos editados en las últimas 2 horas por usuarios NO permitidos:")
		for ruta, fecha, usuario in archivos:
			print(f"{ruta} (modificado: {fecha}) [usuario: {usuario}]")
	else:
		print("No se encontraron archivos editados en las últimas 2 horas por usuarios NO permitidos.")
