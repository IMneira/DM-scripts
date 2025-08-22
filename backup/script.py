
import os
import shutil
import sys
import datetime
import time
from backup.paths import paths

BACKUP_DIR = "gdrt"

def make_backup():
	# Elimina backup anterior si existe
	if os.path.exists(BACKUP_DIR):
		shutil.rmtree(BACKUP_DIR)
	os.makedirs(BACKUP_DIR, exist_ok=True)
	for path in paths:
		if not path:
			continue
		abs_path = os.path.abspath(path)
		dest = os.path.join(BACKUP_DIR, os.path.basename(path))
		if os.path.isfile(abs_path):
			shutil.copy2(abs_path, dest)
		elif os.path.isdir(abs_path):
			shutil.copytree(abs_path, dest)
	# Cambiar permisos a solo lectura para todos
	for root, dirs, files in os.walk(BACKUP_DIR):
		for d in dirs:
			os.chmod(os.path.join(root, d), 0o555)
		for f in files:
			os.chmod(os.path.join(root, f), 0o444)
	os.chmod(BACKUP_DIR, 0o555)
	print(f"Backup creado en: {BACKUP_DIR}")

def restore_backup():
	if not os.path.exists(BACKUP_DIR):
		print("No existe backup para restaurar.")
		return
	for path in paths:
		if not path:
			continue
		src = os.path.join(BACKUP_DIR, os.path.basename(path))
		abs_path = os.path.abspath(path)
		if os.path.exists(src):
			if os.path.isfile(src):
				shutil.copy2(src, abs_path)
			elif os.path.isdir(src):
				if os.path.exists(abs_path):
					shutil.rmtree(abs_path)
				shutil.copytree(src, abs_path)
	print(f"Restauración completada desde: {BACKUP_DIR}")

def delete_originals():
	for path in paths:
		if not path:
			continue
		abs_path = os.path.abspath(path)
		if os.path.isfile(abs_path):
			os.remove(abs_path)
		elif os.path.isdir(abs_path):
			shutil.rmtree(abs_path)
	print("Archivos originales borrados.")

def wait_until(hour, minute, second):
	now = datetime.datetime.now()
	target = now.replace(hour=hour, minute=minute, second=second, microsecond=0)
	if target < now:
		target += datetime.timedelta(days=1)
	wait_seconds = (target - now).total_seconds()
	print(f"Esperando hasta las {hour:02d}:{minute:02d}:{second:02d} para iniciar el ciclo...")
	time.sleep(wait_seconds)

def ciclo():
	while True:
		make_backup()
		delete_originals()
		time.sleep(298)
		restore_backup()
		time.sleep(2)

def main():
	print("Ingrese la hora de inicio (formato 24h):")
	try:
		hour = int(input("Hora: "))
		minute = int(input("Minutos: "))
		second = int(input("Segundos: "))
	except Exception:
		print("Entrada inválida.")
		return
	wait_until(hour, minute, second)
	ciclo()

if __name__ == "__main__":
	main()
