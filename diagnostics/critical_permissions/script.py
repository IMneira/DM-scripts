#!/usr/bin/env python3
import os
import subprocess

def find_suid_sgid():
	print("\n[+] Archivos SUID/SGID:")
	cmd = ["find", "/", "-perm", "/6000", "-type", "f", "-exec", "ls", "-l", "{}", ";"]
	result = subprocess.run(cmd, capture_output=True, text=True)
	if result.stdout:
		print(result.stdout)
	else:
		print("Ninguno encontrado.")
	if result.stderr:
		print("[!] Errores encontrados durante la búsqueda:")
		print(result.stderr)

def find_world_writable():
	print("\n[+] Archivos y directorios world-writable:")
	cmd = ["find", "/", "-xdev", "-perm", "-0002", "-type", "f", "-exec", "ls", "-l", "{}", ";"]
	result = subprocess.run(cmd, capture_output=True, text=True)
	if result.stdout:
		print(result.stdout)
	else:
		print("Ninguno encontrado.")
	if result.stderr:
		print("[!] Errores encontrados durante la búsqueda:")
		print(result.stderr)

def check_sudo_nopasswd():
	print("\n[+] Usuarios con permisos sudo sin contraseña:")
	try:
		with open("/etc/sudoers", "r") as f:
			lines = f.readlines()
		for line in lines:
			if "NOPASSWD" in line and not line.strip().startswith("#"):
				print(line.strip())
		sudoers_d = "/etc/sudoers.d/"
		if os.path.isdir(sudoers_d):
			for fname in os.listdir(sudoers_d):
				with open(os.path.join(sudoers_d, fname), "r") as f:
					for line in f:
						if "NOPASSWD" in line and not line.strip().startswith("#"):
							print(f"{fname}: {line.strip()}")
	except Exception as e:
		print(f"Error: {e}")

def check_root_shells():
	print("\n[+] Usuarios con shell de root:")
	try:
		with open("/etc/passwd", "r") as f:
			for line in f:
				parts = line.strip().split(":")
				if len(parts) > 6 and parts[0] != "root" and parts[6] in ["/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash"] and parts[2] == '0':
					print(line.strip())
	except Exception as e:
		print(f"Error: {e}")

def main():
	print("Revisión de permisos críticos en el servidor:\n")
	find_suid_sgid()
	find_world_writable()
	check_sudo_nopasswd()
	check_root_shells()

if __name__ == "__main__":
	main()
