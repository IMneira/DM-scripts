
from collections import Counter
import getpass
import paramiko

def obtener_usuarios_conectados():
    print("Introduce los datos del servidor remoto:")
    host = input("Host/IP: ")
    user = input("Usuario: ")
    password = getpass.getpass("Contraseña: ")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, username=user, password=password)
        stdin, stdout, stderr = ssh.exec_command('w -h')
        salida = stdout.read().decode()
        ssh.close()
    except Exception as e:
        print(f"Error de conexión SSH: {e}")
        return [], Counter()

    usuarios = []
    actividades = Counter()
    for linea in salida.splitlines():
        partes = linea.split()
        if len(partes) >= 5:
            usuario = partes[0]
            actividad = partes[4]  # Comando principal
            usuarios.append(usuario)
            actividades[(usuario, actividad)] += 1
    return usuarios, actividades

def imprimir_resumen_usuarios():
    usuarios, actividades = obtener_usuarios_conectados()
    usuarios_unicos = set(usuarios)
    print(f"Usuarios conectados: {', '.join(usuarios_unicos)}\n")
    for usuario in usuarios_unicos:
        print(f"Usuario: {usuario}")
        acciones = [(act, count) for (usr, act), count in actividades.items() if usr == usuario]
        total_acciones = sum(count for _, count in acciones)
        print(f"  Sesiones activas: {total_acciones}")
        print("  Acciones/procesos principales:")
        for accion, count in acciones:
            print(f"    {accion}: {count}")
        print()

if __name__ == "__main__":
    imprimir_resumen_usuarios()
