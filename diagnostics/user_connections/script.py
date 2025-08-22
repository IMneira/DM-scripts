from collections import Counter
import subprocess
from diagnostics.allowed_users import users  # Importa la lista de usuarios permitidos

def obtener_usuarios_conectados():
    # Usar ps para obtener la mayor información posible de cada proceso de usuario
    resultado = subprocess.run([
        'ps', '-eo', 'user,pid,tty,stime,etime,comm,args', '--sort=user'
    ], capture_output=True, text=True)
    procesos = []
    for linea in resultado.stdout.splitlines()[1:]:  # Saltar encabezado
        partes = linea.split(None, 6)  # Solo 6 splits, el resto es args
        if len(partes) >= 7:
            usuario, pid, tty, stime, etime, comm, args = partes
            procesos.append({
                'usuario': usuario,
                'pid': pid,
                'tty': tty,
                'inicio': stime,
                'tiempo': etime,
                'comando': comm,
                'args': args
            })
    return procesos

def imprimir_resumen_usuarios():
    # Usa la lista importada de usuarios permitidos
    usuarios_permitidos = users
    procesos = obtener_usuarios_conectados()
    usuarios_unicos = sorted(set(p['usuario'] for p in procesos))
    print(f"Usuarios conectados y cantidad de procesos activos:\n")
    # Revisar usuarios no permitidos
    usuarios_no_permitidos = [u for u in usuarios_unicos if u not in usuarios_permitidos]
    if usuarios_no_permitidos:
        print("\033[91m[ALERTA] Usuarios NO permitidos detectados: {}\033[0m".format(', '.join(usuarios_no_permitidos)))
    for usuario in usuarios_unicos:
        procesos_usuario = [p for p in procesos if p['usuario'] == usuario]
        print(f"Usuario: {usuario} | Procesos activos: {len(procesos_usuario)}")

if __name__ == "__main__":
    imprimir_resumen_usuarios()
