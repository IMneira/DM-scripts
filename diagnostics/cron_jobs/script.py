import pwd

def listar_crontabs_usuario(usuario):
    try:
        from subprocess import check_output
        output = check_output(['crontab', '-l', '-u', usuario], text=True)
        print(f"\n--- Cron jobs para el usuario: {usuario} ---")
        if output.strip():
            print(output)
        else:
            print("(Sin tareas programadas)")
    except Exception as e:
        print(f"No se pudo leer el crontab de {usuario}: {e}")

def listar_crontabs_todos_usuarios():
    usuarios = [u.pw_name for u in pwd.getpwall() if int(u.pw_uid) >= 1000 and 'home' in u.pw_dir]
    usuarios.append('root')
    usuarios = sorted(set(usuarios))
    for usuario in usuarios:
        listar_crontabs_usuario(usuario)

if __name__ == "__main__":
    print("Revisión de tareas programadas (cron) de todos los usuarios:")
    listar_crontabs_todos_usuarios()
