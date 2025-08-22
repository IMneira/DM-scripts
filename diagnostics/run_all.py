import subprocess
import os
import sys

def es_script_py(path):
    return (
        path.endswith(".py")
        and not path.endswith("__init__.py")
        and not os.path.basename(path).startswith("__")
        and os.path.isfile(path)
    )

def encontrar_scripts(directorio):
    scripts = []
    for root, dirs, files in os.walk(directorio):
        # Ignorar __pycache__ y archivos ocultos
        dirs[:] = [d for d in dirs if not d.startswith("__") and not d.startswith(".")]
        for f in files:
            if es_script_py(f) and f != os.path.basename(__file__):
                scripts.append(os.path.join(root, f))
    return scripts

def ejecutar_scripts(scripts):
    for script in scripts:
        print(f"\n--- Ejecutando: {script} ---")
        try:
            resultado = subprocess.run(
                [sys.executable, script],
                capture_output=True,
                text=True,
                timeout=300
            )
            print(resultado.stdout)
            if resultado.stderr:
                print(f"[stderr]:\n{resultado.stderr}")
        except Exception as e:
            print(f"[!] Error ejecutando {script}: {e}")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    scripts = encontrar_scripts(base_dir)
    ejecutar_scripts(scripts)