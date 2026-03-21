import os, sys, subprocess, socket, platform, urllib.request, datetime

PANEL_URL  = "http://TU-SERVIDOR.com/api/alertas"
VERSION    = "1.0"

def log(msg):
    print(f"  >> {msg}")

def instalar_dependencias():
    log("Instalando dependencias...")
    subprocess.run([sys.executable, "-m", "pip", "install",
        "psutil", "requests", "colorama", "-q"], check=True)
    log("Dependencias instaladas correctamente")

def generar_id_cliente():
    hostname = socket.gethostname()
    mac = hex(uuid.getnode()) if __import__('uuid') else hostname
    return f"cliente_{hostname}_{datetime.datetime.now().strftime('%Y%m%d')}"

def crear_agente(cliente_id, panel_url):
    log("Creando agente de seguridad...")
    codigo = f'''
import os, sys, time, socket, platform, datetime, psutil, requests

PANEL_URL  = "{panel_url}/api/alertas"
HEARTBEAT  = "{panel_url}/api/heartbeat"
CLIENTE_ID = "{cliente_id}"
INTERVALO  = 30

def log(tipo, msg):
    hora = datetime.datetime.now().strftime("%H:%M:%S")
    iconos = {{"ok":"OK","scan":">>","peligro":"!!","info":"i"}}
    print(f"[{{hora}}] {{iconos.get(tipo,'?')}}  {{msg}}")

def enviar(url, datos):
    try:
        r = requests.post(url, json=datos, timeout=5)
        return r.status_code == 200
    except:
        return False

def heartbeat():
    datos = {{
        "cliente_id": CLIENTE_ID,
        "estado":     "activo",
        "timestamp":  datetime.datetime.now().isoformat(),
        "sistema": {{
            "os":       platform.system(),
            "hostname": socket.gethostname(),
            "cpu_uso":  psutil.cpu_percent(interval=1),
            "ram_uso":  psutil.virtual_memory().percent,
        }}
    }}
    enviar(HEARTBEAT, datos)

def alerta(nivel, titulo, descripcion):
    enviar(PANEL_URL, {{
        "cliente_id":  CLIENTE_ID,
        "nivel":       nivel,
        "titulo":      titulo,
        "descripcion": descripcion,
        "hostname":    socket.gethostname(),
        "sistema":     platform.system(),
        "timestamp":   datetime.datetime.now().isoformat(),
    }})

def escanear():
    malos = ["mimikatz","meterpreter","netcat","psexec"]
    for p in psutil.process_iter(["pid","name"]):
        try:
            if any(m in p.info["name"].lower() for m in malos):
                alerta("critico", "Proceso sospechoso", f"Se detecto: {{p.info['name']}}")
        except: pass
    puertos = {{4444:"Metasploit", 1337:"Backdoor", 31337:"Back Orifice"}}
    for c in psutil.net_connections():
        try:
            if c.laddr and c.laddr.port in puertos:
                alerta("critico", "Puerto peligroso", f"Puerto {{c.laddr.port}} abierto")
        except: pass

def main():
    while True:
        try:
            escanear()
            heartbeat()
            time.sleep(INTERVALO)
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception as e:
            time.sleep(10)

if __name__ == "__main__":
    main()
'''
    ruta = os.path.join(os.environ.get("PROGRAMFILES","C:\\Program Files"), "SecurityAgent")
    os.makedirs(ruta, exist_ok=True)
    with open(os.path.join(ruta, "agent.py"), "w") as f:
        f.write(codigo)
    log(f"Agente creado en: {ruta}")
    return ruta

def registrar_servicio(ruta_agente):
    log("Registrando servicio de Windows...")
    python_exe = sys.executable
    agente_py  = os.path.join(ruta_agente, "agent.py")
    subprocess.run([
        "schtasks", "/create",
        "/tn", "SecurityAgent",
        "/tr", f'"{python_exe}" "{agente_py}"',
        "/sc", "onstart",
        "/ru", "SYSTEM",
        "/f"
    ], capture_output=True)
    subprocess.run([
        "schtasks", "/run", "/tn", "SecurityAgent"
    ], capture_output=True)
    log("Servicio registrado y ejecutandose")

def main():
    print("\n" + "="*55)
    print("   INSTALADOR AGENTE DE CIBERSEGURIDAD v1.0")
    print("="*55 + "\n")

    cliente_id = f"cliente_{socket.gethostname()}"
    panel_url  = PANEL_URL

    log(f"ID de cliente: {cliente_id}")
    log(f"Servidor: {panel_url}")
    print("")

    try:
        instalar_dependencias()
        ruta = crear_agente(cliente_id, panel_url)
        registrar_servicio(ruta)
        print("\n" + "="*55)
        print("   INSTALACION COMPLETADA")
        print("   El agente esta protegiendo tu equipo")
        print("="*55)
    except Exception as e:
        print(f"\n  ERROR: {e}")
        print("  Ejecuta como Administrador e intenta de nuevo")

    input("\n  Presiona Enter para cerrar...")

if __name__ == "__main__":
    main()
