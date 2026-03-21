import os, sys, time, socket, platform, datetime, psutil, requests

PANEL_URL  = "https://security-agent-zhzi.onrender.com/api/alertas"
HEARTBEAT  = "https://security-agent-zhzi.onrender.com/api/heartbeat"
CLIENTE_ID = f"cliente_{socket.gethostname()}"
INTERVALO  = 30

def log(tipo, msg):
    hora = datetime.datetime.now().strftime("%H:%M:%S")
    iconos = {"ok":"OK","scan":">>","peligro":"!!","info":"i"}
    print(f"[{hora}] {iconos.get(tipo,'?')}  {msg}")

def enviar(url, datos):
    try:
        r = requests.post(url, json=datos, timeout=5)
        return r.status_code == 200
    except:
        return False

def heartbeat():
    datos = {
        "cliente_id": CLIENTE_ID,
        "estado": "activo",
        "timestamp": datetime.datetime.now().isoformat(),
        "sistema": {
            "os":       platform.system(),
            "hostname": socket.gethostname(),
            "cpu_uso":  psutil.cpu_percent(interval=1),
            "ram_uso":  psutil.virtual_memory().percent,
        }
    }
    if enviar(HEARTBEAT, datos):
        log("ok", f"Heartbeat - CPU:{datos['sistema']['cpu_uso']}% RAM:{datos['sistema']['ram_uso']}%")
    else:
        log("info", "Sin conexion al servidor")

def alerta(nivel, titulo, descripcion):
    enviar(PANEL_URL, {
        "cliente_id":  CLIENTE_ID,
        "nivel":       nivel,
        "titulo":      titulo,
        "descripcion": descripcion,
        "hostname":    socket.gethostname(),
        "sistema":     platform.system(),
        "timestamp":   datetime.datetime.now().isoformat(),
    })

def escanear():
    log("scan", "Escaneando procesos...")
    malos = ["mimikatz","meterpreter","netcat","psexec"]
    for p in psutil.process_iter(["pid","name"]):
        try:
            if any(m in p.info["name"].lower() for m in malos):
                log("peligro", f"Proceso sospechoso: {p.info['name']}")
                alerta("critico", "Proceso sospechoso", f"Se detecto: {p.info['name']}")
        except: pass
    log("ok", "Procesos normales")
    puertos = {4444:"Metasploit", 1337:"Backdoor", 31337:"Back Orifice"}
    for c in psutil.net_connections():
        try:
            if c.laddr and c.laddr.port in puertos:
                alerta("critico", "Puerto peligroso", f"Puerto {c.laddr.port} abierto")
        except: pass
    log("ok", "Red normal")

def main():
    print("="*50)
    print("  SHIELDOPS AGENTE v2.0")
    print(f"  Host: {socket.gethostname()}")
    print(f"  ID: {CLIENTE_ID}")
    print(f"  Servidor: {PANEL_URL}")
    print("="*50)
    while True:
        try:
            escanear()
            heartbeat()
            log("info", f"Proximo escaneo en {INTERVALO} segundos...")
            print("")
            time.sleep(INTERVALO)
        except KeyboardInterrupt:
            sys.exit(0)
        except Exception as e:
            log("info", f"Error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()
