import os, sys, time, socket, platform, datetime, psutil, requests, hashlib, json, subprocess, glob

PANEL_URL  = "https://security-agent-zhzi.onrender.com/api/alertas"
HEARTBEAT  = "https://security-agent-zhzi.onrender.com/api/heartbeat"
CLIENTE_ID = "cliente_001"
INTERVALO  = 30

ESTADO = {
    "usbs_conocidas": set(),
    "hashes_sistema": {},
    "usbs_inicializado": False,
    "sistema_inicializado": False,
}

def log(tipo, msg):
    hora = datetime.datetime.now().strftime("%H:%M:%S")
    iconos = {"ok":"OK","scan":">>","peligro":"!!","info":"i","warn":"!!"}
    print(f"[{hora}] {iconos.get(tipo,'?')}  {msg}")

def enviar(url, datos):
    try:
        r = requests.post(url, json=datos, timeout=5)
        return r.status_code == 200
    except:
        return False

def alerta(nivel, titulo, descripcion, extra={}):
    datos = {
        "cliente_id":  CLIENTE_ID,
        "nivel":       nivel,
        "titulo":      titulo,
        "descripcion": descripcion,
        "hostname":    socket.gethostname(),
        "sistema":     platform.system(),
        "timestamp":   datetime.datetime.now().isoformat(),
        "datos_extra": extra
    }
    if enviar(PANEL_URL, datos):
        log("ok", f"Alerta enviada: {titulo}")

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
        cpu = datos["sistema"]["cpu_uso"]
        ram = datos["sistema"]["ram_uso"]
        log("ok", f"Heartbeat - CPU:{cpu}% RAM:{ram}%")

# ══════════════════════════════════════════
# 1. PROCESOS SOSPECHOSOS
# ══════════════════════════════════════════
def detectar_procesos():
    log("scan", "Revisando procesos...")
    malos = ["mimikatz","meterpreter","netcat","psexec","wce","pwdump","fgdump"]
    for p in psutil.process_iter(["pid","name"]):
        try:
            if any(m in p.info["name"].lower() for m in malos):
                log("peligro", f"Proceso sospechoso: {p.info['name']}")
                alerta("critico", "Proceso sospechoso detectado",
                    f"Se detecto el proceso {p.info['name']} (PID:{p.info['pid']})")
        except: pass
    log("ok", "Procesos normales")

# ══════════════════════════════════════════
# 2. PUERTOS PELIGROSOS
# ══════════════════════════════════════════
def detectar_puertos():
    log("scan", "Revisando puertos...")
    puertos = {4444:"Metasploit", 1337:"Backdoor", 31337:"Back Orifice", 12345:"NetBus"}
    for c in psutil.net_connections():
        try:
            if c.laddr and c.laddr.port in puertos:
                log("peligro", f"Puerto peligroso: {c.laddr.port}")
                alerta("critico", "Puerto peligroso abierto",
                    f"Puerto {c.laddr.port} abierto ({puertos[c.laddr.port]})")
        except: pass
    log("ok", "Red normal")

# ══════════════════════════════════════════
# 3. DETECTAR USB CONECTADAS
# ══════════════════════════════════════════
def detectar_usb():
    log("scan", "Revisando dispositivos USB...")
    try:
        usbs_actuales = set()
        particiones = psutil.disk_partitions()
        for p in particiones:
            if "removable" in p.opts.lower() or (platform.system() == "Windows" and len(p.device) == 3):
                usbs_actuales.add(p.device)

        if not ESTADO["usbs_inicializado"]:
            ESTADO["usbs_conocidas"] = usbs_actuales.copy()
            ESTADO["usbs_inicializado"] = True
            log("ok", f"USB inicializado: {len(usbs_actuales)} dispositivos")
            return

        nuevas = usbs_actuales - ESTADO["usbs_conocidas"]
        removidas = ESTADO["usbs_conocidas"] - usbs_actuales

        for usb in nuevas:
            log("peligro", f"Nueva USB detectada: {usb}")
            alerta("advertencia", "USB conectada",
                f"Se conecto un dispositivo USB en {usb}. Verifica si es autorizado.")

        for usb in removidas:
            log("info", f"USB desconectada: {usb}")

        ESTADO["usbs_conocidas"] = usbs_actuales

        if not nuevas:
            log("ok", "Sin nuevas USB")
    except Exception as e:
        log("info", f"Error USB: {e}")

# ══════════════════════════════════════════
# 4. DETECTAR CAPTURAS DE PANTALLA
# ══════════════════════════════════════════
def detectar_capturas():
    log("scan", "Revisando capturas de pantalla...")
    try:
        procesos_captura = ["snippingtool","snagit","greenshot","sharex",
                           "screenpresso","hypersnap","screenshot"]
        sospechosos = []
        for p in psutil.process_iter(["pid","name","create_time"]):
            try:
                nombre = p.info["name"].lower()
                if any(c in nombre for c in procesos_captura):
                    edad = time.time() - p.info["create_time"]
                    if edad < 300:
                        sospechosos.append(p.info["name"])
            except: pass

        carpeta = os.path.join(os.environ.get("USERPROFILE", os.path.expanduser("~")), "Pictures")
        archivos_nuevos = []
        if os.path.exists(carpeta):
            for f in glob.glob(os.path.join(carpeta, "*.png")) + glob.glob(os.path.join(carpeta, "*.jpg")):
                if time.time() - os.path.getmtime(f) < 300:
                    archivos_nuevos.append(os.path.basename(f))

        if sospechosos:
            log("warn", f"Herramienta de captura activa: {sospechosos}")
            alerta("advertencia", "Captura de pantalla detectada",
                f"Se detecto la herramienta {sospechosos[0]} activa en el sistema.")
        elif archivos_nuevos:
            log("warn", f"Capturas recientes: {len(archivos_nuevos)}")
            alerta("advertencia", "Imagenes nuevas detectadas",
                f"Se encontraron {len(archivos_nuevos)} imagenes nuevas en Imagenes.")
        else:
            log("ok", "Sin capturas sospechosas")
    except Exception as e:
        log("info", f"Error capturas: {e}")

# ══════════════════════════════════════════
# 5. DETECTAR ARCHIVOS DESCARGADOS SOSPECHOSOS
# ══════════════════════════════════════════
def detectar_descargas():
    log("scan", "Revisando descargas...")
    try:
        extensiones_peligrosas = [".exe",".bat",".ps1",".vbs",".cmd",".msi",".dll",".scr"]
        carpeta = os.path.join(os.environ.get("USERPROFILE", os.path.expanduser("~")), "Downloads")

        if not os.path.exists(carpeta):
            log("ok", "Carpeta de descargas no encontrada")
            return

        sospechosos = []
        for f in os.listdir(carpeta):
            ruta = os.path.join(carpeta, f)
            ext = os.path.splitext(f)[1].lower()
            if ext in extensiones_peligrosas:
                edad = time.time() - os.path.getmtime(ruta)
                if edad < 3600:
                    sospechosos.append(f)

        if sospechosos:
            log("warn", f"Archivos sospechosos en descargas: {len(sospechosos)}")
            alerta("advertencia", "Archivos peligrosos descargados",
                f"Se encontraron {len(sospechosos)} archivos ejecutables recientes: {', '.join(sospechosos[:3])}")
        else:
            log("ok", "Descargas limpias")
    except Exception as e:
        log("info", f"Error descargas: {e}")

# ══════════════════════════════════════════
# 6. DETECTAR CAMBIOS EN ARCHIVOS DEL SISTEMA
# ══════════════════════════════════════════
def hash_archivo(ruta):
    try:
        h = hashlib.md5()
        with open(ruta, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except: return None

def detectar_cambios_sistema():
    log("scan", "Revisando archivos del sistema...")
    try:
        if platform.system() == "Windows":
            archivos = [
                os.path.join(os.environ.get("WINDIR","C:\\Windows"), "System32", "drivers", "etc", "hosts"),
                os.path.join(os.environ.get("WINDIR","C:\\Windows"), "System32", "cmd.exe"),
            ]
        else:
            archivos = ["/etc/hosts", "/etc/passwd", "/etc/sudoers"]

        cambios = []
        for ruta in archivos:
            if not os.path.exists(ruta):
                continue
            h = hash_archivo(ruta)
            if h is None:
                continue
            nombre = os.path.basename(ruta)
            if not ESTADO["sistema_inicializado"]:
                ESTADO["hashes_sistema"][ruta] = h
            elif ESTADO["hashes_sistema"].get(ruta) != h:
                cambios.append(nombre)
                ESTADO["hashes_sistema"][ruta] = h

        if not ESTADO["sistema_inicializado"]:
            ESTADO["sistema_inicializado"] = True
            log("ok", f"Archivos del sistema registrados: {len(ESTADO['hashes_sistema'])}")
            return

        if cambios:
            log("peligro", f"Archivos modificados: {cambios}")
            alerta("critico", "Archivo del sistema modificado",
                f"Se detectaron cambios en: {', '.join(cambios)}. Posible ataque.")
        else:
            log("ok", "Archivos del sistema intactos")
    except Exception as e:
        log("info", f"Error sistema: {e}")

# ══════════════════════════════════════════
# 7. DETECTAR MINERO DE CRYPTO (CPU ALTA)
# ══════════════════════════════════════════
def detectar_minero():
    log("scan", "Revisando uso de CPU...")
    try:
        cpu = psutil.cpu_percent(interval=2)
        if cpu > 85:
            procesos_cpu = []
            for p in psutil.process_iter(["pid","name","cpu_percent"]):
                try:
                    p.cpu_percent(interval=0.1)
                except: pass
            time.sleep(1)
            for p in psutil.process_iter(["pid","name","cpu_percent"]):
                try:
                    if p.cpu_percent() > 50:
                        procesos_cpu.append(f"{p.info['name']}({p.info['cpu_percent']:.0f}%)")
                except: pass

            log("warn", f"CPU muy alta: {cpu}% - Posible minero")
            alerta("advertencia", "Uso excesivo de CPU detectado",
                f"CPU al {cpu}%. Posible minero de criptomonedas. Procesos: {', '.join(procesos_cpu[:3])}")
        else:
            log("ok", f"CPU normal: {cpu}%")
    except Exception as e:
        log("info", f"Error CPU: {e}")

# ══════════════════════════════════════════
# 8. DETECTAR INTENTOS DE LOGIN FALLIDOS
# ══════════════════════════════════════════
def detectar_logins():
    log("scan", "Revisando intentos de login...")
    try:
        if platform.system() == "Windows":
            cmd = 'wevtutil qe Security /q:"*[System[EventID=4625]]" /c:5 /rd:true /f:text'
            resultado = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            count = resultado.stdout.count("An account failed to log on")
            if count > 3:
                log("warn", f"Intentos fallidos de login: {count}")
                alerta("advertencia", "Multiples intentos de acceso fallidos",
                    f"Se detectaron {count} intentos fallidos de login. Posible ataque de fuerza bruta.")
            else:
                log("ok", f"Logins normales ({count} fallidos)")
        else:
            log_path = "/var/log/auth.log"
            if os.path.exists(log_path):
                with open(log_path, "r") as f:
                    lineas = f.readlines()[-200:]
                fallos = [l for l in lineas if "Failed password" in l]
                if len(fallos) > 5:
                    log("warn", f"Intentos SSH fallidos: {len(fallos)}")
                    alerta("advertencia", "Posible ataque de fuerza bruta SSH",
                        f"Se detectaron {len(fallos)} intentos fallidos de SSH.")
                else:
                    log("ok", f"Logins normales ({len(fallos)} fallidos)")
    except Exception as e:
        log("info", f"Error logins: {e}")

# ══════════════════════════════════════════
# MOTOR PRINCIPAL
# ══════════════════════════════════════════
def escaneo_completo():
    print("\n" + "-"*50)
    log("info", f"Escaneo - {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print("-"*50)
    detectar_procesos()
    detectar_puertos()
    detectar_usb()
    detectar_capturas()
    detectar_descargas()
    detectar_cambios_sistema()
    detectar_minero()
    detectar_logins()
    heartbeat()
    log("info", f"Proximo escaneo en {INTERVALO} segundos...")

def main():
    print("="*50)
    print("  SHIELDOPS AGENTE v2.0")
    print(f"  Host: {socket.gethostname()} | {platform.system()}")
    print(f"  Servidor: {PANEL_URL}")
    print("  Detecciones: 8 modulos activos")
    print("="*50)
    while True:
        try:
            escaneo_completo()
            time.sleep(INTERVALO)
        except KeyboardInterrupt:
            log("info", "Agente detenido.")
            sys.exit(0)
        except Exception as e:
            log("info", f"Error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()
