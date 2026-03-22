from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import uuid, json, os

from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import uuid, json, os

ADMIN_API_KEY = "shieldops-admin-2024-secreto"
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

app = FastAPI(title="ShieldOps Central Server", docs_url=None, redoc_url=None, openapi_url=None)

from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

ADMIN_PASSWORD = "Joel1325@"

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def verificar_admin(api_key: str = Security(api_key_header)):
    if api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Acceso no autorizado")
    return api_key
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

DATABASE_URL = "sqlite:///./shieldops.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class Licencia(Base):
    __tablename__ = "licencias"
    id             = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    cliente_nombre = Column(String)
    cliente_email  = Column(String)
    license_key    = Column(String, unique=True)
    device_id      = Column(String, nullable=True)
    plan           = Column(String, default="basico")
    activa         = Column(Boolean, default=True)
    fecha_creacion = Column(DateTime, default=datetime.utcnow)
    fecha_expira   = Column(DateTime)
    modulos        = Column(JSON, default={"clamav": True, "yara": False, "virustotal": False, "reparacion": False})
    personalizacion= Column(JSON, default={"idioma": "es", "logo": "", "colores": {"primario": "#38bdf8", "fondo": "#080c10"}, "nombre_producto": "ShieldUSB"})

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def generar_license_key():
    return "SHIELD-" + "-".join([uuid.uuid4().hex[:4].upper() for _ in range(4)])

@app.get("/")
def root():
    return {"status": "ShieldOps Central Server v2.0", "online": True}

@app.post("/api/licencias/crear")
def crear_licencia(datos: dict, db: Session = Depends(get_db), _: str = Depends(verificar_admin)):
    plan = datos.get("plan", "basico")
    modulos = {
        "basico":     {"clamav": True,  "yara": False, "virustotal": False, "reparacion": False},
        "pro":        {"clamav": True,  "yara": True,  "virustotal": False, "reparacion": True},
        "enterprise": {"clamav": True,  "yara": True,  "virustotal": True,  "reparacion": True},
    }.get(plan, {"clamav": True, "yara": False, "virustotal": False, "reparacion": False})

    licencia = Licencia(
        cliente_nombre  = datos.get("nombre", "Cliente"),
        cliente_email   = datos.get("email", ""),
        license_key     = generar_license_key(),
        plan            = plan,
        fecha_expira    = datetime.utcnow() + timedelta(days=30),
        modulos         = modulos,
        personalizacion = datos.get("personalizacion", {
            "idioma": "es",
            "logo": "",
            "colores": {"primario": "#38bdf8", "fondo": "#080c10"},
            "nombre_producto": "ShieldUSB"
        })
    )
    db.add(licencia)
    db.commit()
    return {
        "license_key": licencia.license_key,
        "plan": plan,
        "modulos": modulos,
        "expira": licencia.fecha_expira.isoformat()
    }

@app.post("/api/licencias/verificar")
def verificar_licencia(datos: dict, db: Session = Depends(get_db)):
    key       = datos.get("license_key")
    device_id = datos.get("device_id")
    licencia  = db.query(Licencia).filter(Licencia.license_key == key).first()
    if not licencia:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")
    if not licencia.activa:
        raise HTTPException(status_code=403, detail="Licencia inactiva")
    if datetime.utcnow() > licencia.fecha_expira:
        raise HTTPException(status_code=403, detail="Licencia expirada")
    if not licencia.device_id:
        licencia.device_id = device_id
        db.commit()
    return {
        "valida": True,
        "plan": licencia.plan,
        "modulos": licencia.modulos,
        "personalizacion": licencia.personalizacion,
        "expira": licencia.fecha_expira.isoformat()
    }

@app.get("/api/licencias/listar")
def listar_licencias(db: Session = Depends(get_db), _: str = Depends(verificar_admin)):
    licencias = db.query(Licencia).all()
    return [{
        "id": l.id,
        "nombre": l.cliente_nombre,
        "email": l.cliente_email,
        "key": l.license_key,
        "plan": l.plan,
        "activa": l.activa,
        "expira": l.fecha_expira.isoformat(),
        "device_id": l.device_id
    } for l in licencias]

@app.post("/api/licencias/generar-fichero")
def generar_fichero(datos: dict, db: Session = Depends(get_db), _: str = Depends(verificar_admin)):
    key      = datos.get("license_key")
    tipo     = datos.get("tipo", "registro")
    licencia = db.query(Licencia).filter(Licencia.license_key == key).first()
    if not licencia:
        raise HTTPException(status_code=404, detail="Licencia no encontrada")
    if tipo == "registro":
        contenido = {
            "tipo": "registro",
            "license_key": licencia.license_key,
            "cliente": licencia.cliente_nombre,
            "plan": licencia.plan,
            "modulos": licencia.modulos,
            "personalizacion": licencia.personalizacion,
            "servidor": "https://shieldops-server.onrender.com",
            "generado": datetime.utcnow().isoformat()
        }
    else:
        contenido = {
            "tipo": "internet",
            "license_key": licencia.license_key,
            "servidor": "https://shieldops-server.onrender.com",
            "api_endpoint": "/api/licencias/verificar",
            "update_endpoint": "/api/updates/latest",
            "generado": datetime.utcnow().isoformat()
        }
    return {"fichero": json.dumps(contenido), "nombre": f"{tipo}_{key[:8]}.shield"}

@app.post("/api/updates/latest")
def obtener_updates(datos: dict):
    return {
        "version": "2.0.0",
        "clamav_db": "https://database.clamav.net",
        "yara_rules": "https://github.com/Yara-Rules/rules",
        "disponible": True
    }
@app.get("/admin", response_class=HTMLResponse)
def admin_login():
    return """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ShieldOps Admin</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'JetBrains Mono',monospace;background:#080c10;color:#e2e8f0;min-height:100vh;display:flex;justify-content:center;align-items:center}
.box{background:#0d1117;border:1px solid #1e2d3d;border-radius:16px;padding:40px;width:380px}
.logo{font-family:'Syne',sans-serif;font-size:22px;color:#38bdf8;letter-spacing:3px;text-align:center;margin-bottom:6px;display:flex;align-items:center;justify-content:center;gap:10px}
.dot{width:8px;height:8px;background:#38bdf8;border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(56,189,248,0.4)}50%{box-shadow:0 0 0 6px rgba(56,189,248,0)}}
.sub{text-align:center;font-size:11px;color:#334155;margin-bottom:32px}
label{font-size:10px;color:#64748b;letter-spacing:1.5px;text-transform:uppercase;display:block;margin-bottom:6px}
input{width:100%;background:#080c10;border:1px solid #1e2d3d;color:#e2e8f0;padding:12px;border-radius:8px;margin-bottom:20px;font-family:'JetBrains Mono',monospace;font-size:13px}
input:focus{outline:none;border-color:#38bdf8}
button{width:100%;background:#38bdf8;color:#080c10;border:none;padding:13px;border-radius:8px;font-weight:700;font-size:13px;cursor:pointer;font-family:'JetBrains Mono',monospace}
button:hover{background:#0ea5e9}
.error{color:#f87171;font-size:11px;text-align:center;margin-bottom:15px;display:none}
</style>
</head>
<body>
<div class="box">
  <div class="logo"><div class="dot"></div>SHIELDOPS</div>
  <div class="sub">PANEL DE ADMINISTRACION</div>
  <div class="error" id="err">Credenciales incorrectas</div>
  <label>Usuario</label>
  <input type="text" id="user" placeholder="admin">
  <label>Contrasena</label>
  <input type="password" id="pass" placeholder="••••••••">
  <button onclick="login()">INGRESAR</button>
</div>
<script>
function login(){
  var u=document.getElementById('user').value;
  var p=document.getElementById('pass').value;
  fetch('/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({usuario:u,password:p})})
  .then(r=>r.json()).then(d=>{
    if(d.token){
      localStorage.setItem('token',d.token);
      window.location.href='/admin/panel';
    } else {
      document.getElementById('err').style.display='block';
    }
  });
}
</script>
</body>
</html>
"""

@app.post("/admin/login")
def admin_login_post(datos: dict):
    if datos.get("usuario") == "admin" and datos.get("password") == ADMIN_PASSWORD:
        return {"token": ADMIN_API_KEY}
    raise HTTPException(status_code=401, detail="Credenciales incorrectas")

@app.get("/admin/panel", response_class=HTMLResponse)
def admin_panel():
    return """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ShieldOps Panel</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'JetBrains Mono',monospace;background:#080c10;color:#e2e8f0;min-height:100vh}
.topbar{background:#0d1117;border-bottom:1px solid #1e2d3d;padding:14px 24px;display:flex;justify-content:space-between;align-items:center}
.logo{font-family:'Syne',sans-serif;font-size:16px;color:#38bdf8;letter-spacing:2px;display:flex;align-items:center;gap:10px}
.dot{width:8px;height:8px;background:#38bdf8;border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(56,189,248,0.4)}50%{box-shadow:0 0 0 6px rgba(56,189,248,0)}}
.content{padding:24px}
.btn{background:#38bdf8;color:#080c10;border:none;padding:10px 20px;border-radius:8px;font-family:'JetBrains Mono',monospace;font-weight:700;cursor:pointer;font-size:12px}
.btn:hover{background:#0ea5e9}
.btn-red{background:#1c0909;color:#f87171;border:1px solid #7f1d1d}
.card{background:#0d1117;border:1px solid #1e2d3d;border-radius:10px;padding:20px;margin-bottom:16px}
.card-title{font-size:11px;color:#64748b;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:14px}
input,select{background:#080c10;border:1px solid #1e2d3d;color:#e2e8f0;padding:10px;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:12px;margin-right:8px;margin-bottom:8px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{color:#64748b;text-align:left;padding:8px;border-bottom:1px solid #1e2d3d;font-size:10px;letter-spacing:1px}
td{padding:10px 8px;border-bottom:1px solid #0d1117;color:#e2e8f0}
.badge{padding:3px 8px;border-radius:4px;font-size:10px}
.badge-basico{background:#131c27;color:#38bdf8}
.badge-pro{background:#1a1000;color:#fbbf24}
.badge-enterprise{background:#0f2a1a;color:#4ade80}
.badge-activa{background:#0f2a1a;color:#4ade80}
.badge-inactiva{background:#1c0909;color:#f87171}
</style>
</head>
<body>
<div class="topbar">
  <div class="logo"><div class="dot"></div>SHIELDOPS ADMIN</div>
  <button class="btn btn-red" onclick="logout()">SALIR</button>
</div>
<div class="content">
  <div class="card">
    <div class="card-title">Crear nueva licencia</div>
    <input type="text" id="nombre" placeholder="Nombre del cliente">
    <input type="email" id="email" placeholder="Email">
    <select id="plan">
      <option value="basico">Basico - $29/mes</option>
      <option value="pro">Pro - $79/mes</option>
      <option value="enterprise">Enterprise - $199/mes</option>
    </select>
    <button class="btn" onclick="crearLicencia()">CREAR LICENCIA</button>
    <div id="resultado" style="margin-top:10px;font-size:12px;color:#4ade80"></div>
  </div>
  <div class="card">
    <div class="card-title">Clientes activos</div>
    <button class="btn" onclick="cargarLicencias()" style="margin-bottom:14px">ACTUALIZAR</button>
    <table>
      <tr><th>NOMBRE</th><th>EMAIL</th><th>PLAN</th><th>LICENSE KEY</th><th>EXPIRA</th><th>ESTADO</th></tr>
      <tbody id="tabla"></tbody>
    </table>
  </div>
</div>
<script>
var token = localStorage.getItem('token');
if(!token) window.location.href='/admin';

function headers(){return {'Content-Type':'application/json','X-API-Key':token};}

function crearLicencia(){
  var datos={nombre:document.getElementById('nombre').value,email:document.getElementById('email').value,plan:document.getElementById('plan').value};
  fetch('/api/licencias/crear',{method:'POST',headers:headers(),body:JSON.stringify(datos)})
  .then(r=>r.json()).then(d=>{
    document.getElementById('resultado').innerHTML='Licencia creada: '+d.license_key;
    cargarLicencias();
  });
}

function cargarLicencias(){
  fetch('/api/licencias/listar',{headers:headers()})
  .then(r=>r.json()).then(licencias=>{
    var html='';
    licencias.forEach(function(l){
      html+='<tr>';
      html+='<td>'+l.nombre+'</td>';
      html+='<td>'+l.email+'</td>';
      html+='<td><span class="badge badge-'+l.plan+'">'+l.plan.toUpperCase()+'</span></td>';
      html+='<td style="color:#38bdf8">'+l.key+'</td>';
      html+='<td>'+l.expira.slice(0,10)+'</td>';
      html+='<td><span class="badge badge-'+(l.activa?'activa':'inactiva')+'">'+(l.activa?'ACTIVA':'INACTIVA')+'</span></td>';
      html+='</tr>';
    });
    document.getElementById('tabla').innerHTML=html;
  });
}

function logout(){localStorage.removeItem('token');window.location.href='/admin';}
cargarLicencias();
</script>
</body>
</html>
"""
if __name__ == "__main__":
    import uvicorn
    print("="*50)
    print("  SHIELDOPS CENTRAL SERVER v2.0")
    print("  Panel en: http://localhost:8000")
    print("  Docs en:  http://localhost:8000/docs")
    print("="*50)
    uvicorn.run(app, host="0.0.0.0", port=8000)
