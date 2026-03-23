from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, JSON, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import uuid, json, os

ADMIN_API_KEY = "shieldops-admin-2024-secreto"
ADMIN_PASSWORD = "Joel1325@"
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

app = FastAPI(title="ShieldOps Central Server", docs_url=None, redoc_url=None, openapi_url=None)
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

class EscaneoUSB(Base):
    __tablename__ = "escaneos"
    id             = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    cliente_id     = Column(String)
    hostname       = Column(String)
    fecha          = Column(DateTime, default=datetime.utcnow)
    usb_nombre     = Column(String)
    resultado      = Column(String)
    virus_count    = Column(Integer, default=0)
    ejecutables    = Column(Integer, default=0)
    ocultos        = Column(Integer, default=0)
    archivos_total = Column(Integer, default=0)
    archivos_detalle = Column(JSON, default=[])

class Heartbeat(Base):
    __tablename__ = "heartbeats"
    id         = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    cliente_id = Column(String)
    hostname   = Column(String)
    sistema    = Column(String)
    cpu        = Column(String)
    ram        = Column(String)
    fecha      = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

HEARTBEATS = {}
ALERTAS = []

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verificar_admin(api_key: str = Security(api_key_header)):
    if api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Acceso no autorizado")
    return api_key

def generar_license_key():
    return "SHIELD-" + "-".join([uuid.uuid4().hex[:4].upper() for _ in range(4)])

# ═══════════════════════════════════════
# PANEL ADMIN
# ═══════════════════════════════════════

LOGIN_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"><title>ShieldOps</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'JetBrains Mono',monospace;background:#080c10;color:#e2e8f0;min-height:100vh;display:flex;justify-content:center;align-items:center}
.box{background:#0d1117;border:1px solid #1e2d3d;border-radius:16px;padding:44px;width:400px}
.logo{font-family:'Syne',sans-serif;font-size:22px;color:#38bdf8;letter-spacing:3px;text-align:center;margin-bottom:6px;display:flex;align-items:center;justify-content:center;gap:10px}
.dot{width:8px;height:8px;background:#38bdf8;border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(56,189,248,0.4)}50%{box-shadow:0 0 0 6px rgba(56,189,248,0)}}
.sub{text-align:center;font-size:11px;color:#334155;margin-bottom:36px;letter-spacing:1px}
label{font-size:10px;color:#64748b;letter-spacing:1.5px;text-transform:uppercase;display:block;margin-bottom:6px}
input{width:100%;background:#080c10;border:1px solid #1e2d3d;color:#e2e8f0;padding:12px;border-radius:8px;margin-bottom:20px;font-family:'JetBrains Mono',monospace;font-size:13px}
input:focus{outline:none;border-color:#38bdf8}
button{width:100%;background:#38bdf8;color:#080c10;border:none;padding:13px;border-radius:8px;font-weight:700;font-size:13px;cursor:pointer;font-family:'JetBrains Mono',monospace;letter-spacing:1px}
button:hover{background:#0ea5e9}
.error{background:#1c0909;border:1px solid #7f1d1d;color:#f87171;font-size:11px;padding:10px;border-radius:6px;margin-bottom:16px;text-align:center;display:none}
</style>
</head>
<body>
<div class="box">
  <div class="logo"><div class="dot"></div>SHIELDOPS</div>
  <div class="sub">PANEL DE ADMINISTRACION</div>
  <div class="error" id="err">Credenciales incorrectas</div>
  <label>Usuario</label>
  <input type="text" id="user" placeholder="admin" onkeypress="if(event.key=='Enter')login()">
  <label>Contrasena</label>
  <input type="password" id="pass" placeholder="••••••••" onkeypress="if(event.key=='Enter')login()">
  <button onclick="login()">INGRESAR</button>
</div>
<script>
function login(){
  fetch('/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({usuario:document.getElementById('user').value,password:document.getElementById('pass').value})})
  .then(r=>r.json()).then(d=>{
    if(d.token){localStorage.setItem('token',d.token);window.location.href='/admin/panel';}
    else{document.getElementById('err').style.display='block';}
  });
}
</script>
</body></html>"""

PANEL_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"><title>ShieldOps Admin</title>
<meta http-equiv="refresh" content="15">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'JetBrains Mono',monospace;background:#080c10;color:#e2e8f0;display:flex;min-height:100vh}
.sidebar{width:200px;background:#0d1117;border-right:1px solid #1e2d3d;padding:0;flex-shrink:0;min-height:100vh}
.logo{font-family:'Syne',sans-serif;font-size:14px;color:#38bdf8;letter-spacing:2px;padding:20px;border-bottom:1px solid #1e2d3d;display:flex;align-items:center;gap:8px}
.logo-dot{width:7px;height:7px;background:#38bdf8;border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(56,189,248,0.4)}50%{box-shadow:0 0 0 5px rgba(56,189,248,0)}}
.nav-section{padding:14px 20px 6px;font-size:9px;color:#1e2d3d;letter-spacing:2px}
.nav-item{padding:10px 20px;font-size:11px;color:#64748b;cursor:pointer;display:flex;align-items:center;gap:8px;letter-spacing:1px;text-decoration:none}
.nav-item:hover{color:#e2e8f0;background:#131c27}
.nav-item.active{color:#38bdf8;background:#131c27;border-right:2px solid #38bdf8}
.nav-dot{width:5px;height:5px;border-radius:50%;background:currentColor;flex-shrink:0}
.main{flex:1;padding:24px;overflow-y:auto}
.toprow{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.page-title{font-family:'Syne',sans-serif;font-size:18px;color:#e2e8f0}
.page-sub{font-size:9px;color:#334155;margin-top:3px}
.live-badge{background:#0f2a1a;border:1px solid #166534;color:#4ade80;font-size:9px;padding:4px 12px;border-radius:20px;display:flex;align-items:center;gap:6px}
.live-dot{width:5px;height:5px;background:#4ade80;border-radius:50%;animation:blink 1.5s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0.2}}
.btn{background:#38bdf8;color:#080c10;border:none;padding:9px 18px;border-radius:7px;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;cursor:pointer;letter-spacing:1px}
.btn:hover{background:#0ea5e9}
.btn-red{background:#1c0909;color:#f87171;border:1px solid #7f1d1d}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.metric{background:#0d1117;border:1px solid #1e2d3d;border-radius:10px;padding:14px;position:relative;overflow:hidden}
.metric::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.m1::before{background:#38bdf8}.m2::before{background:#4ade80}.m3::before{background:#f87171}.m4::before{background:#fbbf24}
.metric-lbl{font-size:9px;color:#64748b;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px}
.metric-val{font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:#f1f5f9}
.metric-sub{font-size:9px;color:#334155;margin-top:3px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
.card{background:#0d1117;border:1px solid #1e2d3d;border-radius:10px;padding:16px;margin-bottom:14px}
.card-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}
.card-title{font-size:9px;color:#64748b;letter-spacing:1.5px;text-transform:uppercase;display:flex;align-items:center;gap:6px}
.card-title::before{content:'';display:block;width:3px;height:10px;background:#38bdf8;border-radius:2px}
.form-row{display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:10px;align-items:end}
input[type=text],input[type=email],select{background:#080c10;border:1px solid #1e2d3d;color:#e2e8f0;padding:9px 12px;border-radius:7px;font-family:'JetBrains Mono',monospace;font-size:11px;width:100%}
input:focus,select:focus{outline:none;border-color:#38bdf8}
table{width:100%;border-collapse:collapse;font-size:11px}
th{color:#334155;text-align:left;padding:8px;border-bottom:1px solid #1e2d3d;font-size:9px;letter-spacing:1.5px;text-transform:uppercase}
td{padding:10px 8px;border-bottom:1px solid #0a0e15;color:#94a3b8;vertical-align:top}
.badge{padding:2px 8px;border-radius:4px;font-size:9px;letter-spacing:1px;display:inline-block}
.b-basico{background:#131c27;color:#38bdf8}
.b-pro{background:#1a1000;color:#fbbf24}
.b-enterprise{background:#0f2a1a;color:#4ade80}
.b-activa{background:#0f2a1a;color:#4ade80}
.b-inactiva{background:#1c0909;color:#f87171}
.b-virus{background:#1c0909;color:#f87171}
.b-exec{background:#1c1a09;color:#fbbf24}
.b-oculto{background:#1a0f2a;color:#a78bfa}
.b-limpio{background:#0f2a1a;color:#4ade80}
.b-rootkit{background:#1c0909;color:#f87171}
.b-sospechoso{background:#1c1a09;color:#fbbf24}
.key{color:#38bdf8;font-size:10px}
.activity-row{display:flex;align-items:flex-start;gap:10px;padding:9px 0;border-bottom:1px solid #0a0e15}
.activity-row:last-child{border-bottom:none}
.act-icon{width:26px;height:26px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:11px;flex-shrink:0;font-weight:700}
.act-ok{background:#0f2a1a;color:#4ade80}
.act-warn{background:#1c1a09;color:#fbbf24}
.act-crit{background:#1c0909;color:#f87171}
.act-info{background:#131c27;color:#38bdf8}
.act-title{font-size:11px;color:#e2e8f0;margin-bottom:2px}
.act-desc{font-size:9px;color:#64748b}
.act-time{font-size:9px;color:#1e2d3d;margin-left:auto;flex-shrink:0;padding-left:8px}
.client-row{display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-bottom:1px solid #0a0e15}
.client-row:last-child{border-bottom:none}
.avatar{width:28px;height:28px;background:#131c27;border:1px solid #1e2d3d;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:9px;color:#38bdf8;font-weight:700;flex-shrink:0}
.chip{font-size:9px;padding:2px 7px;border-radius:4px;background:#131c27;color:#94a3b8;display:inline-block}
.chip.online{color:#4ade80}
.chip.offline{color:#f87171}
.usb-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:10px 0}
.usb-stat{text-align:center;background:#080c10;border-radius:6px;padding:8px}
.usb-stat-val{font-family:'Syne',sans-serif;font-size:18px;font-weight:800}
.usb-stat-lbl{font-size:8px;color:#64748b;letter-spacing:1px;margin-top:2px}
.action-btn{padding:3px 9px;border-radius:4px;font-size:9px;border:none;cursor:pointer;font-family:'JetBrains Mono',monospace;font-weight:700;margin:2px}
.ab-del{background:#1c0909;color:#f87171;border:1px solid #7f1d1d}
.ab-quar{background:#1c1a09;color:#fbbf24;border:1px solid #854d0e}
.ab-ign{background:#131c27;color:#64748b;border:1px solid #1e2d3d}
.file-path{color:#a78bfa;font-size:10px}
.file-meta{color:#334155;font-size:9px;margin-top:2px}
.hash{color:#334155;font-size:9px}
.success-msg{background:#0f2a1a;border:1px solid #166534;color:#4ade80;padding:10px;border-radius:6px;font-size:11px;margin-top:10px;display:none}
</style>
</head>
<body>
<div class="sidebar">
  <div class="logo"><div class="logo-dot"></div>SHIELDOPS</div>
  <div class="nav-section">MENU</div>
  <a class="nav-item active" onclick="showSection('dashboard')"><div class="nav-dot"></div>DASHBOARD</a>
  <a class="nav-item" onclick="showSection('licencias')"><div class="nav-dot"></div>LICENCIAS</a>
  <a class="nav-item" onclick="showSection('clientes')"><div class="nav-dot"></div>CLIENTES</a>
  <a class="nav-item" onclick="showSection('escaneos')"><div class="nav-dot"></div>ESCANEOS USB</a>
  <a class="nav-item" onclick="showSection('actividad')"><div class="nav-dot"></div>ACTIVIDAD</a>
  <div class="nav-section" style="margin-top:20px">SISTEMA</div>
  <a class="nav-item" onclick="logout()" style="color:#f87171"><div class="nav-dot"></div>CERRAR SESION</a>
</div>

<div class="main">

  <!-- DASHBOARD -->
  <div id="sec-dashboard">
    <div class="toprow">
      <div><div class="page-title">Dashboard</div><div class="page-sub" id="fecha-actual"></div></div>
      <div style="display:flex;gap:10px;align-items:center">
        <div class="live-badge"><div class="live-dot"></div>EN VIVO</div>
        <button class="btn" onclick="showSection('licencias')">+ NUEVA LICENCIA</button>
      </div>
    </div>
    <div class="metrics">
      <div class="metric m1"><div class="metric-lbl">Clientes activos</div><div class="metric-val" id="m-clientes">0</div><div class="metric-sub">licencias activas</div></div>
      <div class="metric m2"><div class="metric-lbl">USB escaneadas hoy</div><div class="metric-val" id="m-escaneos">0</div><div class="metric-sub">escaneos totales</div></div>
      <div class="metric m3"><div class="metric-lbl">Virus detectados</div><div class="metric-val" id="m-virus">0</div><div class="metric-sub">en todos los escaneos</div></div>
      <div class="metric m4"><div class="metric-lbl">Clientes online</div><div class="metric-val" id="m-online">0</div><div class="metric-sub">conectados ahora</div></div>
    </div>
    <div class="grid2">
      <div class="card">
        <div class="card-title">Actividad reciente</div>
        <div id="actividad-lista"><div style="font-size:11px;color:#334155;padding:10px 0">Sin actividad reciente</div></div>
      </div>
      <div class="card">
        <div class="card-title">Clientes conectados</div>
        <div id="clientes-online-lista"><div style="font-size:11px;color:#334155;padding:10px 0">Sin clientes conectados</div></div>
      </div>
    </div>
    <div class="card" id="ultimo-escaneo-card" style="display:none">
      <div class="card-hdr">
        <div class="card-title">Ultimo escaneo USB</div>
        <span id="ultimo-resultado" style="font-size:11px;font-weight:700"></span>
      </div>
      <div id="ultimo-escaneo-contenido"></div>
    </div>
  </div>

  <!-- LICENCIAS -->
  <div id="sec-licencias" style="display:none">
    <div class="toprow"><div class="page-title">Licencias</div></div>
    <div class="card">
      <div class="card-title">Crear nueva licencia</div>
      <div class="form-row" style="margin-top:10px">
        <div><label style="font-size:9px;color:#64748b;letter-spacing:1px;display:block;margin-bottom:5px">NOMBRE</label><input type="text" id="nuevo-nombre" placeholder="Nombre del cliente"></div>
        <div><label style="font-size:9px;color:#64748b;letter-spacing:1px;display:block;margin-bottom:5px">EMAIL</label><input type="email" id="nuevo-email" placeholder="email@empresa.com"></div>
        <div><label style="font-size:9px;color:#64748b;letter-spacing:1px;display:block;margin-bottom:5px">PLAN</label>
          <select id="nuevo-plan">
            <option value="basico">Basico — $29/mes</option>
            <option value="pro">Pro — $79/mes</option>
            <option value="enterprise">Enterprise — $199/mes</option>
          </select>
        </div>
        <button class="btn" onclick="crearLicencia()" style="align-self:end">CREAR</button>
      </div>
      <div class="success-msg" id="lic-creada"></div>
    </div>
    <div class="card">
      <div class="card-hdr">
        <div class="card-title">Todas las licencias</div>
        <button class="btn" onclick="cargarLicencias()" style="padding:6px 12px;font-size:10px">ACTUALIZAR</button>
      </div>
      <table>
        <tr><th>Cliente</th><th>Email</th><th>Plan</th><th>License Key</th><th>Expira</th><th>Estado</th><th>Acciones</th></tr>
        <tbody id="tabla-licencias"></tbody>
      </table>
    </div>
  </div>

  <!-- CLIENTES -->
  <div id="sec-clientes" style="display:none">
    <div class="toprow"><div class="page-title">Clientes</div></div>
    <div class="card">
      <div class="card-title">Estado de clientes</div>
      <div id="clientes-detalle" style="margin-top:10px"></div>
    </div>
  </div>

  <!-- ESCANEOS USB -->
  <div id="sec-escaneos" style="display:none">
    <div class="toprow"><div class="page-title">Escaneos USB</div></div>
    <div class="card">
      <div class="card-title">Historial de escaneos</div>
      <table>
        <tr><th>Cliente</th><th>Host</th><th>USB</th><th>Fecha</th><th>Virus</th><th>Ejecutables</th><th>Ocultos</th><th>Archivos</th><th>Resultado</th></tr>
        <tbody id="tabla-escaneos"></tbody>
      </table>
    </div>
    <div id="detalle-escaneo"></div>
  </div>

  <!-- ACTIVIDAD -->
  <div id="sec-actividad" style="display:none">
    <div class="toprow"><div class="page-title">Actividad</div></div>
    <div class="card">
      <div class="card-title">Todas las alertas</div>
      <div id="todas-alertas"></div>
    </div>
  </div>

</div>

<script>
var token = localStorage.getItem('token');
if(!token) window.location.href='/admin';
var T = {'Content-Type':'application/json','X-API-Key':token};

function showSection(s){
  ['dashboard','licencias','clientes','escaneos','actividad'].forEach(function(x){
    document.getElementById('sec-'+x).style.display = x===s ? 'block' : 'none';
  });
  document.querySelectorAll('.nav-item').forEach(function(el){
    el.classList.remove('active');
    if(el.getAttribute('onclick') && el.getAttribute('onclick').includes("'"+s+"'")){
      el.classList.add('active');
    }
  });
  if(s==='licencias') cargarLicencias();
  if(s==='escaneos') cargarEscaneos();
  if(s==='actividad') cargarActividad();
  if(s==='clientes') cargarClientesDetalle();
}
function logout(){localStorage.removeItem('token');window.location.href='/admin';}

function crearLicencia(){
  var datos={nombre:document.getElementById('nuevo-nombre').value,email:document.getElementById('nuevo-email').value,plan:document.getElementById('nuevo-plan').value};
  fetch('/api/licencias/crear',{method:'POST',headers:T,body:JSON.stringify(datos)})
  .then(r=>r.json()).then(d=>{
    var msg = document.getElementById('lic-creada');
    msg.innerHTML = 'Licencia creada: <strong>'+d.license_key+'</strong> — Plan: '+d.plan.toUpperCase()+' — Expira: '+d.expira.slice(0,10);
    msg.style.display='block';
    cargarLicencias();
    cargarDashboard();
  });
}

function cargarLicencias(){
  fetch('/api/licencias/listar',{headers:T}).then(r=>r.json()).then(function(licencias){
    var html='';
    licencias.forEach(function(l){
      html+='<tr>';
      html+='<td style="color:#e2e8f0">'+l.nombre+'</td>';
      html+='<td>'+l.email+'</td>';
      html+='<td><span class="badge b-'+l.plan+'">'+l.plan.toUpperCase()+'</span></td>';
      html+='<td class="key">'+l.key+'</td>';
      html+='<td>'+l.expira.slice(0,10)+'</td>';
      html+='<td><span class="badge b-'+(l.activa?'activa':'inactiva')+'">'+(l.activa?'ACTIVA':'INACTIVA')+'</span></td>';
      html+='<td><button class="action-btn ab-quar" onclick="generarFichero(\''+l.key+'\',\'registro\')">FICHERO 1</button><button class="action-btn ab-del" style="background:#131c27;color:#38bdf8;border-color:#1e2d3d" onclick="generarFichero(\''+l.key+'\',\'internet\')">FICHERO 2</button></td>';
      html+='</tr>';
    });
    document.getElementById('tabla-licencias').innerHTML = html;
  });
}

function generarFichero(key, tipo){
  fetch('/api/licencias/generar-fichero',{method:'POST',headers:T,body:JSON.stringify({license_key:key,tipo:tipo})})
  .then(r=>r.json()).then(function(d){
    var blob = new Blob([d.fichero], {type:'application/json'});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href=url; a.download=d.nombre; a.click();
  });
}

function cargarDashboard(){
  fetch('/api/licencias/listar',{headers:T}).then(r=>r.json()).then(function(l){
    document.getElementById('m-clientes').textContent = l.filter(x=>x.activa).length;
  });
  fetch('/api/escaneos/listar',{headers:T}).then(r=>r.json()).then(function(e){
    document.getElementById('m-escaneos').textContent = e.length;
    var virus = e.reduce(function(a,x){return a+x.virus_count;},0);
    document.getElementById('m-virus').textContent = virus;
    if(e.length > 0){
      var ultimo = e[e.length-1];
      var card = document.getElementById('ultimo-escaneo-card');
      card.style.display='block';
      document.getElementById('ultimo-resultado').textContent = ultimo.resultado === 'limpio' ? 'USB LIMPIA' : 'USB INFECTADA';
      document.getElementById('ultimo-resultado').style.color = ultimo.resultado === 'limpio' ? '#4ade80' : '#f87171';
      var html = '<div class="usb-stats">';
      html += '<div class="usb-stat"><div class="usb-stat-val" style="color:#f87171">'+ultimo.virus_count+'</div><div class="usb-stat-lbl">VIRUS</div></div>';
      html += '<div class="usb-stat"><div class="usb-stat-val" style="color:#fbbf24">'+ultimo.ejecutables+'</div><div class="usb-stat-lbl">EJECUTABLES</div></div>';
      html += '<div class="usb-stat"><div class="usb-stat-val" style="color:#a78bfa">'+ultimo.ocultos+'</div><div class="usb-stat-lbl">OCULTOS</div></div>';
      html += '<div class="usb-stat"><div class="usb-stat-val" style="color:#38bdf8">'+ultimo.archivos_total+'</div><div class="usb-stat-lbl">ARCHIVOS</div></div>';
      html += '</div>';
      if(ultimo.archivos_detalle && ultimo.archivos_detalle.length > 0){
        html += '<table><tr><th>Archivo</th><th>Tipo</th><th>Amenaza</th><th>Tamano</th><th>Hash MD5</th><th>Accion</th></tr>';
        ultimo.archivos_detalle.forEach(function(f){
          html += '<tr>';
          html += '<td><div class="file-path">'+f.ruta+'</div><div class="file-meta">'+f.modificado+'</div></td>';
          html += '<td><span class="badge b-'+f.tipo+'">'+f.tipo.toUpperCase()+'</span></td>';
          html += '<td style="color:'+(f.tipo==='virus'?'#f87171':f.tipo==='exec'?'#fbbf24':f.tipo==='oculto'?'#a78bfa':'#4ade80')+'">'+f.amenaza+'</td>';
          html += '<td>'+f.tamano+'</td>';
          html += '<td class="hash">'+f.hash+'</td>';
          html += '<td>';
          if(f.tipo !== 'limpio'){
            html += '<button class="action-btn ab-del">ELIMINAR</button>';
            html += '<button class="action-btn ab-quar">CUARENTENA</button>';
          } else {
            html += '<span style="color:#334155;font-size:10px">—</span>';
          }
          html += '</td></tr>';
        });
        html += '</table>';
      }
      document.getElementById('ultimo-escaneo-contenido').innerHTML = html;
    }
  });
  fetch('/api/heartbeat/listar',{headers:T}).then(r=>r.json()).then(function(h){
    document.getElementById('m-online').textContent = h.length;
    var html = '';
    if(h.length === 0){html='<div style="font-size:11px;color:#334155;padding:10px 0">Sin clientes conectados</div>';}
    h.forEach(function(c){
      html += '<div class="client-row">';
      html += '<div style="display:flex;align-items:center;gap:8px">';
      html += '<div class="avatar">'+c.cliente_id.slice(0,2).toUpperCase()+'</div>';
      html += '<div><div style="font-size:11px;color:#e2e8f0">'+c.cliente_id+'</div><div style="font-size:9px;color:#64748b">'+c.hostname+' — '+c.sistema+'</div></div>';
      html += '</div>';
      html += '<div style="display:flex;gap:6px"><span class="chip online">online</span><span class="chip">CPU '+c.cpu+'%</span><span class="chip">RAM '+c.ram+'%</span></div>';
      html += '</div>';
    });
    document.getElementById('clientes-online-lista').innerHTML = html;
  });
  fetch('/api/actividad',{headers:T}).then(r=>r.json()).then(function(a){
    var html = '';
    if(a.length === 0){html='<div style="font-size:11px;color:#334155;padding:10px 0">Sin actividad reciente</div>';}
    a.slice(-8).reverse().forEach(function(item){
      var cls = item.nivel==='critico'?'act-crit':item.nivel==='advertencia'?'act-warn':item.nivel==='info'?'act-info':'act-ok';
      var icon = item.nivel==='critico'?'!':item.nivel==='advertencia'?'?':item.nivel==='info'?'i':'v';
      html += '<div class="activity-row">';
      html += '<div class="act-icon '+cls+'">'+icon+'</div>';
      html += '<div><div class="act-title">'+item.titulo+'</div><div class="act-desc">'+item.descripcion+'</div></div>';
      html += '<div class="act-time">'+item.timestamp+'</div>';
      html += '</div>';
    });
    document.getElementById('actividad-lista').innerHTML = html;
  });
}

function cargarEscaneos(){
  fetch('/api/escaneos/listar',{headers:T}).then(r=>r.json()).then(function(escaneos){
    var html='';
    escaneos.reverse().forEach(function(e){
      html+='<tr>';
      html+='<td style="color:#e2e8f0">'+e.cliente_id+'</td>';
      html+='<td>'+e.hostname+'</td>';
      html+='<td>'+e.usb_nombre+'</td>';
      html+='<td>'+e.fecha.slice(0,16).replace('T',' ')+'</td>';
      html+='<td style="color:#f87171">'+e.virus_count+'</td>';
      html+='<td style="color:#fbbf24">'+e.ejecutables+'</td>';
      html+='<td style="color:#a78bfa">'+e.ocultos+'</td>';
      html+='<td style="color:#38bdf8">'+e.archivos_total+'</td>';
      html+='<td><span class="badge b-'+(e.resultado==='limpio'?'limpio':'virus')+'">'+(e.resultado==='limpio'?'LIMPIA':'INFECTADA')+'</span></td>';
      html+='</tr>';
    });
    document.getElementById('tabla-escaneos').innerHTML = html;
  });
}

function cargarActividad(){
  fetch('/api/actividad',{headers:T}).then(r=>r.json()).then(function(a){
    var html='';
    a.reverse().forEach(function(item){
      var cls = item.nivel==='critico'?'act-crit':item.nivel==='advertencia'?'act-warn':'act-info';
      var icon = item.nivel==='critico'?'!':item.nivel==='advertencia'?'?':'i';
      html += '<div class="activity-row">';
      html += '<div class="act-icon '+cls+'">'+icon+'</div>';
      html += '<div><div class="act-title">'+item.titulo+'</div><div class="act-desc">'+item.descripcion+' — '+item.hostname+'</div></div>';
      html += '<div class="act-time">'+item.timestamp+'</div>';
      html += '</div>';
    });
    document.getElementById('todas-alertas').innerHTML = html || '<div style="color:#334155;font-size:11px;padding:10px 0">Sin alertas</div>';
  });
}

function cargarClientesDetalle(){
  fetch('/api/heartbeat/listar',{headers:T}).then(r=>r.json()).then(function(h){
    var html='';
    if(h.length===0){html='<div style="color:#334155;font-size:11px">Sin clientes conectados</div>';}
    h.forEach(function(c){
      html += '<div class="client-row" style="padding:12px 0">';
      html += '<div style="display:flex;align-items:center;gap:10px">';
      html += '<div class="avatar" style="width:36px;height:36px;font-size:11px">'+c.cliente_id.slice(0,2).toUpperCase()+'</div>';
      html += '<div>';
      html += '<div style="font-size:12px;color:#e2e8f0;margin-bottom:3px">'+c.cliente_id+'</div>';
      html += '<div style="font-size:10px;color:#64748b">'+c.hostname+' | '+c.sistema+' | Ultima conexion: '+c.fecha.slice(0,16).replace('T',' ')+'</div>';
      html += '</div></div>';
      html += '<div style="display:flex;gap:8px">';
      html += '<span class="chip online">online</span>';
      html += '<span class="chip">CPU '+c.cpu+'%</span>';
      html += '<span class="chip">RAM '+c.ram+'%</span>';
      html += '</div></div>';
    });
    document.getElementById('clientes-detalle').innerHTML = html;
  });
}

document.getElementById('fecha-actual').textContent = new Date().toLocaleDateString('es-ES',{weekday:'long',year:'numeric',month:'long',day:'numeric'});
cargarDashboard();
</script>
</body></html>"""

@app.get("/admin", response_class=HTMLResponse)
def admin_login_page():
    return LOGIN_HTML

@app.post("/admin/login")
def admin_login_post(datos: dict):
    if datos.get("usuario") == "admin" and datos.get("password") == ADMIN_PASSWORD:
        return {"token": ADMIN_API_KEY}
    raise HTTPException(status_code=401, detail="Credenciales incorrectas")

@app.get("/admin/panel", response_class=HTMLResponse)
def admin_panel_page():
    return PANEL_HTML

# ═══════════════════════════════════════
# API LICENCIAS
# ═══════════════════════════════════════

@app.post("/api/licencias/crear")
def crear_licencia(datos: dict, db: Session = Depends(get_db), _: str = Depends(verificar_admin)):
    plan = datos.get("plan", "basico")
    modulos = {
        "basico":     {"clamav": True,  "yara": False, "virustotal": False, "reparacion": False},
        "pro":        {"clamav": True,  "yara": True,  "virustotal": False, "reparacion": True},
        "enterprise": {"clamav": True,  "yara": True,  "virustotal": True,  "reparacion": True},
    }.get(plan, {"clamav": True, "yara": False, "virustotal": False, "reparacion": False})
    licencia = Licencia(
        cliente_nombre=datos.get("nombre","Cliente"),
        cliente_email=datos.get("email",""),
        license_key=generar_license_key(),
        plan=plan,
        fecha_expira=datetime.utcnow() + timedelta(days=30),
        modulos=modulos
    )
    db.add(licencia)
    db.commit()
    return {"license_key": licencia.license_key, "plan": plan, "modulos": modulos, "expira": licencia.fecha_expira.isoformat()}

@app.post("/api/licencias/verificar")
def verificar_licencia(datos: dict, db: Session = Depends(get_db)):
    key = datos.get("license_key")
    device_id = datos.get("device_id")
    licencia = db.query(Licencia).filter(Licencia.license_key == key).first()
    if not licencia: raise HTTPException(status_code=404, detail="Licencia no encontrada")
    if not licencia.activa: raise HTTPException(status_code=403, detail="Licencia inactiva")
    if datetime.utcnow() > licencia.fecha_expira: raise HTTPException(status_code=403, detail="Licencia expirada")
    if not licencia.device_id:
        licencia.device_id = device_id
        db.commit()
    return {"valida": True, "plan": licencia.plan, "modulos": licencia.modulos, "personalizacion": licencia.personalizacion, "expira": licencia.fecha_expira.isoformat()}

@app.get("/api/licencias/listar")
def listar_licencias(db: Session = Depends(get_db), _: str = Depends(verificar_admin)):
    licencias = db.query(Licencia).all()
    return [{"id": l.id, "nombre": l.cliente_nombre, "email": l.cliente_email, "key": l.license_key, "plan": l.plan, "activa": l.activa, "expira": l.fecha_expira.isoformat(), "device_id": l.device_id} for l in licencias]

@app.post("/api/licencias/generar-fichero")
def generar_fichero(datos: dict, db: Session = Depends(get_db), _: str = Depends(verificar_admin)):
    key = datos.get("license_key")
    tipo = datos.get("tipo", "registro")
    licencia = db.query(Licencia).filter(Licencia.license_key == key).first()
    if not licencia: raise HTTPException(status_code=404, detail="Licencia no encontrada")
    if tipo == "registro":
        contenido = {"tipo": "registro", "license_key": licencia.license_key, "cliente": licencia.cliente_nombre, "plan": licencia.plan, "modulos": licencia.modulos, "personalizacion": licencia.personalizacion, "servidor": "https://security-agent-zhzi.onrender.com", "generado": datetime.utcnow().isoformat()}
    else:
        contenido = {"tipo": "internet", "license_key": licencia.license_key, "servidor": "https://security-agent-zhzi.onrender.com", "api_endpoint": "/api/licencias/verificar", "update_endpoint": "/api/updates/latest", "generado": datetime.utcnow().isoformat()}
    return {"fichero": json.dumps(contenido), "nombre": f"{tipo}_{key[:8]}.shield"}

# ═══════════════════════════════════════
# API ESCANEOS USB
# ═══════════════════════════════════════

@app.post("/api/escaneos/registrar")
def registrar_escaneo(datos: dict, db: Session = Depends(get_db)):
    escaneo = EscaneoUSB(
        cliente_id=datos.get("cliente_id","desconocido"),
        hostname=datos.get("hostname",""),
        usb_nombre=datos.get("usb_nombre","USB"),
        resultado=datos.get("resultado","limpio"),
        virus_count=datos.get("virus_count",0),
        ejecutables=datos.get("ejecutables",0),
        ocultos=datos.get("ocultos",0),
        archivos_total=datos.get("archivos_total",0),
        archivos_detalle=datos.get("archivos_detalle",[])
    )
    db.add(escaneo)
    db.commit()
    ALERTAS.append({"nivel": "critico" if datos.get("virus_count",0) > 0 else "info", "titulo": f"USB {'infectada' if datos.get('virus_count',0) > 0 else 'limpia'} — {datos.get('cliente_id')}", "descripcion": f"{datos.get('virus_count',0)} virus, {datos.get('ejecutables',0)} ejecutables, {datos.get('ocultos',0)} ocultos", "hostname": datos.get("hostname",""), "timestamp": datetime.now().strftime("%H:%M:%S")})
    return {"status": "ok"}

@app.get("/api/escaneos/listar")
def listar_escaneos(db: Session = Depends(get_db), _: str = Depends(verificar_admin)):
    escaneos = db.query(EscaneoUSB).all()
    return [{"id": e.id, "cliente_id": e.cliente_id, "hostname": e.hostname, "usb_nombre": e.usb_nombre, "fecha": e.fecha.isoformat(), "resultado": e.resultado, "virus_count": e.virus_count, "ejecutables": e.ejecutables, "ocultos": e.ocultos, "archivos_total": e.archivos_total, "archivos_detalle": e.archivos_detalle} for e in escaneos]

# ═══════════════════════════════════════
# API HEARTBEAT Y ALERTAS
# ═══════════════════════════════════════

@app.post("/api/alertas")
def recibir_alerta(datos: dict):
    datos["timestamp"] = datetime.now().strftime("%H:%M:%S")
    ALERTAS.append(datos)
    return {"status": "ok"}

@app.post("/api/heartbeat")
def heartbeat(datos: dict, db: Session = Depends(get_db)):
    cid = datos.get("cliente_id","?")
    sistema = datos.get("sistema",{})
    hb = Heartbeat(cliente_id=cid, hostname=sistema.get("hostname","?"), sistema=sistema.get("os","?"), cpu=str(sistema.get("cpu_uso","?")), ram=str(sistema.get("ram_uso","?")))
    db.query(Heartbeat).filter(Heartbeat.cliente_id == cid).delete()
    db.add(hb)
    db.commit()
    return {"status": "ok"}

@app.get("/api/heartbeat/listar")
def listar_heartbeats(db: Session = Depends(get_db), _: str = Depends(verificar_admin)):
    hbs = db.query(Heartbeat).all()
    return [{"cliente_id": h.cliente_id, "hostname": h.hostname, "sistema": h.sistema, "cpu": h.cpu, "ram": h.ram, "fecha": h.fecha.isoformat()} for h in hbs]

@app.get("/api/actividad")
def listar_actividad(_: str = Depends(verificar_admin)):
    return ALERTAS[-50:]

@app.post("/api/updates/latest")
def obtener_updates(datos: dict):
    return {"version": "2.0.0", "disponible": True}

@app.get("/")
def root():
    return {"status": "ShieldOps Central Server v2.0", "online": True}

if __name__ == "__main__":
    import uvicorn
    print("="*50)
    print("  SHIELDOPS CENTRAL SERVER v2.0")
    print("  Panel en: http://localhost:8000/admin")
    print("="*50)
    uvicorn.run(app, host="0.0.0.0", port=8000)
