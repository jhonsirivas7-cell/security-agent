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

app = FastAPI(title="ShieldOps Central Server")

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

if __name__ == "__main__":
    import uvicorn
    print("="*50)
    print("  SHIELDOPS CENTRAL SERVER v2.0")
    print("  Panel en: http://localhost:8000")
    print("  Docs en:  http://localhost:8000/docs")
    print("="*50)
    uvicorn.run(app, host="0.0.0.0", port=8000)
