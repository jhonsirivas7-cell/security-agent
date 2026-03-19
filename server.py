from flask import Flask, request, jsonify, render_template_string
import datetime

app = Flask(__name__)
ALERTAS = []
HEARTBEATS = {}

PANEL_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>ShieldOps Panel</title>
<meta http-equiv="refresh" content="10">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'JetBrains Mono',monospace;background:#080c10;color:#e2e8f0;min-height:100vh}
.topbar{background:#0d1117;border-bottom:1px solid #1e2d3d;padding:14px 24px;display:flex;justify-content:space-between;align-items:center}
.logo{font-family:'Syne',sans-serif;font-weight:800;font-size:16px;color:#38bdf8;letter-spacing:2px;display:flex;align-items:center;gap:10px}
.logo-dot{width:8px;height:8px;background:#38bdf8;border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(56,189,248,0.4)}50%{opacity:0.7;box-shadow:0 0 0 6px rgba(56,189,248,0)}}
.status-pill{background:#0f2a1a;border:1px solid #166534;color:#4ade80;font-size:11px;padding:4px 12px;border-radius:20px;display:flex;align-items:center;gap:6px}
.status-dot{width:6px;height:6px;background:#4ade80;border-radius:50%;animation:pulse2 1.5s infinite}
@keyframes pulse2{0%,100%{opacity:1}50%{opacity:0.3}}
.content{padding:24px}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
.metric{background:#0d1117;border:1px solid #1e2d3d;border-radius:10px;padding:16px 20px;position:relative;overflow:hidden}
.metric::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.metric.blue::before{background:linear-gradient(90deg,#38bdf8,transparent)}
.metric.green::before{background:linear-gradient(90deg,#4ade80,transparent)}
.metric.red::before{background:linear-gradient(90deg,#f87171,transparent)}
.metric.amber::before{background:linear-gradient(90deg,#fbbf24,transparent)}
.metric-label{font-size:10px;color:#64748b;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:8px}
.metric-value{font-family:'Syne',sans-serif;font-size:28px;font-weight:800;color:#f1f5f9}
.metric-sub{font-size:10px;color:#38bdf8;margin-top:4px}
.metric-sub.ok{color:#4ade80}
.metric-sub.warn{color:#fbbf24}
.metric-sub.danger{color:#f87171}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
.card{background:#0d1117;border:1px solid #1e2d3d;border-radius:10px;padding:18px 20px}
.card-title{font-size:11px;color:#64748b;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.card-title::before{content:'';display:block;width:3px;height:12px;background:#38bdf8;border-radius:2px}
.client-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid #1e2d3d}
.client-row:last-child{border-bottom:none}
.client-info{display:flex;align-items:center;gap:10px}
.client-avatar{width:32px;height:32px;background:#0f2a1a;border:1px solid #166534;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:11px;color:#4ade80;font-weight:700}
.client-name{font-size:13px;color:#e2e8f0}
.client-host{font-size:10px;color:#64748b}
.client-stats{display:flex;gap:8px;flex-wrap:wrap}
.stat-chip{font-size:10px;color:#94a3b8;background:#131c27;padding:3px 8px;border-radius:4px}
.stat-chip.online{color:#4ade80}
.bar-row{margin-bottom:12px}
.bar-label{display:flex;justify-content:space-between;font-size:11px;color:#94a3b8;margin-bottom:4px}
.bar-track{background:#1e2d3d;border-radius:4px;height:6px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 1s}
.alert-row{display:flex;align-items:flex-start;gap:12px;padding:10px 0;border-bottom:1px solid #1e2d3d}
.alert-row:last-child{border-bottom:none}
.alert-icon{width:28px;height:28px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:12px;flex-shrink:0;margin-top:2px}
.alert-icon.ok{background:#0f2a1a;color:#4ade80}
.alert-icon.warn{background:#1c1a09;color:#fbbf24}
.alert-icon.crit{background:#1c0909;color:#f87171}
.alert-title{font-size:12px;color:#e2e8f0;margin-bottom:2px}
.alert-desc{font-size:10px;color:#64748b}
.alert-time{font-size:10px;color:#334155;margin-left:auto;flex-shrink:0}
.empty{color:#334155;font-size:12px;padding:12px 0}
.tag{display:inline-block;font-size:9px;padding:2px 8px;border-radius:4px;margin-left:6px;background:#1e2d3d;color:#38bdf8;border:1px solid #1e3a5f}
@media(max-width:700px){.metrics{grid-template-columns:repeat(2,1fr)}.grid2{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="topbar">
  <div class="logo"><div class="logo-dot"></div>SHIELDOPS</div>
  <div style="display:flex;align-items:center;gap:16px">
    <span style="font-size:11px;color:#334155">{{ fecha }}</span>
    <div class="status-pill"><div class="status-dot"></div>SISTEMA ACTIVO</div>
  </div>
</div>
<div class="content">
  <div class="metrics">
    <div class="metric blue">
      <div class="metric-label">Clientes activos</div>
      <div class="metric-value">{{ clientes }}</div>
      <div class="metric-sub">conectados ahora</div>
    </div>
    <div class="metric green">
      <div class="metric-label">Total alertas</div>
      <div class="metric-value">{{ total }}</div>
      <div class="metric-sub ok">registradas</div>
    </div>
    <div class="metric red">
      <div class="metric-label">Amenazas criticas</div>
      <div class="metric-value">{{ criticas }}</div>
      <div class="metric-sub {% if criticas > 0 %}danger{% else %}ok{% endif %}">
        {% if criticas > 0 %}atencion requerida{% else %}sin amenazas{% endif %}
      </div>
    </div>
    <div class="metric amber">
      <div class="metric-label">Advertencias</div>
      <div class="metric-value">{{ advertencias }}</div>
      <div class="metric-sub warn">detectadas</div>
    </div>
  </div>
  <div class="grid2">
    <div class="card">
      <div class="card-title">Clientes conectados</div>
      {% for id, info in heartbeats.items() %}
      <div class="client-row">
        <div class="client-info">
          <div class="client-avatar">{{ id[:2].upper() }}</div>
          <div>
            <div class="client-name">{{ id }}</div>
            <div class="client-host">{{ info.host }}<span class="tag">{{ info.os }}</span></div>
          </div>
        </div>
        <div class="client-stats">
          <div class="stat-chip">CPU {{ info.cpu }}%</div>
          <div class="stat-chip">RAM {{ info.ram }}%</div>
          <div class="stat-chip online">online {{ info.hora }}</div>
        </div>
      </div>
      {% endfor %}
      {% if not heartbeats %}
      <div class="empty">Sin clientes conectados</div>
      {% endif %}
    </div>
    <div class="card">
      <div class="card-title">Uso del sistema</div>
      {% for id, info in heartbeats.items() %}
      <div class="bar-row">
        <div class="bar-label"><span>CPU — {{ id }}</span><span style="color:#38bdf8">{{ info.cpu }}%</span></div>
        <div class="bar-track"><div class="bar-fill" style="background:#38bdf8;width:{{ info.cpu }}%"></div></div>
      </div>
      <div class="bar-row">
        <div class="bar-label"><span>RAM — {{ id }}</span><span style="color:#a78bfa">{{ info.ram }}%</span></div>
        <div class="bar-track"><div class="bar-fill" style="background:#a78bfa;width:{{ info.ram }}%"></div></div>
      </div>
      {% endfor %}
      {% if not heartbeats %}
      <div class="empty">Sin datos de sistema</div>
      {% endif %}
    </div>
  </div>
  <div class="card">
    <div class="card-title">Ultimas alertas</div>
    {% for a in alertas %}
    <div class="alert-row">
      <div class="alert-icon {% if a.nivel == 'critico' %}crit{% elif a.nivel == 'advertencia' %}warn{% else %}ok{% endif %}">
        {% if a.nivel == 'critico' %}!{% elif a.nivel == 'advertencia' %}?{% else %}v{% endif %}
      </div>
      <div>
        <div class="alert-title">{{ a.titulo }}</div>
        <div class="alert-desc">{{ a.descripcion }} — {{ a.hostname }}</div>
      </div>
      <div class="alert-time">{{ a.timestamp }}</div>
    </div>
    {% endfor %}
    {% if not alertas %}
    <div class="empty">Sin alertas. Todo tranquilo.</div>
    {% endif %}
  </div>
</div>
</body>
</html>
"""

@app.route("/")
def panel():
    criticas    = len([a for a in ALERTAS if a.get("nivel") == "critico"])
    advertencias = len([a for a in ALERTAS if a.get("nivel") == "advertencia"])
    return render_template_string(PANEL_HTML,
        alertas=list(reversed(ALERTAS[-20:])),
        total=len(ALERTAS),
        criticas=criticas,
        advertencias=advertencias,
        clientes=len(HEARTBEATS),
        heartbeats=HEARTBEATS,
        fecha=datetime.datetime.now().strftime("%d/%m/%Y %H:%M"))

@app.route("/api/alertas", methods=["POST"])
def recibir_alerta():
    data = request.json
    data["timestamp"] = datetime.datetime.now().strftime("%d/%m %H:%M:%S")
    ALERTAS.append(data)
    print(f"[ALERTA] {data.get('nivel','?').upper()} - {data.get('titulo','?')}")
    return jsonify({"status": "ok"})

@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    data    = request.json
    cid     = data.get("cliente_id","?")
    sistema = data.get("sistema",{})
    HEARTBEATS[cid] = {
        "cpu":  sistema.get("cpu_uso","?"),
        "ram":  sistema.get("ram_uso","?"),
        "host": sistema.get("hostname","?"),
        "os":   sistema.get("os","?"),
        "hora": datetime.datetime.now().strftime("%H:%M:%S")
    }
    print(f"[HEARTBEAT] {cid} - CPU:{sistema.get('cpu_uso')}%")
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    print("="*50)
    print("  SHIELDOPS SERVIDOR v1.0")
    print("  Panel en: http://localhost:5000")
    print("="*50)
    app.run(host="0.0.0.0", port=5000, debug=False)
