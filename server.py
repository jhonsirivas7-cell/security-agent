from flask import Flask, request, jsonify, render_template_string
import datetime

app = Flask(__name__)
ALERTAS = []
HEARTBEATS = {}

PANEL_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Panel de Seguridad</title>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="5">
    <style>
        body { background:#0a0a0a; color:#00ff88; font-family:monospace; padding:20px; }
        h1 { color:#00ff88; border-bottom:1px solid #00ff88; padding-bottom:10px; }
        .stats { display:flex; gap:20px; margin:20px 0; flex-wrap:wrap; }
        .stat { background:#111; border:1px solid #00ff88; padding:15px; border-radius:8px; text-align:center; min-width:120px; }
        .stat h2 { font-size:2em; margin:5px 0; }
        .stat small { opacity:0.6; }
        .alerta { background:#111; border-left:4px solid #00ff88; padding:12px; margin:8px 0; border-radius:4px; }
        .alerta.critico { border-color:#ff4444; background:#1a0000; }
        .alerta.advertencia { border-color:#ffaa00; background:#1a1000; }
        .alerta.info { border-color:#00aaff; }
        .tiempo { float:right; opacity:0.5; font-size:0.8em; }
        .ok { color:#00ff88; }
        .danger { color:#ff4444; }
        .cliente { background:#111; border:1px solid #333; padding:10px; border-radius:6px; display:inline-block; margin:5px; }
        .activo { border-color:#00ff88; }
    </style>
</head>
<body>
    <h1>🛡️ Panel de Ciberseguridad</h1>
    <div class="stats">
        <div class="stat"><small>Total alertas</small><h2>{{ total }}</h2></div>
        <div class="stat"><small>Criticas</small><h2 class="danger">{{ criticas }}</h2></div>
        <div class="stat"><small>Clientes activos</small><h2 class="ok">{{ clientes }}</h2></div>
    </div>

    <h2>💻 Clientes conectados</h2>
    {% for id, info in heartbeats.items() %}
    <div class="cliente activo">
        ✅ {{ id }}<br>
        <small>CPU: {{ info.cpu }}% | RAM: {{ info.ram }}% | {{ info.hora }}</small>
    </div>
    {% endfor %}
    {% if not heartbeats %}
    <div class="cliente">Sin clientes conectados aun</div>
    {% endif %}

    <h2>📋 Ultimas alertas</h2>
    {% for a in alertas %}
    <div class="alerta {{ a.nivel }}">
        <span class="tiempo">{{ a.timestamp }}</span>
        <strong>{{ a.titulo }}</strong><br>
        <small>{{ a.descripcion }}</small><br>
        <small>🖥️ {{ a.hostname }} | {{ a.sistema }}</small>
    </div>
    {% endfor %}
    {% if not alertas %}
    <div class="alerta">✅ Sin alertas. Todo tranquilo.</div>
    {% endif %}
</body>
</html>
"""

@app.route("/")
def panel():
    criticas = len([a for a in ALERTAS if a.get("nivel") == "critico"])
    return render_template_string(PANEL_HTML,
        alertas=list(reversed(ALERTAS[-20:])),
        total=len(ALERTAS),
        criticas=criticas,
        clientes=len(HEARTBEATS),
        heartbeats=HEARTBEATS)

@app.route("/api/alertas", methods=["POST"])
def recibir_alerta():
    data = request.json
    data["timestamp"] = datetime.datetime.now().strftime("%d/%m %H:%M:%S")
    ALERTAS.append(data)
    print(f"[ALERTA] {data.get('nivel','?').upper()} - {data.get('titulo','?')}")
    return __import__('flask').jsonify({"status": "ok"})

@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    data = request.json
    cliente_id = data.get("cliente_id", "desconocido")
    sistema = data.get("sistema", {})
    HEARTBEATS[cliente_id] = {
        "cpu":  sistema.get("cpu_uso", "?"),
        "ram":  sistema.get("ram_uso", "?"),
        "host": sistema.get("hostname", "?"),
        "hora": datetime.datetime.now().strftime("%H:%M:%S")
    }
    print(f"[HEARTBEAT] {cliente_id} — CPU:{sistema.get('cpu_uso')}% RAM:{sistema.get('ram_uso')}%")
    return __import__('flask').jsonify({"status": "ok"})

if __name__ == "__main__":
    print("="*50)
    print("  SERVIDOR DE SEGURIDAD v1.0")
    print("  Panel en: http://localhost:5000")
    print("="*50)
    app.run(host="0.0.0.0", port=5000, debug=False)
