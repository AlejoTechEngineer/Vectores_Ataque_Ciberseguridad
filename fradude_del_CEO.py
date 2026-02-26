# ── Script OSINT — Recopilación de estructura organizativa pública (Python) ──
# SOLO EDUCATIVO — Muestra cómo los atacantes recopilan info con OSINT
# Usa la API pública de LinkedIn (datos que cualquiera puede ver)

import requests, re # type: ignore
from bs4 import BeautifulSoup # type: ignore

def buscar_directivos_linkedin(empresa: str) -> list:
    """
    Simula la búsqueda de directivos en LinkedIn.
    En un ataque real se usarían herramientas como theHarvester,
    Hunter.io, o Maltego para automatizar la recopilación de OSINT.
    """
    print(f'[OSINT] Buscando directivos de: {empresa}')
    # Búsqueda en Google: 'site:linkedin.com/in CEO empresa'
    query = f'site:linkedin.com/in "{empresa}" (CEO OR CFO OR Director OR "Finance Manager")'
    print(f'[OSINT] Query Google: {query}')

    # En la práctica se parsearía el HTML de los resultados
    # Aquí simulamos los resultados encontrados
    resultados_simulados = [
        {'nombre': 'Ana García López',  'cargo': 'CEO',             'email_probado': 'agarcia@empresa.es'},
        {'nombre': 'Carlos Ruiz Pérez', 'cargo': 'CFO',             'email_probado': 'cruiz@empresa.es'},
        {'nombre': 'María Torres',      'cargo': 'Finance Manager', 'email_probado': 'mtorres@empresa.es'},
    ]
    return resultados_simulados

def inferir_formato_email(nombre: str, dominio: str) -> list:
    """
    Genera variantes de email a partir del nombre.
    Los atacantes validan cuál existe con herramientas como Hunter.io.
    """
    partes  = nombre.lower().split()
    inicial = partes[0][0] if partes else ''
    apellido = partes[-1] if len(partes) > 1 else ''

    formatos = [
        f'{partes[0]}.{apellido}@{dominio}',       # ana.garcia@empresa.es
        f'{inicial}{apellido}@{dominio}',           # agarcia@empresa.es
        f'{partes[0]}@{dominio}',                   # ana@empresa.es
        f'{apellido}@{dominio}',                    # garcia@empresa.es
    ]
    return formatos

# Ejemplo de uso (solo con datos públicos)
directivos = buscar_directivos_linkedin('MiEmpresa S.A.')
for d in directivos:
    emails = inferir_formato_email(d['nombre'], 'miempresa.es')
    print(f'Directivo: {d["nombre"]} ({d["cargo"]})')
    print(f'Emails probables: {emails}')
    print()

# ── Analizador de cabeceras para detectar email spoofing (Python — DEFENSIVO) ──
# Herramienta DEFENSIVA: analiza si un email es legítimo o suplantado
import dns.resolver, re # type: ignore

def verificar_dominio_spf(dominio: str, ip_remitente: str) -> dict:
    """Comprueba si la IP tiene permiso SPF para enviar por ese dominio"""
    resultado = {'dominio': dominio, 'tiene_spf': False, 'ip_autorizada': False, 'registro': ''}
    try:
        respuesta = dns.resolver.resolve(dominio, 'TXT')
        for r in respuesta:
            txt = r.to_text().strip('"')
            if txt.startswith('v=spf1'):
                resultado['tiene_spf'] = True
                resultado['registro']  = txt
                # Comprobar si la IP del remitente aparece autorizada
                if ip_remitente in txt or 'include:' in txt:
                    resultado['ip_autorizada'] = True
    except Exception as e:
        resultado['error'] = str(e)
    return resultado

def verificar_dmarc(dominio: str) -> dict:
    """Comprueba si el dominio tiene política DMARC activa"""
    resultado = {'dominio': dominio, 'tiene_dmarc': False, 'politica': 'none', 'registro': ''}
    try:
        respuesta = dns.resolver.resolve(f'_dmarc.{dominio}', 'TXT')
        for r in respuesta:
            txt = r.to_text().strip('"')
            if 'v=DMARC1' in txt:
                resultado['tiene_dmarc'] = True
                resultado['registro']    = txt
                match = re.search(r'p=(\w+)', txt)
                if match:
                    resultado['politica'] = match.group(1)  # none / quarantine / reject
    except Exception:
        pass
    return resultado

# Ejemplo de análisis de un email sospechoso
dominio_remitente = 'micr0empresa.es'  # Dominio typosquatting
ip_smtp = '185.220.101.35'

spf   = verificar_dominio_spf(dominio_remitente, ip_smtp)
dmarc = verificar_dmarc(dominio_remitente)

print('═' * 50)
print(f'Análisis de: {dominio_remitente}')
print(f'SPF:   {"✓" if spf["tiene_spf"] else "✗ NO CONFIGURADO"}')


