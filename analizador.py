import email
import re
import sys
from email import policy
from email.utils import parseaddr

import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODELO = "llama3.2"

PALABRAS_URGENCIA = [
    "urgente", "inmediatamente", "2 horas", "24 horas", "bloqueada",
    "bloqueado", "suspendida", "verifique", "perderá", "perdera",
    "cancele", "cancelela",
]


def dominio_de(direccion):
    """Devuelve el dominio de una dirección tipo 'Nombre <usuario@dominio.com>'."""
    _, correo = parseaddr(str(direccion))
    return correo.split("@")[-1].lower() if "@" in correo else ""


def extraer_datos_eml(ruta_archivo):
    try:
        with open(ruta_archivo, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
    except FileNotFoundError:
        print(f"[ERROR] No se encontró el archivo: {ruta_archivo}")
        sys.exit(1)

    datos = {
        "from": str(msg.get("From", "Desconocido")),
        "reply_to": str(msg.get("Reply-To", "")),
        "return_path": str(msg.get("Return-Path", "")),
        "subject": str(msg.get("Subject", "Sin asunto")),
        "auth_results": str(msg.get("Authentication-Results", "")),
        "cuerpo": "",
    }

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                datos["cuerpo"] = part.get_content()
                break
    else:
        datos["cuerpo"] = msg.get_content()

    texto = datos["cuerpo"] + " " + datos["auth_results"]
    datos["urls"] = list(set(re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', datos["cuerpo"])))
    datos["ips"] = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", texto)))
    return datos


def comprobaciones_automaticas(datos):
    """Hallazgos verificables con código, sin depender de la IA."""
    hallazgos = []
    dom_from = dominio_de(datos["from"])
    dom_reply = dominio_de(datos["reply_to"])
    dom_return = dominio_de(datos["return_path"])
    auth = datos["auth_results"].lower()
    texto = (datos["subject"] + " " + datos["cuerpo"]).lower()

    if dom_reply and dom_from and dom_reply != dom_from:
        hallazgos.append(f"El Reply-To ({dom_reply}) no coincide con el dominio del remitente ({dom_from}).")
    if dom_return and dom_from and dom_return != dom_from:
        hallazgos.append(f"El Return-Path ({dom_return}) no coincide con el dominio del remitente ({dom_from}).")
    if "spf=fail" in auth or "spf=softfail" in auth:
        hallazgos.append("SPF falla: el servidor emisor no está autorizado por el dominio del remitente.")
    if "dkim=none" in auth or "dkim=fail" in auth:
        hallazgos.append("DKIM ausente o inválido: el mensaje no está firmado correctamente.")
    for url in datos["urls"]:
        if re.match(r"https?://\d{1,3}(?:\.\d{1,3}){3}", url):
            hallazgos.append(f"Enlace con dirección IP en lugar de dominio: {url}")
    encontradas = [p for p in PALABRAS_URGENCIA if p in texto]
    if encontradas:
        hallazgos.append("Lenguaje de urgencia o amenaza: " + ", ".join(encontradas))
    return hallazgos


def analizar_con_ia(datos, hallazgos):
    lista_hallazgos = "\n".join(f"- {h}" for h in hallazgos) or "- Ninguno"
    prompt = f"""
Eres un analista de un Centro de Operaciones de Seguridad (SOC).
Analiza este correo y redacta un informe técnico breve, en español.

HALLAZGOS VERIFICADOS AUTOMÁTICAMENTE (son hechos, no los contradigas):
{lista_hallazgos}

DATOS DEL CORREO:
- Remitente (From): {datos['from']}
- Responder a (Reply-To): {datos['reply_to'] or 'No especificado'}
- Ruta de retorno (Return-Path): {datos['return_path'] or 'No especificado'}
- Resultados de autenticación: {datos['auth_results'] or 'No disponibles'}
- Asunto: {datos['subject']}
- URLs detectadas: {datos['urls']}
- IPs detectadas: {datos['ips']}
- Cuerpo:
{datos['cuerpo']}

ESTRUCTURA DEL INFORME:
1. VEREDICTO Y PUNTUACIÓN DE RIESGO (Legítimo / Sospechoso / Phishing, de 0 a 10).
2. INDICADORES DE COMPROMISO: dominios, IPs y URLs sospechosas.
3. ANÁLISIS TÉCNICO: apóyate en los hallazgos verificados y en la ingeniería social del texto.
4. ACCIONES RECOMENDADAS para el equipo de seguridad.

REGLAS: nunca recomiendes responder al remitente, contactarlo ni abrir los enlaces.
"""

    try:
        respuesta = requests.post(
            OLLAMA_URL,
            json={"model": MODELO, "prompt": prompt, "stream": False},
            timeout=300,
        )
        respuesta.raise_for_status()
        return respuesta.json().get("response", "Sin respuesta del modelo.")
    except requests.exceptions.RequestException as e:
        return f"[ERROR DE CONEXIÓN CON OLLAMA] Comprueba que Ollama está abierto. Detalle: {e}"


if __name__ == "__main__":
    ruta = sys.argv[1] if len(sys.argv) > 1 else "muestras/correo_sospechoso.eml"
    print(f"[*] Analizando archivo: {ruta}")
    datos = extraer_datos_eml(ruta)

    hallazgos = comprobaciones_automaticas(datos)
    print("\n=== COMPROBACIONES AUTOMÁTICAS (sin IA) ===")
    for h in hallazgos:
        print(" -", h)
    if not hallazgos:
        print(" - Ningún indicador detectado")

    print("\n[*] Consultando a la IA local (puede tardar uno o dos minutos)...\n")
    informe = analizar_con_ia(datos, hallazgos)
    print("=" * 60)
    print(informe)
    print("=" * 60)