import email
from email import policy
import re
import sys
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODELO = "llama3.2"


def extraer_datos_eml(ruta_archivo):
    try:
        with open(ruta_archivo, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
    except FileNotFoundError:
        print(f"[ERROR] No se encontró el archivo: {ruta_archivo}")
        sys.exit(1)

    datos = {
        "from": msg.get("From", "Desconocido"),
        "reply_to": msg.get("Reply-To", "No especificado"),
        "return_path": msg.get("Return-Path", "No especificado"),
        "subject": msg.get("Subject", "Sin asunto"),
        "auth_results": msg.get("Authentication-Results", "Sin registros SPF/DKIM"),
        "cuerpo": "",
    }

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                datos["cuerpo"] = part.get_content()
                break
    else:
        datos["cuerpo"] = msg.get_content()

    # Extraer URLs e IPs con expresiones regulares
    datos["urls"] = list(set(re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', datos["cuerpo"])))
    datos["ips"] = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", datos["cuerpo"] + " " + str(datos["auth_results"]))))

    return datos


def analizar_con_ia(datos):
    prompt = f"""
Eres un analista senior de un Centro de Operaciones de Seguridad (SOC).
Analiza los siguientes artefactos de un correo electrónico y genera un informe técnico breve, en español.

DATOS DEL CORREO:
- Remitente (From): {datos['from']}
- Responder a (Reply-To): {datos['reply_to']}
- Ruta de retorno (Return-Path): {datos['return_path']}
- Resultados de autenticación (SPF/DKIM): {datos['auth_results']}
- Asunto: {datos['subject']}
- URLs detectadas: {datos['urls']}
- IPs detectadas: {datos['ips']}
- Cuerpo del mensaje:
{datos['cuerpo']}

ESTRUCTURA OBLIGATORIA DE RESPUESTA:
1. VEREDICTO Y PUNTUACIÓN DE RIESGO: (Legítimo / Sospechoso / Phishing - X/10)
2. INDICADORES DE COMPROMISO (IoCs): IPs, dominios y URLs sospechosas.
3. ANÁLISIS TÉCNICO: fallos de SPF/DKIM, suplantación de identidad y tácticas de ingeniería social.
4. ACCIONES RECOMENDADAS: qué debería hacer el equipo SOC.
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
    ruta = "muestras/correo_sospechoso.eml"
    print(f"[*] Analizando archivo: {ruta}")
    artefactos = extraer_datos_eml(ruta)
    print("[*] Datos extraídos:")
    print("    From:", artefactos["from"])
    print("    URLs:", artefactos["urls"])
    print("    IPs:", artefactos["ips"])
    print("[*] Consultando a la IA local (puede tardar uno o dos minutos)...\n")
    informe = analizar_con_ia(artefactos)
    print("=" * 60)
    print(informe)
    print("=" * 60)