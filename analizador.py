import email
import re
import sys
from email import policy
from email.utils import parseaddr

import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODELO = "llama3.2"

# Puntuación por reglas: de 0 a 10
UMBRAL_SOSPECHOSO = 3
UMBRAL_PHISHING = 6

PALABRAS_URGENCIA = [
    "urgente", "inmediatamente", "2 horas", "24 horas", "bloqueada",
    "bloqueado", "suspendida", "suspendido", "verifique", "perdera",
    "perderá", "cancele", "cancelela", "ultimo aviso", "último aviso",
]
ACORTADORES = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"]

# Marca -> dominios oficiales. Si la marca aparece en el dominio del remitente
# y el dominio no es oficial, se considera una imitación.
MARCAS = {
    "santander": ["santander.es", "santander.com", "gruposantander.com"],
    "bbva": ["bbva.es", "bbva.com"],
    "paypal": ["paypal.com", "paypal.es"],
    "amazon": ["amazon.es", "amazon.com"],
    "microsoft": ["microsoft.com"],
    "google": ["google.com"],
    "correos": ["correos.es"],
    "netflix": ["netflix.com"],
    "apple": ["apple.com"],
    "bancoejemplo": ["bancoejemplo.test"],  # marca ficticia para las pruebas
}


def dominio_de(direccion):
    """Devuelve el dominio de una dirección tipo 'Nombre <usuario@dominio.com>'."""
    _, correo = parseaddr(str(direccion))
    return correo.split("@")[-1].lower() if "@" in correo else ""


def marca_imitada(dominio):
    """Devuelve la marca que imita el dominio, o None."""
    partes = re.split(r"[.\-_]", dominio)
    for marca, oficiales in MARCAS.items():
        es_oficial = any(dominio == o or dominio.endswith("." + o) for o in oficiales)
        if marca in partes and not es_oficial:
            return marca
    return None


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
    """Devuelve una lista de (puntos, descripción). Todo verificable con código, sin IA."""
    hallazgos = []
    dom_from = dominio_de(datos["from"])
    dom_reply = dominio_de(datos["reply_to"])
    dom_return = dominio_de(datos["return_path"])
    auth = datos["auth_results"].lower()
    texto = (datos["subject"] + " " + datos["cuerpo"]).lower()

    if dom_reply and dom_from and dom_reply != dom_from:
        hallazgos.append((2, f"El Reply-To ({dom_reply}) no coincide con el dominio del remitente ({dom_from})."))
    if dom_return and dom_from and dom_return != dom_from:
        hallazgos.append((1, f"El Return-Path ({dom_return}) no coincide con el dominio del remitente ({dom_from})."))
    if "spf=fail" in auth or "spf=softfail" in auth:
        hallazgos.append((3, "SPF falla: el servidor emisor no está autorizado por el dominio del remitente."))
    if "dkim=none" in auth or "dkim=fail" in auth:
        hallazgos.append((2, "DKIM ausente o inválido: el mensaje no está firmado correctamente."))

    marca = marca_imitada(dom_from)
    if marca:
        hallazgos.append((3, f"El dominio del remitente ({dom_from}) parece imitar a la marca '{marca}'."))

    for url in datos["urls"]:
        host = re.match(r"https?://([^/\s:]+)", url)
        host = host.group(1).lower() if host else ""
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            hallazgos.append((3, f"Enlace con dirección IP en lugar de dominio: {url}"))
        elif host in ACORTADORES:
            hallazgos.append((1, f"Enlace acortado, que oculta el destino real: {url}"))

    encontradas = [p for p in PALABRAS_URGENCIA if re.search(r"\b" + re.escape(p) + r"\b", texto)]
    if len(encontradas) >= 2:
        hallazgos.append((2, "Lenguaje de urgencia o amenaza: " + ", ".join(encontradas)))
    elif len(encontradas) == 1:
        hallazgos.append((1, "Lenguaje de urgencia: " + encontradas[0]))
    return hallazgos


def puntuar(hallazgos):
    total = min(10, sum(p for p, _ in hallazgos))
    if total >= UMBRAL_PHISHING:
        nivel = "ALTO (probable phishing)"
    elif total >= UMBRAL_SOSPECHOSO:
        nivel = "MEDIO (sospechoso)"
    else:
        nivel = "BAJO"
    return total, nivel


def analizar_con_ia(datos, hallazgos, puntos, nivel):
    lista = "\n".join(f"- {t}" for _, t in hallazgos) or "- Ninguno"
    prompt = f"""
Eres un analista de un Centro de Operaciones de Seguridad (SOC).
Redacta un informe técnico breve, en español, sobre este correo.

PUNTUACIÓN DE RIESGO CALCULADA POR REGLAS (es un dato, no la cambies ni des otra): {puntos}/10, nivel {nivel}.

HALLAZGOS VERIFICADOS AUTOMÁTICAMENTE (son hechos, no los contradigas):
{lista}

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
1. RESUMEN: una frase con el nivel calculado y el motivo principal.
2. INDICADORES DE COMPROMISO: dominios, IPs y URLs sospechosas.
3. ANÁLISIS: apóyate en los hallazgos verificados y en la ingeniería social del texto.
4. ACCIONES RECOMENDADAS para el equipo de seguridad.

REGLAS: no inventes una puntuación propia. Nunca recomiendes responder al remitente, contactarlo ni abrir los enlaces.
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
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    sin_ia = "--sin-ia" in sys.argv
    ruta = args[0] if args else "muestras/correo_sospechoso.eml"

    print(f"[*] Analizando archivo: {ruta}")
    datos = extraer_datos_eml(ruta)

    hallazgos = comprobaciones_automaticas(datos)
    puntos, nivel = puntuar(hallazgos)
    print("\n=== COMPROBACIONES AUTOMÁTICAS (sin IA) ===")
    for p, texto in hallazgos:
        print(f" +{p}  {texto}")
    if not hallazgos:
        print(" Ningún indicador detectado")
    print(f"\nPUNTUACIÓN POR REGLAS: {puntos}/10, nivel {nivel}")

    if not sin_ia:
        print("\n[*] Consultando a la IA local (puede tardar uno o dos minutos)...\n")
        informe = analizar_con_ia(datos, hallazgos, puntos, nivel)
        print("=" * 60)
        print(informe)
        print("=" * 60)