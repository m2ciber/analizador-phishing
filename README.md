# Analizador de phishing con IA local

Herramienta en Python que automatiza el triaje inicial de correos sospechosos (`.eml`) en dos capas: primero **comprobaciones automáticas verificables con código** (sin IA) y después un **informe redactado por un modelo de lenguaje local** (Llama 3.2 vía Ollama). Todo se ejecuta en local: ningún dato sale del equipo.

## Problema que resuelve

Los analistas de un SOC revisan a diario correos reportados por usuarios. Extraer cabeceras (SPF, DKIM, Return-Path), indicadores de compromiso y redactar el informe lleva tiempo. Este proyecto automatiza la extracción y genera un primer borrador de análisis.

## Cómo funciona

```text
[.eml] -> [Parser Python] -> [Comprobaciones automáticas] -> [Llama 3.2 en Ollama] -> [Informe]
```

1. Lee el archivo `.eml` con la librería estándar `email` y extrae cabeceras, URLs e IPs.
2. **Comprobaciones automáticas (sin IA):** Reply-To o Return-Path que no coinciden con el remitente, SPF o DKIM fallidos, enlaces con IP en lugar de dominio y lenguaje de urgencia.
3. Envía los datos y los hallazgos a Ollama, con la instrucción de no contradecirlos y de **no recomendar nunca responder al remitente ni abrir enlaces**.

## Resultado de ejemplo

Correo ficticio incluido en `muestras/`. La IP `203.0.113.45` está reservada para documentación y no corresponde a ningún servidor real.

```text
=== COMPROBACIONES AUTOMÁTICAS (sin IA) ===
 - El Reply-To (gmail.com) no coincide con el dominio del remitente (bannco-santander-soporte.com).
 - El Return-Path (servidor-malicioso.example) no coincide con el dominio del remitente (bannco-santander-soporte.com).
 - SPF falla: el servidor emisor no está autorizado por el dominio del remitente.
 - DKIM ausente o inválido: el mensaje no está firmado correctamente.
 - Enlace con dirección IP en lugar de dominio: http://203.0.113.45/verificar-cuenta
 - Lenguaje de urgencia o amenaza: urgente, 2 horas, verifique, perdera, cancele, cancelela
```

![Ejecución del analizador](captura.png)

## Calidad observada del informe de la IA

Una primera versión, que dejaba todo el análisis al modelo, recomendó "informar al remitente" y no señaló que el Reply-To era de Gmail. Tras mover esas comprobaciones al código y añadir reglas al *prompt*:

- El informe ya no recomienda contactar al remitente y marca el Reply-To como sospechoso.
- **Sigue fallando el veredicto:** dio "Sospechoso (6/10)" mientras el propio texto lo calificaba de phishing, y antes había dado 9/10 para el mismo correo. La puntuación del modelo **no es fiable**.
- **Razona mal en algún punto:** afirmó que la falta de SPF y DKIM sugiere que el correo "ha sido modificado", cosa que no se deduce de esos datos.

Por eso el informe de la IA es un **borrador que debe revisar una persona**.

## Cómo ejecutarlo (Windows)

Requisitos: Python 3, [Ollama](https://ollama.com) en marcha y el modelo descargado (`ollama pull llama3.2`).

```powershell
git clone https://github.com/m2ciber/analizador-phishing.git
cd analizador-phishing
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python analizador.py
```

Para analizar otro correo: `python analizador.py ruta\al\correo.eml`.

## Limitaciones

- Solo se ha probado con **un correo ficticio** y un modelo (Llama 3.2).
- Las comprobaciones son reglas simples: la lista de palabras de urgencia está en español y no se detectan dominios que imitan a una marca (como `bannco-santander-soporte.com`).
- Los correos solo en HTML, sin parte de texto plano, no se analizan bien.
- No se consulta la reputación de IPs ni URLs.

## Próximos pasos

- Calcular la **puntuación de riesgo con reglas** (número y gravedad de hallazgos) en lugar de dejarla al modelo.
- Detectar dominios parecidos a marcas conocidas.
- Consultar VirusTotal o AbuseIPDB para la reputación de IPs y URLs.
- Probar con más correos, incluidos legítimos, para medir los falsos positivos.