import os

from analizador import (
    UMBRAL_SOSPECHOSO, comprobaciones_automaticas, extraer_datos_eml, puntuar,
)

CARPETA = "muestras/evaluacion"

if __name__ == "__main__":
    if not os.path.isdir(CARPETA):
        raise SystemExit("[ERROR] Falta la carpeta de pruebas. Ejecuta antes: python crear_muestras.py")

    tp = fp = fn = tn = 0
    print(f"{'archivo':<34}{'esperado':<10}{'puntos':<8}{'nivel':<26}resultado")
    for nombre in sorted(os.listdir(CARPETA)):
        if not nombre.endswith(".eml"):
            continue
        esperado = "phishing" if nombre.startswith("phishing") else "legitimo"
        datos = extraer_datos_eml(os.path.join(CARPETA, nombre))
        puntos, nivel = puntuar(comprobaciones_automaticas(datos))
        marcado = puntos >= UMBRAL_SOSPECHOSO

        if esperado == "phishing" and marcado:
            tp += 1; resultado = "OK (detectado)"
        elif esperado == "phishing":
            fn += 1; resultado = "FALLO: no detectado"
        elif marcado:
            fp += 1; resultado = "FALLO: falsa alarma"
        else:
            tn += 1; resultado = "OK"
        print(f"{nombre:<34}{esperado:<10}{puntos:<8}{nivel:<26}{resultado}")

    print(f"\nPhishing detectado: {tp} de {tp + fn}")
    print(f"Legítimos marcados por error: {fp} de {fp + tn}")
    print("Ojo: son pocos correos escritos por nosotros. Sirve para ver cómo se comportan las reglas, no para medir rendimiento real.")