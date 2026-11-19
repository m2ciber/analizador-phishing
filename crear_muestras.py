import os

CARPETA = "muestras/evaluacion"
COMUN = "MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n"

CORREOS = {
"legitimo_reunion.eml": """
Return-Path: <ana.garcia@empresa-ejemplo.test>
Authentication-Results: mx.empresa-ejemplo.test; spf=pass; dkim=pass
From: "Ana Garcia" <ana.garcia@empresa-ejemplo.test>
To: juan.perez@empresa-ejemplo.test
Subject: Reunion del jueves

Hola Juan,

Te recuerdo la reunion del jueves a las 10:00 en la sala 2. Es urgente que confirmes si vienes, para reservar la sala.

Un saludo,
Ana
""",
"legitimo_newsletter.eml": """
Return-Path: <bounce-8841@envios-masivos.example>
Authentication-Results: mx.ejemplo.test; spf=pass; dkim=pass
From: "Tienda Ejemplo" <novedades@tiendaejemplo.test>
Reply-To: atencion@tiendaejemplo.test
To: cliente@correo.test
Subject: Ofertas de otono

Hola, estas son las novedades de la semana. Descuentos de hasta el 30% hasta el domingo.
Ver ofertas: https://www.tiendaejemplo.test/ofertas
Si no quieres recibir mas correos, puedes darte de baja aqui: https://www.tiendaejemplo.test/baja
""",
"legitimo_banco.eml": """
Return-Path: <avisos@bancoejemplo.test>
Authentication-Results: mx.bancoejemplo.test; spf=pass; dkim=pass
From: "Banco Ejemplo" <avisos@bancoejemplo.test>
To: cliente@correo.test
Subject: Su extracto de octubre ya esta disponible

Estimado cliente, su extracto mensual ya esta disponible en la banca online.
Por seguridad, verifique siempre que la direccion empieza por https://www.bancoejemplo.test
Nunca le pediremos su clave por correo.
""",
"legitimo_sin_autenticacion.eml": """
Return-Path: <info@tallerlopez.test>
From: "Taller Lopez" <info@tallerlopez.test>
To: cliente@correo.test
Subject: Su coche esta listo

Buenos dias, su coche esta listo para recoger. Nuestro horario es de 9 a 14. Gracias.
""",
"legitimo_aviso_urgente.eml": """
Return-Path: <admin@comunidadejemplo.test>
Authentication-Results: mx.comunidadejemplo.test; spf=softfail; dkim=pass
From: "Administracion" <admin@comunidadejemplo.test>
To: vecino@correo.test
Subject: Aviso urgente: corte de agua

Aviso urgente: manana habra un corte de agua por obras en la calle. El corte durara 24 horas.
Rogamos que almacene agua con antelacion. Disculpen las molestias.
""",
"phishing_banco.eml": """
Return-Path: <bounce-992@servidor-malicioso.example>
Authentication-Results: mx.ejemplo.test; spf=fail (domain of seguridad@bannco-santander-soporte.com does not designate 203.0.113.45 as permitted sender); dkim=none
From: "Soporte Banco" <seguridad@bannco-santander-soporte.com>
Reply-To: atencion@gmail.com
To: victima@empresa.es
Subject: [URGENTE] Transferencia retenida de 1.450,00 EUR - Verifique su identidad

Estimado cliente,

Hemos detectado una transferencia saliente no autorizada desde su cuenta.
Si usted no realizo esta operacion, cancelela en las proximas 2 horas o perdera sus fondos.

Acceda al portal seguro: http://203.0.113.45/verificar-cuenta

Departamento de Fraude.
""",
"phishing_paquete.eml": """
Return-Path: <aviso@correos-envios-seguimiento.example>
Authentication-Results: mx.ejemplo.test; spf=softfail; dkim=none
From: "Correos" <aviso@correos-envios-seguimiento.example>
To: cliente@correo.test
Subject: No hemos podido entregar su paquete

Su paquete no pudo ser entregado. Sera devuelto en 24 horas. Ultimo aviso.
Pague las tasas de reenvio (1,99 EUR) aqui: http://correos-seguimiento-pago.example/tasas
""",
"phishing_jefe.eml": """
Return-Path: <direccion@empresa-ejemplo.test>
Authentication-Results: mx.empresa-ejemplo.test; spf=pass; dkim=pass
From: "Director General" <direccion@empresa-ejemplo.test>
Reply-To: director.personal@gmail.com
To: empleado@empresa-ejemplo.test
Subject: Un favor

Hola, necesito un favor urgente. Estoy en una reunion y no puedo llamar.
Compra 5 tarjetas regalo de 100 EUR y enviame los codigos por correo. Responde a mi correo personal.
""",
"phishing_cuenta.eml": """
Return-Path: <no-reply@micros0ft-cuenta.example>
Authentication-Results: mx.ejemplo.test; spf=fail; dkim=none
From: "Soporte de cuenta" <no-reply@micros0ft-cuenta.example>
To: usuario@correo.test
Subject: Actividad inusual en su cuenta

Su cuenta sera suspendida en 24 horas. Verifique su identidad ahora: https://bit.ly/ejemplo-verificar
""",
"phishing_sin_senales.eml": """
Return-Path: <marta.ruiz@empresa-ejemplo.test>
Authentication-Results: mx.empresa-ejemplo.test; spf=pass; dkim=pass
From: "Marta Ruiz" <marta.ruiz@empresa-ejemplo.test>
To: empleado@empresa-ejemplo.test
Subject: Factura del mes

Hola, te paso la factura pendiente del mes. Puedes descargarla aqui: http://facturas-pendientes.example/descargar.zip
""",
}

if __name__ == "__main__":
    os.makedirs(CARPETA, exist_ok=True)
    for nombre, texto in CORREOS.items():
        ruta = os.path.join(CARPETA, nombre)
        with open(ruta, "w", encoding="utf-8", newline="\n") as f:
            f.write(COMUN + texto.lstrip("\n"))
    print(f"[+] {len(CORREOS)} correos de prueba creados en {CARPETA}")