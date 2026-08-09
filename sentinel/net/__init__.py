"""net — Consola central del laboratorio (agente + coordinador).

Modelo agente/coordinador para gestionar la SEGURIDAD de un parque de equipos
desde un solo punto, SIN convertirse en una herramienta de intrusion:

  * `agent`       — corre en cada PC: audita localmente y REPORTA (solo lectura)
                    el resultado al coordinador. No abre ningun canal para
                    recibir comandos arbitrarios.
  * `coordinator` — el panel del administrador: recibe los reportes, los agrega
                    (inventario, puntajes, Pareto del parque, ranking) y los
                    sirve. No ejecuta nada en los equipos.
  * `protocol`    — autenticacion por token + firma HMAC del cuerpo, para que
                    solo los agentes legitimos reporten y nadie altere los datos.

Limite de diseno (deliberado): el agente NO acepta ejecutar comandos, no captura
pantalla y no expone un shell. Su unica accion hacia afuera es enviar el reporte
de auditoria. Asi la consola centraliza la VISIBILIDAD de la seguridad sin
volverse un mecanismo de control remoto —lo que contradiria el caracter
defensivo del producto y crearia un riesgo mayor que el que resuelve.
"""
