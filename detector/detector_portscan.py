import time
import logging
logger = logging.getLogger(__name__)

inicio_escaneo = {}
puertos_escaneados = {}

def scan_port(src, dst, dport_tcp, report_manager):
	clave = (src,dst)
	ahora = time.monotonic()

	#Detectamos la primera conexion origen/destino
	if clave not in puertos_escaneados:
		inicio_escaneo[clave] = ahora
		puertos_escaneados[clave] = set()

	#Agregamos el puerto escaneado
	puertos_escaneados[clave].add(dport_tcp)

	tiempo = ahora - inicio_escaneo[clave]

	#comprueba si la ventana esta activa todavia
	if tiempo < 10:
		return

	cantidad = len(puertos_escaneados[clave])

	logger.debug(
		"[TCP] %s -> %s: %s puertos diferentes en %.2f segundos",
		src,
		dst,
		cantidad,
		tiempo	
		)

	if cantidad >= 80:
		logger.warning(
			"[ALERTA] Posible escaneo de puertos: %s -> %s (%d puertos en 10 segundos)",
			src,
			dst,
			cantidad
			)

		report_manager.agregar_resultado("TCP",{
                "tipo":"PORT_SCAN",
                "nivel":"PELIGRO",
                "origen": src,
                "destino": dst,
                "puertos": cantidad,
                "ventana": "10 segundos"
            })

	#reiniciamos la ventana
	puertos_escaneados[clave].clear()
	inicio_escaneo[clave] = ahora