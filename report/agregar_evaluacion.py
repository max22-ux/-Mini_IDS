import logging
import time
logger = logging.getLogger(__name__)

consultas_por_clave = {}
inicio_por_clave = {}

def registrar_consulta(clave):
	if clave not in consultas_por_clave:
		consultas_por_clave[clave] = 0
		inicio_por_clave[clave] = time.monotonic()

	consultas_por_clave[clave] += 1

	tiempo_transcurrido = time.monotonic() - inicio_por_clave[clave]

	if tiempo_transcurrido >= 10:
		return True

	return False

def evaluar_riesgo(clave,tipo,src,dst,dominio=None,report_manager=None):
	if tipo == 'DNS':
		if consultas_por_clave[clave] > 100:
			log_consultas('critical',tipo,consultas_por_clave,clave,src=src,dst=dst)
			report_manager.agregar_resultado(tipo,{
				"tipo":tipo,
				"nivel":"PELIGRO",
				"origen": src,
				"destino": dst,
				"dominio": dominio,
				"cantidad": consultas_por_clave[clave],
				"ventana": "10 segundos",
				"Descripcion": "PELIGRO demasiadas consultas en pocos segundos"
			})
		elif consultas_por_clave[clave] > 50:
			log_consultas('warning',tipo,consultas_por_clave,clave,src=src,dst=dst)
			report_manager.agregar_resultado(tipo,{
				"tipo":tipo,
				"nivel":"ALERTA",
				"origen": src,
				"destino": dst,
				"dominio": dominio,
				"cantidad": consultas_por_clave[clave],
				"ventana": "10 segundos",
				"Descripcion": "ALERTA muchas consultas en pocos segundos"
			})
		elif consultas_por_clave[clave] > 10:
			log_consultas('info',tipo,consultas_por_clave,clave,src=src,dst=dst)
		
		consultas_por_clave[clave] = 0
		inicio_por_clave[clave] = time.monotonic()
	
	elif tipo == 'ICMP':
		if consultas_por_clave[clave] > 100:
			log_consultas('critical',tipo,consultas_por_clave,clave,src=src,dst=dst)
			report_manager.agregar_resultado(tipo,{
                "tipo":tipo,
                "nivel":"PELIGRO",
                "origen": src,
                "destino": dst,
                "cantidad": consultas_por_clave[clave],
                "ventana": "10 segundos",
                "Descripcion": "PELIGRO demasiadas consultas en pocos segundos"
            }) 
		elif consultas_por_clave[clave] > 50:
			log_consultas('warning',tipo,consultas_por_clave,clave,src=src,dst=dst)
			report_manager.agregar_resultado(tipo,{
				"tipo":tipo,
				"nivel":"ALERTA",
				"origen": src,
				"destino": dst,
				"cantidad": consultas_por_clave[clave],
				"ventana": "10 segundos",
				"Descripcion": "ALERTA muchas consultas en pocos segundos"
			})
		elif consultas_por_clave[clave] > 10:
			log_consultas('info',tipo,consultas_por_clave,clave,src=src,dst=dst)
		consultas_por_clave[clave] = 0
		inicio_por_clave[clave] = time.monotonic()
	else:
		logger.error("El tipo no se puede calcular")


def evaluar_por_puerto(clave,tipo,src,dst,dport,puertos,report_manager):
	if tipo in ("TCP","UDP"):
		if consultas_por_clave[clave] > 100:
			log_consultas('critical',tipo,consultas_por_clave,clave,dst=dst,dport=dport,puertos=puertos)
			report_manager.agregar_resultado(tipo,{
                "tipo":tipo,
                "nivel":"PELIGRO",
                "origen": src,
                "destino": dst,
                "cantidad": consultas_por_clave[clave],
                "ventana": "10 segundos",
                "Descripcion": "PELIGRO demasiadas consultas en pocos segundos"
            }) 
		elif consultas_por_clave[clave] > 50:
			log_consultas('warning',tipo,consultas_por_clave,clave,dst=dst,dport=dport,puertos=puertos)
			report_manager.agregar_resultado(tipo,{
				"tipo":tipo,
				"nivel":"ALERTA",
				"origen": src,
				"destino": dst,
				"cantidad": consultas_por_clave[clave],
				"ventana": "10 segundos",
				"Descripcion": "ALERTA muchas consultas en pocos segundos"
			})
		elif consultas_por_clave[clave] > 10:
			log_consultas('info',tipo,consultas_por_clave,clave,dst=dst,dport=dport,puertos=puertos)
		consultas_por_clave[clave] = 0
		inicio_por_clave[clave] = time.monotonic()

def log_consultas(info,tipo,consultas,clave,src=None,dst=None,dport=None,puertos=None):
	if info == 'critical':
		if tipo in ('DNS','ICMP'):
			logger.critical("[PELIGRO] Se realizaron (%s) demasiadas consultas en 10 segundos %s --> %s",consultas[clave],src,dst)
		elif tipo in ('TCP','UDP'):
			logger.critical("[%s] %s  --> %s:%s se realizaron %s en 10 segundos",puertos[dport]['categoria'],puertos[dport]['servicio'],dst,dport,consultas[clave])
	elif info == 'warning':
		if tipo in ('DNS','ICMP'):
			logger.warning("[ALERTA] Se realizaron (%s) consultas sospechosas en 10 segundos %s --> %s",consultas[clave],src,dst)
		elif tipo in ('TCP','UDP'):
			logger.warning("[%s] %s --> %s:%s se realizaron %s en 10 segundos",puertos[dport]['categoria'],puertos[dport]['servicio'],dst,dport,consultas[clave])
	elif info == 'info':
		if tipo in ('DNS','ICMP'):
			logger.info("[ADVERTENCIA] Se realizaron (%s) consultas en 10 segundos %s --> %s",consultas[clave],src,dst)
		elif tipo in ('TCP','UDP'):
			logger.info("[%s] %s --> %s:%s se realizaron %s en 10 segundos",puertos[dport]['categoria'],puertos[dport]['servicio'],dst,dport,consultas[clave])