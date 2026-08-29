import logging
logger = logging.getLogger(__name__)
from report import agregar_evaluacion

def detectar_intento_tcp(dst,src,dport_tcp,puertos,report_manager):
	logger.info(
		"[%s] Intento de Conexion TCP -> %s:%s", 
		puertos[dport_tcp]['categoria'],
		dst,
		dport_tcp
		)
	if dport_tcp in puertos and puertos[dport_tcp]['categoria'] == 'WEB':
		clave_web = (src,dst,dport_tcp)
		detectar_conexion_web(clave_web,src,dst,dport_tcp,puertos,report_manager)

	elif dport_tcp in puertos and puertos[dport_tcp]['categoria'] == 'SENSIBLE':
		clave = (src,dst,dport_tcp)
		puerto_tcp_sensible(clave,src,dst,dport_tcp,puertos,report_manager)

#Detecta conexion tcp
def detectar_conexion_web(clave_web,src,dst,dport,puertos,report_manager):
	if agregar_evaluacion.registrar_consulta(clave_web):
		agregar_evaluacion.evaluar_por_puerto(
			clave_web,
			"TCP",
			src,
			dst,
			dport,
			puertos=puertos,
			report_manager=report_manager
			)

#Detecta las conexiones TCP de puertos sensibles
def puerto_tcp_sensible(clave,src,dst,dport,puertos,report_manager):
	if agregar_evaluacion.registrar_consulta(clave):
		agregar_evaluacion.evaluar_por_puerto(
			clave,
			"TCP",
			src,
			dst,
			dport,
			puertos=puertos,
			report_manager=report_manager
			)