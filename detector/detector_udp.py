import logging
logger = logging.getLogger(__name__)
from report import agregar_evaluacion


def puertos_detectado(clave,src,dst,dport,puertos,report_manager):
	if agregar_evaluacion.registrar_consulta(clave):
		agregar_evaluacion.evaluar_por_puerto(
			clave,
			"UDP",
			src,
			dst,
			dport,
			puertos=puertos,
			report_manager=report_manager
			)