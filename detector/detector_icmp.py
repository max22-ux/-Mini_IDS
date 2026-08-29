import logging
from report import agregar_evaluacion
logger = logging.getLogger(__name__)

def paquetes_icmp(src, dst, report_manager):
    clave = (src,dst)
    analizador_icmp(clave,src,dst,report_manager)

def analizador_icmp(clave, src, dst, report_manager):
    if agregar_evaluacion.registrar_consulta(clave):
        agregar_evaluacion.evaluar_riesgo(
            clave,
            "ICMP",
            src,
            dst,
            report_manager=report_manager
            )