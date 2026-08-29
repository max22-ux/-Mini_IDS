from scapy.all import DNS
import logging
logger = logging.getLogger(__name__)
from report import agregar_evaluacion

def analizador_de_consultas(src,dst,pkt,report_manager):
	#Detecta paquetes DNS que sean consultas
	if pkt.haslayer(DNS) and pkt[DNS].qr == 0: 
		clave = (src,dst)

		dominio = None

		if pkt[DNS].qd:
			dominio = pkt[DNS].qd.qname.decode()

		if agregar_evaluacion.registrar_consulta(clave):
			agregar_evaluacion.evaluar_riesgo(
				clave,
				"DNS",
				src,
				dst,
				dominio=dominio,
				report_manager=report_manager
				)