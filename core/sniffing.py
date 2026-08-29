from scapy.all import IP, UDP, TCP, sniff
import logging
logger = logging.getLogger(__name__)
from core import detector_protocolo
		
def analizar_paquete(pkt,report_manager):
	#Deteccion de puertos TCP y UDP
	if pkt.haslayer(UDP):
		dport_udp = pkt[UDP].dport
	else:
		dport_udp = None

	if pkt.haslayer(TCP):
		dport_tcp = pkt[TCP].dport
	else:
		dport_tcp = None

	if pkt.haslayer(IP):
		src = pkt[IP].src
		dst = pkt[IP].dst
		detector_protocolo.detectar_protocolo(
			dport_udp,
			dport_tcp,
			src,
			dst,
			pkt,
			report_manager
			)

def detector(interfaz,report_manager):
    return sniff(
    	iface=interfaz,
    	prn=lambda pkt:analizar_paquete(pkt,report_manager),
    	store=False)