from scapy.all import TCP, UDP, DNS, ICMP
import logging
from detector import detector_udp
from detector import detector_dns
from detector import detector_tcp
from detector import detector_portscan
from detector import detector_icmp
logger = logging.getLogger(__name__)

puertos = {
	21:{"protocolo": "TCP", "servicio": "FTP", "categoria": "SENSIBLE"},
	22:{"protocolo": "TCP", "servicio": "SSH", "categoria": "SENSIBLE"},
	23:{"protocolo": "TCP", "servicio": "Telnet", "categoria": "SENSIBLE"},
	25:{"protocolo": "TCP", "servicio": "SMTP", "categoria": "SENSIBLE"},
	67:{"protocolo": "UDP", "servicio": "DHCP", "categoria": "RED"},
	68:{"protocolo": "UDP", "servicio": "DHCP", "categoria": "RED"},
	80:{"protocolo": "TCP", "servicio": "HTTP", "categoria": "WEB"},
	110:{"protocolo": "TCP", "servicio": "POP3", "categoria": "SENSIBLE"},
	137:{"protocolo": "TCP/UDP", "servicio": "NetBIOS", "categoria": "SENSIBLE"},
	138:{"protocolo": "TCP/UDP", "servicio": "NetBIOS", "categoria": "SENSIBLE"},
	139:{"protocolo": "TCP/UDP", "servicio": "NetBIOS", "categoria": "SENSIBLE"},
	143:{"protocolo": "TCP", "servicio": "IMAP", "categoria": "SENSIBLE"},
	161:{"protocolo": "UDP", "servicio": "SNMP", "categoria": "RED"},
	162:{"protocolo": "UDP", "servicio": "SNMP Trap", "categoria": "RED"},
	443:{"protocolo": "TCP", "servicio": "HTTPS", "categoria": "WEB"},
	445:{"protocolo": "TCP", "servicio": "SMB", "categoria": "SENSIBLE"},
	1433:{"protocolo": "TCP", "servicio": "MSSQL", "categoria": "SENSIBLE"},
	3306:{"protocolo": "TCP", "servicio": "MySQL", "categoria": "SENSIBLE"},
	3389:{"protocolo": "TCP/UDP", "servicio": "RDP", "categoria": "SENSIBLE"}
}


def detectar_protocolo(dport_udp, dport_tcp, src, dst, pkt, report_manager):
	#Detecta paquetes icmp
	if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
		detector_icmp.paquetes_icmp(
			src,
			dst,
			report_manager
			)

	#Detecta paquetes DNS
	if pkt.haslayer(DNS):
		#Consultas DNS
		detector_dns.analizador_de_consultas(
			src,
			dst,
			pkt,
			report_manager
			)

	#Detecta paquetes UDP
	if pkt.haslayer(UDP) and dport_udp in puertos:
		clave = (src,dst,dport_udp)

		#Detecta paquetes TCP Y UDP no conexiones a puertos
		detector_udp.puertos_detectado(
			clave,
			src,
			dst,
			dport_udp,
			puertos,
			report_manager
			)
		
	if pkt.haslayer(TCP):
		#Detector de intentos de conexion TCP
		if pkt[TCP].flags & 0x02 and not pkt[TCP].flags & 0x10:
			#Detecta posibles escaneos
			detector_portscan.scan_port(src,dst,dport_tcp,report_manager)

			#Detecta puertos conocidos
			if dport_tcp in puertos:
				detector_tcp.detectar_intento_tcp(
					dst,
					src,
					dport_tcp,
					puertos,
					report_manager
					)