# Mini IDS - Network Sniffer

Mini IDS (Intrusion Detection System) desarrollado en Python para la captura y análisis de tráfico de red mediante **Scapy**.

El proyecto analiza paquetes en tiempo real y busca detectar comportamientos potencialmente sospechosos relacionados con tráfico TCP, UDP, DNS, ICMP y escaneos de puertos.


## 🚀 Características
* Captura de tráfico de red mediante Scapy.
* Análisis de protocolos TCP, UDP, DNS e ICMP.
* Detección de múltiples consultas DNS en un período de tiempo.
* Detección de tráfico ICMP excesivo.
* Detección de actividad elevada sobre determinados puertos TCP/UDP.
* Detección básica de posibles escaneos de puertos TCP.
* Identificación de servicios asociados a puertos conocidos.
* Clasificación de eventos según nivel de riesgo.
* Registro de eventos mediante `logging`.
* Generación de reportes en formato JSON.
* Selección de interfaz de red mediante argumentos de línea de comandos.
* Selección del archivo de salida para el reporte.


## 🛡️ Detecciones

### DNS

Analiza consultas DNS y contabiliza la cantidad de consultas realizadas por un origen hacia un destino dentro de una ventana de **10 segundos**.

| Cantidad | Nivel               |
| -------: | ------------------- |
|     > 10 | Advertencia en logs |
|     > 50 | ALERTA              |
|    > 100 | PELIGRO             |


### ICMP

Analiza paquetes ICMP Echo Request y permite detectar una cantidad elevada de paquetes ICMP dentro de una ventana de 10 segundos.

| Cantidad | Nivel               |
| -------: | ------------------- |
|     > 10 | Advertencia en logs |
|     > 50 | ALERTA              |
|    > 100 | PELIGRO             |


### TCP / UDP

El IDS monitoriza determinados puertos conocidos y contabiliza el tráfico dirigido hacia ellos durante una ventana de 10 segundos.

Entre los servicios contemplados se encuentran:
* FTP — 21
* SSH — 22
* Telnet — 23
* SMTP — 25
* DHCP — 67/68
* HTTP — 80
* POP3 — 110
* NetBIOS — 137/138/139
* IMAP — 143
* SNMP — 161/162
* HTTPS — 443
* SMB — 445
* MSSQL — 1433
* MySQL — 3306
* RDP — 3389

Los puertos se encuentran clasificados en diferentes categorías, como `WEB`, `SENSIBLE` y `RED`.


### Port Scan

El detector de escaneo de puertos analiza paquetes TCP SYN y registra los diferentes puertos contactados por un origen hacia un destino.

Si se detectan **80 o más puertos diferentes dentro de una ventana de 10 segundos**, se genera un evento `PORT_SCAN` con nivel `PELIGRO`.


## 📊 Niveles de riesgo

El proyecto utiliza tres niveles principales:
* **INFO / Advertencia:** actividad que supera el comportamiento considerado normal.
* **ALERTA:** actividad potencialmente sospechosa.
* **PELIGRO:** actividad que supera un umbral elevado y puede indicar un comportamiento malicioso.

Los umbrales utilizados son configurables directamente en el código.


## 📁 Estructura del proyecto

```text
sniffer/
│
├── main.py
│
├── core/
│   ├── detector_protocolo.py
│   └── sniffing.py
│
├── detector/
│   ├── detector_dns.py
│   ├── detector_udp.py
│   ├── detector_tcp.py
│   ├── detector_icmp.py
│   └── detector_portscan.py
│
├── report/
│   ├── json_manager.py
│   └── agregar_evaluacion.py
│
├── requirements.txt
├── README.md
└── .gitignore
```

## ⚙️ Requisitos

* Python 3
* Linux
* Permisos de administrador/root para realizar la captura de paquetes.
* Scapy


## 📦 Instalación

Clonar el repositorio:

```bash
git clone https://github.com/max22-ux/Mini-IDS.git
cd Mini-IDS
```

Instalar las dependencias:

```bash
pip install -r requirements.txt
```


## ▶️ Uso

Para iniciar el IDS se debe especificar la interfaz de red que se desea monitorizar.

```bash
sudo python3 main.py -i eth0
```

También es posible especificar el nombre del archivo de salida:

```bash
sudo python3 main.py -i eth0 -o reporte.json
```

Si el archivo indicado no tiene la extensión `.json`, el programa la agrega automáticamente.


## 🔎 Ejemplo

```text
sudo python3 main.py -i eth0 -o reporte.json
```


Salida de ejemplo:

```text
Iniciando Mini Ids
2026-08-28 20:00:00 INFO Interfaz objetivo: eth0
2026-08-28 20:00:05 INFO [SENSIBLE] SSH -> 192.168.1.10:22
2026-08-28 20:00:15 WARNING [ALERTA] Posible escaneo de puertos: 192.168.1.20 -> 192.168.1.10 (85 puertos en 10 segundos)
```

Los eventos detectados se almacenan en el archivo JSON especificado.


## 📄 Reporte JSON

El reporte se organiza por protocolo:
```json
{
    "TCP": [],
    "UDP": [],
    "DNS": [],
    "ICMP": []
}
```

Los eventos detectados se agregan dentro de la categoría correspondiente.

Por ejemplo:
```json
{
    "TCP": [
        {
            "tipo": "PORT_SCAN",
            "nivel": "PELIGRO",
            "origen": "192.168.1.20",
            "destino": "192.168.1.10",
            "puertos": 85,
            "ventana": "10 segundos"
        }
    ],
    "UDP": [],
    "DNS": [],
    "ICMP": []
}
```


## 🧪 Pruebas

El proyecto fue desarrollado y probado en un entorno de laboratorio controlado utilizando herramientas de análisis y generación de tráfico de red.

Para probar el detector de port scan, se puede utilizar una herramienta como Nmap contra un equipo propio o una máquina de laboratorio.

**No realizar pruebas contra sistemas o redes sin autorización.**


## ⚠️ Limitaciones

Este proyecto es un **Mini IDS educativo** y no pretende reemplazar soluciones IDS/IPS profesionales.

Las detecciones se basan principalmente en reglas y umbrales estáticos, por lo que pueden producirse falsos positivos o falsos negativos.

Actualmente no incluye:
* Análisis profundo del contenido de los paquetes.
* Correlación avanzada de eventos.
* Machine Learning.
* Detección avanzada de evasiones.
* Bloqueo automático del tráfico.
* Interfaz gráfica.


## 🎯 Objetivo
El objetivo del proyecto es aplicar de forma práctica conocimientos sobre:
* Redes TCP/IP.
* Análisis de tráfico.
* Scapy.
* Python.
* Detección de anomalías.
* IDS.
* Logging.
* Manejo de archivos JSON.
* Modularización de proyectos.
* Seguridad informática.


## ⚖️ Aviso

Este proyecto fue creado con fines educativos y de investigación en seguridad informática.

Utilízalo únicamente en redes, dispositivos y entornos sobre los que tengas autorización para realizar análisis.
