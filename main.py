import os
from core import sniffing
import argparse
import logging
from report import json_manager
from report.json_manager import ReportManager

if os.geteuid() != 0:
    print("Ejecutá el script con sudo")
    exit()

def argumentos():
    parse = argparse.ArgumentParser(description="Interfaz a escanear")
    parse.add_argument("-i","--interface",required=True,help="Interfaz(ej:eth0)")
    parse.add_argument("-o","--output",default="reporte.json")
    return parse.parse_args()

def main():
    print("Iniciando Mini Ids")

    agrs = argumentos()
    interfaz = agrs.interface
    salida = agrs.output
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
        )
    logging.info("Interfaz objetivo: %s",interfaz)
    #verificar si esta bien
    if not salida.endswith(".json"):
        salida += ".json"        
    path = json_manager.report(salida)
    report_manager = ReportManager(path)
    sniffing.detector(interfaz, report_manager)


if __name__ == "__main__":
    main()