import json
import logging
from pathlib import Path
logger = logging.getLogger(__name__)

class ReportManager:
    def __init__(self,path):
        self.path = path
        self.data = self.cargar_json()

    def cargar_json(self):
        data = {
            "TCP": [],
            "UDP": [], 
            "DNS": [],
            "ICMP": []
            }
        try:
            if not self.path.exists():
                with open(self.path, "w") as f:
                    json.dump(data,f,indent=4)

                return data

            with open (self.path, "r") as f:
                data = json.load(f)

            return data

        except json.JSONDecodeError:
            logger.warning("El archivo JSON esta vacio o corrupto")

            with open(self.path, "w") as f:
                json.dump(data,f,indent=4)
            
            return data

        except FileNotFoundError:
            logger.error("Archivo JSON no encontrado")
            return data

        except PermissionError: 
            logger.error("Error de permiso")
            return data

        except OSError as e:
            logger.error(f"Error al intentar acceder al archivo JSON: {e}")
            return data

    def agregar_resultado(self,tipo,dato):
        data = {
        "TCP": [],
        "UDP": [], 
        "DNS": [],
        "ICMP": []
        }
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {
            "TCP": [],
            "UDP": [], 
            "DNS": [],
            "ICMP": []
            }
        except FileNotFoundError:
            logger.error("Archivo JSON no encontrado")
            return data

        except PermissionError: 
            logger.error("Error de permiso")
            return data

        except OSError as e:
            logger.error(f"Error al intentar acceder al archivo JSON: {e}")
            return data

        tipo = tipo.upper()

        if tipo not in data:
            print(f"[WARN] tipo '{tipo}' no existe. Se crea automaticamente")
            data[tipo] = []

        data[tipo].append(dato)

        with open(self.path,"w") as f:
            json.dump(data, f, indent=4)

def report(output):  #origen del path
    # raíz del proyecto (sube niveles según dónde esté el archivo)
    ROOT_DIR = Path(__file__).resolve().parent.parent
    # ruta a report/reporte.json
    report_path = ROOT_DIR / "report" / output
    return report_path