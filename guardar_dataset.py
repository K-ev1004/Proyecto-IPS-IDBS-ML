import csv
import os
import time
from datetime import datetime

csv_file = "C:/Users/Usuario/Desktop/IDS/IDS_unipaz/Dataset/eventos_detectados.csv"

def guardar_evento_en_dataset(ip_src, ip_dst, puerto, protocolo, flag, tipo_ataque, tipo_ataque_ml):
    carpeta = r"C:\Users\Usuario\Desktop\IDS\IDS_unipaz\Dataset"
    if not os.path.exists(carpeta):
        os.makedirs(carpeta)  # Crea la carpeta si no existe

    nombre_archivo = "eventos_detectados.csv"
    ruta_completa = os.path.join(carpeta, nombre_archivo)

    with open(ruta_completa, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([time.ctime(), ip_src, ip_dst, puerto, protocolo, flag, tipo_ataque, tipo_ataque_ml])

    print(f"📝 Evento guardado en CSV: {ruta_completa}")
