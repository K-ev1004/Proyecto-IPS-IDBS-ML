# =============================================================================
# guardar_dataset.py — Módulo de persistencia de eventos detectados por el IDS
# Registra en un archivo CSV cada evento de red analizado por el sistema,
# incluyendo tanto la clasificación heurística como la predicción del modelo ML
# =============================================================================

# csv: Módulo estándar para escritura de archivos en formato CSV
import csv

# os: Módulo para operaciones del sistema de archivos (rutas, creación de directorios)
import os

# time: Para obtener la hora actual del sistema en formato legible
import time

# datetime: Para manejo avanzado de fechas y horas (importado pero no usado directamente aquí)
from datetime import datetime


# =============================================================================
# VARIABLE GLOBAL: csv_file
# Ruta absoluta al archivo CSV principal de eventos
# Nota: Esta ruta está hardcodeada — en producción sería preferible leerla desde un config
# La función guardar_evento_en_dataset usa su propia ruta interna (carpeta/nombre separados)
# =============================================================================
csv_file = "C:/Users/Usuario/Desktop/IDS/IDS_unipaz/Dataset/eventos_detectados.csv"


# =============================================================================
# FUNCIÓN: guardar_evento_en_dataset
# Propósito: Persiste un evento de red analizado en el archivo CSV del dataset
# Crea el archivo y su directorio si no existen (modo 'append' si ya existe)
#
# Parámetros:
#   ip_src         — IP de origen del paquete capturado
#   ip_dst         — IP de destino del paquete capturado
#   puerto         — Puerto de destino del paquete
#   protocolo      — Protocolo de red (TCP, UDP, etc.)
#   flag           — Bandera TCP del paquete (S, A, F, etc.)
#   tipo_ataque    — Clasificación heurística (proveniente de clasificador_ml.py)
#   tipo_ataque_ml — Clasificación del modelo ML (proveniente de CEREBRO.PY)
# =============================================================================
def guardar_evento_en_dataset(ip_src, ip_dst, puerto, protocolo, flag, tipo_ataque, tipo_ataque_ml):

    # Ruta absoluta a la carpeta donde se almacenará el dataset
    # Se usa raw string (r"...") para evitar que las barras invertidas sean interpretadas
    # como secuencias de escape de Python en Windows
    carpeta = r"C:\Users\Usuario\Desktop\IDS\IDS_unipaz\Dataset"

    # Verifica si la carpeta existe antes de intentar escribir
    # Si no existe, la crea para evitar FileNotFoundError
    # os.makedirs: Crea directorios de forma recursiva (incluyendo subdirectorios intermedios)
    if not os.path.exists(carpeta):
        os.makedirs(carpeta)

    # Nombre del archivo CSV donde se acumulan todos los eventos detectados
    nombre_archivo = "eventos_detectados.csv"

    # os.path.join: Construye la ruta completa uniendo carpeta + nombre de archivo
    # Independiente del sistema operativo (usa \ en Windows, / en Linux/Mac)
    ruta_completa = os.path.join(carpeta, nombre_archivo)

    # Apertura del archivo en modo APPEND ('a'):
    # - Si el archivo no existe: lo crea desde cero
    # - Si el archivo ya existe: agrega al final sin borrar el contenido previo
    # newline='': Necesario en Windows para evitar líneas en blanco dobles en CSV
    # encoding='utf-8': Garantiza compatibilidad con caracteres especiales (tildes, ñ)
    with open(ruta_completa, 'a', newline='', encoding='utf-8') as f:

        # Crea el objeto escritor de CSV asociado al archivo abierto
        writer = csv.writer(f)

        # Escribe una fila con todos los datos del evento
        # time.ctime(): Retorna el tiempo actual como string legible (ej: "Thu Jun 20 14:23:01 2024")
        # Se incluyen ambas clasificaciones para comparar heurística vs ML en el análisis posterior
        writer.writerow([
            time.ctime(),       # Timestamp del momento en que se guardó el evento
            ip_src,             # IP origen del tráfico capturado
            ip_dst,             # IP destino del tráfico capturado
            puerto,             # Puerto de destino
            protocolo,          # Protocolo de red
            flag,               # Flag TCP (vacío para UDP)
            tipo_ataque,        # Clasificación por reglas heurísticas (clasificador_ml.py)
            tipo_ataque_ml      # Clasificación por modelo de Machine Learning (CEREBRO.PY)
        ])

    # Mensaje de confirmación en consola indicando que el evento fue registrado exitosamente
    print(f"📝 Evento guardado en CSV: {ruta_completa}")

# =============================================================================
# FIN DEL SCRIPT — guardar_dataset.py
# =============================================================================
