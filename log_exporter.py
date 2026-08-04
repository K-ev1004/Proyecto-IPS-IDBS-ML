# =============================================================================
# log_exporter.py — Exportador de Logs Semanales para el Sistema IDS/IPS
# Exporta ataques desde SQLite a archivos .log formateados
# Soporta exportación semanal automática y registro en vivo de bloqueos
# =============================================================================

import os
import re
import time
import sqlite3
from datetime import datetime, timedelta

# =============================================================================
# CONSTANTES
# =============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Ruta del directorio de logs - puede ser sobrescrita con variable de entorno LOG_FOLDER
def _get_logs_folder():
    env_folder = os.environ.get('LOG_FOLDER')
    if env_folder:
        return os.path.expandvars(env_folder)
    
    try:
        return r"D:\logs_ciberseguridad"
    except Exception:
        return os.path.join(BASE_DIR, 'logs_ciberseguridad')

# Intentar crear la carpeta de logs, si no es posible, usar la carpeta local
try:
    LOGS_FOLDER = _get_logs_folder()
    os.makedirs(LOGS_FOLDER, exist_ok=True)
except Exception:
    LOGS_FOLDER = os.path.join(BASE_DIR, 'logs_ciberseguridad')
    os.makedirs(LOGS_FOLDER, exist_ok=True)
    print(f"[INFO] Usando carpeta local para logs: {LOGS_FOLDER}")


def obtener_carpeta_logs():
    """Retorna la carpeta activa donde se escriben los .log del sistema."""
    return LOGS_FOLDER


# =============================================================================
# FUNCIÓN AUXILIAR: _ts_en_rango
# =============================================================================def _ts_en_rango(timestamp_str, inicio, fin):
    """
    Determina si un timestamp (formato time.ctime(), p.ej.
    'Fri Apr 24 09:00:30 2026') cae dentro del rango [inicio, fin].
    Devuelve True si no se puede parsear (se conserva por seguridad).
    """
    try:
        ts_dt = datetime.strptime(timestamp_str, "%a %b %d %H:%M:%S %Y")
    except Exception:
        try:
            ts_dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            # Formato no reconocido: conservar el registro
            return True
    return inicio <= ts_dt <= fin


# =============================================================================
# FUNCIÓN: exportar_logs_semanales
# =============================================================================
def exportar_logs_semanales():
    """
    Exporta registros de ataques de los últimos 7 días desde SQLite a un archivo .log
    
    Returns:
        str: Ruta del archivo .log exportado
    """
    try:
        # Asegurar que la carpeta existe
        if not os.path.exists(LOGS_FOLDER):
            os.makedirs(LOGS_FOLDER)
        
        # Calcular el rango de fechas (7 días atrás hasta hoy)
        hoy = datetime.now()
        hace_7_dias = hoy - timedelta(days=7)
        
        nombre_archivo = f"logsciberseguridad {hace_7_dias.strftime('%Y-%m-%d')} al {hoy.strftime('%Y-%m-%d')}.log"
        ruta_archivo = os.path.join(LOGS_FOLDER, nombre_archivo)
        
        # Conectar a la base de datos SQLite
        ruta_db = os.path.join(BASE_DIR, 'intrusiones.db')
        conn = sqlite3.connect(ruta_db)
        cursor = conn.cursor()
        
        # Obtener todos los ataques (el filtro se hace en Python porque los
        # timestamps se guardan en formato time.ctime(), no ISO)
        cursor.execute('''
            SELECT timestamp, tipo_ataque, ip_src, protocolo, puerto
            FROM ataques
            ORDER BY rowid
        ''')
        
        todos = cursor.fetchall()
        conn.close()
        
        # Filtrar solo los registros de la última semana (parsing de time.ctime)
        registros = [r for r in todos if _ts_en_rango(r[0], hace_7_dias, hoy)]
        
        # Escribir al archivo .log
        with open(ruta_archivo, 'w', encoding='utf-8') as f:
            # Encabezado
            f.write(f"================================================================================\n")
            f.write(f"LOGS CIBERSEGURIDAD - SEMANA: {hace_7_dias.strftime('%Y-%m-%d')} al {hoy.strftime('%Y-%m-%d')}\n")
            f.write(f"Sistema IDS/IPS - UNIPAZ\n")
            f.write(f"================================================================================\n\n")
            
            # Líneas de cada registro
            for timestamp, tipo_ataque, ip_src, protocolo, puerto in registros:
                # Extraer nivel de registro del tipo de ataque
                if 'ML:' in tipo_ataque:
                    nivel = "[CRITICAL]"
                elif '(Heurística)' in tipo_ataque:
                    nivel = "[WARNING]"
                else:
                    nivel = "[INFO]"
                
                f.write(f"{timestamp} | {nivel} | IP_SRC: {ip_src} | TIPO: {tipo_ataque} | PROTO: {protocolo} | PUERTO: {puerto}\n")
        
        return ruta_archivo
        
    except Exception as e:
        print(f"[X] Error exportando logs semanales: {e}")
        raise

# =============================================================================
# FUNCIÓN: registrar_bloqueo_log
# =============================================================================
def registrar_bloqueo_log(ip, accion, duracion):
    """
    Escribe un registro de bloqueo en vivo al archivo .log
    
    Args:
        ip (str): Dirección IP del host bloqueado/desbloqueado
        accion (str): Tipo de acción (BLOQUEO_AUTOMATICO o DESBLOQUEO_AUTOMATICO)
        duracion (int): Duración del bloqueo en minutos
    """
    try:
        # Asegurar que la carpeta existe
        if not os.path.exists(LOGS_FOLDER):
            os.makedirs(LOGS_FOLDER)
        
        ruta_archivo = os.path.join(LOGS_FOLDER, "logs_bloqueos.log")
        
        with open(ruta_archivo, 'a', encoding='utf-8') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] IP: {ip} | Acción: {accion} | Duración: {duracion} min\n")
            
    except Exception as e:
        print(f"[X] Error registrando bloqueo en log: {e}")

# =============================================================================
# EJECUCIÓN PRINCIPAL (para pruebas directas)
# =============================================================================
if __name__ == "__main__":
    print("Exportando logs semanales...")
    ruta = exportar_logs_semanales()
    print(f"✓ Logs exportados a: {ruta}")