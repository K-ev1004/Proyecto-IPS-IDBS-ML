# =============================================================================
# respuesta_activa.py — Módulo de Respuesta Activa (IPS)
# Implementa el bloqueo de IPs maliciosas usando comandos del sistema (Windows)
# =============================================================================

import subprocess
import logging
import os
import threading
import time
from datetime import datetime

# Configuración de logs para auditoría de bloqueos
LOG_BLOQUEOS = "logs_bloqueos.txt"

def is_admin():
    """Verifica si el script tiene privilegios de administrador (Windows)."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        # En sistemas no-Windows o si falla la llamada
        return False

def _ejecutar_comando_firewall(comando):
    """Ejecuta un comando de netsh en Windows de forma segura."""
    try:
        resultado = subprocess.run(
            ["powershell", "-Command", comando],
            capture_output=True,
            text=True,
            check=False
        )
        if resultado.returncode == 0:
            return True, resultado.stdout
        else:
            return False, resultado.stderr
    except Exception as e:
        return False, str(e)

def registrar_bloqueo(ip, accion, duracion=None):
    """Registra la acción de bloqueo en un archivo persistente."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{timestamp}] IP: {ip} | Acción: {accion}"
    if duracion:
        msg += f" | Duración: {duracion} min"
    
    with open(LOG_BLOQUEOS, "a", encoding="utf-8") as f:
        f.write(msg + "\n")
    print(msg)

def bloquear_ip(ip, duracion_minutos=30):
    """
    Bloquea una IP en el Firewall de Windows creando una regla de entrada.
    """
    if not is_admin():
        print(f"[X] ERROR CRÍTICO: No se puede bloquear {ip}. Se requieren privilegios de ADMINISTRADOR.")
        return False

    nombre_regla = f"IDS_BLOCK_{ip}"
    
    # Comando de PowerShell para crear regla de bloqueo
    comando = (
        f"New-NetFirewallRule -DisplayName '{nombre_regla}' "
        f"-Direction Inbound -Action Block -RemoteAddress {ip} -Description 'Bloqueo automático IDS UNIPAZ'"
    )
    
    exito, output = _ejecutar_comando_firewall(comando)
    if exito:
        registrar_bloqueo(ip, "BLOQUEO_AUTOMATICO", duracion_minutos)
        # Programar el desbloqueo automático
        threading.Thread(target=programar_desbloqueo, args=(ip, duracion_minutos), daemon=True).start()
        return True
    else:
        print(f"[X] Error al ejecutar comando de bloqueo para {ip}. Verifique que PowerShell esté disponible.")
        logging.error(f"Error Firewall: {output}")
        return False

def desbloquear_ip(ip):
    """Elimina la regla de bloqueo de una IP en el Firewall de Windows."""
    nombre_regla = f"IDS_BLOCK_{ip}"
    comando = f"Remove-NetFirewallRule -DisplayName '{nombre_regla}'"
    
    exito, output = _ejecutar_comando_firewall(comando)
    if exito:
        registrar_bloqueo(ip, "DESBLOQUEO_AUTOMATICO")
        return True
    else:
        # Si la regla no existe, 'netsh' retorna error pero el objetivo es el mismo
        print(f"[!] Aviso al desbloquear IP {ip}: {output}")
        return False

def programar_desbloqueo(ip, minutos):
    """Hilo de espera para desbloqueo automático."""
    time.sleep(minutos * 60)
    print(f"[WAIT] El tiempo de bloqueo para {ip} ha expirado. Procediendo a desbloqueo...")
    desbloquear_ip(ip)

# =============================================================================
# BLOQUE DE PRUEBA (Solo manual)
# =============================================================================
if __name__ == "__main__":
    test_ip = "192.168.1.50"
    print(f"--- Iniciando prueba de bloqueo para {test_ip} ---")
    if bloquear_ip(test_ip, 1):
        print("[OK] Bloqueo exitoso (durará 1 minuto).")
    else:
        print("[X] Fallo en el bloqueo inicial.")
