# mikrotik_api.py — Módulo de Interacción con RouterOS (MikroTik CCR2004)
# Universidad UNIPAZ
# =============================================================================
# Propósito: Ejecuta comandos remotos vía SSH para bloquear dinámicamente
# las direcciones IP atacantes en el Firewall Perimetral de la institución.
# =============================================================================

import logging
import datetime

# Nota: En producción, instalar 'paramiko' (pip install paramiko)
try:
    import paramiko
    PARAMIKO_DISPONIBLE = True
except ImportError:
    PARAMIKO_DISPONIBLE = False

# ============================================================
# CONFIGURACIÓN DEL ROUTER (Ajustar credenciales de UNIPAZ)
# ============================================================
ROUTER_IP = "192.168.1.1"      # IP de gestión del MikroTik Core
ROUTER_USER = "admin_ids"      # Usuario con permisos de firewall
ROUTER_PASS = "UnipazSegura2026" 
ROUTER_PORT = 22               # Puerto SSH estándar (o custom)

LISTA_BLOQUEO = "IDS_BLACKLIST" # Nombre del Address-List en MikroTik

def bloquear_ip_mikrotik(ip_atacante, duracion_horas=24):
    """
    Se conecta al MikroTik y añade la IP a la lista de bloqueo del firewall.
    """
    print(f"\n[IPS MIKROTIK] Iniciando bloqueo activo para {ip_atacante}")
    
    if not PARAMIKO_DISPONIBLE:
        print("[!] Paramiko no está instalado. Bloqueo simulado (Mock).")
        print(f"[!] MOCK COMMAND: /ip firewall address-list add list={LISTA_BLOQUEO} address={ip_atacante} timeout={duracion_horas}h")
        return True

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        print(f"[*] Conectando a MikroTik ({ROUTER_IP})...")
        ssh.connect(ROUTER_IP, port=ROUTER_PORT, username=ROUTER_USER, password=ROUTER_PASS, timeout=5.0)
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        comando = (
            f'/ip firewall address-list add '
            f'list="{LISTA_BLOQUEO}" '
            f'address={ip_atacante} '
            f'timeout={duracion_horas}h '
            f'comment="Bloqueado automáticamente por NIPS CatBoost - {timestamp}"'
        )
        
        print(f"[*] Ejecutando: {comando}")
        stdin, stdout, stderr = ssh.exec_command(comando)
        
        error = stderr.read().decode().strip()
        salida = stdout.read().decode().strip()
        
        ssh.close()
        
        if error:
            if "already have" in error or "already exists" in error:
                print(f"[OK] La IP {ip_atacante} ya estaba bloqueada en el MikroTik.")
                return True
            print(f"[X] Error desde MikroTik: {error}")
            return False
            
        print(f"[OK] IP {ip_atacante} bloqueada exitosamente por {duracion_horas} horas.")
        return True

    except Exception as e:
        print(f"[X] Falla crítica al conectar con MikroTik: {e}")
        return False

def desbloquear_ip_mikrotik(ip_atacante):
    """
    Se conecta al MikroTik y elimina la IP de la lista de bloqueo del firewall.
    """
    print(f"\n[IPS MIKROTIK] Iniciando desbloqueo activo para {ip_atacante}")
    
    if not PARAMIKO_DISPONIBLE:
        print("[!] Paramiko no está instalado. Desbloqueo simulado (Mock).")
        print(f"[!] MOCK COMMAND: /ip firewall address-list remove [find list={LISTA_BLOQUEO} address={ip_atacante}]")
        return True

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        print(f"[*] Conectando a MikroTik ({ROUTER_IP})...")
        ssh.connect(ROUTER_IP, port=ROUTER_PORT, username=ROUTER_USER, password=ROUTER_PASS, timeout=5.0)
        
        comando = f'/ip firewall address-list remove [find list="{LISTA_BLOQUEO}" address="{ip_atacante}"]'
        
        print(f"[*] Ejecutando: {comando}")
        stdin, stdout, stderr = ssh.exec_command(comando)
        
        error = stderr.read().decode().strip()
        salida = stdout.read().decode().strip()
        
        ssh.close()
        
        if error:
            print(f"[X] Error desde MikroTik: {error}")
            return False
            
        print(f"[OK] IP {ip_atacante} desbloqueada exitosamente.")
        return True

    except Exception as e:
        print(f"[X] Falla crítica al conectar con MikroTik: {e}")
        return False
