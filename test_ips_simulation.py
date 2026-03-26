# =============================================================================
# test_ips_simulation.py — Script de Prueba de Respuesta Activa
# Simula un ataque detectado para verificar el bloqueo automático (IPS)
# =============================================================================

import sys
import os
import time

# Añadir el directorio actual al path para importar los módulos del proyecto
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    import ids
    import respuesta_activa
except ImportError as e:
    print(f"[X] Error al importar módulos: {e}")
    sys.exit(1)

def simular_ataque_sql_injection():
    print("\n🚀 --- SIMULACIÓN DE ATAQUE: SQL INJECTION ---")
    
    # Configuramos el modo IPS como activo
    ids.ips_activo = True
    print("[OK] Modo IPS habilitado en ids.py")

    # Datos del ataque simulado
    ip_atacante = "10.99.99.99"
    ip_destino  = "192.168.1.100"
    puerto      = 80
    protocolo   = "TCP"
    flag        = "PA" # Push Ack (tráfico de datos)
    tipo_ataque = "SQL Injection"

    print(f"📡 Simulando detección de {tipo_ataque} desde {ip_atacante}...")

    # Llamamos directamente a guardar_ataque
    # Forzamos usar_ml=True y confianza=0.95 para saltar los umbrales de bloqueo
    # Nota: En un escenario real, esto lo haría el sniffer + el modelo ML
    try:
        # Mocking/Overriding parcial: Modificamos temporalmente el comportamiento de ML 
        # para esta prueba manual controlada.
        
        # Guardamos el ataque (esto debería disparar la lógica de IPS en ids.py)
        # Usamos un pequeño hack: pasamos usar_ml=True. 
        # Como no tenemos el modelo real cargado o funcionando en este entorno,
        # ids.py llamará a clasificar_ataque_ml y obtendrá "Desconocido" o fallará.
        # Para la prueba, modificamos el valor de confianza retornado por el wrapper.
        
        original_clasificar = ids.clasificar_ataque_ml
        ids.clasificar_ataque_ml = lambda *args: ("SQL Injection", 0.98) # Simulamos 98% de confianza
        
        print("🛠️ Simulación: Modelo ML configurado para retornar 98% de confianza.")
        
        ids.guardar_ataque(
            ip_src=ip_atacante,
            tipo_ataque=tipo_ataque,
            protocolo=protocolo,
            puerto=puerto,
            ip_dst=ip_destino,
            flag=flag,
            usar_ml=True
        )
        
        # Restauramos la función original
        ids.clasificar_ataque_ml = original_clasificar
        
        print("\n[OK] Simulación completada.")
        print("🔍 Revisa 'logs_bloqueos.txt' y la tabla 'bloqueos' en 'intrusiones.db' para confirmar.")
        
    except Exception as e:
        print(f"[X] Error durante la simulación: {e}")

if __name__ == "__main__":
    # Verificamos si estamos en Windows (necesario para powershell)
    if os.name != 'nt':
        print("[!] Advertencia: Este test está diseñado para Windows (Netsh/PowerShell).")
    
    simular_ataque_sql_injection()
