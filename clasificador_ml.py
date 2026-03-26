from collections import defaultdict
import time

# Diccionario para contar paquetes por IP en ventana de tiempo
contador_ips = defaultdict(list)

def clasificar_ataque_ml(ip_src, ip_dst, puerto, protocolo, flag):
    tiempo_actual = time.time()
    ventana_tiempo = 5  # segundos
    umbral_paquetes = 10  # más de 10 paquetes en 5 segundos desde la misma IP

    # Registrar el tiempo del paquete
    contador_ips[ip_src].append(tiempo_actual)

    # Limpiar los tiempos viejos fuera de la ventana
    contador_ips[ip_src] = [t for t in contador_ips[ip_src] if tiempo_actual - t <= ventana_tiempo]

    # Verifica SYN Flood
    if protocolo == "TCP" and flag == "S":
        return "SYN Flood"

    # Verifica DDoS Distribuido
    ips_multiples = [ip for ip, tiempos in contador_ips.items() if len(tiempos) >= umbral_paquetes]
    if len(ips_multiples) >= 5:
        return "DDoS Distribuido"

    return "Tráfico Normal"