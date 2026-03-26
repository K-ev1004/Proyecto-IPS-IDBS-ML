# =============================================================================
# clasificador_ml.py — Clasificador de tráfico de red en tiempo real
# Detecta ataques SYN Flood y DDoS mediante análisis de ventana temporal
# Este módulo opera de forma independiente al modelo ML de CEREBRO.PY,
# usando heurísticas basadas en frecuencia de paquetes por IP
# =============================================================================

# defaultdict: Diccionario que asigna un valor por defecto cuando se accede a una clave inexistente
# Aquí se usa con list como default_factory → cada nueva clave inicia con lista vacía []
from collections import defaultdict

# time: Módulo estándar para obtener marcas de tiempo en segundos desde el epoch Unix
import time


# =============================================================================
# ESTRUCTURA DE DATOS: contador_ips
# Diccionario global que registra los timestamps de cada paquete recibido por IP de origen
# Clave: IP de origen (string) — Valor: Lista de timestamps (float, segundos Unix)
# Se mantiene entre llamadas a la función gracias a su alcance global (módulo)
# Ejemplo: {"192.168.1.5": [1720000001.23, 1720000001.45, 1720000001.67]}
# =============================================================================
contador_ips = defaultdict(list)


# =============================================================================
# FUNCIÓN: clasificar_ataque_ml
# Propósito: Analiza el tráfico de red en tiempo real y clasifica si es un ataque
# Parámetros:
#   ip_src    — Dirección IP de origen del paquete
#   ip_dst    — Dirección IP de destino del paquete
#   puerto    — Puerto de destino del paquete
#   protocolo — Protocolo de red ("TCP", "UDP", etc.)
#   flag      — Bandera TCP del paquete ("S", "A", "F", etc.)
# Retorna: String con la clasificación del tráfico detectado
# =============================================================================
def clasificar_ataque_ml(ip_src, ip_dst, puerto, protocolo, flag):

    # time.time(): Retorna el tiempo actual como número de punto flotante en segundos
    # Se usa como marca temporal precisa para comparar contra paquetes anteriores
    tiempo_actual = time.time()

    # VENTANA TEMPORAL: Solo se consideran paquetes recibidos en los últimos 5 segundos
    # Una ventana corta permite detectar ataques rápidos y descartar tráfico antiguo
    ventana_tiempo = 5  # segundos

    # UMBRAL: Si una IP envía más de 10 paquetes en 5 segundos, se considera sospechosa
    # Este valor determina la sensibilidad del detector (trade-off: falsos positivos vs detección)
    umbral_paquetes = 10

    # Registra el timestamp actual del paquete en la lista de la IP de origen
    # defaultdict garantiza que si ip_src es nueva, crea una lista vacía automáticamente
    contador_ips[ip_src].append(tiempo_actual)

    # --- LIMPIEZA DE VENTANA TEMPORAL ---
    # Filtra y conserva SOLO los timestamps que están dentro de la ventana activa (últimos 5 seg)
    # tiempo_actual - t <= ventana_tiempo: True si el paquete es reciente
    # Esta operación es fundamental para que el detector no acumule datos obsoletos indefinidamente
    # List comprehension: crea una nueva lista reemplazando la anterior (filtro in-place)
    contador_ips[ip_src] = [
        t for t in contador_ips[ip_src]
        if tiempo_actual - t <= ventana_tiempo
    ]

    # =========================================================================
    # REGLA 1: DETECCIÓN DE SYN FLOOD
    # Condición: protocolo TCP + flag SYN activo
    # Justificación: Un paquete TCP con solo SYN indica intento de apertura de conexión
    # sin completarla — patrón directo del ataque SYN Flood
    # Esta regla tiene PRIORIDAD sobre DDoS (se evalúa primero)
    # =========================================================================
    if protocolo == "TCP" and flag == "S":
        return "SYN Flood"

    # =========================================================================
    # REGLA 2: DETECCIÓN DE DDoS DISTRIBUIDO
    # Condición: 5 o más IPs distintas superando el umbral de paquetes simultáneamente
    # Justificación: El DDoS distribuido (botnet) se distingue del flood individual
    # por el número de IPs origen activas al mismo tiempo
    # ips_multiples: Lista de IPs que en la ventana actual superaron el umbral
    # =========================================================================
    # List comprehension que filtra las IPs con alta frecuencia de paquetes
    ips_multiples = [
        ip for ip, tiempos in contador_ips.items()
        if len(tiempos) >= umbral_paquetes
    ]

    # Si hay 5 o más IPs distintas activas con tráfico elevado → ataque distribuido
    if len(ips_multiples) >= 5:
        return "DDoS Distribuido"

    # =========================================================================
    # CASO DEFAULT: Si ninguna regla se activa, el tráfico se clasifica como normal
    # =========================================================================
    return "Tráfico Normal"

# =============================================================================
# FIN DEL SCRIPT — clasificador_ml.py
# =============================================================================
