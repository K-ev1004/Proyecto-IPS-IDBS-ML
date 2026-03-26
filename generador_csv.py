# =============================================================================
# generador_csv.py — Generador sintético de tráfico de red para dataset IDS
# Genera datos simulados de cuatro tipos de tráfico: Normal, Port Scan,
# SYN Flood y DDoS, y los escribe en un archivo CSV estructurado.
# =============================================================================

# os: Módulo del sistema operativo para manejo de rutas, directorios y archivos
import os

# csv: Módulo estándar para lectura y escritura de archivos en formato CSV
import csv

# random: Módulo para generación de valores pseudoaleatorios (IPs, puertos, protocolos)
import random

# datetime, timedelta: Para generar timestamps secuenciales y calcular intervalos de tiempo
from datetime import datetime, timedelta


# =============================================================================
# BLOQUE DE PARÁMETROS DE CONFIGURACIÓN
# Define cuántos paquetes simulados generará cada tipo de tráfico
# =============================================================================

# Número de IPs que generarán tráfico DDoS (activo)
# Las variables comentadas (normales, portscan, synflood) están desactivadas temporalmente
# num_ips_normales = 10
# num_ips_portscan = 10
# num_ips_synflood = 9
num_ips_ddos = 1000  # 1000 IPs distintas atacando simultáneamente (simula botnet)

puertos_totales = 65535  # Rango máximo de puertos TCP/UDP según el estándar RFC 793

# Paquetes que genera cada IP según el tipo de ataque
paquetes_por_ip_normal = 100      # Bajo volumen — comportamiento legítimo
paquetes_por_ip_portscan = 2000   # Alto volumen de puertos distintos — reconocimiento
paquetes_por_ip_synflood = 5000   # Altísimo volumen al mismo puerto — agotamiento de recursos
paquetes_por_ip_ddos = 3000       # Alto volumen de múltiples IPs — saturación del servicio


# =============================================================================
# CONFIGURACIÓN DE RUTA DE SALIDA
# =============================================================================

# Construye la ruta de salida de forma dinámica relativa al directorio actual
# os.getcwd(): Retorna el directorio de trabajo actual
# os.path.join(): Combina segmentos de ruta de manera independiente al OS (Win/Linux/Mac)
output_file = os.path.join(os.getcwd(), "Dataset", "trafico_mixto.csv")

# Extrae solo la parte del directorio de la ruta completa (sin el nombre de archivo)
output_dir = os.path.dirname(output_file)

# Crea el directorio si no existe para evitar FileNotFoundError al escribir el CSV
if not os.path.exists(output_dir):
    os.makedirs(output_dir)  # makedirs crea directorios anidados recursivamente


# =============================================================================
# FUNCIÓN: generar_ip
# Propósito: Genera una dirección IPv4 aleatoria en el rango privado 192.168.x.x
# Retorna: String con formato "192.168.X.Y"
# Nota: Se usa rango privado RFC 1918 para simular tráfico de red local (LAN)
# =============================================================================
def generar_ip():
    # random.randint(a, b): Genera entero aleatorio en rango [a, b] (ambos inclusive)
    # Tercer octeto: 0-255 (256 subredes posibles)
    # Cuarto octeto: 1-254 (evita .0 = dirección de red y .255 = broadcast)
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"


# =============================================================================
# PUNTO DE INICIO DEL TIEMPO BASE
# Todos los timestamps se generan a partir de este momento
# datetime.now(): Captura la fecha y hora exacta en el momento de ejecución del script
# =============================================================================
start_time = datetime.now()


# =============================================================================
# ESCRITURA DEL ARCHIVO CSV
# open(..., mode='w'): Abre en modo escritura; si existe, lo sobreescribe
# newline='': Previene líneas en blanco dobles en Windows (comportamiento del módulo csv)
# =============================================================================
with open(output_file, mode='w', newline='') as csvfile:

    # csv.writer: Objeto que formatea filas como strings separados por coma
    writer = csv.writer(csvfile)

    # Escribe la cabecera del CSV con los nombres de las columnas
    # Estas columnas coinciden con las que espera CEREBRO.PY para el entrenamiento
    writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'flag', 'tipo_ataque'])

    # =========================================================================
    # BLOQUE 1: TRÁFICO NORMAL
    # Simula navegación web, correo, DNS — comportamiento legítimo de usuarios
    # Patron: Intervalos largos (0.5-2 seg), puertos comunes, protocolos mixtos
    # =========================================================================
    for _ in range(num_ips_normales):          # Itera por cada IP "normal"
        ip_src = generar_ip()                   # IP de origen aleatoria
        for i in range(paquetes_por_ip_normal): # 100 paquetes por IP
            # timedelta(seconds=...): Desplaza el tiempo base en segundos
            # random.uniform(0.5, 2): Intervalo variable → simula comportamiento humano irregular
            timestamp = (start_time + timedelta(seconds=i*random.uniform(0.5, 2))).strftime('%Y-%m-%d %H:%M:%S')
            ip_dst = generar_ip()
            dst_port = random.choice([80, 443, 22, 25, 53])  # HTTP, HTTPS, SSH, SMTP, DNS
            protocol = random.choice(['TCP', 'UDP'])
            # Las flags TCP solo aplican cuando el protocolo es TCP
            # A=ACK, S=SYN, F=FIN, P=PUSH, R=RST, ''=sin flag
            flag = random.choice(['A', 'S', 'F', 'P', 'R', '']) if protocol == 'TCP' else ''
            tipo_ataque = 'Normal'
            writer.writerow([timestamp, ip_src, ip_dst, dst_port, protocol, flag, tipo_ataque])

    # =========================================================================
    # BLOQUE 2: TRÁFICO PORT SCAN
    # Simula reconocimiento de red mediante escaneo masivo de puertos
    # Patrón: Muchos puertos distintos, intervalo muy corto (50ms), solo TCP+SYN
    # =========================================================================
    for _ in range(num_ips_portscan):
        ip_src = generar_ip()
        ip_dst = generar_ip()  # IP destino fija por iteración (escanea un host a la vez)
        for i in range(paquetes_por_ip_portscan):  # 2000 paquetes = 2000 puertos distintos
            # Intervalo de 50ms entre paquetes — velocidad característica de herramientas como nmap
            # [:-3]: Recorta los últimos 3 caracteres (microsegundos) para formato legible
            timestamp = (start_time + timedelta(seconds=i*0.05)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            dst_port = random.randint(1, puertos_totales)  # Puerto completamente aleatorio
            protocol = 'TCP'   # Port Scan usa TCP para detectar puertos abiertos
            flag = 'S'         # Solo SYN — intenta iniciar conexión sin completarla (half-open scan)
            tipo_ataque = 'Port Scan'
            writer.writerow([timestamp, ip_src, ip_dst, dst_port, protocol, flag, tipo_ataque])

    # =========================================================================
    # BLOQUE 3: TRÁFICO SYN FLOOD
    # Simula ataque de denegación de servicio mediante inundación de paquetes SYN
    # Patrón: Un puerto destino fijo, 10ms entre paquetes, solo TCP+SYN
    # =========================================================================
    for _ in range(num_ips_synflood):
        ip_src = generar_ip()
        ip_dst = generar_ip()
        # Elige un puerto de servicio web como objetivo (los más atacados en SYN Flood)
        dst_port = random.choice([80, 443, 8080])  # HTTP, HTTPS, HTTP-alt
        for i in range(paquetes_por_ip_synflood):  # 5000 paquetes por IP — altísimo volumen
            # 10ms entre paquetes — velocidad muy alta para saturar la tabla de conexiones del servidor
            timestamp = (start_time + timedelta(seconds=i*0.01)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            protocol = 'TCP'
            flag = 'S'  # Solo SYN sin ACK de vuelta → agota half-open connections del servidor
            tipo_ataque = 'SYN Flood'
            writer.writerow([timestamp, ip_src, ip_dst, dst_port, protocol, flag, tipo_ataque])

    # =========================================================================
    # BLOQUE 4: TRÁFICO DDoS (Distributed Denial of Service)
    # Simula botnet de 1000 IPs atacando una misma IP destino simultáneamente
    # Patrón: IP destino fija, múltiples IPs origen, UDP, alto volumen
    # =========================================================================
    # IP destino fija — el "servidor víctima" del ataque DDoS
    ip_dst_ddos = generar_ip()

    for _ in range(num_ips_ddos):  # 1000 IPs distintas (nodos de la botnet)
        ip_src = generar_ip()
        dst_port = random.choice([80, 443])  # Servicios web principales como objetivo
        for i in range(paquetes_por_ip_ddos):  # 3000 paquetes por nodo de la botnet
            # 20ms entre paquetes — espaciado para evadir detección individual
            timestamp = (start_time + timedelta(seconds=i*0.02)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            protocol = 'UDP'  # UDP amplification es técnica común en DDoS volumétrico
            flag = ''          # UDP no usa flags TCP
            tipo_ataque = 'DDoS'
            writer.writerow([timestamp, ip_src, ip_dst_ddos, dst_port, protocol, flag, tipo_ataque])

# Confirmación en consola con la ruta donde quedó guardado el archivo
print(f"CSV generado en {output_file}")

# =============================================================================
# FIN DEL SCRIPT — generador_csv.py
# =============================================================================
