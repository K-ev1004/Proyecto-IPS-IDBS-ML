# =============================================================================
# ids.py — Motor principal del IDS (Intrusion Detection System)
# Captura tráfico de red en tiempo real, detecta patrones de ataque,
# clasifica con ML, persiste en SQLite/CSV y notifica por Telegram
# =============================================================================

# Módulos estándar del sistema
import sys          # Acceso al intérprete y argumentos de línea de comandos
import os           # Operaciones de sistema de archivos y rutas
import time         # Marcas de tiempo en segundos (epoch Unix)
import re           # Expresiones regulares para detección de SQLi
import ipaddress    # Manipulación y validación de direcciones/rangos IP (RFC 4291)
import sqlite3      # Base de datos embebida para persistencia de eventos
import joblib       # Carga de modelos ML serializados (.pkl)

# Módulos de concurrencia
from threading import Thread           # Hilos para alertas asíncronas sin bloquear captura
from collections import defaultdict, deque  # Estructuras de datos eficientes para conteo

# Scapy: Framework de captura y análisis de paquetes de red
import scapy.all as scapy              # Todos los módulos de Scapy (capas, protocolos)
from scapy.all import AsyncSniffer, conf    # Sniffer asíncrono no bloqueante
conf.use_pcap = True                        # Fuerza el uso de WinPcap/Npcap en Windows

# Módulos internos del proyecto IDS
from telegram_alert import enviar_alerta          # Notificaciones Telegram
from guardar_dataset import guardar_evento_en_dataset  # Persistencia CSV
import respuesta_activa                              # Módulo de Respuesta Activa (IP Blocking)

# PyQt5: Señales para comunicación entre el motor IDS y la interfaz gráfica
from PyQt5.QtCore import QObject, pyqtSignal


# =============================================================================
# BASE_DIR: Ruta absoluta al directorio del proyecto
# os.path.abspath(__file__): convierte la ruta relativa del script a absoluta
# os.path.dirname(...): extrae solo el directorio, sin el nombre del archivo
# Permite que todas las rutas de archivos funcionen independientemente del
# directorio desde donde se ejecute el script
# =============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# =============================================================================
# CLASE: ComunicadorIDS
# Patrón: Observer / Signal-Slot de Qt
# Propósito: Desacoplar el motor IDS (ids.py) de la interfaz gráfica (interfasc.py)
# mediante señales de Qt que cruzan hilos de forma thread-safe
# =============================================================================
class ComunicadorIDS(QObject):
    # pyqtSignal(list): Señal que transporta una lista con los datos del evento detectado
    # Formato esperado: [timestamp, ip_src, ip_dst, puerto, protocolo, flag, tipo_final]
    nuevo_evento = pyqtSignal(list)

    # pyqtSignal(list): Señal que transporta datos de un bloqueo de IP [ip, accion, duracion]
    nuevo_bloqueo = pyqtSignal(list)

    # pyqtSignal(str): Señal que transporta el resumen en texto de cada paquete capturado
    # Se usa para el panel "Tráfico en Vivo" de la interfaz
    nuevo_trafico = pyqtSignal(str)

# Instancia global del comunicador — actúa como bus de mensajes entre módulos
comunicador = ComunicadorIDS()


# =============================================================================
# VARIABLES GLOBALES DE ESTADO Y CONFIGURACIÓN
# =============================================================================

# Bandera booleana que controla si el sniffer está activo
sniffing_activo = False

# Bandera para habilitar/deshabilitar el modo IPS (Respuesta Activa)
ips_activo = False

# Referencia global al objeto AsyncSniffer para poder detenerlo posteriormente
sniffer: AsyncSniffer = None

# --- UMBRALES DE DETECCIÓN ---
# Número de paquetes SYN en 500ms para declarar SYN Flood
THRESHOLD_SYN_FLOOD  = 10

# Número de paquetes hacia un destino en 1s para declarar DDoS
THRESHOLD_DDOS       = 500

# Número de puertos únicos desde una IP para declarar Port Scan
PORT_SCAN_THRESHOLD  = 10

# Número de paquetes UDP hacia un destino en 1s para declarar UDP Flood
THRESHOLD_UDP_FLOOD  = 500

# Tiempo mínimo en segundos entre alertas de la misma IP (anti-spam)
TIEMPO_ENTRE_ALERTAS = 2

# IP local del sistema — se detecta automáticamente para evitar auto-detección falsa
try:
    from scapy.all import get_if_addr
    MI_IP = get_if_addr(conf.iface)
    print(f"[OK] IP local detectada: {MI_IP}")
except Exception:
    MI_IP = "127.0.0.1"

# --- ESTRUCTURAS DE DATOS DE DETECCIÓN ---
# defaultdict(list): Para cada IP, lista de timestamps de paquetes recientes
paquetes_por_ip    = defaultdict(list)

# defaultdict(set): Para cada IP origen, conjunto de puertos destino únicos tocados
puertos_por_ip     = defaultdict(set)

# deque con maxlen: Buffer circular de los últimos 100 eventos detectados
# maxlen evita crecimiento ilimitado en memoria
eventos_detectados = deque(maxlen=100)

# Contador de advertencias acumuladas por IP origen
advertencias_cont  = defaultdict(int)

# Diccionario que registra el último timestamp de alerta por IP
# Permite implementar el throttle (TIEMPO_ENTRE_ALERTAS)
ultimo_ataque_por_ip = {}


# =============================================================================
# WHITELIST: IPs y rangos de red de confianza
# Las IPs en estas listas serán ignoradas por los detectores de ataques
# Evita falsos positivos con CDNs (Cloudflare, Akamai), servicios propios, etc.
# =============================================================================
IPS_CONFIABLES = {
    "192.168.0.15",
    "192.168.0.17",
    "8.243.166.74",
    "172.67.9.68",
    "104.22.1.235",  # Cloudflare
    "2.22.20.72",    # Akamai
}

# Rangos CIDR de redes confiables
# ipaddress.ip_network(): Crea objeto de red para comparación eficiente
RANGOS_CONFIABLES = [
    ipaddress.ip_network('10.0.0.0/8'),        # Red privada clase A (RFC 1918)
    ipaddress.ip_network('172.16.0.0/12'),      # Red privada clase B (RFC 1918)
    ipaddress.ip_network('20.110.205.0/24'),    # Azure / Microsoft
    ipaddress.ip_network('40.0.0.0/8'),         # Azure
    ipaddress.ip_network('52.0.0.0/8'),         # AWS
    ipaddress.ip_network('54.0.0.0/8'),         # AWS
    ipaddress.ip_network('104.16.0.0/12'),      # Cloudflare
    ipaddress.ip_network('140.82.0.0/16'),      # GitHub
    ipaddress.ip_network('143.204.0.0/16'),     # Amazon CloudFront
    ipaddress.ip_network('34.192.0.0/12'),      # Google Cloud
    ipaddress.ip_network('35.192.0.0/12'),      # Google Cloud
    ipaddress.ip_network('172.217.0.0/16'),     # Google
    ipaddress.ip_network('2.22.20.0/24'),       # Akamai
    ipaddress.ip_network('52.178.17.0/24'),     # Microsoft Azure
]


# =============================================================================
# FUNCIÓN: ip_en_rangos
# Propósito: Verifica si una IP pertenece a algún rango CIDR de la whitelist
# Parámetros: ip — string con la dirección IP a verificar
# Retorna: True si la IP está en un rango confiable, False en caso contrario
# =============================================================================
def ip_en_rangos(ip: str) -> bool:
    try:
        # ipaddress.ip_address(): Convierte el string a objeto IPv4Address
        ip_obj = ipaddress.ip_address(ip)
        # any(): Retorna True si al menos un rango contiene la IP
        # Evaluación cortocircuitada — se detiene al primer match
        return any(ip_obj in net for net in RANGOS_CONFIABLES)
    except ValueError:
        # IP con formato inválido — se trata como no confiable
        return False


# =============================================================================
# CARGA DE MODELOS Y ENCODERS DE MACHINE LEARNING
# Rutas relativas a BASE_DIR para portabilidad del proyecto
# Cada carga está envuelta en try/except para degradación elegante:
# si falta un archivo, el sistema sigue funcionando con detección heurística
# =============================================================================
ruta_modelo           = os.path.join(BASE_DIR, 'modelo_ensamble_optimizado.pkl')
ruta_features         = os.path.join(BASE_DIR, 'features_seleccionadas.pkl')
ruta_flag_encoder     = os.path.join(BASE_DIR, 'flag_encoder.pkl')
ruta_protocol_encoder = os.path.join(BASE_DIR, 'protocol_encoder.pkl')
ruta_tipo_encoder     = os.path.join(BASE_DIR, 'tipo_ataque_encoder.pkl')

# joblib.load(): Deserializa el objeto Python desde archivo .pkl
# Cada bloque try/except permite inicio parcial si algún archivo falta
try:
    modelo_ml = joblib.load(ruta_modelo)
    print("[OK] Modelo de Machine Learning cargado correctamente.")
except FileNotFoundError:
    print(f"[X] Error: no se encontró {ruta_modelo}")
    modelo_ml = None  # El sistema usará solo detección heurística

try:
    features_seleccionadas = joblib.load(ruta_features)
    print("[OK] Características seleccionadas cargadas.")
except FileNotFoundError:
    print(f"[X] Error: no se encontró {ruta_features}")
    features_seleccionadas = None

try:
    flag_encoder = joblib.load(ruta_flag_encoder)
    print("[OK] Flag encoder cargado.")
except FileNotFoundError:
    print(f"[X] Error: no se encontró {ruta_flag_encoder}")
    flag_encoder = None

try:
    protocol_encoder = joblib.load(ruta_protocol_encoder)
    print("[OK] Protocol encoder cargado.")
except FileNotFoundError:
    print(f"[X] Error: no se encontró {ruta_protocol_encoder}")
    protocol_encoder = None

try:
    tipo_ataque_encoder = joblib.load(ruta_tipo_encoder)
    print("[OK] Tipo ataque encoder cargado.")
except FileNotFoundError:
    print(f"[X] Error: no se encontró {ruta_tipo_encoder}")
    tipo_ataque_encoder = None


# =============================================================================
# BASE DE DATOS SQLite — Persistencia estructurada de ataques detectados
# check_same_thread=False: Permite acceso desde múltiples hilos (necesario
# porque los detectores corren en el hilo del sniffer)
# =============================================================================
ruta_bd = os.path.join(BASE_DIR, 'intrusiones.db')
conn   = sqlite3.connect(ruta_bd, check_same_thread=False)
cursor = conn.cursor()

# Crea la tabla si no existe (idempotente gracias a IF NOT EXISTS)
# AUTOINCREMENT: genera ID único automáticamente para cada registro
cursor.execute('''
    CREATE TABLE IF NOT EXISTS ataques (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT,
        tipo_ataque TEXT,
        ip_src     TEXT,
        protocolo  TEXT,
        puerto     INTEGER
    )
''')

# Tabla para registro histórico de bloqueos realizados por el IPS
cursor.execute('''
    CREATE TABLE IF NOT EXISTS bloqueos (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT,
        ip_src     TEXT,
        tipo_ataque TEXT,
        duracion   INTEGER,
        estado     TEXT  -- 'ACTIVO' o 'EXPIRADO'
    )
''')
conn.commit()  # Persiste el esquema en el archivo .db


# =============================================================================
# FUNCIÓN: _enviar_alerta_async
# Propósito: Envía alertas de Telegram en un hilo daemon independiente
# Motivo: Las peticiones HTTP pueden tardar 1-5 segundos; ejecutarlas en el
# hilo del sniffer bloquearía la captura de paquetes durante ese tiempo
# daemon=True: El hilo se termina automáticamente cuando cierra el proceso principal
# =============================================================================
def _enviar_alerta_async(mensaje: str):
    Thread(target=lambda: enviar_alerta(mensaje), daemon=True).start()


# =============================================================================
# FUNCIÓN: preprocesar_datos
# Propósito: Transforma atributos de red al vector numérico que espera el modelo
# Nota: Esta función es complementaria a la de CEREBRO.PY — usa hash() en lugar
# de ip_to_int() porque opera en tiempo real sin los encoders de IP
# =============================================================================
def preprocesar_datos(ip_src, ip_dst, puerto, protocolo, flag):
    # Codifica flag — si no está en el vocabulario del encoder, usa -1
    if flag_encoder and flag in flag_encoder.classes_:
        flag_encoded = flag_encoder.transform([flag])[0]
    else:
        flag_encoded = -1  # Valor de fallback para valores desconocidos

    # Codifica protocolo — mismo criterio de fallback
    if protocol_encoder and protocolo in protocol_encoder.classes_:
        protocolo_encoded = protocol_encoder.transform([protocolo])[0]
    else:
        protocolo_encoded = -1

    # hash(): Convierte la IP string a entero de forma determinista en la sesión
    # % (10**8): Limita el valor a 8 dígitos para evitar overflow en el modelo
    datos = {
        "ip_src":         hash(ip_src),
        "ip_dst":         hash(ip_dst),
        "puerto":         puerto,
        "protocolo_tcp":  1 if protocolo == 'TCP' else 0,  # Feature binaria
        "flag":           flag_encoded,
        "protocolo_num":  protocolo_encoded
    }

    # Ordena los valores según el orden exacto de las features del modelo entrenado
    if features_seleccionadas:
        return [datos.get(f, 0) for f in features_seleccionadas]
    return list(datos.values())


# =============================================================================
# FUNCIÓN: clasificar_ataque_ml
# Propósito: Usa el modelo ML para clasificar el tipo de ataque con probabilidad
# Retorna: Tupla (tipo_str, confianza) — el tipo predicho y su probabilidad
# Incluye logs de depuración detallados para diagnóstico del modelo
# =============================================================================
def clasificar_ataque_ml(ip_src, ip_dst, puerto, protocolo, flag):
    print("\n" + "="*60)
    print("🔍 DEBUG clasificar_ataque_ml INICIADO")
    print("="*60)

    # Verificación de componentes: si alguno es None, retorna "Desconocido"
    # Permite degradación elegante cuando los modelos no están disponibles
    if modelo_ml is None or features_seleccionadas is None or tipo_ataque_encoder is None:
        return "Desconocido", 0.0

    try:
        import pandas as pd

        # pd.Timestamp.now().hour: Extrae la hora actual como feature temporal
        hora = pd.Timestamp.now().hour

        # hash() % (10**8): Convierte IPs a enteros de 8 dígitos de forma reproducible
        src_ip_int = hash(str(ip_src)) % (10**8)
        dst_ip_int = hash(str(ip_dst)) % (10**8)

        # Codificación de protocolo y flag con fallback a 0
        protocolo_encoded = protocol_encoder.transform([protocolo])[0] \
            if protocol_encoder and protocolo in protocol_encoder.classes_ else 0
        flag_encoded = flag_encoder.transform([flag])[0] \
            if flag_encoder and flag in flag_encoder.classes_ else 0

        # Construye DataFrame con las mismas columnas usadas en CEREBRO.PY
        # El modelo espera exactamente estos nombres de columna en este orden
        df_entrada = pd.DataFrame({
            'src_ip_int':        [src_ip_int],
            'dst_ip_int':        [dst_ip_int],
            'dst_port':          [puerto],
            'protocol_encoded':  [protocolo_encoded],
            'flag_encoded':      [flag_encoded],
            'hour':              [hora]
        })

        # .predict(): Retorna la clase predicha como entero codificado
        tipo_pred = modelo_ml.predict(df_entrada)[0]

        # .predict_proba(): Retorna probabilidades para cada clase
        # .max(): La probabilidad más alta es la confianza de la predicción
        probs     = modelo_ml.predict_proba(df_entrada)[0]
        confianza = probs.max()

        # inverse_transform(): Convierte el entero predicho de vuelta al nombre original
        tipo_str = tipo_ataque_encoder.inverse_transform([tipo_pred])[0]

        return tipo_str, confianza

    except Exception as e:
        import traceback
        traceback.print_exc()
        return "Desconocido", 0.0


# =============================================================================
# FUNCIÓN: guardar_ataque
# Propósito: Orquestador central — coordina todas las acciones ante un ataque:
#   1. Throttle anti-spam por IP
#   2. Clasificación ML opcional
#   3. Persistencia en SQLite
#   4. Persistencia en CSV (dataset)
#   5. Emisión de señal a la interfaz
#   6. Notificación Telegram asíncrona
# =============================================================================
def guardar_ataque(ip_src, tipo_ataque, protocolo, puerto, ip_dst="DESCONOCIDA", flag="N/A", usar_ml=True):
    # Ignora ataques que provienen de la IP local del sistema
    if ip_src == MI_IP:
        return

    # THROTTLE: Evita múltiples alertas de la misma IP en menos de TIEMPO_ENTRE_ALERTAS segundos
    # Previene spam de notificaciones durante ataques sostenidos
    ahora = time.time()
    if ahora - ultimo_ataque_por_ip.get(ip_src, 0) < TIEMPO_ENTRE_ALERTAS:
        return
    ultimo_ataque_por_ip[ip_src] = ahora
    advertencias_cont[ip_src] += 1  # Incrementa contador de advertencias por IP

    timestamp = time.ctime()  # Timestamp legible: "Mon Jun 10 14:23:01 2024"

    # Clasificación ML: si está habilitada y el modelo cargó correctamente
    if ips_activo and usar_ml:
        pred_ml, confianza = clasificar_ataque_ml(ip_src, ip_dst, puerto, protocolo, flag)
        
        # Solo confiamos en el ML si la probabilidad es ALTA (>= 70%)
        # Si tiene < 70%, es mejor confiar en la regla Heurística que sí lo detectó con seguridad
        if pred_ml and pred_ml != "Normal" and confianza >= 0.70:
            tipo_final = f"{pred_ml} (ML: {confianza*100:.1f}%)"
        else:
            tipo_final = f"{tipo_ataque} (Heurística)"
            
        # Si ML es confiable, se usa su probabilidad; sino asume alta severidad por caer en regla heurística
        prob_str = f"probablemente" if confianza < 0.70 else f"seguridad {confianza*100:.1f}%"
    else:
        tipo_final = f"{tipo_ataque} (Heurística)"
        prob_str = "detectado por regla"
        mensaje_ml = "📊 Confianza ML: N/A"

    # Construye el mensaje de alerta para Telegram con emojis para visibilidad
    mensaje = (
        f"SISTEMA DE INTRUSIÓN:\n"
        f"ALERT [IDS] {tipo_final} detectado\n"
        f"IP Origen: {ip_src}\n"
        f"Protocolo: {protocolo}\n"
        f"Puerto Destino: {puerto}\n"
        f"IP Destino: {ip_dst}\n"
    )

    # Persistencia en SQLite: registro estructurado para consultas SQL posteriores
    try:
        cursor.execute('''
            INSERT INTO ataques (timestamp, tipo_ataque, ip_src, protocolo, puerto)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, tipo_final, ip_src, protocolo, puerto))
        # ? son placeholders paramétricos que previenen SQL Injection en la propia BD
        conn.commit()
    except Exception as e:
        print(f"[X] Error guardando en SQLite: {e}")

    # Persistencia en CSV: para retroalimentación del modelo ML con datos reales
    try:
        guardar_evento_en_dataset(ip_src, ip_dst, puerto, protocolo, flag, tipo_final, tipo_ataque)
    except Exception as e:
        print(f"[X] Error al guardar evento en dataset: {e}")

    # Emite señal Qt con los datos del evento para actualizar la tabla de la interfaz
    # La señal cruza el hilo del sniffer al hilo de la UI de forma thread-safe
    evento = [timestamp, ip_src, ip_dst, puerto, protocolo, flag, tipo_final]
    eventos_detectados.append(evento)
    comunicador.nuevo_evento.emit(evento)

    # Envía alerta a Telegram en hilo separado para no bloquear la captura
    try:
        _enviar_alerta_async(mensaje)
    except Exception as e:
        print(f"[X] No se pudo lanzar alerta a Telegram: {e}")

    # --- LÓGICA DE RESPUESTA ACTIVA (IPS) ---
    if ips_activo:
        # Calcula severidad basada en tipo de ataque
        t_lower = tipo_final.lower()
        es_critico = "exploit" in t_lower or "sql" in t_lower or "flood" in t_lower or "ddos" in t_lower or "escaneo" in t_lower

        if "exploit" in t_lower or "sql" in t_lower:
            severidad_ips = "CRITICA"
        elif "flood" in t_lower or "ddos" in t_lower:
            severidad_ips = "ALTA"
        elif "escaneo" in t_lower or "scan" in t_lower:
            severidad_ips = "MEDIA"
        else:
            severidad_ips = "ALTA"

        # Criterio de bloqueo:
        # Si la decisión final fue tomada por ML (está en el label), exigimos 70% de confianza.
        # Si la decisión final fue por Heurística (porque ML estuvo por debajo del 50% o falló),
        # entonces confiamos en la severidad de la regla heurística y bloqueamos.
        puede_bloquear = False
        if es_critico:
            if "(ml:" in t_lower:
                if confianza >= 0.70:
                    puede_bloquear = True
            else:
                # Cayó en Heurística pura
                puede_bloquear = True

        if puede_bloquear:
            print(f"ALERT [IPS] Criterios de bloqueo cumplidos para {ip_src} | Tipo: {tipo_ataque} | Severidad: {severidad_ips}")
            
            # Intenta bloquear la IP en el firewall (requiere admin)
            duracion = 60
            bloqueo_real = False
            try:
                bloqueo_real = respuesta_activa.bloquear_ip(ip_src, duracion)
            except Exception as e:
                print(f"[!] Bloqueo en firewall no disponible (requiere admin): {e}")

            # Registra en la base de datos local (siempre, independiente del firewall)
            try:
                estado_bd = 'ACTIVO' if bloqueo_real else 'SIMULADO'
                cursor.execute('''
                    INSERT INTO bloqueos (timestamp, ip_src, tipo_ataque, duracion, estado)
                    VALUES (?, ?, ?, ?, ?)
                ''', (timestamp, ip_src, tipo_final, duracion, estado_bd))
                conn.commit()
            except Exception as e:
                print(f"[X] Error guardando bloqueo en SQLite: {e}")
            
            # Emite señal a la interfaz SIEMPRE (para que se vea en la tabla IPS)
            accion = "Bloqueo real" if bloqueo_real else "Bloqueo simulado"
            comunicador.nuevo_bloqueo.emit([ip_src, accion, duracion, tipo_ataque, severidad_ips])




# =============================================================================
# FUNCIÓN: mostrar_paquete
# Propósito: Genera resumen textual del paquete y lo emite a la interfaz
# packet.summary(): Método de Scapy que retorna string con capas del paquete
# =============================================================================
def mostrar_paquete(packet):
    resumen = packet.summary()
    print(f"Paquete capturado: {resumen}")
    comunicador.nuevo_trafico.emit(f"{resumen}")  # Actualiza "Tráfico en Vivo" en la UI


# =============================================================================
# DETECTORES DE ATAQUES — Cada función analiza un tipo específico de amenaza
# =============================================================================

# --- DETECTOR 1: SYN FLOOD ---
# Patrón: Una IP envía >1000 paquetes TCP SYN en 500ms
# SYN sin ACK de respuesta agota la tabla de conexiones half-open del servidor
def detectar_syn_flood(packet):
    # haslayer(TCP): Verifica si el paquete tiene capa TCP
    # flags == 'S': Solo flag SYN activa (inicio de conexión sin completar)
    if packet.haslayer(scapy.TCP) and str(packet[scapy.TCP].flags) == 'S':
        ip_src  = packet[scapy.IP].src
        ip_dst  = packet[scapy.IP].dst
        puerto  = packet[scapy.TCP].dport  # Puerto de destino del ataque
        t       = time.time()

        # Ventana deslizante de 500ms: agrega timestamp y limpia los viejos
        paquetes_por_ip[ip_src].append(t)
        paquetes_por_ip[ip_src] = [ts for ts in paquetes_por_ip[ip_src] if t - ts <= 0.5]

        # Si supera el umbral en la ventana → alerta
        if len(paquetes_por_ip[ip_src]) > THRESHOLD_SYN_FLOOD:
            guardar_ataque(ip_src, "SYN Flood", 'TCP', puerto, ip_dst, flag=str(packet[scapy.TCP].flags))


# --- DETECTOR 2: DDoS DISTRIBUIDO ---
# Patrón: >2000 paquetes llegan a la misma IP destino en 1 segundo
# Se cuenta por IP destino (no origen) para detectar tráfico convergente
def detectar_ddos(packet):
    if packet.haslayer(scapy.IP):
        ip_dst   = packet[scapy.IP].dst
        ip_src   = packet[scapy.IP].src
        puerto   = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else 0
        protocolo = 'TCP' if packet.haslayer(scapy.TCP) else 'UDP'

        # Filtra UDP sin puerto — paquetes fragmentados o malformados
        if protocolo == 'UDP' and puerto == 0:
            return

        t = time.time()
        paquetes_por_ip[ip_dst].append(t)
        # Ventana de 1 segundo para medir volumen de tráfico hacia el destino
        paquetes_por_ip[ip_dst] = [ts for ts in paquetes_por_ip[ip_dst] if t - ts <= 1]

        if len(paquetes_por_ip[ip_dst]) > THRESHOLD_DDOS:
            guardar_ataque(ip_src, "DDoS Distribuido", protocolo, puerto, ip_dst)


# --- DETECTOR 3: ESCANEO DE PUERTOS ---
# Patrón: Una IP toca >1000 puertos distintos en el destino
# Herramientas como nmap generan este patrón al mapear servicios activos
def detectar_escaneo_puertos(packet):
    if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        puerto = packet[scapy.TCP].dport

        # set.add(): Agrega el puerto al conjunto (ignora duplicados automáticamente)
        puertos_por_ip[ip_src].add(puerto)

        # len(set): Número de puertos ÚNICOS probados — métrica clave del Port Scan
        if len(puertos_por_ip[ip_src]) > PORT_SCAN_THRESHOLD:
            guardar_ataque(ip_src, "Escaneo de Puertos", 'TCP', puerto, ip_dst)


# --- DETECTOR 4: EXPLOITS ---
# Patrón: Conexiones TCP a puertos vulnerables conocidos desde IPs no confiables
# Solo flags SYN o SYN-ACK (intentos de conexión, no tráfico establecido)
def detectar_exploit(packet):
    if not packet.haslayer(scapy.IP):
        return

    ip_src = packet[scapy.IP].src
    # Whitelist: ignora IPs y rangos conocidos para evitar falsos positivos
    if ip_src in IPS_CONFIABLES or ip_en_rangos(ip_src):
        return

    ip_dst    = packet[scapy.IP].dst
    protocolo = 'TCP' if packet.haslayer(scapy.TCP) else \
                'UDP' if packet.haslayer(scapy.UDP) else 'OTRO'

    if protocolo not in {'TCP', 'UDP'}:
        return

    puerto = packet[scapy.TCP].dport if protocolo == 'TCP' else packet[scapy.UDP].dport
    flag   = str(packet[scapy.TCP].flags) if protocolo == 'TCP' else 'N/A'

    if puerto == 0:
        return

    # Puertos históricamente explotados — CVEs documentados para cada uno:
    # 135/139/445: SMB/RPC (EternalBlue, WannaCry), 3389: RDP (BlueKeep),
    # 5900: VNC, 21: FTP, 22: SSH, 23: Telnet, 69: TFTP
    PUERTOS_EXPLOIT = {135, 139, 445, 3389, 5900, 21, 22, 23, 69}

    if puerto in PUERTOS_EXPLOIT:
        # Solo alerta en SYN o SYN-ACK — filtra tráfico legítimo establecido (ACK, PSH, etc.)
        if protocolo == 'TCP' and flag not in ['S', 'SA']:
            return
        guardar_ataque(ip_src, "Posible Exploit", protocolo, puerto, ip_dst, flag=flag)


# --- DETECTOR 5: SQL INJECTION ---
# Patrón: Payload HTTP/TCP contiene patrones SQL maliciosos
# Analiza la carga útil del paquete (capa Raw de Scapy) con regex
def detectar_sql_injection(packet):
    if packet.haslayer(scapy.Raw):
        try:
            ip_src = packet[scapy.IP].src
            if ip_src in IPS_CONFIABLES or ip_en_rangos(ip_src):
                return

            # Raw.load: bytes del payload — .decode(errors='ignore') descarta bytes no-UTF8
            carga = packet[scapy.Raw].load.decode(errors='ignore')

            # Filtros de calidad: solo texto ASCII de longitud razonable
            if not carga.isascii() or len(carga) > 1000:
                return

            puerto = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else 0
            if puerto == 0 or puerto > 65535:
                return

            # Lista de exclusión: parámetros HTTP legítimos que contienen palabras clave SQL
            # sin ser maliciosos (ej: "order=desc" es navegación normal, no SQLi)
            exclusiones = [
                "order=desc", "mode=debug", "file=", "page=", "limit=",
                "search=", "token=", "session=", "csrf", "user-agent", "referer",
                "accept-encoding", "connection", "content-length", "host"
            ]
            if any(excl in carga.lower() for excl in exclusiones):
                return

            # Regex multi-patrón para detectar técnicas comunes de SQL Injection:
            # - Palabras clave SQL + comentarios (-- # ; /**/)
            # - OR 1=1 (bypass de autenticación)
            # - UNION SELECT (extracción de datos)
            # - EXEC xp_* (ejecución de stored procedures)
            # - WAITFOR DELAY / SLEEP (inyección de tiempo ciego)
            sql_pattern = re.compile(
                r"(?i)(\b(select|union|insert|update|delete|drop|alter|create|exec|execute|cast|declare|grant|revoke)\b"
                r".?(--|#|;|/\|\*/|@@|char\(|nchar\(|varchar\(|nvarchar\()|"
                r"('(\s)or(\s)\d+=\d+)|"
                r"(\bunion\b.*\bselect\b)|"
                r"(\bexec\b(\s|\+)+(s|x)p\w+)|"
                r"(;?\s*--)|"
                r"(\bwaitfor\b\s+delay\b)|"
                r"(sleep\(\d+\))"
                r")"
            )
            if sql_pattern.search(carga):
                ip_dst = packet[scapy.IP].dst
                # usar_ml=False: El payload ya fue analizado; no necesita clasificación ML
                guardar_ataque(ip_src, "SQL Injection", "TCP", puerto, ip_dst, usar_ml=False)
        except Exception as e:
            print(f"[X] Error en SQLi: {e}")


# --- DETECTOR 6: UDP FLOOD ---
# Patrón: >1000 paquetes UDP hacia el mismo destino en 1 segundo
# Variante volumétrica del DDoS usando protocolo UDP (sin handshake)
def detectar_udp_flood(packet):
    if packet.haslayer(scapy.IP):
        ip_dst    = packet[scapy.IP].dst
        ip_src    = packet[scapy.IP].src
        puerto    = packet[scapy.UDP].dport if packet.haslayer(scapy.UDP) else 0
        protocolo = 'UDP' if packet.haslayer(scapy.UDP) else 'TCP'

        if protocolo == 'TCP' and puerto == 0:
            return

        t = time.time()
        paquetes_por_ip[ip_dst].append(t)
        paquetes_por_ip[ip_dst] = [ts for ts in paquetes_por_ip[ip_dst] if t - ts <= 1]

        if len(paquetes_por_ip[ip_dst]) > THRESHOLD_UDP_FLOOD:
            guardar_ataque(ip_src, "UDP Flood", protocolo, puerto, ip_dst)


# =============================================================================
# FUNCIÓN: procesar_paquete
# Propósito: Callback principal del sniffer — se ejecuta por cada paquete capturado
# Encadena todos los detectores sobre el mismo paquete
# El try/except global evita que un error en un detector colapse el sniffer completo
# =============================================================================
def procesar_paquete(packet):
    try:
        mostrar_paquete(packet)  # Emite resumen a la interfaz

        # Solo procesa paquetes con capa IP (descarta tramas ARP, etc.)
        if packet.haslayer(scapy.IP):
            detectar_syn_flood(packet)
            detectar_ddos(packet)
            detectar_escaneo_puertos(packet)
            detectar_exploit(packet)
            detectar_sql_injection(packet)
            detectar_udp_flood(packet)
    except Exception as e:
        print(f"[X] Excepción en procesar_paquete: {e}")


# =============================================================================
# FUNCIÓN: iniciar_monitoreo
# Propósito: Arranca el AsyncSniffer en un hilo propio sin bloquear la UI
# Parámetros:
#   iface — Nombre de la interfaz de red (ej: "Ethernet", "Wi-Fi")
#            Si es None, Scapy usa la interfaz por defecto del sistema
# =============================================================================
def iniciar_monitoreo(iface=None):
    global sniffing_activo, sniffer
    if sniffing_activo:
        print("🔍 Sniffing ya está activo.")
        return

    sniffing_activo = True

    # AsyncSniffer: Captura paquetes en un hilo interno de Scapy
    # prn=procesar_paquete: Callback ejecutado por cada paquete capturado
    # store=False: No acumula paquetes en memoria (evita memory leak)
    # filter=None: Sin filtro BPF — captura todo el tráfico (puede cambiarse)
    sniffer = AsyncSniffer(
        iface=iface,
        prn=procesar_paquete,
        store=False,
        filter=None
    )
    try:
        sniffer.start()  # Inicia el hilo interno de captura
        print("[OK] AsyncSniffer arrancado correctamente.")
    except Exception as e:
        print(f"[X] Error iniciando AsyncSniffer: {e}")
        sniffing_activo = False  # Revierte el estado si falla el inicio


# =============================================================================
# FUNCIÓN: detener_monitoreo
# Propósito: Para el AsyncSniffer de forma limpia liberando el socket de captura
# =============================================================================
def detener_monitoreo():
    global sniffing_activo, sniffer
    if not sniffing_activo:
        print("⏹ Sniffing no estaba activo.")
        return

    sniffing_activo = False
    try:
        if sniffer is not None:
            sniffer.stop()  # Envía señal de parada al hilo interno de Scapy
            sniffer = None  # Libera la referencia para permitir garbage collection
            print("[OK] AsyncSniffer detenido correctamente.")
    except Exception as e:
        print(f"[X] Error deteniendo AsyncSniffer: {e}")


# =============================================================================
# BLOQUE DE PRUEBA DIRECTA
# =============================================================================
if __name__ == "__main__":
    print("🔍 Ejecutando ids.py directamente para prueba.")
    iniciar_monitoreo()
    print("[WAIT] Deja correr 10 segundos para verificar tráfico…")
    time.sleep(10)  # Captura tráfico durante 10 segundos
    print("⏹ Deteniendo monitoreo de prueba.")
    detener_monitoreo()
    conn.close()  # Cierra la conexión SQLite limpiamente
    print("[OK] ids.py finalizado.")

# =============================================================================
# FIN DEL SCRIPT — ids.py
# =============================================================================
