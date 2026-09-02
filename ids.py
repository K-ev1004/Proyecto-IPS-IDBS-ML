# =============================================================================
# ids.py v3 — Motor principal del IDS (Intrusion Detection System)
# Captura tráfico de red en tiempo real, detecta patrones de ataque,
# clasifica con ML, persiste en SQLite/CSV y notifica por Telegram
# Universidad UNIPAZ
# =============================================================================
#
# CAMBIOS PRINCIPALES vs v2:
# - Integración de flujos_red.py para cálculo de variables complejas.
# - Integración de mikrotik_api.py para respuesta activa.
# - Análisis de VLANs (Dot1Q) para segmentación.
# =============================================================================

# Módulos estándar del sistema
import os           
import time         
import re           
import socket       
import struct       
import ipaddress    
import sqlite3      
import joblib       
import json         
import pandas as pd
import numpy as np

# Módulos de concurrencia
from threading import Thread           
from collections import defaultdict, deque  

# Scapy: Framework de captura y análisis de paquetes de red
import scapy.all as scapy              
from scapy.all import AsyncSniffer, conf    
conf.use_pcap = True                        

# Módulos internos del proyecto IDS
from telegram_alert import enviar_alerta          
import mikrotik_api
from flujos_red import FlowTracker

# Importar el módulo de exportador de logs
from log_exporter import registrar_bloqueo_log

# PyQt5: Señales para comunicación entre el motor IDS y la interfaz gráfica
from PyQt5.QtCore import QObject, pyqtSignal


# =============================================================================
# BASE_DIR: Ruta absoluta al directorio del proyecto
# =============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# =============================================================================
# FUNCIÓN: ip_to_int
# =============================================================================
def ip_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except socket.error:
        return 0


# =============================================================================
# CLASE: ComunicadorIDS
# =============================================================================
class ComunicadorIDS(QObject):
    nuevo_evento = pyqtSignal(list)
    nuevo_bloqueo = pyqtSignal(list)
    nuevo_trafico = pyqtSignal(str)
    actualizacion_dashboard = pyqtSignal(dict) # Para enviar métricas al dashboard PyQt

comunicador = ComunicadorIDS()


# =============================================================================
# VARIABLES GLOBALES DE ESTADO Y CONFIGURACIÓN
# =============================================================================
sniffing_activo = False
ips_activo = False
modo_ips_autonomo = False # True = Bloquea, False = Semi-Autónomo (alerta)
sniffer: AsyncSniffer = None

# --- UMBRALES BASE DE DETECCIÓN ---
BASE_THRESHOLD_SYN_FLOOD  = 50    
BASE_THRESHOLD_DDOS       = 500   
BASE_PORT_SCAN_THRESHOLD  = 40    
BASE_THRESHOLD_UDP_FLOOD  = 500   
TIEMPO_ENTRE_ALERTAS = 30    

# --- VARIABLES PARA EWMA (UMBRALES DINÁMICOS) ---
ewma_pps = 0.0
alpha_ewma = 0.1
_pkts_ultimo_segundo = 0

def calcular_umbral_dinamico(base, max_mult=10.0):
    # Base baseline de paquetes por segundo considerados 'normales' para la red
    baseline_esperado = 200.0
    if ewma_pps <= baseline_esperado:
        return base
    
    factor = ewma_pps / baseline_esperado
    factor = min(factor, max_mult) # Evitar que suba indefinidamente
    return int(base * factor)

# --- PROTOCOLOS DE DISCOVERY (RUIDO) ---
DISCOVERY_PORTS = {5353, 5355, 1900, 137, 138}

# IP local del sistema
try:
    from scapy.all import get_if_addr
    MI_IP = get_if_addr(conf.iface)
    print(f"[OK] IP local detectada: {MI_IP}")
except Exception:
    MI_IP = "127.0.0.1"

# --- ESTRUCTURAS DE DATOS DE DETECCIÓN ---
paquetes_por_ip    = defaultdict(list)
puertos_por_ip     = defaultdict(set)
eventos_detectados = deque(maxlen=100)
advertencias_cont  = defaultdict(int)
ultimo_ataque_por_ip = {}

# Métricas para el Dashboard
metricas_trafico = {
    'docentes_pkts': 0,
    'admin_pkts': 0,
    'estudiantes_pkts': 0,
    'externos_pkts': 0,
    'pps_actual': 0,
    'flujos_activos': 0,
    'flujos_totales': 0,
    'detecciones_ataque': 0,
    'detecciones_normal': 0,
}


def _clasificar_departamento_ip(ip):
    """Clasifica IP en departamento según subredes UNIPAZ."""
    try:
        partes = ip.strip().split('.')
        if len(partes) != 4:
            return 'externos'
        o1, o2 = int(partes[0]), int(partes[1])
        if o1 == 172 and o2 == 20:
            return 'docentes'
        if o1 == 172 and o2 == 10:
            return 'admin'
        if o1 == 172 and o2 == 30:
            return 'estudiantes'
        return 'externos'
    except Exception:
        return 'externos'


# =============================================================================
# WHITELIST: IPs y rangos de red de confianza — AMPLIADO PARA UNIPAZ
# =============================================================================
IPS_CONFIABLES = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9", "208.67.222.222",
}

RANGOS_CONFIABLES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('20.0.0.0/11'),       
    ipaddress.ip_network('40.0.0.0/8'),        
    ipaddress.ip_network('52.0.0.0/8'),        
    ipaddress.ip_network('54.0.0.0/8'),        
    ipaddress.ip_network('104.16.0.0/12'),     
    ipaddress.ip_network('140.82.0.0/16'),     
    ipaddress.ip_network('143.204.0.0/16'),    
    ipaddress.ip_network('172.217.0.0/16'),    
    ipaddress.ip_network('2.22.20.0/24'),      
    ipaddress.ip_network('13.107.0.0/16'),     
    ipaddress.ip_network('52.114.0.0/16'),     
    ipaddress.ip_network('34.192.0.0/12'),     
    ipaddress.ip_network('35.192.0.0/12'),     
    ipaddress.ip_network('142.250.0.0/16'),    
    ipaddress.ip_network('151.101.0.0/16'),    
]

def ip_en_rangos(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in RANGOS_CONFIABLES)
    except ValueError:
        return False


# =============================================================================
# CARGA DE MODELOS V5 + SQLIGUARD (2a etapa)
# =============================================================================
model_path = os.path.join(BASE_DIR, 'Modelos_Entrenados', 'pipeline_catboost_v5.pkl')
features_path = os.path.join(BASE_DIR, 'Modelos_Entrenados', 'selected_features_v5.pkl')
le_path = os.path.join(BASE_DIR, 'Modelos_Entrenados', 'label_encoder_v5.pkl')

sqli_guard_path = os.path.join(BASE_DIR, 'Modelos_Entrenados', 'sqli_guard.pkl')
sqli_guard_meta_path = os.path.join(BASE_DIR, 'Modelos_Entrenados', 'sql_guard_features.pkl')

modelo_ml = None
features_seleccionadas = None
tipo_ataque_encoder = None

sqli_guard = None
SQLI_GUARD_FEATURES = None
UMBRAL_SQLI_GUARD = 0.30

if os.path.exists(model_path) and os.path.exists(features_path) and os.path.exists(le_path):
    try:
        modelo_ml = joblib.load(model_path)
        features_seleccionadas = joblib.load(features_path)
        tipo_ataque_encoder = joblib.load(le_path)
        print("[OK] Modelo ML v5 (Multi-Dataset) cargado correctamente.")
    except Exception as e:
        print(f"[X] Error cargando modelo v5: {e}")
        modelo_ml = None
else:
    print("[!] No se encontró modelo ML v5. Se usará solo detección heurística.")

# SQLiGuard: detector binario dedicado de Inyeccion SQL (2ª etapa)
if os.path.exists(sqli_guard_path) and os.path.exists(sqli_guard_meta_path):
    try:
        sqli_guard = joblib.load(sqli_guard_path)
        _sqli_meta = joblib.load(sqli_guard_meta_path)
        SQLI_GUARD_FEATURES = _sqli_meta['features']
        UMBRAL_SQLI_GUARD = float(_sqli_meta.get('umbral', 0.30))
        print("[OK] SQLiGuard (detector binario SQLi) cargado correctamente.")
        print(f"       Umbral confirmación SQLi: {UMBRAL_SQLI_GUARD}")
    except Exception as e:
        print(f"[X] Error cargando SQLiGuard: {e}")
        sqli_guard = None
else:
    print("[!] No se encontró SQLiGuard. La clase Inyeccion_SQL dependerá solo del modelo v5.")

# Convierte las features CIC del flujo en las features NetFlow que espera
# SQLiGuard (mismas unidades y orden usados en entrenar_sqli_guard.py).
def _features_sqli_guard(features_dict):
    fwd_pkts  = float(features_dict.get('Tot Fwd Pkts', 0) or 0)
    bwd_pkts  = float(features_dict.get('Tot Bwd Pkts', 0) or 0)
    fwd_bytes = float(features_dict.get('TotLen Fwd Pkts', 0) or 0)
    bwd_bytes = float(features_dict.get('TotLen Bwd Pkts', 0) or 0)
    # 'Flow Duration' está en microsegundos (CIC); SQLiGuard se entrenó en ms.
    dur_ms = max(float(features_dict.get('Flow Duration', 0) or 0) / 1000.0, 1e-6)
    # Bitmask TCP OR (0-31) reconstruido desde los contadores de flags.
    tcp_flags = 0
    if float(features_dict.get('FIN Flag Cnt', 0) or 0) > 0: tcp_flags |= 1
    if float(features_dict.get('SYN Flag Cnt', 0) or 0) > 0: tcp_flags |= 2
    if float(features_dict.get('RST Flag Cnt', 0) or 0) > 0: tcp_flags |= 4
    if float(features_dict.get('PSH Flag Cnt', 0) or 0) > 0: tcp_flags |= 8
    if float(features_dict.get('ACK Flag Cnt', 0) or 0) > 0: tcp_flags |= 16
    total_pkts = fwd_pkts + bwd_pkts
    total_bytes = fwd_bytes + bwd_bytes
    return {
        'src_port':       float(features_dict.get('Src Port', 0) or 0),
        'dst_port':       float(features_dict.get('Dst Port', 0) or 0),
        'protocol':       float(features_dict.get('Protocol', 0) or 0),
        'flow_duration_ms': dur_ms,
        'total_packets':  total_pkts,
        'total_bytes':    total_bytes,
        'flow_byts_s':    float(features_dict.get('Flow Byts/s', 0) or 0),
        'flow_pkts_s':    float(features_dict.get('Flow Pkts/s', 0) or 0),
        'tcp_flags':      float(tcp_flags),
    }


# =============================================================================
# BASE DE DATOS SQLite
# =============================================================================
ruta_bd = os.path.join(BASE_DIR, 'intrusiones.db')
conn   = sqlite3.connect(ruta_bd, check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS ataques (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT,
        tipo_ataque TEXT,
        ip_src     TEXT,
        protocolo  TEXT,
        puerto     INTEGER,
        confianza_ml REAL DEFAULT 0.0,
        features_json TEXT
    )
''')

# ALTER para bases SQLite ya existentes (compatible si ya existen las columnas)
try:
    cursor.execute("ALTER TABLE ataques ADD COLUMN confianza_ml REAL DEFAULT 0.0")
except sqlite3.OperationalError:
    pass
try:
    cursor.execute("ALTER TABLE ataques ADD COLUMN features_json TEXT")
except sqlite3.OperationalError:
    pass
try:
    cursor.execute("ALTER TABLE ataques ADD COLUMN ip_dst TEXT DEFAULT 'DESCONOCIDA'")
except sqlite3.OperationalError:
    pass
try:
    cursor.execute("ALTER TABLE ataques ADD COLUMN vlan_id INTEGER DEFAULT 0")
except sqlite3.OperationalError:
    pass
try:
    cursor.execute("ALTER TABLE ataques ADD COLUMN ttl INTEGER DEFAULT 0")
except sqlite3.OperationalError:
    pass
try:
    cursor.execute("ALTER TABLE ataques ADD COLUMN packet_size INTEGER DEFAULT 0")
except sqlite3.OperationalError:
    pass

cursor.execute('''
    CREATE TABLE IF NOT EXISTS bloqueos (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT,
        ip_src     TEXT,
        tipo_ataque TEXT,
        duracion   INTEGER,
        estado     TEXT
    )
''')
conn.commit()


def _enviar_alerta_async(mensaje: str):
    Thread(target=lambda: enviar_alerta(mensaje), daemon=True).start()

# =============================================================================
# FUNCIÓN DE PREDICCIÓN ML (CALLBACK DE FLUJOS_RED)
# =============================================================================
# Umbral unificado de logueo/bloqueo para clasificaciones ML (v3):
# antes se logueaba con >=0.85 y se bloqueaba con >=0.70 (inconsistente:
# había flujos bloqueados sin registro ML). Ahora AMBOS usan >= UMBRAL_ML.
UMBRAL_ML = 0.85

def on_flow_ready(ip_src, ip_dst, features_dict):
    """
    Este callback es llamado por flujos_red.py cuando un flujo expira/se completa.
    Flujo de decisión v3:
      1) El modelo v5 (multiclase, features CIC) predice la clase del flujo.
      2) SQLiGuard (detector binario, 200K SQLi reales) CONFIRMA/NIEGA el SQLi.
         - Si SQLiGuard confirma (P >= umbral) -> Inyeccion_SQL (precision ~99.8%).
         - Si v5 decía Inyeccion_SQL pero SQLiGuard no confirma -> se trata como
           la clase que v5 asigna para la otra rama pero se registra el caso.
    """
    if modelo_ml is None or features_seleccionadas is None:
        return

    try:
        row = [features_dict.get(f, 0) for f in features_seleccionadas]
        df_in = pd.DataFrame([row], columns=features_seleccionadas)

        pred_idx = modelo_ml.predict(df_in)[0]
        if isinstance(pred_idx, (list, np.ndarray)):
            pred_idx = pred_idx[0]

        probs = modelo_ml.predict_proba(df_in)[0]
        confianza_v5 = float(np.max(probs))
        tipo_str = tipo_ataque_encoder.inverse_transform([pred_idx])[0]

        # --- SQLiGuard (2ª etapa) ---
        confianza_guard = 0.0
        es_sqli_guard = False
        if sqli_guard is not None and SQLI_GUARD_FEATURES is not None:
            try:
                fila_guard = {k: _features_sqli_guard(features_dict)[k] for k in SQLI_GUARD_FEATURES}
                df_guard = pd.DataFrame([fila_guard], columns=SQLI_GUARD_FEATURES)
                prob_guard = sqli_guard.predict_proba(df_guard)[0][1]
                confianza_guard = float(prob_guard)
                es_sqli_guard = confianza_guard >= UMBRAL_SQLI_GUARD
            except Exception as e:
                print(f"[X] Error SQLiGuard: {e}")

        # --- Decisión final ---
        metricas_trafico['flujos_totales'] += 1

        if es_sqli_guard:
            tipo_final = 'Inyeccion_SQL'
            confianza_ml = max(confianza_guard, confianza_v5)
            metricas_trafico['detecciones_ataque'] += 1
            guardar_ataque(ip_src, tipo_final, "TCP/UDP", features_dict.get('Dst Port', 0),
                           ip_dst, flag="SQLiGuard", es_ml_puro=True, confianza_ml=confianza_ml,
                           features_json=json.dumps(_features_sqli_guard(features_dict)))
        elif tipo_str != 'Normal':
            if confianza_v5 >= UMBRAL_ML:
                metricas_trafico['detecciones_ataque'] += 1
                guardar_ataque(ip_src, tipo_str, "TCP/UDP", features_dict.get('Dst Port', 0),
                               ip_dst, flag="N/A", es_ml_puro=True, confianza_ml=confianza_v5,
                               features_json=json.dumps(_features_sqli_guard(features_dict)))
            else:
                metricas_trafico['detecciones_normal'] += 1
        else:
            metricas_trafico['detecciones_normal'] += 1

    except Exception as e:
        print(f"[X] Advertencia en ML Predict Flow: {e}")

# Instanciamos el tracker global
flow_tracker = FlowTracker(on_flow_ready)


# =============================================================================
# FUNCIÓN: guardar_ataque
# =============================================================================
def guardar_ataque(ip_src, tipo_ataque, protocolo, puerto, ip_dst="DESCONOCIDA", flag="N/A", es_ml_puro=False, confianza_ml=0.0, features_json=None, vlan_id=0, ttl=0, packet_size=0):
    if ip_src == MI_IP:
        return

    # Auto-completar datos del paquete desde el dict global
    datos = _ultimo_datos_paquete.get(ip_src, {})
    if not ip_dst or ip_dst == "DESCONOCIDA":
        ip_dst = datos.get("ip_dst", "DESCONOCIDA")
    if not vlan_id:
        vlan_id = datos.get("vlan_id", 0)
    if not ttl:
        ttl = datos.get("ttl", 0)
    if not packet_size:
        packet_size = datos.get("packet_size", 0)

    # THROTTLE
    ahora = time.time()
    if ahora - ultimo_ataque_por_ip.get(ip_src, 0) < TIEMPO_ENTRE_ALERTAS:
        return
    ultimo_ataque_por_ip[ip_src] = ahora
    advertencias_cont[ip_src] += 1

    timestamp = time.ctime()

    if es_ml_puro:
        tipo_final = f"{tipo_ataque} (ML: {confianza_ml*100:.1f}%)"
    else:
        tipo_final = f"{tipo_ataque} (Heuristica)"

    # Mensaje de alerta
    mensaje = (
        f"SISTEMA DE INTRUSION:\n"
        f"ALERT [IDS] {tipo_final} detectado\n"
        f"IP Origen: {ip_src}\n"
        f"IP Destino: {ip_dst}\n"
        f"Protocolo: {protocolo}\n"
        f"Puerto Destino: {puerto}\n"
    )

    # Persistencia en SQLite
    try:
        cursor.execute('''
            INSERT INTO ataques (timestamp, tipo_ataque, ip_src, ip_dst, protocolo, puerto,
                                 confianza_ml, features_json, vlan_id, ttl, packet_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, tipo_final, ip_src, ip_dst, protocolo, puerto,
              confianza_ml, features_json, vlan_id, ttl, packet_size))
        conn.commit()
    except Exception as e:
        pass

    # Emitir señal Qt (tupla extendida: 10 elementos)
    evento = [timestamp, ip_src, ip_dst, puerto, protocolo, flag, tipo_final,
              vlan_id, ttl, packet_size]
    eventos_detectados.append(evento)
    comunicador.nuevo_evento.emit(evento)

    # Alerta Telegram
    try:
        _enviar_alerta_async(mensaje)
    except Exception as e:
        pass

    # --- LÓGICA DE RESPUESTA ACTIVA (IPS) ---
    if ips_activo:
        t_lower = tipo_final.lower()
        es_critico = "exploit" in t_lower or "sql" in t_lower or "flood" in t_lower or "ddos" in t_lower or "escaneo" in t_lower or "scan" in t_lower or "bruteforce" in t_lower

        severidad_ips = "ALTA"
        if "exploit" in t_lower or "sql" in t_lower:
            severidad_ips = "CRITICA"

        puede_bloquear = False
        if es_critico:
            if es_ml_puro:
                if confianza_ml >= UMBRAL_ML:
                    puede_bloquear = True
            else:
                puede_bloquear = True

        if puede_bloquear:
            print(f"ALERT [IPS] Criterios de bloqueo cumplidos para {ip_src} | Tipo: {tipo_ataque} | Severidad: {severidad_ips}")

            duracion = 24 # 24 horas por defecto en MikroTik
            bloqueo_real = False
            
            if modo_ips_autonomo:
                try:
                    # Intento de bloqueo vía MikroTik Core
                    bloqueo_real = mikrotik_api.bloquear_ip_mikrotik(ip_src, duracion_horas=duracion)
                except Exception as e:
                    print(f"[!] Bloqueo MikroTik fallido: {e}")
            else:
                print(f"[*] Modo Semi-Autónomo activo. Bloqueo de {ip_src} omitido (Solo Alerta).")

            estado_bd = 'ACTIVO' if bloqueo_real else 'SIMULADO/SEMI'
            try:
                cursor.execute('''
                    INSERT INTO bloqueos (timestamp, ip_src, tipo_ataque, duracion, estado)
                    VALUES (?, ?, ?, ?, ?)
                ''', (timestamp, ip_src, tipo_final, duracion, estado_bd))
                conn.commit()
            except Exception:
                pass

            # Registrar el bloqueo en el archivo .log
            registrar_bloqueo_log(ip_src, f"BLOQUEO_{tipo_ataque.upper().replace(' ', '_')}", duracion)

            accion = "Bloqueo real (MikroTik)" if bloqueo_real else "Alerta Semi-Autónoma"
            comunicador.nuevo_bloqueo.emit([ip_src, accion, duracion, tipo_ataque, severidad_ips])


# =============================================================================
# FUNCIÓN: mostrar_paquete y Métricas Dashboard
# =============================================================================
_ultimo_tiempo_emision = 0

def procesar_metricas(packet):
    # Clasificar por subred IP (departamento UNIPAZ)
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        depto = _clasificar_departamento_ip(ip_src)
    else:
        depto = 'externos'

    if depto == 'docentes':
        metricas_trafico['docentes_pkts'] += 1
    elif depto == 'admin':
        metricas_trafico['admin_pkts'] += 1
    elif depto == 'estudiantes':
        metricas_trafico['estudiantes_pkts'] += 1
    else:
        metricas_trafico['externos_pkts'] += 1

    # Emitir métricas al dashboard cada 1 segundo
    global _ultimo_tiempo_emision, _pkts_ultimo_segundo, ewma_pps
    _pkts_ultimo_segundo += 1
    current_time = time.time()

    if current_time - _ultimo_tiempo_emision > 1.0:
        # Actualización EWMA
        if ewma_pps == 0.0:
            ewma_pps = _pkts_ultimo_segundo
        else:
            ewma_pps = alpha_ewma * _pkts_ultimo_segundo + (1 - alpha_ewma) * ewma_pps

        metricas_trafico['pps_actual'] = _pkts_ultimo_segundo
        metricas_trafico['flujos_activos'] = len(flow_tracker.flujos) if hasattr(flow_tracker, 'flujos') else 0

        comunicador.actualizacion_dashboard.emit(metricas_trafico.copy())

        # Reset contadores por segundo
        metricas_trafico['docentes_pkts'] = 0
        metricas_trafico['admin_pkts'] = 0
        metricas_trafico['estudiantes_pkts'] = 0
        metricas_trafico['externos_pkts'] = 0

        resumen = packet.summary()
        comunicador.nuevo_trafico.emit(resumen)
        _ultimo_tiempo_emision = current_time
        _pkts_ultimo_segundo = 0


# =============================================================================
# DETECTORES DE ATAQUES (HEURÍSTICA DE RESPALDO)
# =============================================================================

def detectar_syn_flood(packet):
    if packet.haslayer(scapy.TCP) and str(packet[scapy.TCP].flags) == 'S':
        ip_src  = packet[scapy.IP].src
        ip_dst  = packet[scapy.IP].dst
        puerto  = packet[scapy.TCP].dport
        t       = time.time()

        paquetes_por_ip[ip_src].append(t)
        paquetes_por_ip[ip_src] = [ts for ts in paquetes_por_ip[ip_src] if t - ts <= 0.5]

        if len(paquetes_por_ip[ip_src]) > calcular_umbral_dinamico(BASE_THRESHOLD_SYN_FLOOD):
            guardar_ataque(ip_src, "SYN Flood", 'TCP', puerto, ip_dst, flag=str(packet[scapy.TCP].flags))

def detectar_ddos(packet):
    if packet.haslayer(scapy.IP):
        ip_dst   = packet[scapy.IP].dst
        ip_src   = packet[scapy.IP].src

        if packet.haslayer(scapy.TCP):
            puerto = packet[scapy.TCP].dport
            protocolo = 'TCP'
        elif packet.haslayer(scapy.UDP):
            puerto = packet[scapy.UDP].dport
            protocolo = 'UDP'
        else:
            puerto = 0
            protocolo = 'OTRO'

        if puerto in DISCOVERY_PORTS:
            return
        if protocolo == 'UDP' and puerto == 0:
            return

        t = time.time()
        paquetes_por_ip[ip_dst].append(t)
        paquetes_por_ip[ip_dst] = [ts for ts in paquetes_por_ip[ip_dst] if t - ts <= 1]

        umbral_ddos = calcular_umbral_dinamico(BASE_THRESHOLD_DDOS)
        if len(paquetes_por_ip[ip_dst]) > umbral_ddos:
            if protocolo == 'UDP' and len(paquetes_por_ip[ip_dst]) > calcular_umbral_dinamico(BASE_THRESHOLD_UDP_FLOOD):
                return
            guardar_ataque(ip_src, "DDoS Distribuido", protocolo, puerto, ip_dst)

def detectar_escaneo_puertos(packet):
    if not packet.haslayer(scapy.IP):
        return

    ip_src = packet[scapy.IP].src
    ip_dst = packet[scapy.IP].dst

    if packet.haslayer(scapy.TCP):
        flags = str(packet[scapy.TCP].flags)
        puerto = packet[scapy.TCP].dport
        if flags != 'A':
            puertos_por_ip[ip_src].add(f"TCP:{puerto}")

    elif packet.haslayer(scapy.UDP):
        puerto = packet[scapy.UDP].dport
        if puerto not in DISCOVERY_PORTS:
            puertos_por_ip[ip_src].add(f"UDP:{puerto}")

    umbral_scan = calcular_umbral_dinamico(BASE_PORT_SCAN_THRESHOLD)
    if len(puertos_por_ip[ip_src]) > umbral_scan:
        guardar_ataque(ip_src, "Escaneo de Puertos", "TCP/UDP", "Múltiples", ip_dst)
        if len(puertos_por_ip[ip_src]) > umbral_scan + 20:
             puertos_por_ip[ip_src].clear()

def detectar_exploit(packet):
    if not packet.haslayer(scapy.IP):
        return

    ip_src = packet[scapy.IP].src
    if ip_src in IPS_CONFIABLES or ip_en_rangos(ip_src):
        return

    ip_dst    = packet[scapy.IP].dst
    protocolo = 'TCP' if packet.haslayer(scapy.TCP) else 'UDP' if packet.haslayer(scapy.UDP) else 'OTRO'

    if protocolo not in {'TCP', 'UDP'}:
        return

    puerto = packet[scapy.TCP].dport if protocolo == 'TCP' else packet[scapy.UDP].dport
    flag   = str(packet[scapy.TCP].flags) if protocolo == 'TCP' else 'N/A'

    if puerto == 0:
        return

    PUERTOS_EXPLOIT = {135, 139, 445, 3389, 5900, 21, 22, 23, 69}

    if puerto in PUERTOS_EXPLOIT:
        if protocolo == 'TCP' and flag not in ['S', 'SA']:
            return
        guardar_ataque(ip_src, "Posible Exploit", protocolo, puerto, ip_dst, flag=flag)

def detectar_sql_injection(packet):
    if packet.haslayer(scapy.Raw):
        try:
            ip_src = packet[scapy.IP].src
            if ip_src in IPS_CONFIABLES or ip_en_rangos(ip_src):
                return

            carga = packet[scapy.Raw].load.decode(errors='ignore')

            if not carga.isascii() or len(carga) > 1000:
                return

            puerto = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else 0
            if puerto == 0 or puerto > 65535:
                return

            exclusiones = ["order=desc", "session=", "csrf", "user-agent", "host"]
            if any(excl in carga.lower() for excl in exclusiones):
                return

            sql_pattern = re.compile(
                r"(?i)(\b(select|union|insert|update|delete|drop|alter|exec|cast)\b"
                r".?(--|#|;|/\|\*/)|"
                r"('(\s)or(\s)\d+=\d+)|"
                r"(\bunion\b.*\bselect\b))"
            )
            if sql_pattern.search(carga):
                ip_dst = packet[scapy.IP].dst
                guardar_ataque(ip_src, "SQL Injection", "TCP", puerto, ip_dst)
        except Exception:
            pass

def detectar_udp_flood(packet):
    if packet.haslayer(scapy.UDP):
        ip_dst    = packet[scapy.IP].dst
        ip_src    = packet[scapy.IP].src
        puerto    = packet[scapy.UDP].dport

        if puerto in DISCOVERY_PORTS:
            return

        t = time.time()
        paquetes_por_ip[ip_dst].append(t)
        paquetes_por_ip[ip_dst] = [ts for ts in paquetes_por_ip[ip_dst] if t - ts <= 1]

        if len(paquetes_por_ip[ip_dst]) > calcular_umbral_dinamico(BASE_THRESHOLD_UDP_FLOOD):
            guardar_ataque(ip_src, "UDP Flood", 'UDP', puerto, ip_dst)


# =============================================================================
# FUNCIÓN: procesar_paquete
# =============================================================================
# Datos del ultimo paquete por IP (para pasar a guardar_ataque)
_ultimo_datos_paquete = {}

def procesar_paquete(packet):
    try:
        procesar_metricas(packet)

        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            packet_len = len(packet)
            timestamp = packet.time
            ttl = packet[scapy.IP].ttl

            vlan_id = 0
            if packet.haslayer(scapy.Dot1Q):
                vlan_id = packet[scapy.Dot1Q].vlan

            protocolo = 'OTRO'
            puerto_src = 0
            puerto_dst = 0
            tcp_flags = None
            
            if packet.haslayer(scapy.TCP):
                protocolo = 'TCP'
                puerto_src = packet[scapy.TCP].sport
                puerto_dst = packet[scapy.TCP].dport
                tcp_flags = str(packet[scapy.TCP].flags)
            elif packet.haslayer(scapy.UDP):
                protocolo = 'UDP'
                puerto_src = packet[scapy.UDP].sport
                puerto_dst = packet[scapy.UDP].dport

            # Guardar datos del paquete para guardar_ataque()
            _ultimo_datos_paquete[ip_src] = {
                "ip_dst": ip_dst,
                "vlan_id": vlan_id,
                "ttl": ttl,
                "packet_size": packet_len,
            }

            # Alimentar el FlowTracker para ML
            flow_tracker.procesar_paquete(
                ip_src, ip_dst, puerto_src, puerto_dst, 
                protocolo, packet_len, tcp_flags, timestamp
            )

            # Heurística de respaldo (inmediata)
            detectar_syn_flood(packet)
            detectar_ddos(packet)
            detectar_escaneo_puertos(packet)
            detectar_exploit(packet)
            detectar_sql_injection(packet)
            detectar_udp_flood(packet)
    except Exception as e:
        print(f"[X] Excepcion en procesar_paquete: {e}")


# =============================================================================
# CONTROL DEL SNIFFER
# =============================================================================
def iniciar_monitoreo(iface=None):
    global sniffing_activo, sniffer
    if sniffing_activo:
        return

    sniffing_activo = True
    sniffer = AsyncSniffer(iface=iface, prn=procesar_paquete, store=False, filter=None)
    try:
        sniffer.start()
        print("[OK] AsyncSniffer arrancado correctamente.")
    except Exception as e:
        print(f"[X] Error iniciando AsyncSniffer: {e}")
        sniffing_activo = False

def detener_monitoreo():
    global sniffing_activo, sniffer
    if not sniffing_activo:
        return
    sniffing_activo = False
    try:
        if sniffer is not None:
            sniffer.stop()
            sniffer = None
            print("[OK] AsyncSniffer detenido.")
    except Exception as e:
        pass

if __name__ == "__main__":
    iniciar_monitoreo()
    time.sleep(10)
    detener_monitoreo()
    conn.close()
