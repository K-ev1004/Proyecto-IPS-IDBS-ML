import sys
import os
import time
import re
import ipaddress
import sqlite3
import joblib

from threading import Thread
from collections import defaultdict, deque

import scapy.all as scapy
from scapy.all import AsyncSniffer

from telegram_alert import enviar_alerta
from guardar_dataset import guardar_evento_en_dataset

from PyQt5.QtCore import QObject, pyqtSignal


# BASE_DIR: carpeta base del proyecto (para rutas relativas)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# Señales para comunicar eventos y tráfico a la interfaz

class ComunicadorIDS(QObject):
    nuevo_evento = pyqtSignal(list)  # [timestamp, ip_src, ip_dst, puerto, protocolo, flag, tipo_final]
    nuevo_trafico = pyqtSignal(str)  # línea de texto con resumen de paquete

comunicador = ComunicadorIDS()


# Variables globales de captura y detección

sniffing_activo = False
sniffer: AsyncSniffer = None  # Instancia de AsyncSniffer

# Umbrales y configuraciones
THRESHOLD_SYN_FLOOD   = 1000
THRESHOLD_DDOS        = 2000
PORT_SCAN_THRESHOLD   = 1000
THRESHOLD_UDP_FLOOD   = 1000
TIEMPO_ENTRE_ALERTAS  = 2          # segundos mínimos entre alertas por misma IP
MI_IP                 = "192.138.1.18"  # IP local para ignorar ataques propios
 
# Contenedores para conteo de paquetes/ataques
paquetes_por_ip      = defaultdict(list)
puertos_por_ip       = defaultdict(set)
eventos_detectados   = deque(maxlen=100)
advertencias_cont    = defaultdict(int)
ultimo_ataque_por_ip = {}


# IPS y rangos “confiables” para evitar falsos positivos

IPS_CONFIABLES = {
    "192.168.0.15",
    "192.168.0.17",
    "8.243.166.74",
    "172.67.9.68",
    "104.22.1.235",  # Cloudflare
    "2.22.20.72",    # Akamai
}

RANGOS_CONFIABLES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    #ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('20.110.205.0/24'),
    ipaddress.ip_network('40.0.0.0/8'),
    ipaddress.ip_network('52.0.0.0/8'),
    ipaddress.ip_network('54.0.0.0/8'),
    ipaddress.ip_network('104.16.0.0/12'),
    ipaddress.ip_network('140.82.0.0/16'),
    ipaddress.ip_network('143.204.0.0/16'),
    ipaddress.ip_network('34.192.0.0/12'),
    ipaddress.ip_network('35.192.0.0/12'),
    ipaddress.ip_network('172.217.0.0/16'),
    ipaddress.ip_network('2.22.20.0/24'),
    ipaddress.ip_network('52.178.17.0/24')
]

def ip_en_rangos(ip: str) -> bool:
    """
    Retorna True si la IP está dentro de alguno de los RANGOS_CONFIABLES.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in RANGOS_CONFIABLES)
    except ValueError:
        return False


# Cargar modelos y encoders (rutas relativas a BASE_DIR)

ruta_modelo           = os.path.join(BASE_DIR, 'modelo_ensamble_optimizado.pkl')
ruta_features         = os.path.join(BASE_DIR, 'features_seleccionadas.pkl')
ruta_flag_encoder     = os.path.join(BASE_DIR, 'flag_encoder.pkl')
ruta_protocol_encoder = os.path.join(BASE_DIR, 'protocol_encoder.pkl')
ruta_tipo_encoder     = os.path.join(BASE_DIR, 'tipo_ataque_encoder.pkl')

try:
    modelo_ml = joblib.load(ruta_modelo)
    print("✅ Modelo de Machine Learning cargado correctamente.")
except FileNotFoundError:
    print(f"❌ Error: no se encontró {ruta_modelo}")
    modelo_ml = None

try:
    features_seleccionadas = joblib.load(ruta_features)
    print("✅ Características seleccionadas cargadas.")
except FileNotFoundError:
    print(f"❌ Error: no se encontró {ruta_features}")
    features_seleccionadas = None

try:
    flag_encoder = joblib.load(ruta_flag_encoder)
    print("✅ Flag encoder cargado.")
except FileNotFoundError:
    print(f"❌ Error: no se encontró {ruta_flag_encoder}")
    flag_encoder = None

try:
    protocol_encoder = joblib.load(ruta_protocol_encoder)
    print("✅ Protocol encoder cargado.")
except FileNotFoundError:
    print(f"❌ Error: no se encontró {ruta_protocol_encoder}")
    protocol_encoder = None

try:
    tipo_ataque_encoder = joblib.load(ruta_tipo_encoder)
    print("✅ Tipo ataque encoder cargado.")
except FileNotFoundError:
    print(f"❌ Error: no se encontró {ruta_tipo_encoder}")
    tipo_ataque_encoder = None


# Base de datos SQLite (intrusiones.db en BASE_DIR)

ruta_bd = os.path.join(BASE_DIR, 'intrusiones.db')
conn = sqlite3.connect(ruta_bd, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS ataques (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        tipo_ataque TEXT,
        ip_src TEXT,
        protocolo TEXT,
        puerto INTEGER
    )
''')
conn.commit()


# Envío de alerta a Telegram en hilo demonio

def _enviar_alerta_async(mensaje: str):
    """
    Ejecuta enviar_alerta(mensaje) en un hilo daemon para que no bloquee
    la detección si la API de Telegram tarda o falla.
    """
    Thread(target=lambda: enviar_alerta(mensaje), daemon=True).start()


# Preprocesamiento y clasificación con ML

def preprocesar_datos(ip_src, ip_dst, puerto, protocolo, flag):
    """
    Transforma atributos en vector de features según los encoders y lista de features.
    """
    if flag_encoder and flag in flag_encoder.classes_:
        flag_encoded = flag_encoder.transform([flag])[0]
    else:
        flag_encoded = -1

    if protocol_encoder and protocolo in protocol_encoder.classes_:
        protocolo_encoded = protocol_encoder.transform([protocolo])[0]
    else:
        protocolo_encoded = -1

    datos = {
        "ip_src": hash(ip_src),
        "ip_dst": hash(ip_dst),
        "puerto": puerto,
        "protocolo_tcp": 1 if protocolo == 'TCP' else 0,
        "flag": flag_encoded,
        "protocolo_num": protocolo_encoded
    }

    if features_seleccionadas:
        return [datos.get(f, 0) for f in features_seleccionadas]
    return list(datos.values())

def clasificar_ataque_ml(ip_src, ip_dst, puerto, protocolo, flag):
    """
    Versión con logs detallados para depuración
    """
    print("\n" + "="*60)
    print("🔍 DEBUG clasificar_ataque_ml INICIADO")
    print("="*60)
    print(f"📥 Parámetros recibidos:")
    print(f"   IP src: {ip_src}")
    print(f"   IP dst: {ip_dst}")
    print(f"   Puerto: {puerto}")
    print(f"   Protocolo: {protocolo}")
    print(f"   Flag: {flag}")
    
    # Verificar componentes
    print(f"\n🔧 Verificando componentes:")
    print(f"   modelo_ml: {modelo_ml is not None}")
    print(f"   features_seleccionadas: {features_seleccionadas is not None}")
    print(f"   tipo_ataque_encoder: {tipo_ataque_encoder is not None}")
    print(f"   protocol_encoder: {protocol_encoder is not None}")
    print(f"   flag_encoder: {flag_encoder is not None}")
    
    if modelo_ml is None:
        print("❌ modelo_ml es None - RETORNANDO (Desconocido, 0.0)")
        return "Desconocido", 0.0
    
    if features_seleccionadas is None:
        print("❌ features_seleccionadas es None - RETORNANDO (Desconocido, 0.0)")
        return "Desconocido", 0.0
    
    if tipo_ataque_encoder is None:
        print("❌ tipo_ataque_encoder es None - RETORNANDO (Desconocido, 0.0)")
        return "Desconocido", 0.0

    try:
        import pandas as pd
        
        # Preparar datos
        print(f"\n📊 Preparando datos...")
        timestamp = pd.Timestamp.now()
        hour = timestamp.hour
        print(f"   Hora: {hour}")
        
        # Hashear IPs
        src_ip_int = hash(str(ip_src)) % (10**8)
        dst_ip_int = hash(str(ip_dst)) % (10**8)
        print(f"   src_ip_int: {src_ip_int}")
        print(f"   dst_ip_int: {dst_ip_int}")
        
        # Encodear protocolo
        if protocol_encoder and protocolo in protocol_encoder.classes_:
            protocolo_encoded = protocol_encoder.transform([protocolo])[0]
            print(f"   protocolo_encoded: {protocolo_encoded} (de {protocolo})")
        else:
            protocolo_encoded = 0
            print(f"   protocolo_encoded: 0 (default, {protocolo} no en classes)")
        
        # Encodear flag
        if flag_encoder and flag in flag_encoder.classes_:
            flag_encoded = flag_encoder.transform([flag])[0]
            print(f"   flag_encoded: {flag_encoded} (de {flag})")
        else:
            flag_encoded = 0
            print(f"   flag_encoded: 0 (default, {flag} no en classes)")
        
        # Crear DataFrame
        print(f"\n🔨 Creando DataFrame...")
        datos_dict = {
            'src_ip_int': [src_ip_int],
            'dst_ip_int': [dst_ip_int],
            'dst_port': [puerto],
            'protocol_encoded': [protocolo_encoded],
            'flag_encoded': [flag_encoded],
            'hour': [hour]
        }
        
        df_entrada = pd.DataFrame(datos_dict)
        print(f"   DataFrame shape: {df_entrada.shape}")
        print(f"   DataFrame columnas: {list(df_entrada.columns)}")
        print(f"   DataFrame valores:")
        print(df_entrada)
        
        # Hacer predicción
        print(f"\n🤖 Haciendo predicción...")
        tipo_pred = modelo_ml.predict(df_entrada)[0]
        print(f"   tipo_pred (encoded): {tipo_pred}")
        
        probs = modelo_ml.predict_proba(df_entrada)[0]
        print(f"   probabilidades: {probs}")
        
        # Decodificar
        print(f"\n🔓 Decodificando resultado...")
        tipo_str = tipo_ataque_encoder.inverse_transform([tipo_pred])[0]
        confianza = probs.max()
        
        print(f"   ✅ tipo_str: {tipo_str}")
        print(f"   ✅ confianza: {confianza} ({confianza*100:.2f}%)")
        
        print("="*60)
        print(f"✅ RETORNANDO: ({tipo_str}, {confianza})")
        print("="*60 + "\n")
        
        return tipo_str, confianza
        
    except Exception as e:
        print(f"\n❌❌❌ EXCEPCIÓN CAPTURADA ❌❌❌")
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        print("="*60 + "\n")
        return "Desconocido", 0.0


# Función para guardar un ataque: alerta, BD, dataset, señales

def guardar_ataque(ip_src, tipo_ataque, protocolo, puerto, ip_dst="DESCONOCIDA", flag="N/A", usar_ml=True):
    print(f"DEBUG: Guardando ataque - ip_src: {ip_src}, ip_dst: {ip_dst}, tipo_ataque: {tipo_ataque}")
    if ip_src == MI_IP:
        return

    ahora = time.time()
    if ahora - ultimo_ataque_por_ip.get(ip_src, 0) < TIEMPO_ENTRE_ALERTAS:
        return
    ultimo_ataque_por_ip[ip_src] = ahora
    advertencias_cont[ip_src] += 1

    timestamp = time.ctime()

    if usar_ml:
        tipo_ml, confianza = clasificar_ataque_ml(ip_src, ip_dst, puerto, protocolo, flag)
        tipo_final = f"{tipo_ataque} ({tipo_ml})"
        mensaje_ml = f"📊 Confianza ML: {confianza*100:.2f}%"
    else:
        tipo_final = tipo_ataque
        mensaje_ml = "📊 Confianza ML: N/A"

    mensaje = (
        f"SISTEMA DE INTRUSIÓN:\n"
        f"🚨 [IDS] {tipo_final} detectado\n"
        f"🧑‍💻 IP Origen: {ip_src}\n"
        f"📦 Protocolo: {protocolo}\n"
        f"🔌 Puerto Destino: {puerto}\n"
        f"📍 IP Destino: {ip_dst}\n"
        #f"{mensaje_ml}"
    )
    # Guardar en SQLite
    try:
        cursor.execute('''
            INSERT INTO ataques (timestamp, tipo_ataque, ip_src, protocolo, puerto)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, tipo_final, ip_src, protocolo, puerto))
        conn.commit()
    except Exception as e:
        print(f"❌ Error guardando en SQLite: {e}")

    # Guardar en dataset CSV (si existe la función)
    try:
        guardar_evento_en_dataset(ip_src, ip_dst, puerto, protocolo, flag, tipo_final, tipo_ataque)
        print("DEBUG: Evento guardado en dataset.")
    except Exception as e:
        print(f"❌ Error al guardar evento en dataset: {e}")

    # Agregar a cola de eventos y emitir señal a la interfaz
    evento = [timestamp, ip_src, ip_dst, puerto, protocolo, flag, tipo_final]
    eventos_detectados.append(evento)
    comunicador.nuevo_evento.emit(evento)

    try:
        _enviar_alerta_async(mensaje)
        print("DEBUG: Alerta enviada a Telegram.")
    except Exception as e:
        print(f"❌ No se pudo lanzar alerta a Telegram: {e}")


# Mostrar resumen de paquete e emitir señal de tráfico

def mostrar_paquete(packet):
    resumen = packet.summary()
    print(f"Paquete capturado: {resumen}")
    comunicador.nuevo_trafico.emit(f"{resumen}")


# Detectores de distintos tipos de ataque


def detectar_syn_flood(packet):
    if packet.haslayer(scapy.TCP) and str(packet[scapy.TCP].flags) == 'S':
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        puerto = packet[scapy.TCP].dport
        protocolo = 'TCP'
        t = time.time()

        paquetes_por_ip[ip_src].append(t)
        paquetes_por_ip[ip_src] = [ts for ts in paquetes_por_ip[ip_src] if t - ts <= 0.5]

        if len(paquetes_por_ip[ip_src]) > THRESHOLD_SYN_FLOOD:
            guardar_ataque(ip_src, "SYN Flood", protocolo, puerto, ip_dst, flag=str(packet[scapy.TCP].flags))

def detectar_ddos(packet):
    if packet.haslayer(scapy.IP):
        ip_dst = packet[scapy.IP].dst
        ip_src = packet[scapy.IP].src
        puerto = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else 0
        protocolo = 'TCP' if packet.haslayer(scapy.TCP) else 'UDP'

        if protocolo == 'UDP' and puerto == 0:
            return

        t = time.time()
        paquetes_por_ip[ip_dst].append(t)
        paquetes_por_ip[ip_dst] = [ts for ts in paquetes_por_ip[ip_dst] if t - ts <= 1]

        if len(paquetes_por_ip[ip_dst]) > THRESHOLD_DDOS:
            guardar_ataque(ip_src, "DDoS Distribuido", protocolo, puerto, ip_dst)

def detectar_escaneo_puertos(packet):
    if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst  # Agregar la IP de destino
        puerto = packet[scapy.TCP].dport
        protocolo = 'TCP'

        puertos_por_ip[ip_src].add(puerto)
        if len(puertos_por_ip[ip_src]) > PORT_SCAN_THRESHOLD:
            guardar_ataque(ip_src, "Escaneo de Puertos", protocolo, puerto, ip_dst)  # Pasar ip_dst

def detectar_exploit(packet):
    if not packet.haslayer(scapy.IP):
        return

    ip_src = packet[scapy.IP].src
    if ip_src in IPS_CONFIABLES or ip_en_rangos(ip_src):
        return

    ip_dst = packet[scapy.IP].dst
    protocolo = 'TCP' if packet.haslayer(scapy.TCP) else 'UDP' if packet.haslayer(scapy.UDP) else 'OTRO'

    if protocolo not in {'TCP', 'UDP'}:
        return

    puerto = packet[scapy.TCP].dport if protocolo == 'TCP' else packet[scapy.UDP].dport
    flag = str(packet[scapy.TCP].flags) if protocolo == 'TCP' else 'N/A'

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

            exclusiones = [
                "order=desc", "mode=debug", "file=", "page=", "limit=",
                "search=", "token=", "session=", "csrf", "user-agent", "referer",
                "accept-encoding", "connection", "content-length", "host"
            ]
            if any(excl in carga.lower() for excl in exclusiones):
                return

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
                guardar_ataque(ip_src, "SQL Injection", "TCP", puerto, ip_dst, usar_ml=False)
        except Exception as e:
            print(f"❌ Error en SQLi: {e}")

def detectar_udp_flood(packet):
    if packet.haslayer(scapy.IP):
        ip_dst = packet[scapy.IP].dst
        ip_src = packet[scapy.IP].src
        puerto = packet[scapy.UDP].dport if packet.haslayer(scapy.UDP) else 0
        protocolo = 'UDP' if packet.haslayer(scapy.UDP) else 'TCP'

        if protocolo == 'TCP' and puerto == 0:
            return

        t = time.time()
        paquetes_por_ip[ip_dst].append(t)
        paquetes_por_ip[ip_dst] = [ts for ts in paquetes_por_ip[ip_dst] if t - ts <= 1]

        if len(paquetes_por_ip[ip_dst]) > THRESHOLD_UDP_FLOOD:
            guardar_ataque(ip_src, "UDP Flood", protocolo, puerto, ip_dst)


# Procesar cada paquete con try/except para no colgar el sniffer

def procesar_paquete(packet):
    try:
        print("DEBUG: procesar_paquete recibió paquete:", packet.summary())
        mostrar_paquete(packet)

        if packet.haslayer(scapy.IP):
            detectar_syn_flood(packet)
            detectar_ddos(packet)
            detectar_escaneo_puertos(packet)
            detectar_exploit(packet)
            detectar_sql_injection(packet)
            detectar_udp_flood(packet)
    except Exception as e:
        print(f"❌ Excepción en procesar_paquete: {e}")


# Funciones para iniciar y detener AsyncSniffer

def iniciar_monitoreo(iface=None):
    """
    Inicia un AsyncSniffer en un hilo aparte para capturar tráfico
    sin bloquear la ejecución principal.
    """
    global sniffing_activo, sniffer
    if sniffing_activo:
        print("🔍 Sniffing ya está activo.")
        return

    print(f"📡 Iniciando AsyncSniffer... iface={iface}")
    sniffing_activo = True

    sniffer = AsyncSniffer(
        iface=iface,
        prn=procesar_paquete,
        store=False,
        filter=None  # Puedes cambiar a un filtro BPF si lo deseas
    )
    try:
        sniffer.start()
        print("✅ AsyncSniffer arrancado correctamente.")
    except Exception as e:
        print(f"❌ Error iniciando AsyncSniffer: {e}")
        sniffing_activo = False

def detener_monitoreo():
    """
    Detiene el AsyncSniffer si está corriendo.
    """
    global sniffing_activo, sniffer
    if not sniffing_activo:
        print("⏹ Sniffing no estaba activo.")
        return

    print("⏹ Deteniendo AsyncSniffer...")
    sniffing_activo = False
    try:
        if sniffer is not None:
            sniffer.stop()
            sniffer = None
            print("✅ AsyncSniffer detenido correctamente.")
    except Exception as e:
        print(f"❌ Error deteniendo AsyncSniffer: {e}")


# Si se invoca directamente, podemos probar un ciclo simple

if __name__ == "__main__":
    print("🔍 Ejecutando ids.py directamente para prueba.")
    iniciar_monitoreo()
    print("⏳ Deja correr 10 segundos para verificar tráfico…")
    time.sleep(10)
    print("⏹ Deteniendo monitoreo de prueba.")
    detener_monitoreo()
    conn.close()
    print("✅ ids.py finalizado.")