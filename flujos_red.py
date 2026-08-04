# flujos_red.py — Motor de Extracción de Flujos en Tiempo Real (V3)
# Universidad UNIPAZ
# =============================================================================
# Propósito: Agrupa paquetes individuales de Scapy en "Flujos Bidireccionales"
# y calcula en vivo las características estadísticas que necesita el modelo
# entrenado con CSE-CIC-IDS2018 (NetFlow-like features).
# =============================================================================

import time
from collections import defaultdict
import numpy as np

# Tiempo máximo de inactividad antes de considerar un flujo como "Terminado" y predecirlo
FLOW_TIMEOUT = 5.0 # Segundos

class FlujoBidireccional:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocolo, timestamp):
        # 5-Tuple (La clave de dirección Forward)
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocolo = protocolo
        
        # Tiempos
        self.start_time = timestamp
        self.last_time = timestamp
        
        # Paquetes y Bytes (Forward)
        self.fwd_pkts = 0
        self.fwd_bytes = 0
        self.fwd_pkt_lens = []
        
        # Paquetes y Bytes (Backward)
        self.bwd_pkts = 0
        self.bwd_bytes = 0
        self.bwd_pkt_lens = []
        
        # Flags (combinados o específicos si es TCP)
        self.fin_flag_cnt = 0
        self.syn_flag_cnt = 0
        self.rst_flag_cnt = 0
        self.psh_flag_cnt = 0
        self.ack_flag_cnt = 0
        self.urg_flag_cnt = 0

    def add_packet(self, packet_len, timestamp, is_forward, tcp_flags=None):
        self.last_time = timestamp
        
        if is_forward:
            self.fwd_pkts += 1
            self.fwd_bytes += packet_len
            self.fwd_pkt_lens.append(packet_len)
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += packet_len
            self.bwd_pkt_lens.append(packet_len)
            
        if tcp_flags:
            if 'F' in tcp_flags: self.fin_flag_cnt += 1
            if 'S' in tcp_flags: self.syn_flag_cnt += 1
            if 'R' in tcp_flags: self.rst_flag_cnt += 1
            if 'P' in tcp_flags: self.psh_flag_cnt += 1
            if 'A' in tcp_flags: self.ack_flag_cnt += 1
            if 'U' in tcp_flags: self.urg_flag_cnt += 1

    def is_expired(self, current_time):
        return (current_time - self.last_time) > FLOW_TIMEOUT

    def get_features_dict(self):
        """
        Calcula y retorna un diccionario con las características del flujo.
        Estos nombres DEBEN coincidir exactamente con los que use CEREBRO V3 al entrenar.
        """
        # Calcular duraciones
        flow_duration_sec = self.last_time - self.start_time
        # Convertir a microsegundos para coincidir con CIC-IDS2018
        flow_duration = max(1.0, flow_duration_sec * 1e6) 
        
        total_pkts = self.fwd_pkts + self.bwd_pkts
        total_bytes = self.fwd_bytes + self.bwd_bytes
        
        flow_byts_s = (total_bytes / flow_duration_sec) if flow_duration_sec > 0 else 0
        flow_pkts_s = (total_pkts / flow_duration_sec) if flow_duration_sec > 0 else 0

        # Estadísticas Fwd
        fwd_pkt_len_max = max(self.fwd_pkt_lens) if self.fwd_pkt_lens else 0
        fwd_pkt_len_min = min(self.fwd_pkt_lens) if self.fwd_pkt_lens else 0
        fwd_pkt_len_mean = np.mean(self.fwd_pkt_lens) if self.fwd_pkt_lens else 0
        fwd_pkt_len_std = np.std(self.fwd_pkt_lens) if len(self.fwd_pkt_lens) > 1 else 0

        # Estadísticas Bwd
        bwd_pkt_len_max = max(self.bwd_pkt_lens) if self.bwd_pkt_lens else 0
        bwd_pkt_len_min = min(self.bwd_pkt_lens) if self.bwd_pkt_lens else 0
        bwd_pkt_len_mean = np.mean(self.bwd_pkt_lens) if self.bwd_pkt_lens else 0
        bwd_pkt_len_std = np.std(self.bwd_pkt_lens) if len(self.bwd_pkt_lens) > 1 else 0

        features = {
            'Src Port': self.src_port,
            'Dst Port': self.dst_port,
            'Protocol': 6 if self.protocolo == 'TCP' else (17 if self.protocolo == 'UDP' else 0),
            'Flow Duration': flow_duration,
            'Tot Fwd Pkts': self.fwd_pkts,
            'Tot Bwd Pkts': self.bwd_pkts,
            'TotLen Fwd Pkts': self.fwd_bytes,
            'TotLen Bwd Pkts': self.bwd_bytes,
            'Fwd Pkt Len Max': fwd_pkt_len_max,
            'Fwd Pkt Len Min': fwd_pkt_len_min,
            'Fwd Pkt Len Mean': fwd_pkt_len_mean,
            'Fwd Pkt Len Std': fwd_pkt_len_std,
            'Bwd Pkt Len Max': bwd_pkt_len_max,
            'Bwd Pkt Len Min': bwd_pkt_len_min,
            'Bwd Pkt Len Mean': bwd_pkt_len_mean,
            'Bwd Pkt Len Std': bwd_pkt_len_std,
            'Flow Byts/s': flow_byts_s,
            'Flow Pkts/s': flow_pkts_s,
            'FIN Flag Cnt': self.fin_flag_cnt,
            'SYN Flag Cnt': self.syn_flag_cnt,
            'RST Flag Cnt': self.rst_flag_cnt,
            'PSH Flag Cnt': self.psh_flag_cnt,
            'ACK Flag Cnt': self.ack_flag_cnt,
            'URG Flag Cnt': self.urg_flag_cnt,
        }
        return features

class FlowTracker:
    def __init__(self, callback_prediccion):
        """
        callback_prediccion: Función a la que se le pasará el diccionario de features 
        cuando un flujo esté listo para ser analizado.
        """
        self.flujos = {}
        self.callback_prediccion = callback_prediccion
        self.ultimo_chequeo = time.time()

    def procesar_paquete(self, ip_src, ip_dst, puerto_src, puerto_dst, protocolo, packet_len, tcp_flags, timestamp):
        # Para identificar el flujo ignoramos la dirección inicial.
        # Ordenamos las IPs y Puertos de manera predecible para crear la clave
        if ip_src < ip_dst:
            flow_key = (ip_src, ip_dst, puerto_src, puerto_dst, protocolo)
            is_forward = True
        else:
            flow_key = (ip_dst, ip_src, puerto_dst, puerto_src, protocolo)
            is_forward = False

        if flow_key not in self.flujos:
            # Si is_forward es False en el primer paquete, la lógica técnica de CIC
            # asume que el primer paquete visto es el Fwd. Para simplificar y mantener 
            # consistencia, usamos src/dst literales del primer paquete.
            self.flujos[flow_key] = FlujoBidireccional(ip_src, ip_dst, puerto_src, puerto_dst, protocolo, timestamp)
            # Como acabamos de instanciarlo con ip_src, este primer paquete SIEMPRE es fwd respecto al objeto
            is_forward = True 

        flujo = self.flujos[flow_key]
        
        # Corregir is_forward relativo al flujo instanciado
        if flujo.src_ip == ip_src:
            is_forward = True
        else:
            is_forward = False

        flujo.add_packet(packet_len, timestamp, is_forward, tcp_flags)

        # Chequear flujos expirados cada 2 segundos aprox
        if timestamp - self.ultimo_chequeo > 2.0:
            self._limpiar_flujos_expirados(timestamp)
            self.ultimo_chequeo = timestamp

    def _limpiar_flujos_expirados(self, current_time):
        keys_to_delete = []
        for key, flujo in self.flujos.items():
            if flujo.is_expired(current_time):
                features = flujo.get_features_dict()
                # Llamar a la función de ML (CEREBRO / ids.py)
                self.callback_prediccion(flujo.src_ip, flujo.dst_ip, features)
                keys_to_delete.append(key)
        
        for key in keys_to_delete:
            del self.flujos[key]
