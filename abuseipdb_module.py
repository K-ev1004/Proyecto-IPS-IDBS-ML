import requests
from datetime import datetime, timedelta
from PyQt5.QtCore import QThread, pyqtSignal
import json
import time
import logging

class AbuseIPDBChecker(QThread):
    """
    Thread para verificar IPs contra AbuseIPDB sin bloquear la UI
    """
    resultado_obtenido = pyqtSignal(dict)  # Emite resultado de verificación
    error_signal = pyqtSignal(str)  # Emite errores
    
    def __init__(self, api_key, ips_a_verificar=None):
        super().__init__()
        self.api_key = api_key
        self.ips_a_verificar = ips_a_verificar or []
        self.base_url = "https://api.abuseipdb.com/api/v2/check"
        self.headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        self.cache_ips = {}
        self.cache_duracion = 3600  # 1 hora
        self.running = True
        
    def run(self):
        """Ejecuta la verificación en thread separado"""
        for ip in self.ips_a_verificar:
            if not self.running:
                break
            try:
                resultado = self.verificar_ip(ip)
                self.resultado_obtenido.emit(resultado)
                time.sleep(0.2)  # Espera para no saturar API
            except Exception as e:
                self.error_signal.emit(f"Error verificando {ip}: {str(e)}")
    
    def verificar_ip(self, ip):
        """Verifica una IP en AbuseIPDB"""
        # Verificar cache
        if ip in self.cache_ips:
            timestamp_cache, datos = self.cache_ips[ip]
            if (datetime.now() - timestamp_cache).seconds < self.cache_duracion:
                return datos
        
        try:
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(
                self.base_url,
                headers=self.headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                ip_data = data.get('data', {})
                
                resultado = {
                    'ip': ip,
                    'abuse_score': ip_data.get('abuseConfidenceScore', 0),
                    'total_reports': ip_data.get('totalReports', 0),
                    'es_vpn': ip_data.get('isVpn', False),
                    'es_tor': ip_data.get('isTor', False),
                    'es_proxy': ip_data.get('isProxy', False),
                    'isp': ip_data.get('isp', 'Desconocido'),
                    'uso': ip_data.get('usageType', 'Desconocido'),
                    'pais': ip_data.get('countryName', 'Desconocido'),
                    'timestamp': datetime.now().isoformat(),
                    'riesgo': self._calcular_nivel_riesgo(ip_data.get('abuseConfidenceScore', 0))
                }
                
                # Guardar en cache
                self.cache_ips[ip] = (datetime.now(), resultado)
                return resultado
                
            elif response.status_code == 429:
                raise Exception("Límite de API alcanzado")
            else:
                raise Exception(f"Error API: {response.status_code}")
                
        except requests.exceptions.Timeout:
            raise Exception(f"Timeout verificando {ip}")
        except Exception as e:
            raise Exception(str(e))
    
    def _calcular_nivel_riesgo(self, score):
        """Clasifica el nivel de riesgo según el score"""
        if score >= 75:
            return "🔴 CRÍTICO"
        elif score >= 50:
            return "🟠 ALTO"
        elif score >= 25:
            return "🟡 MEDIO"
        else:
            return "🟢 BAJO"
    
    def stop_thread(self):
        self.running = False


class GestorAbuseIPDB:
    """Gestor de verificaciones de AbuseIPDB con historial"""
    def __init__(self, api_key):
        self.api_key = api_key
        self.checker = None
        self.historial = {}
        self.ips_bloqueadas = set()
        self.ips_verificadas = set()
    
    def verificar_ips(self, ips, callback_resultado=None, callback_error=None):
        """
        Verifica una lista de IPs
        callback_resultado: función que recibe cada resultado
        callback_error: función que recibe cada error
        """
        # Filtrar IPs ya verificadas
        ips_nuevas = [ip for ip in ips if ip not in self.ips_verificadas]
        
        if not ips_nuevas:
            logging.info("Todas las IPs ya han sido verificadas")
            return
        
        # Detener thread anterior si existe
        if self.checker and self.checker.isRunning():
            self.checker.stop_thread()
            self.checker.wait()
        
        self.checker = AbuseIPDBChecker(self.api_key, ips_nuevas)
        
        if callback_resultado:
            self.checker.resultado_obtenido.connect(lambda r: self._procesar_resultado(r, callback_resultado))
        
        if callback_error:
            self.checker.error_signal.connect(callback_error)
        
        self.checker.start()
    
    def _procesar_resultado(self, resultado, callback):
        """Procesa un resultado y lo guarda"""
        ip = resultado['ip']
        self.ips_verificadas.add(ip)
        
        if ip not in self.historial:
            self.historial[ip] = []
        
        self.historial[ip].append(resultado)
        
        # Marcar como bloqueada si riesgo es crítico
        if "CRÍTICO" in resultado['riesgo']:
            self.ips_bloqueadas.add(ip)
        
        callback(resultado)
    
    def obtener_historial_ip(self, ip):
        """Obtiene historial de una IP"""
        return self.historial.get(ip, [])
    
    def obtener_ips_bloqueadas(self):
        """Retorna lista de IPs bloqueadas"""
        return list(self.ips_bloqueadas)
    
    def exportar_reporte(self, archivo_json):
        """Exporta reporte a JSON"""
        try:
            with open(archivo_json, 'w', encoding='utf-8') as f:
                json.dump(self.historial, f, indent=2, ensure_ascii=False)
            logging.info(f"Reporte exportado: {archivo_json}")
        except Exception as e:
            logging.error(f"Error exportando reporte: {e}")
    
    def limpiar(self):
        """Limpia recursos"""
        if self.checker and self.checker.isRunning():
            self.checker.stop_thread()
            self.checker.wait()