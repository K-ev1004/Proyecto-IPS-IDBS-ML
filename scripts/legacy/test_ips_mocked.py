# =============================================================================
# test_ips_mocked_v2.py — Prueba de Integración Mocked para IPS (Fix Unicode)
# Verifica la lógica de decisión de bloqueo sin dependencias externas
# =============================================================================

import sys
import os
import io
from unittest.mock import MagicMock, patch

# Forzar salida en UTF-8 para evitar errores de charmap con emojis
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Mocking de dependencias pesadas antes de importar ids
sys.modules['joblib'] = MagicMock()
sys.modules['scapy'] = MagicMock()
sys.modules['scapy.all'] = MagicMock()
sys.modules['scapy.all'].AsyncSniffer = MagicMock()
sys.modules['PyQt5'] = MagicMock()
sys.modules['PyQt5.QtCore'] = MagicMock()
sys.modules['PyQt5.QtWidgets'] = MagicMock()
sys.modules['PyQt5.QtGui'] = MagicMock()
sys.modules['pandas'] = MagicMock()
sys.modules['xgboost'] = MagicMock()
sys.modules['imblearn'] = MagicMock()
sys.modules['imblearn.pipeline'] = MagicMock()
sys.modules['sklearn'] = MagicMock()
sys.modules['sklearn.ensemble'] = MagicMock()
sys.modules['sklearn.metrics'] = MagicMock()
sys.modules['sklearn.model_selection'] = MagicMock()
sys.modules['sklearn.preprocessing'] = MagicMock()
sys.modules['sklearn.feature_selection'] = MagicMock()
sys.modules['sklearn.pipeline'] = MagicMock()
sys.modules['sklearn.neural_network'] = MagicMock()

# Mocking de módulos internos que pueden fallar
sys.modules['telegram_alert'] = MagicMock()
sys.modules['guardar_dataset'] = MagicMock()

import ids
import respuesta_activa

def test_blocking_logic():
    print("🧪 --- TEST DE LÓGICA DE BLOQUEO IPS ---")
    
    # Configuración de la prueba
    ids.ips_activo = True
    ids.comunicador = MagicMock() # Mock de las señales Qt
    
    # Mock de la ejecución de comandos de firewall
    with patch('respuesta_activa._ejecutar_comando_firewall') as mock_fw:
        mock_fw.return_value = (True, "Comando simulado ejecutado con éxito")
        
        # Escenario: Ataque Crítico con Alta Confianza
        ip_test = "1.2.3.4"
        print(f"📡 Escenario 1: Ataque SQLi desde {ip_test} con 95% de confianza...")
        
        with patch('ids.clasificar_ataque_ml') as mock_ml:
            mock_ml.return_value = ("SQL Injection", 0.95)
            
            ids.guardar_ataque(
                ip_src=ip_test,
                tipo_ataque="SQL Injection",
                protocolo="TCP",
                puerto=80,
                ip_dst="192.168.1.1",
                flag="S",
                usar_ml=True
            )
            
            if mock_fw.called:
                print("[OK] ÉXITO: El sistema intentó bloquear la IP maliciosa.")
                last_call = mock_fw.call_args[0][0]
                if ip_test in last_call:
                    print(f"[OK] Comando generado correctamente para la IP {ip_test}")
                else:
                    print(f"[X] ERROR: El comando no contiene la IP esperada.")
            else:
                print("[X] ERROR: El sistema NO intentó bloquear la IP a pesar de la alta confianza.")

        # Escenario 2: Ataque con Baja Confianza (No debería bloquear)
        ip_test_safe = "5.6.7.8"
        mock_fw.reset_mock()
        print(f"\n📡 Escenario 2: Ataque sospechoso desde {ip_test_safe} con 40% de confianza...")
        
        with patch('ids.clasificar_ataque_ml') as mock_ml:
            mock_ml.return_value = ("Posible Escaneo", 0.40)
            
            ids.guardar_ataque(
                ip_src=ip_test_safe,
                tipo_ataque="Port Scan",
                protocolo="TCP",
                puerto=443,
                ip_dst="192.168.1.1",
                flag="S",
                usar_ml=True
            )
            
            if not mock_fw.called:
                print("[OK] ÉXITO: El sistema NO bloqueó la IP debido a la baja confianza.")
            else:
                print("[X] ERROR: El sistema bloqueó una IP con baja confianza.")

if __name__ == "__main__":
    test_blocking_logic()
