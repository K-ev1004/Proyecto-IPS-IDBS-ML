# =============================================================================
# abuseipdb_module.py — Módulo de Reputación IP (MOCK)
# Este módulo es una simulación para permitir que la interfaz principal funcione
# ante la ausencia del módulo original.
# =============================================================================

import logging

class GestorAbuseIPDB:
    def __init__(self, api_key):
        self.api_key = api_key
        print(f"DEBUG: GestorAbuseIPDB inicializado con llave: {api_key[:5]}...")

    def verificar_ips(self, ips, callback_resultado=None, callback_error=None):
        """Simula la verificación de una lista de IPs."""
        print(f"DEBUG: Verificando IPs: {ips}")
        for ip in ips:
            # Simulamos un resultado genérico
            resultado = {
                'ip': ip,
                'abuse_score': 15,
                'riesgo': 'RIESGO MEDIO (Simulado)',
                'total_reports': 5,
                'pais': 'COLOMBIA (Simulado)'
            }
            if callback_resultado:
                callback_resultado(resultado)

    def exportar_reporte(self, ruta):
        print(f"DEBUG: Exportando reporte simulado a: {ruta}")
        return True

    def limpiar(self):
        print("DEBUG: Limpieza de GestorAbuseIPDB completada.")

if __name__ == "__main__":
    g = GestorAbuseIPDB("test_key")
    g.verificar_ips(["8.8.8.8"])
