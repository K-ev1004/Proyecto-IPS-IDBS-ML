from scapy.all import Ether, IP, TCP, UDP, sendp, get_if_hwaddr, conf
import random
import sys

# =============================================================================
# Simulador de Múltiples Ataques para probar el modelo de Machine Learning
# Usa Layer 2 (sendp) para que los paquetes sean visibles al sniffer en Windows
# =============================================================================

iface = conf.iface
try:
    mi_mac = get_if_hwaddr(iface)
except Exception:
    mi_mac = "ff:ff:ff:ff:ff:ff"

target_ip = "172.10.14.181"

print("="*50)
print("[*] SIMULADOR DE ATAQUES PARA IDS (MACHINE LEARNING) ")
print("="*50)
print("Elige el ataque a simular:")
print("1) Escaneo de Puertos (Port Scan)")
print("2) DDoS Distribuido (Múltiples IPs origen)")
print("3) UDP Flood (Tráfico saturado DNS/Juegos)")
print("4) Posible Exploit (Conexiones a SMB, RDP, FTP, SSH)")
opcion = input("\nOpción [1-4]: ").strip()

paquetes = []

if opcion == "1":
    attacker_ip = "192.168.100.5" # IP falsa
    print(f"\n[+] Simulando Escaneo de Puertos desde {attacker_ip}...")
    for port in range(1, 1000):
        # Enviar paquetes SYN a puertos secuenciales
        pkt = Ether(dst=mi_mac)/IP(src=attacker_ip, dst=target_ip)/TCP(dport=port, flags="S")
        paquetes.append(pkt)

elif opcion == "2":
    print("\n[+] Simulando DDoS Distribuido (Botnet)...")
    for _ in range(1500):
        # Múltiples IPs falsas de origen atacando al puerto 80
        attacker_ip_falsa = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        pkt = Ether(dst=mi_mac)/IP(src=attacker_ip_falsa, dst=target_ip)/TCP(dport=80, flags="S")
        paquetes.append(pkt)

elif opcion == "3":
    attacker_ip = "203.0.113.99"
    print(f"\n[+] Simulando UDP Flood desde {attacker_ip}...")
    for _ in range(1500):
        dport = random.randint(1024, 65535)
        pkt = Ether(dst=mi_mac)/IP(src=attacker_ip, dst=target_ip)/UDP(dport=dport)
        paquetes.append(pkt)

elif opcion == "4":
    attacker_ip = f"192.168.100.{random.randint(10, 250)}"
    print(f"\n[+] Simulando Intento de Exploit desde {attacker_ip}...")
    puertos_vuln = [21, 22, 23, 445, 3389]
    for _ in range(100):
        dport = random.choice(puertos_vuln)
        # IDS detecta exploits basados en intentos de conexión (SYN) a puertos vulnerables
        pkt = Ether(dst=mi_mac)/IP(src=attacker_ip, dst=target_ip)/TCP(dport=dport, flags="S")
        paquetes.append(pkt)

else:
    print("[!] Opción inválida.")
    sys.exit()

print("Enviando paquetes a la interfaz...")
# Enviar lotes de 100 paquetes
for i in range(0, len(paquetes), 100):
    lote = paquetes[i:i+100]
    sendp(lote, iface=iface, verbose=False)
    enviados = min(i + 100, len(paquetes))
    print(f"  [{enviados}/{len(paquetes)}] paquetes enviados")

print("\n[OK] Ataque simulado exitosamente.")
print("[>] Revisa la interfaz del IDS y comprueba la detección de Machine Learning en el gráfico y tabla.")
