import os  # Asegúrate de importar os
import csv
import random
from datetime import datetime, timedelta

# Parámetros
#num_ips_normales = 10
#num_ips_portscan = 10
#num_ips_synflood = 9
num_ips_ddos = 1000

puertos_totales = 65535
paquetes_por_ip_normal = 100
paquetes_por_ip_portscan = 2000  # Muchos puertos para escaneo
paquetes_por_ip_synflood = 5000  # Muchos paquetes al mismo puerto para SYN flood
paquetes_por_ip_ddos = 3000      # Muchos paquetes de varias IPs para DDoS

# Generar ruta dinámica para el CSV de salida
output_file = os.path.join(os.getcwd(), "Dataset", "trafico_mixto.csv")

# Asegurarse de que la carpeta exista
output_dir = os.path.dirname(output_file)
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Generar IPs aleatorias
def generar_ip():
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"

# Generar timestamps secuenciales empezando desde ahora
start_time = datetime.now()

with open(output_file, mode='w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'flag', 'tipo_ataque'])

    # Tráfico normal
    for _ in range(num_ips_normales):
        ip_src = generar_ip()
        for i in range(paquetes_por_ip_normal):
            timestamp = (start_time + timedelta(seconds=i*random.uniform(0.5, 2))).strftime('%Y-%m-%d %H:%M:%S')
            ip_dst = generar_ip()
            dst_port = random.choice([80, 443, 22, 25, 53])
            protocol = random.choice(['TCP', 'UDP'])
            flag = random.choice(['A', 'S', 'F', 'P', 'R', '']) if protocol == 'TCP' else ''
            tipo_ataque = 'Normal'
            writer.writerow([timestamp, ip_src, ip_dst, dst_port, protocol, flag, tipo_ataque])

    # Tráfico Port Scan
    for _ in range(num_ips_portscan):
        ip_src = generar_ip()
        ip_dst = generar_ip()
        for i in range(paquetes_por_ip_portscan):
            timestamp = (start_time + timedelta(seconds=i*0.05)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            dst_port = random.randint(1, puertos_totales)
            protocol = 'TCP'
            flag = 'S'
            tipo_ataque = 'Port Scan'
            writer.writerow([timestamp, ip_src, ip_dst, dst_port, protocol, flag, tipo_ataque])

    # Tráfico SYN Flood
    for _ in range(num_ips_synflood):
        ip_src = generar_ip()
        ip_dst = generar_ip()
        dst_port = random.choice([80, 443, 8080])  # Pocos puertos típicos de destino
        for i in range(paquetes_por_ip_synflood):
            timestamp = (start_time + timedelta(seconds=i*0.01)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            protocol = 'TCP'
            flag = 'S'
            tipo_ataque = 'SYN Flood'
            writer.writerow([timestamp, ip_src, ip_dst, dst_port, protocol, flag, tipo_ataque])

    # Tráfico DDoS
    ip_dst_ddos = generar_ip()  # IP destino fija para DDoS
    for _ in range(num_ips_ddos):
        ip_src = generar_ip()
        dst_port = random.choice([80, 443])
        for i in range(paquetes_por_ip_ddos):
            timestamp = (start_time + timedelta(seconds=i*0.02)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            protocol = 'UDP'  # Puede ser UDP para DDoS
            flag = ''  # Sin flag para UDP
            tipo_ataque = 'DDoS'
            writer.writerow([timestamp, ip_src, ip_dst_ddos, dst_port, protocol, flag, tipo_ataque])

print(f"CSV generado en {output_file}")
