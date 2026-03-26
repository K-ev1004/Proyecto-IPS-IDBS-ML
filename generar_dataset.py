import pandas as pd
import random
import os
from datetime import datetime, timedelta

def random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_dataset(num_samples=20000):
    data = []
    base_time = datetime.now() - timedelta(days=7)
    
    # Objetivo simulado
    target_ip = "172.10.14.181"
    
    # Atacantes persistentes (para Port Scan)
    scanner_ip_1 = "203.0.113.10"
    scanner_ip_2 = "203.0.113.11"
    
    print(f"Generando {num_samples} registros de tráfico sintético...")
    
    for _ in range(num_samples):
        # Distribución de clases realista (mayormente normal)
        attack_type = random.choices(
            ["Normal", "SYN Flood", "DDoS Distribuido", "PORT scanner", "Posible Exploit", "UDP Flood", "Inyección SQL"],
            weights=[0.60, 0.08, 0.08, 0.08, 0.05, 0.08, 0.03],
            k=1
        )[0]
        
        timestamp = base_time + timedelta(seconds=random.randint(0, 604800))
        
        if attack_type == "Normal":
            src_ip = random_ip()
            dst_ip = target_ip
            dst_port = random.choice([80, 443, 53, 22])
            protocol = random.choice(["TCP", "TCP", "UDP"])
            flag = random.choice(["A", "PA", "FA"]) if protocol == "TCP" else "N/A"
            
        elif attack_type == "SYN Flood":
            src_ip = random_ip()
            dst_ip = target_ip
            dst_port = random.choice([80, 443])
            protocol = "TCP"
            flag = "S"
            
        elif attack_type == "DDoS Distribuido":
            src_ip = random_ip()
            dst_ip = target_ip
            dst_port = random.choice([80, 443, 8080])
            protocol = random.choice(["TCP", "UDP"])
            flag = "S" if protocol == "TCP" else "N/A"
            
        elif attack_type == "PORT scanner":
            src_ip = random.choice([scanner_ip_1, scanner_ip_2])
            dst_ip = target_ip
            dst_port = random.randint(1, 1024)
            protocol = "TCP"
            flag = "S"
            
        elif attack_type == "Posible Exploit":
            src_ip = random_ip()
            dst_ip = target_ip
            # Puertos comúnmente explotados (SMB, RDP, FTP, Telnet)
            dst_port = random.choice([445, 3389, 21, 23])
            protocol = "TCP"
            flag = "PA"
            
        elif attack_type == "UDP Flood":
            src_ip = random_ip()
            dst_ip = target_ip
            dst_port = random.randint(1024, 65535)
            protocol = "UDP"
            flag = "N/A"
            
        elif attack_type == "Inyección SQL":
            src_ip = random_ip()
            dst_ip = target_ip
            # Bases de datos comunes o web
            dst_port = random.choice([3306, 5432, 1433, 80])
            protocol = "TCP"
            flag = "PA"

        ts_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        data.append([src_ip, dst_ip, dst_port, protocol, flag, attack_type, ts_str])
        
    df = pd.DataFrame(data, columns=['src_ip', 'dst_ip', 'dst_port', 'protocol', 'flag', 'tipo_ataque', 'timestamp'])
    
    os.makedirs('Dataset', exist_ok=True)
    df.to_csv('Dataset/escanerpuertos.csv', index=False)
    print(f"✅ ¡Dataset generado con éxito en Dataset/escanerpuertos.csv!")
    print(df['tipo_ataque'].value_counts())

if __name__ == "__main__":
    generate_dataset()
