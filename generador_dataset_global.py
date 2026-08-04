"""
generador_dataset_global.py — Pipeline unificado de datasets (CIC 2017 + 2018 + 2019)
Objetivo: Producir un dataset de alta calidad, balanceado (downsampling masivos),
conteniendo las 23 características del modelo v4.
Para el IDS/IPS de la Universidad UNIPAZ
"""
import pandas as pd
import numpy as np
import os
import gc
from tqdm import tqdm

# ============================================================
# CONFIGURACIÓN
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
DIR_2017 = os.path.join(DATASETS_DIR, "CIC-IDS2017")
DIR_2018 = os.path.join(DATASETS_DIR, "CSE-CIC-IDS2018")
DIR_2019 = os.path.join(DATASETS_DIR, "CIC-DDoS2019")
OUTPUT_DIR = os.path.join(BASE_DIR, "Dataset_Limpio")
os.makedirs(OUTPUT_DIR, exist_ok=True)

RANDOM_STATE = 42

FEATURES_V4 = [
    'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min',
    'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
    'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 
    'ACK Flag Cnt', 'URG Flag Cnt'
]

MAPEO_CLASES = {
    'BENIGN': 'Normal',
    'Benign': 'Normal',
    'PortScan': 'Port_Scanner',
    'DoS slowloris': 'SYN_Flood',
    'DoS attacks-Slowloris': 'SYN_Flood',
    'DoS Slowhttptest': 'SYN_Flood',
    'DoS attacks-SlowHTTPTest': 'SYN_Flood',
    'DoS Hulk': 'SYN_Flood',
    'DoS attacks-Hulk': 'SYN_Flood',
    'DoS GoldenEye': 'SYN_Flood',
    'DoS attacks-GoldenEye': 'SYN_Flood',
    'DoS': 'UDP_Flood',
    'DDOS attack-LOIC-UDP': 'UDP_Flood',
    'DDoS': 'DDoS_Distribuido',
    'DDOS attack-HOIC': 'DDoS_Distribuido',
    'DDoS attacks-LOIC-HTTP': 'DDoS_Distribuido',
    'Bot': 'DDoS_Distribuido',
    'LDAP': 'DDoS_Distribuido',
    'MSSQL': 'DDoS_Distribuido',
    'NetBIOS': 'DDoS_Distribuido',
    'Portmap': 'DDoS_Distribuido',
    'Syn': 'SYN_Flood',
    'UDP': 'UDP_Flood',
    'UDPLag': 'UDP_Flood',
    'Brute Force': 'Posible_Exploit',
    'FTP-Patator': 'Posible_Exploit',
    'SSH-Patator': 'Posible_Exploit',
    'FTP-BruteForce': 'Posible_Exploit',
    'SSH-Bruteforce': 'Posible_Exploit',
    'Infiltration': 'Posible_Exploit',
    'Infilteration': 'Posible_Exploit',
    'Heartbleed': 'Posible_Exploit',
    'Web Attack - Sql Injection': 'Inyeccion_SQL',
    'SQL Injection': 'Inyeccion_SQL',
    'Web Attack - XSS': 'Inyeccion_SQL',
    'Brute Force -XSS': 'Inyeccion_SQL',
    'Web Attack - Brute Force': 'Inyeccion_SQL',
    'Brute Force -Web': 'Inyeccion_SQL',
    'Web Attack \u2013 Brute Force': 'Inyeccion_SQL',
    'Web Attack \u2013 XSS': 'Inyeccion_SQL',
    'Web Attack \u2013 Sql Injection': 'Inyeccion_SQL',
}

LIMITES_CLASE = {
    'Normal': 1_500_000,
    'DDoS_Distribuido': 1_000_000,
    'SYN_Flood': 500_000,
    'UDP_Flood': 500_000,
    'Port_Scanner': None,
    'Posible_Exploit': None,
    'Inyeccion_SQL': None
}

def normalizar_columnas(df):
    df.columns = df.columns.str.strip()
    return df

# Carácter de reemplazo (U+FFFD) que aparece corrupto en algunos CSVs de 2017
# y que impide mapear correctamente los ataques web (Web Attack � XSS, etc.)
_replace_caracter = {'\ufffd': '-', '\u2013': '-', '\u2014': '-'}

def _normalizar_label(valor):
    if not isinstance(valor, str):
        return valor
    for origen, destino in _replace_caracter.items():
        if origen in valor:
            valor = valor.replace(origen, destino)
    return valor

def procesar_chunk(chunk):
    chunk = normalizar_columnas(chunk)
    if 'Destination Port' in chunk.columns:
        chunk = chunk.rename(columns={'Destination Port': 'Dst Port'})
    
    if 'Label' in chunk.columns:
        chunk = chunk[chunk['Label'] != 'Label']
        # Normalizar caracteres corruptos (U+FFFD, guiones) antes del mapeo
        chunk['Label'] = chunk['Label'].map(_normalizar_label)
        chunk['Label_UNIPAZ'] = chunk['Label'].map(MAPEO_CLASES)
        chunk = chunk.dropna(subset=['Label_UNIPAZ'])
        
        for f in FEATURES_V4:
            if f not in chunk.columns:
                chunk[f] = 0
                
        chunk = chunk[FEATURES_V4 + ['Label_UNIPAZ']]
        for col in FEATURES_V4:
            chunk[col] = pd.to_numeric(chunk[col], errors='coerce')
        return chunk
    return pd.DataFrame()

def procesar_carpeta(carpeta_path, origen_nombre):
    print(f"\n[*] Procesando dataset: {origen_nombre} ({carpeta_path})")
    
    if not os.path.exists(carpeta_path):
        print(f"  [!] La carpeta {carpeta_path} no existe. Saltando...")
        return pd.DataFrame()
        
    archivos = [f for f in os.listdir(carpeta_path) if f.endswith('.csv') or f.endswith('.parquet')]
    chunks_procesados = []
    
    posibles_features = FEATURES_V4 + ['Label', 'Destination Port']
    
    for archivo in tqdm(archivos, desc=f"Procesando {origen_nombre}", unit="archivo", ncols=100):
        ruta = os.path.join(carpeta_path, archivo)
        print(f"    -> Leyendo: {archivo}")
        
        try:
            if archivo.endswith('.parquet'):
                # Los parquets se pueden cargar enteros porque son comprimidos y más pequeños
                chunk = pd.read_parquet(ruta)
                chunk_proc = procesar_chunk(chunk)
                if not chunk_proc.empty:
                    chunks_procesados.append(chunk_proc)
            else:
                # CSV
                header = pd.read_csv(ruta, nrows=0)
                # Seleccionar columnas que tras hacer strip() sean válidas
                cols_a_leer = [c for c in header.columns if c.strip() in posibles_features]
                
                for chunk in tqdm(pd.read_csv(ruta, usecols=cols_a_leer, chunksize=250000, low_memory=False),
                                  desc=f"    chunk {archivo}", unit="chunk", ncols=100, leave=False):
                    chunk_proc = procesar_chunk(chunk)
                    if not chunk_proc.empty:
                        chunks_procesados.append(chunk_proc)
                
        except Exception as e:
            print(f"      [ERROR] Falló procesamiento de {archivo}: {e}")
            
    if not chunks_procesados:
        return pd.DataFrame()
        
    df_consolidado = pd.concat(chunks_procesados, ignore_index=True)
    del chunks_procesados
    gc.collect()
    
    print(f"  Total {origen_nombre} procesado: {len(df_consolidado):,} registros.")
    return df_consolidado

def aplicar_downsampling(df):
    print("\n[*] Aplicando Downsampling Inteligente...")
    df_final_chunks = []
    
    clases = sorted(df['Label_UNIPAZ'].unique())
    
    for clase in tqdm(clases, desc="Balanceando clases", unit="clase", ncols=100):
        subset = df[df['Label_UNIPAZ'] == clase]
        limite = LIMITES_CLASE.get(clase)
        
        if limite is not None and len(subset) > limite:
            print(f"    - {clase}: Reduciendo de {len(subset):,} a {limite:,}")
            subset = subset.sample(n=limite, random_state=RANDOM_STATE)
        else:
            print(f"    - {clase}: Preservando {len(subset):,} registros (sin recorte)")
            
        df_final_chunks.append(subset)
        
    return pd.concat(df_final_chunks, ignore_index=True)

if __name__ == "__main__":
    print("======================================================")
    print(" GENERADOR DE DATASET GLOBAL (CIC 2017+2018+2019)")
    print("======================================================")
    
    df_2017 = procesar_carpeta(DIR_2017, "CIC-IDS2017")
    df_2018 = procesar_carpeta(DIR_2018, "CSE-CIC-IDS2018")
    df_2019 = procesar_carpeta(DIR_2019, "CIC-DDoS2019")
    
    print("\n[*] Fusionando datasets...")
    df_total = pd.concat([df_2017, df_2018, df_2019], ignore_index=True)
    
    del df_2017, df_2018, df_2019
    gc.collect()
    
    print(f"    Total bruto fusionado: {len(df_total):,} registros.")
    
    df_total.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_total = df_total.fillna(0)
    
    df_total = aplicar_downsampling(df_total)
    df_total = df_total.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)
    
    ruta_csv = os.path.join(OUTPUT_DIR, "dataset_global_unipaz_v5.csv")
    print(f"\n[*] Guardando dataset definitivo en: {ruta_csv}")
    df_total.to_csv(ruta_csv, index=False)
    
    print("\n======================================================")
    print(" RESUMEN FINAL DEL DATASET v5")
    print("======================================================")
    resumen = df_total['Label_UNIPAZ'].value_counts()
    print(resumen)
    sql = resumen.get('Inyeccion_SQL', 0)
    print(f"\n  [!] Inyeccion_SQL en v5: {sql:,} (objetivo >3000, recuperado del bug U+FFFD de 2017)")
    print("\n  [OK] Dataset global v5 generado exitosamente. Listo para CEREBRO_V5.")
