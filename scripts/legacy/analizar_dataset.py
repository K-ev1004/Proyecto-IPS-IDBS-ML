"""
analizar_dataset.py — Análisis de viabilidad de los datasets disponibles
"""
import pandas as pd
import numpy as np
import os

BASE = os.path.dirname(os.path.abspath(__file__))
CIC2018 = os.path.join(BASE, "CSE-CIC-IDS2018")

files = sorted([f for f in os.listdir(CIC2018) if f.endswith('.csv')])

total_rows = 0
total_size_mb = 0
label_global = {}
issues = []

print("=" * 70)
print("ANÁLISIS DE VIABILIDAD DEL DATASET CSE-CIC-IDS2018")
print("=" * 70)

for fname in files:
    ruta = os.path.join(CIC2018, fname)
    size_mb = os.path.getsize(ruta) / (1024 * 1024)
    total_size_mb += size_mb

    print(f"\n[{fname}] ({size_mb:.0f} MB)")
    try:
        # Leer solo las primeras 500K filas para análisis rápido
        df = pd.read_csv(ruta, nrows=200000, low_memory=False)
        df.columns = df.columns.str.strip()

        rows_sample = len(df)
        cols = len(df.columns)

        # Verificar columna Label
        has_label = 'Label' in df.columns
        if not has_label:
            issues.append(f"  [!] {fname}: Sin columna 'Label'")
            print(f"  ERROR: Sin columna Label")
            continue

        # Limpiar filas donde Label == 'Label' (header duplicado)
        df = df[df['Label'] != 'Label']

        # Distribución de clases (muestra)
        label_counts = df['Label'].value_counts()
        print(f"  Columnas: {cols} | Filas leídas (muestra): {rows_sample:,}")
        print(f"  Distribución de clases:")
        for label, count in label_counts.items():
            pct = count / len(df) * 100
            print(f"    {label:<35s}: {count:>8,} ({pct:.1f}%)")
            label_global[label] = label_global.get(label, 0) + count

        # Verificar features necesarias para el modelo
        FEATURES_V3 = [
            'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
            'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min',
            'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
            'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s',
            'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt',
            'ACK Flag Cnt', 'URG Flag Cnt'
        ]

        # Normalizar nombres de columnas para comparar
        cols_norm = [c.strip() for c in df.columns]
        missing_feat = [f for f in FEATURES_V3 if f not in cols_norm]
        present_feat = [f for f in FEATURES_V3 if f in cols_norm]

        print(f"  Features del modelo v3 presentes: {len(present_feat)}/23")
        if missing_feat:
            print(f"  Features FALTANTES: {missing_feat}")
            issues.append(f"  [!] {fname}: Faltan features: {missing_feat}")

        # Verificar NaN / inf en features presentes
        numeric_cols = [f for f in present_feat if f in df.columns]
        if numeric_cols:
            df_num = df[numeric_cols].apply(pd.to_numeric, errors='coerce')
            nan_count = df_num.isnull().sum().sum()
            inf_count = np.isinf(df_num.values).sum()
            print(f"  NaN total (muestra): {nan_count:,} | Inf: {inf_count:,}")
            if nan_count > 0 or inf_count > 0:
                issues.append(f"  [!] {fname}: {nan_count} NaN, {inf_count} Inf en features")

        total_rows += rows_sample

    except Exception as e:
        print(f"  ERROR al leer: {e}")
        issues.append(f"  [ERROR] {fname}: {e}")

# ================================================================
print("\n" + "=" * 70)
print("RESUMEN GLOBAL DEL DATASET")
print("=" * 70)
print(f"  Archivos analizados  : {len(files)}")
print(f"  Tamaño total en disco: {total_size_mb:.0f} MB ({total_size_mb/1024:.1f} GB)")
print(f"  Filas muestreadas    : {total_rows:,}")
print(f"\n  Distribución global de clases (muestra):")
for label, count in sorted(label_global.items(), key=lambda x: -x[1]):
    print(f"    {label:<35s}: {count:>8,}")

if issues:
    print(f"\n  PROBLEMAS DETECTADOS:")
    for i in issues:
        print(i)
else:
    print(f"\n  No se detectaron problemas críticos.")

print("\n" + "=" * 70)
print("VEREDICTO DE VIABILIDAD")
print("=" * 70)
