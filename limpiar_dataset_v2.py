"""
limpiar_dataset_v2.py — Pipeline completo de limpieza CIC-IDS2017 + CIC-DDoS2019
Objetivo: producir un dataset limpio con las 7 clases UNIPAZ
Para el IDS/IPS de la Universidad UNIPAZ
"""
import pandas as pd
import numpy as np
import os
import joblib
import json
import warnings
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
from imblearn.over_sampling import SMOTE

warnings.filterwarnings("ignore")

# ============================================================
# CONFIGURACION
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CIC_FOLDER = os.path.join(BASE_DIR, "CIC-IDS2017")
DDOS_FOLDER = os.path.join(BASE_DIR, "CICDDoS2019")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "Dataset_Limpio")
RANDOM_STATE = 42

os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# ============================================================
# MAPEO DE CLASES CIC-IDS2017 -> UNIPAZ (7 clases)
# ============================================================
MAPEO_CIC = {
    "BENIGN":                           "Normal",
    "DoS slowloris":                    "SYN_Flood",
    "DoS Slowhttptest":                 "SYN_Flood",
    "DoS Hulk":                         "SYN_Flood",
    "DoS GoldenEye":                    "SYN_Flood",
    "DDoS":                             "DDoS_Distribuido",
    "DDoS HOIC":                        "DDoS_Distribuido",
    "DDoS LOIC-HTTP":                   "DDoS_Distribuido",
    "DDoS LOIC-UDP":                    "DDoS_Distribuido",
    "Bot":                              "DDoS_Distribuido",
    "PortScan":                         "Port_Scanner",
    "Brute Force":                      "Posible_Exploit",
    "FTP-Patator":                      "Posible_Exploit",
    "SSH-Patator":                      "Posible_Exploit",
    "Infiltration":                     "Posible_Exploit",
    "Heartbleed":                       "Posible_Exploit",
    "DoS":                              "UDP_Flood",
}

# Variantes con caracteres especiales (replacement character, em-dash, en-dash, etc.)
MAPEO_CIC_ALT = {
    # Replacement character (ord=65533) - lo que lee pandas cuando hay encoding roto
    "Web Attack \ufffd Brute Force":    "Inyeccion_SQL",
    "Web Attack \ufffd XSS":            "Inyeccion_SQL",
    "Web Attack \ufffd Sql Injection":  "Inyeccion_SQL",
    # Em-dash (ord=8212)
    "Web Attack \u2014 Brute Force":    "Inyeccion_SQL",
    "Web Attack \u2014 XSS":            "Inyeccion_SQL",
    "Web Attack \u2014 Sql Injection":  "Inyeccion_SQL",
    # En-dash (ord=8211)
    "Web Attack \u2013 Brute Force":    "Inyeccion_SQL",
    "Web Attack \u2013 XSS":            "Inyeccion_SQL",
    "Web Attack \u2013 Sql Injection":  "Inyeccion_SQL",
    # Guion normal
    "Web Attack - Brute Force":         "Inyeccion_SQL",
    "Web Attack - XSS":                 "Inyeccion_SQL",
    "Web Attack - Sql Injection":       "Inyeccion_SQL",
    "Web Attack - SQL Injection":       "Inyeccion_SQL",
}

# ============================================================
# MAPEO DE CLASES CIC-DDoS2019 -> UNIPAZ
# ============================================================
MAPEO_DDOS = {
    "Benign":                           "Normal",
    "UDP":                              "UDP_Flood",
    "DrDoS_UDP":                        "UDP_Flood",
    "UDPLag":                           "UDP_Flood",
    "UDP-lag":                          "UDP_Flood",
    "Syn":                              "SYN_Flood",
    "DrDoS_DNS":                        "DDoS_Distribuido",
    "DrDoS_LDAP":                       "DDoS_Distribuido",
    "DrDoS_MSSQL":                      "DDoS_Distribuido",
    "DrDoS_NTP":                        "DDoS_Distribuido",
    "DrDoS_NetBIOS":                    "DDoS_Distribuido",
    "DrDoS_SNMP":                       "DDoS_Distribuido",
    "TFTP":                             "DDoS_Distribuido",
    "WebDDoS":                          "DDoS_Distribuido",
    "LDAP":                             "Posible_Exploit",
    "MSSQL":                            "Posible_Exploit",
    "NetBIOS":                          "Posible_Exploit",
    "Portmap":                          "Port_Scanner",
}

# ============================================================
# FUNCION AUXILIAR: normalizar columnas
# ============================================================
def normalizar_columnas(df):
    """Elimina espacios en nombres de columnas y estandariza."""
    df.columns = df.columns.str.strip()
    return df

# ============================================================
# PASO 1: CARGA CIC-IDS2017
# ============================================================
print("=" * 70)
print("FASE 1: CARGA CIC-IDS2017")
print("=" * 70)

archivos_cic = [f for f in os.listdir(CIC_FOLDER) if f.endswith('.csv')]
dfs_cic = []
for archivo in sorted(archivos_cic):
    ruta = os.path.join(CIC_FOLDER, archivo)
    print(f"  Cargando: {archivo}...", end=" ")
    try:
        df = pd.read_csv(ruta)
        df = normalizar_columnas(df)
        print(f"{len(df):,} registros, {len(df.columns)} columnas")
        dfs_cic.append(df)
    except Exception as e:
        print(f"ERROR: {e}")

df_cic = pd.concat(dfs_cic, ignore_index=True)
print(f"  Total CIC-IDS2017: {len(df_cic):,} registros")

# ============================================================
# PASO 2: CARGA CIC-DDoS2019
# ============================================================
print("\n" + "=" * 70)
print("FASE 2: CARGA CIC-DDoS2019")
print("=" * 70)

archivos_ddos = [f for f in os.listdir(DDOS_FOLDER) if f.endswith('.parquet')]
dfs_ddos = []
for archivo in sorted(archivos_ddos):
    ruta = os.path.join(DDOS_FOLDER, archivo)
    print(f"  Cargando: {archivo}...", end=" ")
    try:
        df = pd.read_parquet(ruta)
        df = normalizar_columnas(df)
        print(f"{len(df):,} registros, {len(df.columns)} columnas")
        dfs_ddos.append(df)
    except Exception as e:
        print(f"ERROR: {e}")

df_ddos = pd.concat(dfs_ddos, ignore_index=True)
print(f"  Total CIC-DDoS2019: {len(df_ddos):,} registros")

# ============================================================
# PASO 3: UNIFICAR COLUMNAS
# ============================================================
print("\n" + "=" * 70)
print("FASE 3: UNIFICAR COLUMNAS ENTRE DATASETS")
print("=" * 70)

cols_cic = set(df_cic.columns)
cols_ddos = set(df_ddos.columns)

# Columnas comunes
cols_comunes = cols_cic.intersection(cols_ddos)
print(f"  Columnas CIC-IDS2017: {len(cols_cic)}")
print(f"  Columnas CIC-DDoS2019: {len(cols_ddos)}")
print(f"  Columnas comunes: {len(cols_comunes)}")

# Columnas solo en CIC-IDS2017
solo_cic = cols_cic - cols_ddos
print(f"  Solo en CIC-IDS2017: {len(solo_cic)}")

# Columnas solo en CIC-DDoS2019
solo_ddos = cols_ddos - cols_cic
print(f"  Solo en CIC-DDoS2019: {len(solo_ddos)}")

# Eliminar columna Label de ambos para unificar
df_cic_labels = df_cic['Label'].copy()
df_ddos_labels = df_ddos['Label'].copy()

# Mantener solo columnas comunes (excluyendo Label)
cols_comunes_sin_label = cols_comunes - {'Label'}
df_cic_features = df_cic[list(cols_comunes_sin_label)]
df_ddos_features = df_ddos[list(cols_comunes_sin_label)]

print(f"  Features comunes a usar: {len(cols_comunes_sin_label)}")

# ============================================================
# PASO 4: MAPEO DE CLASES
# ============================================================
print("\n" + "=" * 70)
print("FASE 4: MAPEO DE CLASES A 7 CATEGORIAS UNIPAZ")
print("=" * 70)

# CIC-IDS2017
df_cic_features['Label_UNIPAZ'] = df_cic_labels.map(MAPEO_CIC)
mask_alt = df_cic_features['Label_UNIPAZ'].isnull()
df_cic_features.loc[mask_alt, 'Label_UNIPAZ'] = df_cic_labels.loc[mask_alt].map(MAPEO_CIC_ALT)

no_mapeados_cic = df_cic_features['Label_UNIPAZ'].isnull().sum()
print(f"  CIC-IDS2017: {len(df_cic_features):,} registros, {no_mapeados_cic:,} no mapeados")
if no_mapeados_cic > 0:
    print(f"    Etiquetas no mapeadas: {df_cic_labels[df_cic_features['Label_UNIPAZ'].isnull()].value_counts().to_dict()}")

# CIC-DDoS2019
df_ddos_features['Label_UNIPAZ'] = df_ddos_labels.map(MAPEO_DDOS)
no_mapeados_ddos = df_ddos_features['Label_UNIPAZ'].isnull().sum()
print(f"  CIC-DDoS2019: {len(df_ddos_features):,} registros, {no_mapeados_ddos:,} no mapeados")
if no_mapeados_ddos > 0:
    print(f"    Etiquetas no mapeadas: {df_ddos_labels[df_ddos_features['Label_UNIPAZ'].isnull()].value_counts().to_dict()}")

# Eliminar registros no mapeados
df_cic_features = df_cic_features.dropna(subset=['Label_UNIPAZ'])
df_ddos_features = df_ddos_features.dropna(subset=['Label_UNIPAZ'])

# ============================================================
# PASO 5: COMBINAR DATASETS
# ============================================================
print("\n" + "=" * 70)
print("FASE 5: COMBINAR CIC-IDS2017 + CIC-DDoS2019")
print("=" * 70)

df_total = pd.concat([df_cic_features, df_ddos_features], ignore_index=True)
print(f"  Total combinado: {len(df_total):,} registros")

print("\n  Distribucion de clases:")
print(df_total['Label_UNIPAZ'].value_counts().to_string())

# ============================================================
# PASO 6: LIMPIEZA DE DATOS
# ============================================================
print("\n" + "=" * 70)
print("FASE 6: LIMPIEZA DE DATOS")
print("=" * 70)

# Reemplazar infinitos por NaN
df_total.replace([np.inf, -np.inf], np.nan, inplace=True)

# Columnas numericas
cols_numericas = df_total.select_dtypes(include=[np.number]).columns
if 'Label_UNIPAZ' in cols_numericas:
    cols_numericas = cols_numericas.drop('Label_UNIPAZ')

# Imputar NaN con mediana
nan_count = 0
for col in cols_numericas:
    nulos = df_total[col].isnull().sum()
    if nulos > 0:
        mediana = df_total[col].median()
        df_total[col].fillna(mediana, inplace=True)
        nan_count += nulos

print(f"  Valores NaN imputados: {nan_count:,}")

# Eliminar outliers extremos (IQR x 3)
outliers_imputados = 0
for col in cols_numericas:
    Q1 = df_total[col].quantile(0.25)
    Q3 = df_total[col].quantile(0.75)
    IQR = Q3 - Q1
    if IQR > 0:
        lower = Q1 - 3 * IQR
        upper = Q3 + 3 * IQR
        outliers = ((df_total[col] < lower) | (df_total[col] > upper))
        n_outliers = outliers.sum()
        if n_outliers > 0:
            mediana = df_total[col].median()
            df_total.loc[outliers, col] = mediana
            outliers_imputados += n_outliers

print(f"  Outliers extremos imputados: {outliers_imputados:,}")
print(f"  Registros finales: {len(df_total):,}")

# ============================================================
# PASO 7: CODIFICACION Y DIVISION
# ============================================================
print("\n" + "=" * 70)
print("FASE 7: CODIFICACION Y DIVISION TRAIN/TEST")
print("=" * 70)

label_encoder = LabelEncoder()
y = label_encoder.fit_transform(df_total['Label_UNIPAZ'])
X = df_total.drop('Label_UNIPAZ', axis=1)

print(f"  Clases ({len(label_encoder.classes_)}):")
for i, clase in enumerate(label_encoder.classes_):
    count = (y == i).sum()
    print(f"    {i}: {clase} -> {count:,} ({count/len(y)*100:.1f}%)")

# Split estratificado
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
)
print(f"  Train: {len(X_train):,} | Test: {len(X_test):,}")

# ============================================================
# PASO 8: FEATURE SELECTION (con subconjunto para evitar OOM)
# ============================================================
print("\n" + "=" * 70)
print("FASE 8: SELECCION DE FEATURES (k=20, subconjunto 500K)")
print("=" * 70)

# Usar subconjunto para feature selection
FS_SAMPLES = 500000
if len(X_train) > FS_SAMPLES:
    from sklearn.utils import resample
    X_fs, y_fs = resample(X_train, y_train, n_samples=FS_SAMPLES,
                           random_state=RANDOM_STATE, stratify=y_train)
    print(f"  Usando subconjunto de {FS_SAMPLES:,} para feature selection")
else:
    X_fs, y_fs = X_train, y_train

scaler_pre = StandardScaler()
X_fs_scaled = scaler_pre.fit_transform(X_fs)

K_FEATURES = 20
selector = SelectKBest(score_func=f_classif, k=K_FEATURES)
X_fs_selected = selector.fit_transform(X_fs_scaled, y_fs)

feature_scores = pd.DataFrame({
    'feature': X.columns,
    'score': selector.scores_
}).sort_values('score', ascending=False)

selected_features = feature_scores.head(K_FEATURES)['feature'].tolist()

print(f"  Top {K_FEATURES} features:")
for i, (_, row) in enumerate(feature_scores.head(K_FEATURES).iterrows(), 1):
    print(f"    {i:2d}. {row['feature']:<40s} score={row['score']:>12.1f}")

# ============================================================
# PASO 9: SMOTE REDUCIDO (Opcion A)
# ============================================================
print("\n" + "=" * 70)
print("FASE 9: SMOTE REDUCIDO (Opcion A)")
print("=" * 70)

print("\n  Distribucion ANTES de SMOTE (Train):")
unique, counts = np.unique(y_train, return_counts=True)
for u, c in zip(unique, counts):
    print(f"    {label_encoder.inverse_transform([u])[0]}: {c:,}")

# SMOTE con estrategia personalizada para evitar oversampling excesivo
# Limitar a maximo 200K por clase (en vez de igualar a 1.9M de Normal)
MAX_SAMPLES_PER_CLASS = 200000

# Calcular estrategia de sampling
from collections import Counter
class_counts = Counter(y_train)
sampling_strategy = {}
for clase, count in class_counts.items():
    if count < MAX_SAMPLES_PER_CLASS:
        sampling_strategy[clase] = min(count * 5, MAX_SAMPLES_PER_CLASS)
    else:
        sampling_strategy[clase] = count  # No oversamplear clases ya grandes

print(f"  Estrategia de SMOTE:")
for clase, target in sorted(sampling_strategy.items()):
    nombre = label_encoder.inverse_transform([clase])[0]
    actual = class_counts[clase]
    print(f"    {nombre}: {actual:,} -> {target:,}")

smote = SMOTE(random_state=RANDOM_STATE, k_neighbors=3, sampling_strategy=sampling_strategy)

# Aplicar SMOTE solo sobre training con features seleccionadas
X_train_smote = pd.DataFrame(X_train, columns=X.columns)[selected_features]
X_train_resampled, y_train_resampled = smote.fit_resample(X_train_smote, y_train)

print(f"\n  Distribucion DESPUES de SMOTE (Train):")
unique, counts = np.unique(y_train_resampled, return_counts=True)
for u, c in zip(unique, counts):
    print(f"    {label_encoder.inverse_transform([u])[0]}: {c:,}")
print(f"  Total training despues de SMOTE: {len(y_train_resampled):,}")

# ============================================================
# PASO 10: NORMALIZACION FINAL
# ============================================================
print("\n" + "=" * 70)
print("FASE 10: NORMALIZACION FINAL")
print("=" * 70)

scaler_final = StandardScaler()
X_train_final = scaler_final.fit_transform(X_train_resampled)
X_test_final = scaler_final.transform(
    pd.DataFrame(X_test, columns=X.columns)[selected_features]
)

print(f"  X_train_final: {X_train_final.shape}")
print(f"  X_test_final:  {X_test_final.shape}")

# ============================================================
# GUARDAR ARTEFACTOS
# ============================================================
print("\n" + "=" * 70)
print("GUARDANDO ARTEFACTOS")
print("=" * 70)

artefactos = {
    'scaler_final': scaler_final,
    'label_encoder': label_encoder,
    'selected_features': selected_features,
    'feature_selector': selector,
    'scaler_pre': scaler_pre,
    'smote': smote,
}

for nombre, objeto in artefactos.items():
    ruta = os.path.join(OUTPUT_FOLDER, f"{nombre}.pkl")
    joblib.dump(objeto, ruta)
    print(f"  Guardado: {ruta}")

np.save(os.path.join(OUTPUT_FOLDER, "X_train.npy"), X_train_final)
np.save(os.path.join(OUTPUT_FOLDER, "X_test.npy"), X_test_final)
np.save(os.path.join(OUTPUT_FOLDER, "y_train.npy"), y_train_resampled)
np.save(os.path.join(OUTPUT_FOLDER, "y_test.npy"), y_test)

print(f"\n  Guardado: X_train.npy ({X_train_final.shape})")
print(f"  Guardado: X_test.npy  ({X_test_final.shape})")
print(f"  Guardado: y_train.npy ({y_train_resampled.shape})")
print(f"  Guardado: y_test.npy  ({y_test.shape})")

# Resumen
resumen = {
    'clases': label_encoder.classes_.tolist(),
    'total_registros': len(df_total),
    'total_train': len(X_train),
    'total_test': len(X_test),
    'total_train_smote': len(y_train_resampled),
    'n_features': K_FEATURES,
    'features_seleccionadas': selected_features,
    'datasets_usados': ['CIC-IDS2017', 'CIC-DDoS2019'],
}

with open(os.path.join(OUTPUT_FOLDER, "resumen_limpieza.json"), 'w') as f:
    json.dump(resumen, f, indent=2, ensure_ascii=False)

print(f"\n  Guardado: resumen_limpieza.json")

# ============================================================
# RESUMEN FINAL
# ============================================================
print("\n" + "=" * 70)
print("RESUMEN FINAL")
print("=" * 70)
print(f"  Registros CIC-IDS2017:    {len(df_cic):,}")
print(f"  Registros CIC-DDoS2019:   {len(df_ddos):,}")
print(f"  Registros combinados:     {len(df_total):,}")
print(f"  Train (antes SMOTE):      {len(X_train):,}")
print(f"  Train (despues SMOTE):    {len(y_train_resampled):,}")
print(f"  Test:                     {len(X_test):,}")
print(f"  Features seleccionadas:   {K_FEATURES}")
print(f"  Clases:                   {len(label_encoder.classes_)}")
print(f"\n  Dataset listo para entrenamiento.")
print(f"  Ejecutar: python entrenar_rapido.py")
print("=" * 70)
