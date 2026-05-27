"""
limpiar_dataset.py — Pipeline completo de limpieza del CIC-IDS2017
Objetivo: producir un dataset limpio, balanceado y listo para entrenamiento
Para el IDS/IPS de la Universidad UNIPAZ
"""
import pandas as pd
import numpy as np
import os
import joblib
import warnings
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
from imblearn.over_sampling import SMOTE

warnings.filterwarnings("ignore")

# ============================================================
# CONFIGURACIÓN
# ============================================================
CIC_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "CIC-IDS2017")
OUTPUT_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Dataset_Limpio")
RANDOM_STATE = 42

# ============================================================
# MAPEO DE CLASES CIC-IDS2017 -> UNIPAZ (7 tipos de ataque)
# ============================================================
MAPEO_CLASES = {
    # --- NORMAL ---
    "BENIGN":                           "Normal",

    # --- SYN FLOOD (DoS variados) ---
    "DoS slowloris":                    "SYN_Flood",
    "DoS Slowhttptest":                 "SYN_Flood",
    "DoS Hulk":                         "SYN_Flood",
    "DoS GoldenEye":                    "SYN_Flood",

    # --- DDoS DISTRIBUIDO ---
    "DDoS":                             "DDoS_Distribuido",
    "DDoS HOIC":                        "DDoS_Distribuido",
    "DDoS LOIC-HTTP":                   "DDoS_Distribuido",
    "DDoS LOIC-UDP":                    "DDoS_Distribuido",
    "Bot":                              "DDoS_Distribuido",

    # --- PORT SCANNER ---
    "PortScan":                         "Port_Scanner",

    # --- POSIBLE EXPLOIT (fuerza bruta, infiltracion, exploits) ---
    "Brute Force":                      "Posible_Exploit",
    "FTP-Patator":                      "Posible_Exploit",
    "SSH-Patator":                      "Posible_Exploit",
    "Infiltration":                     "Posible_Exploit",
    "Heartbleed":                       "Posible_Exploit",

    # --- INYECCION SQL / WEB ATTACKS ---
    "Web Attack - SQL Injection":       "Inyeccion_SQL",
    "Web Attack - XSS":                 "Inyeccion_SQL",
    "Web Attack - Brute Force":         "Inyeccion_SQL",

    # --- UDP FLOOD (mapeado desde DoS genericos con patrones UDP) ---
    "DoS":                              "UDP_Flood",
}

# Variantes con caracteres especiales (em-dash, en-dash, etc.)
MAPEO_CLASES_ALT = {
    "Web Attack \u2013 Brute Force":    "Inyeccion_SQL",
    "Web Attack \u2013 XSS":            "Inyeccion_SQL",
    "Web Attack \u2013 Sql Injection":  "Inyeccion_SQL",
    "Web Attack \u2014 Brute Force":    "Inyeccion_SQL",
    "Web Attack \u2014 XSS":            "Inyeccion_SQL",
    "Web Attack \u2014 Sql Injection":  "Inyeccion_SQL",
    "Web Attack - Brute Force":         "Inyeccion_SQL",
    "Web Attack - XSS":                 "Inyeccion_SQL",
    "Web Attack - Sql Injection":       "Inyeccion_SQL",
}

# ============================================================
# PASO 1: CARGA Y CONSOLIDACIÓN
# ============================================================
print("=" * 70)
print("FASE 1: CARGA Y CONSOLIDACIÓN DEL CIC-IDS2017")
print("=" * 70)

archivos = [f for f in os.listdir(CIC_FOLDER) if f.endswith('.csv')]
print(f"Archivos encontrados: {len(archivos)}")

dfs = []
for archivo in sorted(archivos):
    ruta = os.path.join(CIC_FOLDER, archivo)
    print(f"  Cargando: {archivo}...", end=" ")
    try:
        df = pd.read_csv(ruta)
        # Strip leading/trailing spaces from column names
        df.columns = df.columns.str.strip()
        print(f"{len(df):,} registros, {len(df.columns)} columnas")
        dfs.append(df)
    except Exception as e:
        print(f"ERROR: {e}")

if not dfs:
    print("[X] No se pudieron cargar archivos. Verifica la ruta.")
    exit(1)

df_total = pd.concat(dfs, ignore_index=True)
print(f"\nTotal consolidado: {len(df_total):,} registros, {len(df_total.columns)} columnas")

# ============================================================
# PASO 2: MAPEO DE CLASES
# ============================================================
print("\n" + "=" * 70)
print("FASE 2: MAPEO DE CLASES CIC-IDS2017 -> UNIPAZ")
print("=" * 70)

print("\nDistribución ORIGINAL de etiquetas CIC-IDS2017:")
print(df_total['Label'].value_counts().to_string())

# Aplicar mapeo principal
df_total['Label_UNIPAZ'] = df_total['Label'].map(MAPEO_CLASES)

# Aplicar mapeo alternativo para caracteres especiales
mask_alt = df_total['Label_UNIPAZ'].isnull()
df_total.loc[mask_alt, 'Label_UNIPAZ'] = df_total.loc[mask_alt, 'Label'].map(MAPEO_CLASES_ALT)

# Contar registros no mapeados
no_mapeados = df_total['Label_UNIPAZ'].isnull().sum()
registros_antes = len(df_total)

if no_mapeados > 0:
    print(f"\n[!] {no_mapeados:,} registros con etiquetas no mapeadas:")
    print(df_total[df_total['Label_UNIPAZ'].isnull()]['Label'].value_counts().to_string())

# Eliminar registros no mapeados
df_total = df_total.dropna(subset=['Label_UNIPAZ'])
registros_despues = len(df_total)
print(f"\nRegistros después del mapeo: {registros_despues:,} "
      f"(se eliminaron {registros_antes - registros_despues:,} no mapeados)")

print("\nDistribución DESPUÉS del mapeo (clases UNIPAZ):")
print(df_total['Label_UNIPAZ'].value_counts().to_string())

# ============================================================
# PASO 3: ELIMINACIÓN DE COLUMNAS IRRELEVANTES
# ============================================================
print("\n" + "=" * 70)
print("FASE 3: ELIMINACIÓN DE COLUMNAS IRRELEVANTES")
print("=" * 70)

# Columnas que no son features útiles
columnas_eliminar = ['Label']  # La original ya no se necesita

# Identificar columnas con varianza cero (constantes)
for col in df_total.columns:
    if col not in ['Label', 'Label_UNIPAZ'] and df_total[col].nunique() <= 1:
        columnas_eliminar.append(col)
        print(f"  Eliminada (constante): {col}")

# Identificar columnas con todos los valores iguales o casi iguales
for col in df_total.columns:
    if col not in columnas_eliminar and col != 'Label_UNIPAZ':
        try:
            if df_total[col].dtype in ['float64', 'int64']:
                if df_total[col].std() == 0:
                    columnas_eliminar.append(col)
                    print(f"  Eliminada (std=0): {col}")
        except:
            pass

df_total = df_total.drop(columns=columnas_eliminar)
print(f"\nColumnas eliminadas: {len(columnas_eliminar)}")
print(f"Columnas restantes: {len(df_total.columns)} (incluyendo Label_UNIPAZ)")

# ============================================================
# PASO 4: MANEJO DE VALORES FALTANTES E INFINITOS
# ============================================================
print("\n" + "=" * 70)
print("FASE 4: MANEJO DE VALORES FALTANTES E INFINITOS")
print("=" * 70)

# Reemplazar infinitos por NaN
df_total.replace([np.inf, -np.inf], np.nan, inplace=True)

# Contar NaN por columna
# Columnas numericas
cols_numericas = df_total.select_dtypes(include=[np.number]).columns
if 'Label_UNIPAZ' in cols_numericas:
    cols_numericas = cols_numericas.drop('Label_UNIPAZ')
total_nan = df_total[cols_numericas].isnull().sum()
nan_cols = total_nan[total_nan > 0]

if len(nan_cols) > 0:
    print("\nColumnas con valores NaN:")
    for col, count in nan_cols.items():
        print(f"  {col}: {count:,} NaN ({count/len(df_total)*100:.1f}%)")

    # Imputar con mediana
    for col in cols_numericas:
        if df_total[col].isnull().sum() > 0:
            mediana = df_total[col].median()
            df_total[col].fillna(mediana, inplace=True)
            print(f"  Imputada '{col}': mediana={mediana:.4f}")
else:
    print("\nNo se encontraron valores NaN en columnas numéricas.")

# ============================================================
# PASO 5: ELIMINACIÓN DE OUTLIERS EXTREMOS (IQR × 3)
# ============================================================
print("\n" + "=" * 70)
print("FASE 5: ELIMINACIÓN DE OUTLIERS EXTREMOS (IQR × 3)")
print("=" * 70)

outliers_imputados = 0
for col in cols_numericas:
    Q1 = df_total[col].quantile(0.25)
    Q3 = df_total[col].quantile(0.75)
    IQR = Q3 - Q1
    if IQR > 0:
        lower_extreme = Q1 - 3 * IQR
        upper_extreme = Q3 + 3 * IQR
        outliers = ((df_total[col] < lower_extreme) | (df_total[col] > upper_extreme))
        n_outliers = outliers.sum()
        if n_outliers > 0:
            mediana = df_total[col].median()
            df_total.loc[outliers, col] = mediana
            outliers_imputados += n_outliers

print(f"Outliers extremos imputados con mediana: {outliers_imputados:,}")
print(f"Registros totales después de limpieza: {len(df_total):,}")

# ============================================================
# PASO 6: CODIFICACIÓN DE LABELS
# ============================================================
print("\n" + "=" * 70)
print("FASE 6: CODIFICACIÓN DE ETIQUETAS")
print("=" * 70)

label_encoder = LabelEncoder()
y = label_encoder.fit_transform(df_total['Label_UNIPAZ'])
X = df_total.drop('Label_UNIPAZ', axis=1)

print(f"Clases encontradas ({len(label_encoder.classes_)}):")
for i, clase in enumerate(label_encoder.classes_):
    count = (y == i).sum()
    print(f"  {i}: {clase} -> {count:,} ({count/len(y)*100:.1f}%)")

# ============================================================
# PASO 7: DIVISIÓN TRAIN/TEST (ESTRATIFICADA 80/20)
# ============================================================
print("\n" + "=" * 70)
print("FASE 7: DIVISIÓN TRAIN/TEST (80/20 ESTRATIFICADA)")
print("=" * 70)

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=RANDOM_STATE
)

print(f"  Train: {len(X_train):,} registros")
print(f"  Test:  {len(X_test):,} registros")

print("\n  Distribución Train:")
unique, counts = np.unique(y_train, return_counts=True)
for u, c in zip(unique, counts):
    print(f"    {label_encoder.inverse_transform([u])[0]}: {c:,} ({c/len(y_train)*100:.1f}%)")

print("\n  Distribución Test:")
unique, counts = np.unique(y_test, return_counts=True)
for u, c in zip(unique, counts):
    print(f"    {label_encoder.inverse_transform([u])[0]}: {c:,} ({c/len(y_test)*100:.1f}%)")

# ============================================================
# PASO 8: FEATURE SELECTION (SelectKBest con ANOVA F-test)
# ============================================================
print("\n" + "=" * 70)
print("FASE 8: SELECCIÓN DE FEATURES (SelectKBest, k=20)")
print("=" * 70)

# Primero escalar para que ANOVA sea justo
scaler_pre = StandardScaler()
X_train_scaled_temp = scaler_pre.fit_transform(X_train)

# Seleccionar top-20 features
K_FEATURES = 20
selector = SelectKBest(score_func=f_classif, k=K_FEATURES)
X_train_selected = selector.fit_transform(X_train_scaled_temp, y_train)

# Obtener nombres de features seleccionadas
feature_scores = pd.DataFrame({
    'feature': X.columns,
    'score': selector.scores_,
    'p_value': selector.pvalues_
}).sort_values('score', ascending=False)

selected_features = feature_scores.head(K_FEATURES)['feature'].tolist()

print(f"\nTop {K_FEATURES} features seleccionadas:")
for i, (_, row) in enumerate(feature_scores.head(K_FEATURES).iterrows(), 1):
    print(f"  {i:2d}. {row['feature']:<40s} score={row['score']:>12.1f}  p-value={row['p_value']:.2e}")

# ============================================================
# PASO 9: BALANCEO CON SMOTE (SOLO EN TRAINING)
# ============================================================
print("\n" + "=" * 70)
print("FASE 9: BALANCEO CON SMOTE (SOLO TRAINING)")
print("=" * 70)

print("\nDistribución ANTES de SMOTE (Train):")
unique, counts = np.unique(y_train, return_counts=True)
for u, c in zip(unique, counts):
    print(f"  {label_encoder.inverse_transform([u])[0]}: {c:,}")

# Aplicar SMOTE solo sobre training con las features seleccionadas
smote = SMOTE(random_state=RANDOM_STATE, k_neighbors=5)
X_train_resampled, y_train_resampled = smote.fit_resample(
    pd.DataFrame(X_train, columns=X.columns)[selected_features], y_train
)

print(f"\nDistribución DESPUÉS de SMOTE (Train):")
unique, counts = np.unique(y_train_resampled, return_counts=True)
for u, c in zip(unique, counts):
    print(f"  {label_encoder.inverse_transform([u])[0]}: {c:,}")
print(f"Total training después de SMOTE: {len(y_train_resampled):,}")

# ============================================================
# PASO 10: NORMALIZACIÓN FINAL
# ============================================================
print("\n" + "=" * 70)
print("FASE 10: NORMALIZACIÓN FINAL")
print("=" * 70)

scaler_final = StandardScaler()
X_train_final = scaler_final.fit_transform(X_train_resampled)
X_test_final = scaler_final.transform(
    pd.DataFrame(X_test, columns=X.columns)[selected_features]
)

print(f"  X_train_final: {X_train_final.shape}")
print(f"  X_test_final:  {X_test_final.shape}")

# ============================================================
# GUARDAR ARTIFACTOS Y DATASET LIMPIO
# ============================================================
print("\n" + "=" * 70)
print("GUARDANDO ARTEFACTOS Y DATASET LIMPIO")
print("=" * 70)

os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Guardar artefactos del modelo
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

# Guardar datasets procesados
np.save(os.path.join(OUTPUT_FOLDER, "X_train.npy"), X_train_final)
np.save(os.path.join(OUTPUT_FOLDER, "X_test.npy"), X_test_final)
np.save(os.path.join(OUTPUT_FOLDER, "y_train.npy"), y_train_resampled)
np.save(os.path.join(OUTPUT_FOLDER, "y_test.npy"), y_test)

print(f"\n  Guardado: X_train.npy ({X_train_final.shape})")
print(f"  Guardado: X_test.npy  ({X_test_final.shape})")
print(f"  Guardado: y_train.npy ({y_train_resampled.shape})")
print(f"  Guardado: y_test.npy  ({y_test.shape})")

# Guardar resumen de distribución
resumen = {
    'clases': label_encoder.classes_.tolist(),
    'distribucion_train_original': dict(zip(
        [label_encoder.inverse_transform([u])[0] for u in unique],
        [int(c) for c in counts]
    )),
    'distribucion_test': dict(zip(
        [label_encoder.inverse_transform([u])[0] for u in np.unique(y_test, return_counts=True)[0]],
        [int(c) for c in np.unique(y_test, return_counts=True)[1]]
    )),
    'total_registros': len(df_total),
    'total_train': len(X_train),
    'total_test': len(X_test),
    'total_train_smote': len(y_train_resampled),
    'n_features': K_FEATURES,
    'features_seleccionadas': selected_features,
}

import json
with open(os.path.join(OUTPUT_FOLDER, "resumen_limpieza.json"), 'w') as f:
    json.dump(resumen, f, indent=2, ensure_ascii=False)

print(f"\n  Guardado: resumen_limpieza.json")

# ============================================================
# RESUMEN FINAL
# ============================================================
print("\n" + "=" * 70)
print("RESUMEN FINAL DEL PIPELINE DE LIMPIEZA")
print("=" * 70)
print(f"  Registros originales CIC-IDS2017: {sum(len(d) for d in dfs):,}")
print(f"  Registros después de limpieza:    {len(df_total):,}")
print(f"  Train (antes SMOTE):              {len(X_train):,}")
print(f"  Train (después SMOTE):            {len(y_train_resampled):,}")
print(f"  Test:                             {len(X_test):,}")
print(f"  Features seleccionadas:           {K_FEATURES}")
print(f"  Clases:                           {len(label_encoder.classes_)}")
print(f"\n  Dataset listo para entrenamiento.")
print(f"  Ejecutar: python entrenar.py")
print("=" * 70)
