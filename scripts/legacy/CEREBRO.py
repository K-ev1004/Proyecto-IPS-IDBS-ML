# CEREBRO.PY v3 — Módulo principal de entrenamiento y predicción del modelo IDS
# Universidad UNIPAZ
# =============================================================================
# CAMBIOS PRINCIPALES vs v2:
# - Dataset real: CSE-CIC-IDS2018
# - Features limitadas estrictamente a las extraíbles en tiempo real por flujos_red.py
# - Modelo: CatBoost (Optimizado para GPU) + RandomForest (Opcional en ensamble)
# =============================================================================

import os
import time
import pandas as pd
import numpy as np
import joblib
import warnings
warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score, f1_score, cohen_kappa_score
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
from catboost import CatBoostClassifier

# ============================================================
# CONFIGURACIÓN
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CIC_FOLDER = os.path.join(BASE_DIR, "CSE-CIC-IDS2018")
MODELOS_FOLDER = os.path.join(BASE_DIR, "Modelos_Entrenados")
RANDOM_STATE = 42

os.makedirs(MODELOS_FOLDER, exist_ok=True)

# ============================================================
# MAPEO DE CLASES CSE-CIC-IDS2018 -> UNIPAZ
# ============================================================
MAPEO_CLASES = {
    'Benign':                   'Normal',
    'DoS attacks-Slowloris':    'SYN_Flood',
    'DoS attacks-SlowHTTPTest': 'SYN_Flood',
    'DoS attacks-Hulk':         'SYN_Flood',
    'DoS attacks-GoldenEye':    'SYN_Flood',
    'DDOS attack-HOIC':         'DDoS_Distribuido',
    'DDoS attacks-LOIC-HTTP':   'DDoS_Distribuido',
    'DDOS attack-LOIC-UDP':     'UDP_Flood',
    'Bot':                      'DDoS_Distribuido',
    'FTP-BruteForce':           'Posible_Exploit',
    'SSH-Bruteforce':           'Posible_Exploit',
    'Infilteration':            'Posible_Exploit',
    'Brute Force -Web':         'Posible_Exploit',
    'Brute Force -XSS':         'Posible_Exploit',
    'SQL Injection':            'Inyeccion_SQL'
}

# Estas son las variables exactas que extrae flujos_red.py
# DEBEN existir en el CSV del dataset.
FEATURES_ESPERADAS = [
    'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min',
    'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
    'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 
    'ACK Flag Cnt', 'URG Flag Cnt'
]

def cargar_y_consolidar():
    print("[*] Cargando archivos CSE-CIC-IDS2018 (con muestreo inteligente para no saturar la RAM)...")
    archivos = [f for f in os.listdir(CIC_FOLDER) if f.endswith('.csv')]
    dfs = []
    
    # Pre-configurar tipos de datos para ahorrar RAM
    dtypes_dict = {f: np.float32 for f in FEATURES_ESPERADAS}
    
    for archivo in sorted(archivos):
        ruta = os.path.join(CIC_FOLDER, archivo)
        print(f"    Leyendo: {archivo}...", end=" ")
        try:
            chunks = []
            # Leer en chunks de 200k filas para no agotar la RAM (y evitar numpy.ArrayMemoryError)
            cols_to_load = FEATURES_ESPERADAS + ['Label']
            for chunk in pd.read_csv(ruta, usecols=cols_to_load, chunksize=200000, low_memory=False):
                # Limpieza rápida en el chunk
                chunk = chunk[chunk['Label'] != 'Label']
                
                # Muestreo: Quedarnos con el 100% de los ataques, pero solo con el 10% del tráfico "Benign"
                # Esto soluciona problemas de desbalanceo y reduce la RAM requerida de 16M a ~2M filas.
                ataques = chunk[chunk['Label'] != 'Benign']
                benignos = chunk[chunk['Label'] == 'Benign']
                
                if len(benignos) > 0:
                    benignos = benignos.sample(frac=0.10, random_state=RANDOM_STATE)
                    
                chunks.append(pd.concat([ataques, benignos]))
                
            df_file = pd.concat(chunks, ignore_index=True)
            print(f"{len(df_file):,} registros retenidos")
            dfs.append(df_file)
        except Exception as e:
            print(f"ERROR: {e} - Posiblemente faltan columnas en este archivo.")
            
    if not dfs:
        raise FileNotFoundError("No se pudieron cargar archivos del dataset 2018")
        
    df_total = pd.concat(dfs, ignore_index=True)
    print(f"    Total consolidado (balanceado): {len(df_total):,} registros.")
    return df_total

def mapear_y_limpiar(df_total):
    print("[*] Mapeando clases y limpiando datos...")
    
    # 1. Eliminar filas donde Label sea 'Label' (sucede cuando concatenan CSVs mal)
    df_total = df_total[df_total['Label'] != 'Label']
    
    # 2. Mapeo
    df_total['Label_UNIPAZ'] = df_total['Label'].map(MAPEO_CLASES)
    df_total = df_total.dropna(subset=['Label_UNIPAZ'])
    
    # 3. Limpiar Numéricos
    for col in FEATURES_ESPERADAS:
        if col in df_total.columns:
            # Convertir a numérico por si algo llegó como texto
            df_total[col] = pd.to_numeric(df_total[col], errors='coerce')
            
    df_total.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_total = df_total.dropna() # Drop any row with NaNs left
    
    print(f"    Registros listos: {len(df_total):,}")
    return df_total

def entrenar():
    print("=" * 70)
    print("CEREBRO.PY v3 — Entrenamiento de IDS/IPS con Flow Tracking")
    print("=" * 70)

    # 1. Cargar Datos
    df = cargar_y_consolidar()
    df = mapear_y_limpiar(df)

    # 2. Preparar X, y
    X = df[FEATURES_ESPERADAS]
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df['Label_UNIPAZ'])

    print(f"\n[*] Distribución de Clases:")
    for clase, num in zip(label_encoder.classes_, np.bincount(y)):
        print(f"    {clase}: {num:,}")

    # 3. Split
    print("\n[*] Dividiendo en Train/Test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )

    # Opcional: Submuestreo para agilizar pruebas (descomentar si la RAM se satura)
    # _, X_train, _, y_train = train_test_split(X_train, y_train, test_size=0.1, stratify=y_train)

    # 4. Pipeline: StandardScaler -> SMOTE -> CatBoost
    print("[*] Configurando Pipeline (Scaler + SMOTE + CatBoost)...")
    
    # Se recomienda quitar GPU si no tienes CUDA instalado correctamente, 
    # pero el usuario indicó tener RTX 4070 SUPER.
    cat = CatBoostClassifier(
        iterations=500,
        learning_rate=0.1,
        depth=8,
        task_type='GPU', 
        verbose=100,
        random_state=RANDOM_STATE
    )

    # Si SMOTE tarda mucho por la cantidad de datos, se puede omitir o reducir.
    # Usaremos pipeline normal.
    pipeline = ImbPipeline([
        ('scaler', StandardScaler()),
        # ('smote', SMOTE(random_state=RANDOM_STATE, k_neighbors=3)), # Descomentar si hay extremo desbalance
        ('clf', cat)
    ])

    print("[*] Entrenando Modelo...")
    inicio = time.time()
    pipeline.fit(X_train, y_train)
    print(f"    Entrenamiento completado en {time.time() - inicio:.1f} segundos.")

    # 5. Evaluación
    print("[*] Evaluando Modelo...")
    y_pred = pipeline.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='macro')
    kappa = cohen_kappa_score(y_test, y_pred)

    print(f"    Accuracy: {acc:.4f}")
    print(f"    F1-Macro: {f1:.4f}")
    print(f"    Kappa:    {kappa:.4f}")
    print("\nReporte Detallado:")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

    # 6. Guardar
    print("[*] Guardando Artefactos...")
    joblib.dump(pipeline, os.path.join(MODELOS_FOLDER, 'pipeline_catboost_v3.pkl'))
    joblib.dump(label_encoder, os.path.join(MODELOS_FOLDER, 'label_encoder_v3.pkl'))
    joblib.dump(FEATURES_ESPERADAS, os.path.join(MODELOS_FOLDER, 'selected_features_v3.pkl'))
    print("[OK] Modelo V3 guardado exitosamente.")

def predecir(features_dict):
    """
    Función para que ids.py realice la predicción de un flujo en vivo.
    """
    try:
        pipeline = joblib.load(os.path.join(MODELOS_FOLDER, 'pipeline_catboost_v3.pkl'))
        label_encoder = joblib.load(os.path.join(MODELOS_FOLDER, 'label_encoder_v3.pkl'))
        selected_features = joblib.load(os.path.join(MODELOS_FOLDER, 'selected_features_v3.pkl'))
        
        # Validar y ordenar features
        row = [features_dict.get(f, 0) for f in selected_features]
        df_in = pd.DataFrame([row], columns=selected_features)
        
        # Predecir
        pred_idx = pipeline.predict(df_in)[0]
        # CatBoost devuelve array 2D para predict(), extraemos
        if isinstance(pred_idx, (list, np.ndarray)):
            pred_idx = pred_idx[0]
            
        probs = pipeline.predict_proba(df_in)[0]
        confianza = float(np.max(probs))
        
        clase = label_encoder.inverse_transform([pred_idx])[0]
        return clase, confianza
    except Exception as e:
        print(f"[X] Error en predecir (ML V3): {e}")
        return "Desconocido", 0.0

if __name__ == "__main__":
    entrenar()
