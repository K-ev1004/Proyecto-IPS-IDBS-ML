"""
CEREBRO_V4.py — Entrenamiento del Modelo Maestro IDS/IPS
Universidad UNIPAZ

Usa el dataset consolidado generado por `generador_dataset_global.py`.
Implementa Balanceo con SMOTE para SQL Injection y Entrenamiento con CatBoost.
"""

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
DATASET_PATH = os.path.join(BASE_DIR, "Dataset_Limpio", "dataset_global_unipaz_v4.csv")
MODELOS_FOLDER = os.path.join(BASE_DIR, "Modelos_Entrenados")
os.makedirs(MODELOS_FOLDER, exist_ok=True)

RANDOM_STATE = 42

FEATURES_V4 = [
    'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min',
    'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
    'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 
    'ACK Flag Cnt', 'URG Flag Cnt'
]

def cargar_datos():
    print("[*] Cargando dataset global...")
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"No se encontró el dataset en {DATASET_PATH}. Ejecuta generador_dataset_global.py primero.")
        
    df = pd.read_csv(DATASET_PATH)
    print(f"    Registros cargados: {len(df):,}")
    return df

def entrenar():
    print("======================================================")
    print(" CEREBRO_V4 — ENTRENAMIENTO MULTI-DATASET (CIC)")
    print("======================================================")

    df = cargar_datos()

    X = df[FEATURES_V4]
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df['Label_UNIPAZ'])

    print(f"\n[*] Distribución Original (Antes de SMOTE):")
    for clase, num in zip(label_encoder.classes_, np.bincount(y)):
        print(f"    {clase}: {num:,}")

    print("\n[*] Dividiendo Train/Test (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )
    print(f"    X_train: {X_train.shape[0]:,} | X_test: {X_test.shape[0]:,}")

    print("\n[*] Configurando Pipeline...")
    print("    - Scaler: StandardScaler")
    print("    - Balanceo: SMOTE (k=3)")
    print("    - Modelo: CatBoost (GPU)")
    
    smote = SMOTE(random_state=RANDOM_STATE, k_neighbors=3)
    
    cat = CatBoostClassifier(
        iterations=1000,
        learning_rate=0.08,
        depth=8,
        task_type='GPU',
        verbose=100,
        random_state=RANDOM_STATE,
        eval_metric='MultiClass'
    )

    pipeline = ImbPipeline([
        ('scaler', StandardScaler()),
        ('smote', smote),
        ('clf', cat)
    ])

    print("\n[*] Iniciando Entrenamiento (esto puede tardar unos minutos)...")
    inicio = time.time()
    pipeline.fit(X_train, y_train)
    print(f"    [OK] Entrenamiento completado en {(time.time() - inicio)/60:.1f} minutos.")

    print("\n[*] Evaluando Modelo en datos no vistos (Test Set)...")
    y_pred = pipeline.predict(X_test)
    
    if len(y_pred.shape) > 1 and y_pred.shape[1] == 1:
        y_pred = y_pred.ravel()

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='macro')
    kappa = cohen_kappa_score(y_test, y_pred)

    print(f"\n    Accuracy General: {acc:.4f}")
    print(f"    F1-Macro (Balance): {f1:.4f}")
    print(f"    Kappa Cohen:        {kappa:.4f}")
    
    print("\nReporte Detallado de Clasificación:")
    reporte = classification_report(y_test, y_pred, target_names=label_encoder.classes_)
    print(reporte)

    print("\n[*] Guardando Modelo y Artefactos (V4)...")
    
    ruta_modelo = os.path.join(MODELOS_FOLDER, 'pipeline_catboost_v4.pkl')
    ruta_le = os.path.join(MODELOS_FOLDER, 'label_encoder_v4.pkl')
    ruta_features = os.path.join(MODELOS_FOLDER, 'selected_features_v4.pkl')
    
    joblib.dump(pipeline, ruta_modelo)
    joblib.dump(label_encoder, ruta_le)
    joblib.dump(FEATURES_V4, ruta_features)
    
    print(f"    Guardado: {ruta_modelo}")
    print(f"    Guardado: {ruta_le}")
    print(f"    Guardado: {ruta_features}")
    
    with open(os.path.join(MODELOS_FOLDER, 'metricas_v4.txt'), 'w') as f:
        f.write("MÉTRICAS MODELO V4 (MULTI-DATASET CON SMOTE)\n")
        f.write("="*50 + "\n")
        f.write(f"Accuracy: {acc:.4f}\n")
        f.write(f"F1-Macro: {f1:.4f}\n")
        f.write(f"Kappa:    {kappa:.4f}\n\n")
        f.write("REPORTE CLASIFICACIÓN:\n")
        f.write(reporte)

    print("\n[ÉXITO] Todo el proceso v4 finalizado. Listo para integrarse a ids.py.")

if __name__ == "__main__":
    entrenar()
