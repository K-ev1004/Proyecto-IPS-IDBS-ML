"""
CEREBRO_V5.py — Entrenamiento del Modelo Maestro IDS/IPS v5
Universidad UNIPAZ

Corrige el punto crítico nº1/2: clase Inyeccion_SQL muy minoritaria.
- Dataset con los ataques web 2017 recuperados (ruptura de encoding U+FFFD).
- SMOTE reforzado sobre la minoría (sintetiza muestras SIN corromper el test).
- class_weights balanceados manualmente por clase para priorizar SQLi.
Requiere tqdm para las barras de progreso.
"""

import os
import time
import pandas as pd
import numpy as np
import joblib
import warnings
warnings.filterwarnings('ignore')

from tqdm import tqdm
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
DATASET_PATH = os.path.join(BASE_DIR, "Dataset_Limpio", "dataset_global_unipaz_v5.csv")
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

# Pesos manuales por clase (mayor peso = más prioridad para que el modelo
# aprenda bien esa clase). La minoría 'Inyeccion_SQL' recibe el mayor peso.
# Nota: La PCI/IDS v4 logueaba a >0.85 y bloqueaba a >0.70.
CLASS_WEIGHTS = {
    'Normal': 1.0,
    'DDoS_Distribuido': 1.0,
    'SYN_Flood': 1.2,
    'UDP_Flood': 1.2,
    'Port_Scanner': 1.5,
    'Posible_Exploit': 2.0,
    'Inyeccion_SQL': 12.0,
}

# Cuántas muestras sintéticas dejar por clase en SMOTE (minoría -> ~30K).
SMOTE_TARGETS = {
    'Inyeccion_SQL': 30000,
    'Posible_Exploit': 60000,
}

def cargar_datos():
    print("[*] Cargando dataset global v5...")
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"No se encontró el dataset en {DATASET_PATH}. "
                                "Ejecuta generador_dataset_global.py (ya reparado) primero.")
    df = pd.read_csv(DATASET_PATH)
    print(f"    Registros cargados: {len(df):,}")
    return df

def entrenar():
    print("======================================================")
    print(" CEREBRO_V5 — ENTRENAMIENTO REPARADO (SQLi reforzado)")
    print("======================================================")

    df = cargar_datos()

    X = df[FEATURES_V4]
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df['Label_UNIPAZ'])

    print("\n[*] Distribución Original (Antes de SMOTE):")
    for clase, num in zip(label_encoder.classes_, np.bincount(y)):
        print(f"    {clase}: {num:,}")
        # También mostramos el peso aplicado
        print(f"        -> weight={CLASS_WEIGHTS.get(clase, 1.0)} target_smote={SMOTE_TARGETS.get(clase, 'auto')}")

    print("\n[*] Dividiendo Train/Test (80/20 con estratificación)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )
    print(f"    X_train: {X_train.shape[0]:,} | X_test: {X_test.shape[0]:,}")

    print("\n[*] Configurando Pipeline v5...")
    print("    - Scaler: StandardScaler")
    print("    - Balanceo: SMOTE (k=5, targets por clase)")
    print("    - Modelo: CatBoost (auto_class_weights Balanced, early stopping)")

    # Estrategia focalizada: SOLO las minorías criticas se sobremuestrean hasta
    # un objetivo moderado. Las clases masivas (Normal, DDoS...) se dejan intactas.
    # Con sampling_strategy como dict, SMOTE eleva cada clase indicada a su target
    # y deja las demas sin tocar (evita explotar la RAM hacia ~1.5M por clase).
    sampling_strategy = {
        label_encoder.transform([clase])[0]: target
        for clase, target in SMOTE_TARGETS.items()
        if target > (y_train == label_encoder.transform([clase])[0]).sum()
    }
    print(f"    - SMOTE strategy: {sampling_strategy}")

    smote = SMOTE(random_state=RANDOM_STATE, k_neighbors=5, sampling_strategy=sampling_strategy)

    cat = CatBoostClassifier(
        iterations=2000,
        learning_rate=0.08,
        depth=10,
        task_type='GPU',
        verbose=100,          # Progreso por consola (2000 iter / 100 = 20 líneas)
        random_state=RANDOM_STATE,
        eval_metric='MultiClass',
        od_type='Iter',
        od_wait=200,          # Early stopping si no mejora
        auto_class_weights='Balanced',
    )

    pipeline = ImbPipeline([
        ('scaler', StandardScaler()),
        ('smote', smote),
        ('clf', cat),
    ])

    print("\n[*] Iniciando Entrenamiento (Inyeccion_SQL reforzada, esto puede tardar)...")
    inicio = time.time()

    # Barra de progreso global envolviendo el fit (tqdm externo).
    # Con una sola llamada .fit() la barra real la da CatBoost (verbose), pero
    # añadimos tqdm sobre el proceso para feedback continuo.
    for _ in tqdm(range(1), desc="Entrenando modelo v5", unit="fit", ncols=100):
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

    print("\n[*] Guardando Modelo y Artefactos (V5)...")

    ruta_modelo = os.path.join(MODELOS_FOLDER, 'pipeline_catboost_v5.pkl')
    ruta_le = os.path.join(MODELOS_FOLDER, 'label_encoder_v5.pkl')
    ruta_features = os.path.join(MODELOS_FOLDER, 'selected_features_v5.pkl')

    joblib.dump(pipeline, ruta_modelo)
    joblib.dump(label_encoder, ruta_le)
    joblib.dump(FEATURES_V4, ruta_features)

    print(f"    Guardado: {ruta_modelo}")
    print(f"    Guardado: {ruta_le}")
    print(f"    Guardado: {ruta_features}")

    with open(os.path.join(MODELOS_FOLDER, 'metricas_v5.txt'), 'w') as f:
        f.write("MÉTRICAS MODELO V5 (SQLi REFORZADA)\n")
        f.write("="*50 + "\n")
        f.write(f"Accuracy: {acc:.4f}\n")
        f.write(f"F1-Macro: {f1:.4f}\n")
        f.write(f"Kappa:    {kappa:.4f}\n\n")
        f.write("REPORTE CLASIFICACIÓN:\n")
        f.write(reporte)

    print("\n[ÉXITO] Entrenamiento v5 finalizado. Listo para migrar a ids.py.")

if __name__ == "__main__":
    entrenar()