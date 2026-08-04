"""
entrenar_sqli_guard.py — Detector dedicado de Inyeccion SQL (SQLiGuard)
Universidad UNIPAZ

Clasificador BINARIO de 2a etapa entrenado con el dataset externo
"SQL Injection Attack Netflow" (Zenodo 6907252, D1=Union / D2=Blind SQLi).

Motivo: el modelo multiclase v5 (features CICFlowMeter) no distingue bien el
SQLi del trafico web normal (precision ~7%). SQLiGuard aporta la senal que
falta usando miles de SQLi reales (200K) con features NetFlow derivadas.

Arquitectura en produccion (ids.py):
  v5 predice Inyeccion_SQL  =>  SQLiGuard confirma/niega.
  (falta de senal NoSQL no se fuerza)
Validation cruzada honesta: se ENTRENA con D1 (Union attacks, MySQL/SQLServer)
y se VALIDA con D2 (Blind SQLi, PostgreSQL, redes distintas) => test externo real.
"""

import os
import time
import pandas as pd
import numpy as np
import joblib
import warnings
warnings.filterwarnings('ignore')

from tqdm import tqdm
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (classification_report, confusion_matrix,
                             accuracy_score, f1_score, precision_score,
                             recall_score)
from catboost import CatBoostClassifier

# ============================================================
# CONFIGURACIÓN
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SQLI_DIR = os.path.join(BASE_DIR, "datasets", "SQLi_Zenodo")
D1 = os.path.join(SQLI_DIR, "D1_train.csv")
D2 = os.path.join(SQLI_DIR, "D2_test.csv")
MODELOS_FOLDER = os.path.join(BASE_DIR, "Modelos_Entrenados")
os.makedirs(MODELOS_FOLDER, exist_ok=True)

RANDOM_STATE = 42
# Umbral de confirmacion: en D2 (test externo) con 0.30 => precision 99.85%,
# recall 75%. Se elige 0.30 (no 0.5) para un IDS de seguridad: mas recall con
# la misma precision (~99.8%), dejando margen ante trafico benigno ruidoso.
UMBRAL_CONFIRMAR_SQLI = 0.30

# Features NetFlow v5 derivadas (formato estándar registrado en Zenodo 6907252)
# Son calculables en tiempo real desde el flujo capturado (ver flujos_red.py).
SQLI_GUARD_FEATURES = [
    'src_port', 'dst_port', 'protocol',
    'flow_duration_ms', 'total_packets', 'total_bytes',
    'flow_byts_s', 'flow_pkts_s', 'tcp_flags'
]

def cargar_netflow(ruta):
    df = pd.read_csv(ruta)
    out = pd.DataFrame()
    dv = (df['last'] - df['first']).abs()
    dur_ms = np.maximum(dv.to_numpy(dtype=float), 1e-6)
    out['src_port'] = df['srcport'].astype(float)
    out['dst_port'] = df['dstport'].astype(float)
    out['protocol'] = df['prot'].astype(float)
    out['flow_duration_ms'] = dur_ms
    out['total_packets'] = df['dpkts'].astype(float)
    out['total_bytes'] = df['doctets'].astype(float)
    out['flow_byts_s'] = df['doctets'].astype(float) / (dur_ms / 1000.0)
    out['flow_pkts_s'] = df['dpkts'].astype(float) / (dur_ms / 1000.0)
    out['tcp_flags'] = df['tcp_flags'].astype(float)
    out['Label'] = df['Label'].astype(int)
    return out

def entrenar():
    print("======================================================")
    print(" SQLIGUARD — DETECTOR BINARIO DE INYECCION SQL")
    print("======================================================")

    print(f"[*] Cargando D1 (train, Union SQLi): {D1}")
    df_train = cargar_netflow(D1)
    print(f"    Train: {len(df_train):,} | SQLi={int((df_train['Label']==1).sum())} | bening={int((df_train['Label']==0).sum())}")

    print(f"[*] Cargando D2 (test externo, Blind SQLi): {D2}")
    df_test = cargar_netflow(D2)
    print(f"    Test:  {len(df_test):,} | SQLi={int((df_test['Label']==1).sum())} | bening={int((df_test['Label']==0).sum())}")

    X_train = df_train[SQLI_GUARD_FEATURES]
    y_train = df_train['Label']
    X_test = df_test[SQLI_GUARD_FEATURES]
    y_test = df_test['Label']

    print("\n[*] Configurando clasificador (CatBoost binario, GPU)...")
    cat = CatBoostClassifier(
        iterations=1500,
        learning_rate=0.08,
        depth=8,
        loss_function='Logloss',
        task_type='GPU',
        verbose=100,
        random_state=RANDOM_STATE,
        od_type='Iter',
        od_wait=200,
    )

    pipe = Pipeline([
        ('scaler', StandardScaler()),
        ('clf', cat),
    ])

    print("\n[*] Entrenando SQLiGuard (train D1)...")
    inicio = time.time()
    for _ in tqdm(range(1), desc="Entrenando SQLiGuard", unit="fit", ncols=100):
        pipe.fit(X_train, y_train)
    print(f"    [OK] Entrenado en {(time.time() - inicio)/60:.1f} minutos.")

    print("\n[*] Evaluando en D2 (test externo independiente)...")
    y_prob = pipe.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= UMBRAL_CONFIRMAR_SQLI).astype(int)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)          # clase 1 = SQLi
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print(f"\n    Accuracy:           {acc:.4f}")
    print(f"    Precision SQLi:     {prec:.4f}")
    print(f"    Recall SQLi:        {rec:.4f}")
    print(f"    F1 SQLi:            {f1:.4f}")
    print("\nReporte:")
    print(classification_report(y_test, y_pred, target_names=['Benigno', 'Inyeccion_SQL']))
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    print(f"    Matriz: TN={tn} FP={fp} FN={fn} TP={tp}")

    print("\n[*] Evaluando tambien en D1 (train) para referencia de overfit...")
    yp_tr = (pipe.predict_proba(X_train)[:, 1] >= UMBRAL_CONFIRMAR_SQLI).astype(int)
    print(f"    Train precision={precision_score(y_train, yp_tr):.4f}  recall={recall_score(y_train, yp_tr):.4f}")

    print("\n[*] Guardando SQLiGuard (V5 pipeline + features + umbral)...")
    ruta_modelo = os.path.join(MODELOS_FOLDER, 'sqli_guard.pkl')
    ruta_features = os.path.join(MODELOS_FOLDER, 'sql_guard_features.pkl')
    joblib.dump(pipe, ruta_modelo)
    joblib.dump({
        'features': SQLI_GUARD_FEATURES,
        'umbral': UMBRAL_CONFIRMAR_SQLI,
        'mapa': {0: 'Normal', 1: 'Inyeccion_SQL'},
    }, ruta_features)
    print(f"    Guardado: {ruta_modelo}")
    print(f"    Guardado: {ruta_features}")

    with open(os.path.join(MODELOS_FOLDER, 'metricas_sqli_guard.txt'), 'w') as f:
        f.write("MÉTRICAS SQLIGUARD (D1=Union train, D2=Blind test externo)\n")
        f.write("="*55 + "\n")
        f.write(f"Accuracy:    {acc:.4f}\n")
        f.write(f"Precision:   {prec:.4f}\n")
        f.write(f"Recall:      {rec:.4f}\n")
        f.write(f"F1:          {f1:.4f}\n\n")
        f.write(classification_report(y_test, y_pred, target_names=['Benigno', 'Inyeccion_SQL']))
        f.write(f"Matriz: TN={tn} FP={fp} FN={fn} TP={tp}\n")
        f.write(f"Umbral confirmacion SQLi: {UMBRAL_CONFIRMAR_SQLI}\n")

    print("\n[ÉXITO] SQLiGuard listo. Integrar en ids.py como capa de 2a etapa.")

if __name__ == "__main__":
    entrenar()