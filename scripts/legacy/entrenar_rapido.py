"""
entrenar_rapido.py — Entrenamiento optimizado del modelo ensamble IDS v2
Usa subconjunto de 500K registros para entrenamiento rapido
Para el IDS/IPS de la Universidad UNIPAZ
"""
import pandas as pd
import numpy as np
import os
import joblib
import json
import warnings
import time
import shutil
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    f1_score, cohen_kappa_score, accuracy_score,
    precision_score, recall_score
)
from sklearn.utils import resample
from xgboost import XGBClassifier
from catboost import CatBoostClassifier

warnings.filterwarnings("ignore")

# ============================================================
# CONFIGURACION
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_FOLDER = os.path.join(BASE_DIR, "Dataset_Limpio")
MODELOS_FOLDER = os.path.join(BASE_DIR, "Modelos_Entrenados")
RANDOM_STATE = 42

os.makedirs(MODELOS_FOLDER, exist_ok=True)

# ============================================================
# CARGAR DATOS PROCESADOS
# ============================================================
print("=" * 70)
print("CARGANDO DATOS PROCESADOS")
print("=" * 70)

X_train = np.load(os.path.join(DATASET_FOLDER, "X_train.npy"))
X_test = np.load(os.path.join(DATASET_FOLDER, "X_test.npy"))
y_train = np.load(os.path.join(DATASET_FOLDER, "y_train.npy"))
y_test = np.load(os.path.join(DATASET_FOLDER, "y_test.npy"))

label_encoder = joblib.load(os.path.join(DATASET_FOLDER, "label_encoder.pkl"))
selected_features = joblib.load(os.path.join(DATASET_FOLDER, "selected_features.pkl"))

print(f"  X_train completo: {X_train.shape}")
print(f"  X_test:  {X_test.shape}")
print(f"  Clases: {label_encoder.classes_}")
print(f"  Features: {len(selected_features)}")

# ============================================================
# SUBCONJUNTO PARA ENTRENAMIENTO (500K)
# ============================================================
TRAIN_SAMPLES = 800000
if len(X_train) > TRAIN_SAMPLES:
    print(f"\n  Reduciendo a {TRAIN_SAMPLES:,} registros para entrenamiento...")
    X_train, y_train = resample(X_train, y_train, n_samples=TRAIN_SAMPLES,
                                 random_state=RANDOM_STATE, stratify=y_train)
    print(f"  X_train reducido: {X_train.shape}")

# ============================================================
# VALIDACION CRUZADA RAPIDA (3-FOLD, 100K)
# ============================================================
print("\n" + "=" * 70)
print("VALIDACION CRUZADA RAPIDA (3-FOLD, 100K)")
print("=" * 70)

CV_SAMPLES = 100000
X_cv, y_cv = resample(X_train, y_train, n_samples=CV_SAMPLES,
                       random_state=RANDOM_STATE, stratify=y_train)

skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=RANDOM_STATE)

modelos_cv = [
    ("RandomForest", RandomForestClassifier(n_estimators=100, max_depth=15,
                                             class_weight='balanced_subsample',
                                             random_state=RANDOM_STATE, n_jobs=-1)),
    ("XGBoost", XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1,
                               eval_metric='mlogloss', use_label_encoder=False,
                               random_state=RANDOM_STATE, n_jobs=-1)),
    ("CatBoost", CatBoostClassifier(iterations=100, depth=6, learning_rate=0.1,
                                     verbose=0, random_state=RANDOM_STATE,
                                     task_type='CPU')),
]

for nombre, modelo in modelos_cv:
    print(f"\n  Evaluando {nombre}...")
    inicio = time.time()
    scores = cross_val_score(modelo, X_cv, y_cv, cv=skf, scoring='f1_macro', n_jobs=1)
    tiempo = time.time() - inicio
    print(f"    F1-macro: {scores.mean():.4f} +/- {scores.std():.4f}")
    print(f"    Tiempo: {tiempo:.1f}s")

# ============================================================
# ENTRENAMIENTO FINAL
# ============================================================
print("\n" + "=" * 70)
print("ENTRENANDO MODELOS FINALES")
print("=" * 70)

# 1. Random Forest
print("\n[1/3] Entrenando Random Forest...")
inicio = time.time()
rf = RandomForestClassifier(n_estimators=200, max_depth=20,
                             min_samples_split=5, min_samples_leaf=2,
                             class_weight='balanced_subsample',
                             random_state=RANDOM_STATE, n_jobs=-1)
rf.fit(X_train, y_train)
print(f"  Completado en {time.time()-inicio:.1f}s")

# 2. XGBoost
print("\n[2/3] Entrenando XGBoost...")
inicio = time.time()
xgb = XGBClassifier(n_estimators=200, max_depth=8, learning_rate=0.1,
                     subsample=0.8, colsample_bytree=0.8,
                     eval_metric='mlogloss', use_label_encoder=False,
                     random_state=RANDOM_STATE, n_jobs=-1)
xgb.fit(X_train, y_train)
print(f"  Completado en {time.time()-inicio:.1f}s")

# 3. CatBoost
print("\n[3/3] Entrenando CatBoost...")
inicio = time.time()
cat = CatBoostClassifier(iterations=200, depth=8, learning_rate=0.1,
                          verbose=0, random_state=RANDOM_STATE,
                          task_type='CPU')
cat.fit(X_train, y_train)
print(f"  Completado en {time.time()-inicio:.1f}s")

# ============================================================
# ENSAMBLE
# ============================================================
print("\n" + "=" * 70)
print("CREANDO ENSAMBLE")
print("=" * 70)

ensemble = VotingClassifier(
    estimators=[('rf', rf), ('xgb', xgb), ('cat', cat)],
    voting='soft',
    weights=[1, 2, 1.5],
    n_jobs=-1
)

# El VotingClassifier necesita fit() para funcionar correctamente
# Pero como ya tenemos los modelos entrenados, usamos un enfoque manual
# para combinar las predicciones (soft voting)
print("  Evaluando ensamble (soft voting manual)...")

def ensamble_predict(X, models, weights):
    """Soft voting manual con modelos ya entrenados."""
    probs = np.zeros((X.shape[0], len(label_encoder.classes_)))
    for modelo, w in zip(models, weights):
        probs += modelo.predict_proba(X) * w
    probs /= sum(weights)
    return np.argmax(probs, axis=1)

modelos = [rf, xgb, cat]
pesos = [1, 2, 1.5]
y_pred_ensamble = ensamble_predict(X_test, modelos, pesos)

acc_ens = accuracy_score(y_test, y_pred_ensamble)
f1_ens = f1_score(y_test, y_pred_ensamble, average='macro')
kappa_ens = cohen_kappa_score(y_test, y_pred_ensamble, weights='quadratic')
print(f"  Accuracy: {acc_ens:.4f}")
print(f"  F1-macro: {f1_ens:.4f}")
print(f"  Kappa:    {kappa_ens:.4f}")

# Usar y_pred_ensamble para el reporte final
y_pred = y_pred_ensamble

# ============================================================
# EVALUACION
# ============================================================
print("\n" + "=" * 70)
print("EVALUACION EN TEST SET")
print("=" * 70)

for nombre, modelo in [("RF", rf), ("XGB", xgb), ("CatBoost", cat)]:
    print(f"\n--- {nombre} ---")
    y_pred = modelo.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='macro')
    kappa = cohen_kappa_score(y_test, y_pred, weights='quadratic')
    print(f"  Accuracy: {acc:.4f}")
    print(f"  F1-macro: {f1:.4f}")
    print(f"  Kappa:    {kappa:.4f}")

# Evaluacion del ensamble (ya calculada arriba)
print(f"\n--- Ensamble (soft voting) ---")
print(f"  Accuracy: {acc_ens:.4f}")
print(f"  F1-macro: {f1_ens:.4f}")
print(f"  Kappa:    {kappa_ens:.4f}")
print("\n" + "=" * 70)
print("REPORTE DE CLASIFICACION (ENSAMBLE)")
print("=" * 70)
print(classification_report(y_test, y_pred,
                             target_names=label_encoder.classes_,
                             zero_division=0))

# Matriz de confusion del ensamble
cm = confusion_matrix(y_test, y_pred)
print("\nMATRIZ DE CONFUSION:")
print("  Predicho ->")
header = "Real | " + "  ".join([f"{c:>10s}" for c in label_encoder.classes_])
print(f"  {header}")
for i, row in enumerate(cm):
    nombre = label_encoder.classes_[i]
    fila = "  ".join([f"{v:>10d}" for v in row])
    print(f"  {nombre:<10s} {fila}")

# ============================================================
# GUARDAR
# ============================================================
print("\n" + "=" * 70)
print("GUARDANDO MODELO")
print("=" * 70)

# Guardar modelos individuales (el ensamble se reconstruye con estos)
for nombre, modelo in [("rf_individual.pkl", rf), ("xgb_individual.pkl", xgb), ("cat_individual.pkl", cat)]:
    ruta = os.path.join(MODELOS_FOLDER, nombre)
    joblib.dump(modelo, ruta)
    print(f"  Guardado: {nombre}")

# Guardar configuracion del ensamble
ensamble_config = {
    'modelos': ['rf_individual.pkl', 'xgb_individual.pkl', 'cat_individual.pkl'],
    'weights': [1, 2, 1.5],
    'voting': 'soft'
}
with open(os.path.join(MODELOS_FOLDER, 'ensamble_config.json'), 'w') as f:
    json.dump(ensamble_config, f, indent=2)
print(f"  Guardado: ensamble_config.json")

for artefacto in ['label_encoder.pkl', 'selected_features.pkl', 'scaler_final.pkl']:
    src = os.path.join(DATASET_FOLDER, artefacto)
    dst = os.path.join(MODELOS_FOLDER, artefacto)
    if os.path.exists(src):
        shutil.copy2(src, dst)
        print(f"  Copiado: {artefacto}")

metricas = {
    'accuracy': float(acc_ens),
    'f1_macro': float(f1_ens),
    'precision_macro': float(precision_score(y_test, y_pred, average='macro')),
    'recall_macro': float(recall_score(y_test, y_pred, average='macro')),
    'kappa': float(kappa_ens),
    'individual': {
        'RF': {'accuracy': float(accuracy_score(y_test, rf.predict(X_test))),
               'f1_macro': float(f1_score(y_test, rf.predict(X_test), average='macro'))},
        'XGB': {'accuracy': float(accuracy_score(y_test, xgb.predict(X_test))),
                'f1_macro': float(f1_score(y_test, xgb.predict(X_test), average='macro'))},
        'CatBoost': {'accuracy': float(accuracy_score(y_test, cat.predict(X_test))),
                     'f1_macro': float(f1_score(y_test, cat.predict(X_test), average='macro'))},
    },
    'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
    'clases': label_encoder.classes_.tolist(),
    'features_seleccionadas': selected_features,
    'n_train': len(X_train),
    'n_test': len(X_test),
}

ruta_metricas = os.path.join(MODELOS_FOLDER, "metricas_modelo_v2.json")
with open(ruta_metricas, 'w') as f:
    json.dump(metricas, f, indent=2, ensure_ascii=False)
print(f"  Metricas guardadas: {ruta_metricas}")

print("\n" + "=" * 70)
print("ENTRENAMIENTO COMPLETADO")
print("=" * 70)
print(f"  Accuracy: {metricas['accuracy']:.4f}")
print(f"  F1-macro: {metricas['f1_macro']:.4f}")
print(f"  Kappa:    {metricas['kappa']:.4f}")
print(f"  Train: {len(X_train):,} | Test: {len(X_test):,}")
print("=" * 70)
