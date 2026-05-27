"""
entrenar.py v2 — Entrenamiento del modelo ensamble IDS v2
Optimizado para memoria con 9M+ registros
Para el IDS/IPS de la Universidad UNIPAZ
"""
import pandas as pd
import numpy as np
import os
import joblib
import json
import warnings
import time
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    f1_score, cohen_kappa_score, accuracy_score,
    precision_score, recall_score
)
from xgboost import XGBClassifier
from catboost import CatBoostClassifier
from sklearn.utils import resample

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

print(f"  X_train: {X_train.shape}")
print(f"  X_test:  {X_test.shape}")
print(f"  Clases: {label_encoder.classes_}")
print(f"  Features: {len(selected_features)}")

# ============================================================
# VALIDACION CRUZADA con subconjunto (100K para evitar OOM)
# ============================================================
print("\n" + "=" * 70)
print("VALIDACION CRUZADA ESTRATIFICADA (5-FOLD, subconjunto 100K)")
print("=" * 70)

CV_SAMPLES = 100000
X_cv, y_cv = resample(X_train, y_train, n_samples=CV_SAMPLES,
                       random_state=RANDOM_STATE, stratify=y_train)
print(f"  Subconjunto CV: {X_cv.shape}")

# Modelos ligeros para CV
rf_cv = RandomForestClassifier(n_estimators=100, max_depth=15,
                                class_weight='balanced_subsample',
                                random_state=RANDOM_STATE, n_jobs=-1)

xgb_cv = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1,
                        eval_metric='mlogloss', use_label_encoder=False,
                        random_state=RANDOM_STATE, n_jobs=-1)

cat_cv = CatBoostClassifier(iterations=100, depth=6, learning_rate=0.1,
                             verbose=0, random_state=RANDOM_STATE,
                             task_type='CPU')

skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)

for nombre, modelo in [("RF", rf_cv), ("XGB", xgb_cv), ("CatBoost", cat_cv)]:
    print(f"\n  Evaluando {nombre}...")
    inicio = time.time()
    scores = cross_val_score(modelo, X_cv, y_cv, cv=skf, scoring='f1_macro', n_jobs=1)
    tiempo = time.time() - inicio
    print(f"    F1-macro: {scores.mean():.4f} +/- {scores.std():.4f}")
    print(f"    Tiempo: {tiempo:.1f}s")

# ============================================================
# ENTRENAMIENTO FINAL con dataset completo
# ============================================================
print("\n" + "=" * 70)
print("ENTRENANDO MODELOS FINALES CON DATASET COMPLETO")
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

# 3. CatBoost con GPU
print("\n[3/3] Entrenando CatBoost (GPU)...")
inicio = time.time()
cat = CatBoostClassifier(iterations=200, depth=8, learning_rate=0.1,
                          verbose=1, random_state=RANDOM_STATE,
                          task_type='GPU', devices='0')
cat.fit(X_train, y_train)
print(f"  Completado en {time.time()-inicio:.1f}s")

# ============================================================
# ENSAMBLE
# ============================================================
print("\n" + "=" * 70)
print("CREANDO ENSAMBLE CON VOTING SOFT")
print("=" * 70)

ensemble = VotingClassifier(
    estimators=[('rf', rf), ('xgb', xgb), ('cat', cat)],
    voting='soft',
    weights=[1, 2, 1.5],
    n_jobs=-1
)

print("  Ensamble creado con pesos: RF=1, XGB=2, CatBoost=1.5")

# ============================================================
# EVALUACION EN TEST SET
# ============================================================
print("\n" + "=" * 70)
print("EVALUACION EN TEST SET (datos no vistos)")
print("=" * 70)

# Evaluar cada modelo individual
for nombre, modelo in [("RF", rf), ("XGB", xgb), ("CatBoost", cat), ("Ensamble", ensemble)]:
    print(f"\n--- {nombre} ---")
    y_pred = modelo.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='macro')
    kappa = cohen_kappa_score(y_test, y_pred, weights='quadratic')
    print(f"  Accuracy: {acc:.4f}")
    print(f"  F1-macro: {f1:.4f}")
    print(f"  Kappa:    {kappa:.4f}")

# Evaluacion detallada del ensamble
y_pred = ensemble.predict(X_test)
print("\n" + "=" * 70)
print("REPORTE DE CLASIFICACION (ENSAMBLE)")
print("=" * 70)
print(classification_report(y_test, y_pred,
                             target_names=label_encoder.classes_,
                             zero_division=0))

# Matriz de confusion
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
# GUARDAR MODELO Y ARTEFACTOS
# ============================================================
print("\n" + "=" * 70)
print("GUARDANDO MODELO Y ARTEFACTOS")
print("=" * 70)

# Guardar modelo ensamble
ruta_modelo = os.path.join(MODELOS_FOLDER, "modelo_ensamble_v2.pkl")
joblib.dump(ensemble, ruta_modelo)
print(f"  Modelo guardado: {ruta_modelo}")

# Guardar modelos individuales tambien
for nombre, modelo in [("rf_individual.pkl", rf), ("xgb_individual.pkl", xgb), ("cat_individual.pkl", cat)]:
    ruta = os.path.join(MODELOS_FOLDER, nombre)
    joblib.dump(modelo, ruta)
    print(f"  Modelo individual guardado: {nombre}")

# Copiar artefactos necesarios
import shutil
for artefacto in ['label_encoder.pkl', 'selected_features.pkl', 'scaler_final.pkl']:
    src = os.path.join(DATASET_FOLDER, artefacto)
    dst = os.path.join(MODELOS_FOLDER, artefacto)
    if os.path.exists(src):
        shutil.copy2(src, dst)
        print(f"  Copiado: {artefacto}")

# Guardar metricas
metricas = {
    'accuracy': float(accuracy_score(y_test, y_pred)),
    'f1_macro': float(f1_score(y_test, y_pred, average='macro')),
    'precision_macro': float(precision_score(y_test, y_pred, average='macro')),
    'recall_macro': float(recall_score(y_test, y_pred, average='macro')),
    'kappa': float(cohen_kappa_score(y_test, y_pred, weights='quadratic')),
    'confusion_matrix': cm.tolist(),
    'clases': label_encoder.classes_.tolist(),
    'features_seleccionadas': selected_features,
    'n_train': len(X_train),
    'n_test': len(X_test),
}

ruta_metricas = os.path.join(MODELOS_FOLDER, "metricas_modelo_v2.json")
with open(ruta_metricas, 'w') as f:
    json.dump(metricas, f, indent=2, ensure_ascii=False)
print(f"  Metricas guardadas: {ruta_metricas}")

# ============================================================
# RESUMEN FINAL
# ============================================================
print("\n" + "=" * 70)
print("RESUMEN FINAL DEL ENTRENAMIENTO")
print("=" * 70)
print(f"  Modelo: VotingClassifier(RF + XGB + CatBoost)")
print(f"  Accuracy:     {metricas['accuracy']:.4f}")
print(f"  F1-macro:     {metricas['f1_macro']:.4f}")
print(f"  Kappa:        {metricas['kappa']:.4f}")
print(f"  Train samples: {len(X_train):,}")
print(f"  Test samples:  {len(X_test):,}")
print(f"\n  Modelo listo para despliegue.")
print(f"  Archivos en: {MODELOS_FOLDER}")
print("=" * 70)
