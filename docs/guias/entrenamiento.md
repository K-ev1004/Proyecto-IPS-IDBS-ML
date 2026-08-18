# Guía de entrenamiento

Cómo regenerar el dataset y entrenar los modelos actuales (v5 + SQLiGuard).

> Artefactos actuales en `Modelos_Entrenados/`: `pipeline_catboost_v5.pkl`,
> `label_encoder_v5.pkl`, `selected_features_v5.pkl`, `sqli_guard.pkl`,
> `sql_guard_features.pkl`, `metricas_v5.txt`, `metricas_sqli_guard.txt`.

## 1. Datasets necesarios

| Dataset | Ubicación esperada | Origen |
|---|---|---|
| CIC-IDS2017 | `datasets/CIC-IDS2017/` | CIC (descargar manualmente) |
| CSE-CIC-IDS2018 | `datasets/CSE-CIC-IDS2018/` | CIC (descargar manualmente) |
| CIC-DDoS2019 | `datasets/CIC-DDoS2019/` | CIC (descargar manualmente) |
| SQLi Zenodo | `datasets/SQLi_Zenodo/D1_train.csv`, `D2_test.csv` | Zenodo 6907252 |

> [!CAUTION]
> `datasets/` está en `.gitignore` por tamaño. Debes descargar los datasets por separado.

## 2. Pipeline de datos (reproducir v5)

```powershell
python generador_dataset_global.py
```

Genera `Dataset_Limpio/dataset_global_unipaz_v5.csv` (~3.74 M filas), normalizando los labels
corruptos (U+FFFD) y consolidando 7 clases UNIPAZ. (Ver ADR-0001.)

## 3. Entrenar el modelo multiclase v5

```powershell
python CEREBRO_V5.py
```

- Modelo: `ImbPipeline` CatBoost (GPU, `auto_class_weights='Balanced'`, SMOTE focalizado en SQLi).
- Salidas: `pipeline_catboost_v5.pkl`, `label_encoder_v5.pkl`, `selected_features_v5.pkl`,
  `metricas_v5.txt`.
- Referencia: acc **0.8641** · F1-macro **0.7442** · Kappa **0.8138**.

## 4. Entrenar SQLiGuard

```powershell
python entrenar_sqli_guard.py
```

- Entrena CatBoost binario con **D1** (200 K SQLi Union) y valida con **D2**
  (28 614 Blind SQLi) → test externo independiente.
- Salidas: `sqli_guard.pkl`, `sql_guard_features.pkl` (incluye features + umbral 0.30),
  `metricas_sqli_guard.txt`.
- Referencia en D2: **precisión 99.85 % · recall 75 %**.

## 5. Probar el resultado end-to-end

```powershell
python test_masivo.py
```

Genera `informe_test_masivo.json` con: precisión/recall de v5 sobre flujos sintéticos,
rendimiento de SQLiGuard sobre D2 y cadena completa de decisión + trazabilidad SQLite
(usa una BD temporal; no toca `intrusiones.db` real).

## 6. Ajuste fino de sensibilidad

- **SQLiGuard:** bajar `UMBRAL_SQLI_GUARD` (p. ej. a 0.10) en `ids.py` o desde la GUI
  → mayor recall de SQLi (83 %) manteniendo precisión ~99.8 %.
- **Multiclase:** subir/bajar `ids.UMBRAL_ML` para balancear falsos positivos vs detección.
