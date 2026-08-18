# ADR-0001 · Pipeline de datos unificado y reparación del bug U+FFFD

- **Estado:** Aceptado
- **Fecha:** 2026
- **Relacionado con:** `generador_dataset_global.py`, `CEREBRO_V5.py`

## Contexto

Los labels del dataset CIC-IDS2017 aparecían corruptos con el carácter de reemplazo **U+FFFD**
(`'Web Attack \ufffd Sql Injection'`). El mapeo de clases fallaba y se perdían ~2 180 ataques
web (1 507 Brute Force, 652 XSS, 21 SQLi). Además, el entrenamiento se hacía sobre datasets
separados con features incompatibles entre versiones.

## Decisión

1. **Normalizar etiquetas** con `_normalizar_label()` (reemplaza U+FFFD y guiones por `-`)
   antes de aplicar `MAPEO_CLASES`.
2. **Pipeline unificado** sobre CIC-IDS2017 + CSE-CIC-IDS2018 + CIC-DDoS2019 → salida
   `dataset_global_unipaz_v5.csv` (~3.74 M filas).
3. `Inyeccion_SQL` pasa de **928 → 3 108** muestras; barras `tqdm` en todo el procesamiento.

## Consecuencias

- Más datos de ataques web para la clase `Inyeccion_SQL`.
- El pipeline es reproducible ejecutando `python generador_dataset_global.py`.

## Referencias

- [Guía de entrenamiento](../guias/entrenamiento.md)
- [`docs/ml/viabilidad-datasets.md`](../ml/viabilidad-datasets.md) (contexto previo)