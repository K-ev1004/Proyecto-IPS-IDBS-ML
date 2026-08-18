# ADR-0002 · SQLiGuard: detector binario de Inyección SQL como 2.ª etapa

- **Estado:** Aceptado
- **Fecha:** 2026
- **Relacionado con:** `entrenar_sqli_guard.py`, `ids.py`

## Contexto

La clase `Inyeccion_SQL` era minoritaria (~0.07 % del dataset) y en v4 la precisión era de
solo **~1 %**, con muchos falsos positivos. Rebalancear la multiclase (v5) subió la precisión
a 7 % pero el **techo físico** del data disponible impedía más.

## Decisión

Construir un **detector binario dedicado** entrenado con dataset externo de SQLi reales
(Zenodo 6907252, NetFlow v5):

- **D1** (200 K SQLi Union, MySQL/SQLServer) → entrenamiento.
- **D2** (28 614 Blind SQLi, PostgreSQL, red distinta) → validación externa honesta.

En `ids.py`, si `P(SQLi) ≥ UMBRAL_SQLI_GUARD (0.30)` el tipo final es `Inyeccion_SQL`.
Resultados en D2: **precisión 99.85 % · recall 75 %** (FP solo 0.115 %).

## Consecuencias

- Aumenta sustancialmente la precisión de SQLi en producción (v4: 1 % → ~99.8 %).
- Añade dependencia de artefactos `sqli_guard.pkl` + `sql_guard_features.pkl`.
- Se puede ajustar recall/precisión bajando/subiendo `UMBRAL_SQLI_GUARD` (0.10 → recall 83 %).

## Referencias

- [Guía de entrenamiento](../guias/entrenamiento.md)
- [Arquitectura (README)](../../README.md)