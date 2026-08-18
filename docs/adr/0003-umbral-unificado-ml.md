# ADR-0003 · Umbral unificado de confianza ML para logueo y bloqueo

- **Estado:** Aceptado
- **Fecha:** 2026
- **Relacionado con:** `ids.py`, `interfasc.py`

## Contexto

En versiones anteriores el sistema logueaba clasificaciones ML con confianza `≥ 0.85` pero
bloqueaba con `≥ 0.70`, generando **bloqueos sin registro ML** y decisiones inconsistentes.

## Decisión

Unificar ambos criterios bajo **`UMBRAL_ML = 0.85`** (`ids.py`): un flujo ML se registra Y
puede bloquerse únicamente si `confianza_ml ≥ UMBRAL_ML`. Los umbrales
(`UMBRAL_ML`, `UMBRAL_SQLI_GUARD`) son ajustables **en vivo desde la GUI**
(sección "Umbrales del Motor ML") y se persisten en QSettings.

## Consecuencias

- Consistencia entre registro y acción.
- El operador puede calibrar sensibilidad sin tocar código.
- Los valores por defecto se documentan en `README.md` y la guía de uso.

## Referencias

- [Guía de uso](../guias/uso.md)