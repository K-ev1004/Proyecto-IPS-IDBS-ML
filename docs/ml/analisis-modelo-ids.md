# 🛡️ Análisis Técnico del Sistema IDS/IPS con ML — UNIPAZ

> [!WARNING] Documento histórico (v2/v3)
> Este análisis corresponde al **estado del sistema hasta junio de 2026 (modelos v2/v3)**.
> El modelo en producción actual es **CatBoost v5 + SQLiGuard** (v. infra).
> Ver métricas actuales en [`../guias/entrenamiento.md`](../guias/entrenamiento.md) y decisiones en [`../adr/`](../adr/).

> **Fecha del análisis:** 2 de junio de 2026  
> **Herramientas usadas:** Skills de Machine Learning, Scikit-learn, Senior Data Scientist, Pandas Pro

---

## 1. Arquitectura General del Sistema

El sistema implementa un **IDS/IPS híbrido de dos capas** sobre Python:

```
Tráfico de Red (Scapy)
        │
        ▼
┌─────────────────────┐     ┌──────────────────────┐
│  Capa 1: Heurística │     │  Capa 2: ML Flow-Based│
│  (Detección rápida) │     │  (FlowTracker + Model) │
│  - SYN Flood        │     │  - Flujos bidir.       │
│  - UDP Flood        │     │  - Timeout: 5s          │
│  - Port Scan        │     │  - CatBoost v3          │
│  - SQL Injection    │     │  - Confianza ≥ 70%     │
│  - Exploit (ports)  │     │                        │
└─────────────────────┘     └──────────────────────┘
        │                           │
        └──────────┬────────────────┘
                   ▼
          SQLite + Telegram + IPS (MikroTik)
```

**Modelo activo en producción:** `pipeline_catboost_v3.pkl` (CatBoost solo, ~7.2 MB)  
**Modelo de referencia/evaluación:** Ensamble RF + XGB + CatBoost (`metricas_modelo_v2.json`)

---

## 2. Dataset — Calidad y Preprocesamiento

### 2.1 Fuentes de Datos

| Dataset | Descripción |
|--------|-------------|
| **CIC-IDS2017** | Canadian Institute for Cybersecurity — 8 días de tráfico real |
| **CSE-CIC-IDS2018** | Versión ampliada 2018 con más tipos de ataque |

> [!IMPORTANT]
> Se usaron **dos datasets distintos** en diferentes versiones del pipeline:  
> - `limpiar_dataset.py` usa **CIC-IDS2017** → genera el ensamble v2  
> - `CEREBRO.py` usa **CSE-CIC-IDS2018** → genera el pipeline v3 (el que está en producción)
>
> Esto crea **una inconsistencia de features** entre el modelo evaluado y el modelo en producción.

### 2.2 Volumen de Datos

| Etapa | Registros |
|-------|-----------|
| Raw (CIC-IDS2017) | ~3.26 millones |
| Después de limpieza | 3,262,114 |
| Train set (80%) | 2,609,691 |
| Después de SMOTE | 2,888,631 |
| Test set (20%) | 652,423 |
| Train reducido (entrenamiento rápido) | 800,000 |

### 2.3 Mapeo de Clases

El dataset original CIC-IDS2017 tiene ~15 tipos de ataque, que se consolidan en **7 clases UNIPAZ**:

| Clase UNIPAZ | Ataques Mapeados |
|-------------|-----------------|
| `Normal` | BENIGN |
| `SYN_Flood` | DoS slowloris, Slowhttptest, Hulk, GoldenEye |
| `DDoS_Distribuido` | DDoS, HOIC, LOIC-HTTP, Bot |
| `Port_Scanner` | PortScan |
| `Posible_Exploit` | Brute Force, FTP-Patator, SSH-Patator, Infiltration, Heartbleed |
| `Inyeccion_SQL` | Web Attack SQL/XSS/BruteForce |
| `UDP_Flood` | DoS genérico |

> [!NOTE]
> El mapeo de `DoS` genérico como `UDP_Flood` y de XSS/BruteForce web como `Inyeccion_SQL` es una **simplificación funcional** adecuada para el contexto universitario, aunque puede reducir la granularidad de detección.

### 2.4 Pipeline de Preprocesamiento (10 Fases)

| Fase | Técnica | Evaluación |
|------|---------|-----------|
| Carga y consolidación | Concatenación CSV | ✅ Correcto |
| Mapeo de clases | Diccionario + variantes especiales | ✅ Robusto |
| Eliminación de columnas | Varianza cero / std=0 | ✅ Buena práctica |
| Manejo de NaN/inf | Imputación con mediana | ✅ Correcto |
| Outliers | IQR × 3 → mediana | ⚠️ Conservador pero válido |
| Label encoding | LabelEncoder sklearn | ✅ Correcto |
| Train/Test split | 80/20 estratificado | ✅ Correcto |
| Feature selection | SelectKBest (ANOVA F, k=20) | ⚠️ Ver nota abajo |
| Balanceo | SMOTE (solo en train) | ✅ Excelente práctica |
| Normalización | StandardScaler (fit solo en train) | ✅ Sin data leakage |

> [!WARNING]
> **Feature Selection con ANOVA F:** Se aplicó `SelectKBest(f_classif)` **después** de escalar con `StandardScaler`, lo cual es correcto. Sin embargo, ANOVA asume distribuciones normales — los features de red rara vez las siguen. Una alternativa más robusta sería `mutual_info_classif` o selección por importancia de árbol.

### 2.5 Features Seleccionadas (Top 20 por ANOVA F)

```
Idle Mean, Idle Max, Idle Min, Packet Length Mean, Bwd Header Length,
Flow Packets/s, PSH Flag Count, Bwd Packet Length Min, Fwd Header Length,
Fwd Packets/s, Down/Up Ratio, Fwd Packet Length Max, Avg Bwd Segment Size,
Bwd Packet Length Mean, ACK Flag Count, Flow IAT Min, Fwd Packet Length Min,
FIN Flag Count, Bwd Packet Length Max, Subflow Bwd Packets
```

> [!CAUTION]
> **Desconexión crítica:** Las features seleccionadas por ANOVA incluyen `Idle Mean/Max/Min`, `Subflow Bwd Packets`, `Down/Up Ratio` — características que **NO son calculadas por `flujos_red.py`** en tiempo real.  
> El `FlowTracker` solo extrae: `Fwd/Bwd Pkt Len`, `Flow Pkts/s`, `Flag Counts`, `Flow Duration`, etc.  
> Esto significa que **el modelo v2 (ensamble) no puede ejecutarse en producción** — por eso se creó el v3 con features compatibles.

---

## 3. Entrenamiento — Evaluación Técnica

### 3.1 Arquitectura del Ensamble v2

```python
VotingClassifier(
    estimators=[
        ('rf',  RandomForestClassifier(n_estimators=200, max_depth=20)),  # peso: 1
        ('xgb', XGBClassifier(n_estimators=200, max_depth=8, lr=0.1)),    # peso: 2
        ('cat', CatBoostClassifier(iterations=200, depth=8, lr=0.1)),     # peso: 1.5
    ],
    voting='soft',  # Combina probabilidades
    weights=[1, 2, 1.5]
)
```

| Parámetro | Evaluación |
|-----------|-----------|
| Soft voting | ✅ Mejor que hard voting para clasificación probabilística |
| Pesos [1, 2, 1.5] | ⚠️ Empíricos, no optimizados — XGB tiene doble peso sin evidencia cruzada |
| n_estimators=200 | ✅ Suficiente para este tamaño de dataset |
| max_depth=20 (RF) | ⚠️ Puede generar overfitting en RF — muy profundo |
| Validación cruzada | ✅ 3-fold (rápido) sobre 100K muestras estratificadas |

### 3.2 Modelo v3 en Producción (CEREBRO.py)

```python
ImbPipeline([
    ('scaler', StandardScaler()),
    # SMOTE comentado — solo CatBoost
    ('clf', CatBoostClassifier(iterations=500, depth=8, lr=0.1, task_type='GPU'))
])
```

> [!NOTE]
> El modelo v3 fue entrenado sobre CSE-CIC-IDS2018 con solo un 10% del tráfico benigno (downsampling), lo que puede introducir sesgo hacia detección de ataques. No hay métricas guardadas de su desempeño.

---

## 4. Métricas de Detección — Análisis Detallado

### 4.1 Métricas Globales del Ensamble v2

| Métrica | Valor | Interpretación |
|---------|-------|---------------|
| **Accuracy** | **98.20%** | 🟢 Excelente — muy alta tasa de acierto global |
| **F1-macro** | **90.15%** | 🟡 Bueno — promedio balanceado entre clases |
| **Precision-macro** | **87.68%** | 🟡 Bueno — bajo tasa de falsos positivos promedio |
| **Recall-macro** | **93.99%** | 🟢 Muy bueno — alta tasa de detección |
| **Kappa de Cohen** | **93.98%** | 🟢 Excelente concordancia (>0.8 = casi perfecto) |

### 4.2 Comparativa Modelos Individuales vs Ensamble

| Modelo | Accuracy | F1-macro | Observación |
|--------|---------|---------|-------------|
| Random Forest | 95.82% | 77.30% | ⚠️ F1 bajo — problema con clases minoritarias |
| XGBoost | **98.37%** | **90.87%** | 🥇 Mejor modelo individual |
| CatBoost | 98.20% | 90.38% | 🥈 Muy cercano a XGBoost |
| **Ensamble** | 98.20% | 90.15% | 🟡 Ensamble no supera a XGBoost solo |

> [!WARNING]
> **El ensamble NO mejora al mejor modelo individual (XGBoost).** Esto es inusual y sugiere que los pesos actuales [1, 2, 1.5] no están bien calibrados, o que RF está arrastrando el rendimiento hacia abajo. Se recomienda probar ensamble solo XGB+CatBoost con pesos iguales.

### 4.3 Análisis por Clase (Matriz de Confusión)

| Clase | Total Test | Correctos | Errores | Acc. por Clase | Notas |
|-------|-----------|-----------|---------|----------------|-------|
| **Normal** | 72,993 | 69,900 | 3,093 | 95.76% | ⚠️ 2,352 confundidos con Exploit |
| **Inyeccion_SQL** | 436 | 371 | 65 | 85.09% | ⚠️ Clase más pequeña, difícil de detectar |
| **Normal (tráfico)** | 474,186 | 469,079 | 5,107 | 98.92% | 🟢 Muy bien clasificado |
| **Port_Scanner** | 31,923 | 31,779 | 144 | 99.55% | 🟢 Excelente |
| **Posible_Exploit** | 4,991 | 4,231 | 760 | 84.77% | ⚠️ 616 confundidos con Normal |
| **SYN_Flood** | 60,407 | 58,018 | 2,389 | 96.04% | 🟡 Bueno |
| **UDP_Flood** | 7,487 | 7,323 | 164 | 97.81% | 🟢 Muy bueno |

### 4.4 Clases Problemáticas

```
Inyeccion_SQL:   85.09% recall → 64 muestras perdidas de 436
                 Causa: clase muy pequeña (0.07% del test set)

Posible_Exploit: 84.77% recall → 760 muestras perdidas de 4,991
                 Causa: amplio espectro (BruteForce+Infiltration+Heartbleed)
                 152 confundidas con Normal (FP inversos peligrosos)
```

> [!CAUTION]
> **Falsos Negativos Críticos:** 101 casos de `DDoS_Distribuido` clasificados como `Normal` y 616 de `Posible_Exploit` como `Normal`. En un IDS, estos falsos negativos son el riesgo más alto — un ataque pasa desapercibido.

---

## 5. Análisis del Sistema en Tiempo Real

### 5.1 FlowTracker — Extracción de Features

El módulo `flujos_red.py` implementa un tracker de flujos bidireccionales con:

| Característica | Valor | Evaluación |
|---------------|-------|-----------|
| Timeout de flujo | 5 segundos | ⚠️ Puede perder flujos largos (HTTP, SSH) |
| Check de expiración | Cada 2 segundos | ✅ Razonable |
| Features calculadas | 23 | ⚠️ Solo un subconjunto de features del modelo v2 |
| Manejo de dirección | Bidireccional (Forward/Backward) | ✅ Correcto |
| Estadísticas de flags TCP | Sí (FIN/SYN/RST/PSH/ACK/URG) | ✅ Bueno |

### 5.2 Detección Heurística — Umbrales

| Ataque | Umbral Base | Ventana | EWMA dinámico |
|--------|------------|---------|--------------|
| SYN Flood | 50 pkt/IP | 0.5s | ✅ Sí |
| DDoS | 500 pkt/destino | 1s | ✅ Sí |
| Port Scan | 40 puertos/IP | Acumulado | ✅ Sí |
| UDP Flood | 500 pkt/destino | 1s | ✅ Sí |
| SQL Injection | Regex + payload | Por paquete | ❌ No |

> [!NOTE]
> Los umbrales dinámicos con EWMA (`alpha=0.1`) son una decisión de diseño correcta para adaptarse al tráfico base de la red universitaria. Sin embargo, `alpha=0.1` es bastante lento en reaccionar — subir a `0.2–0.3` daría más agilidad.

### 5.3 Lógica de Bloqueo IPS

```
Ataque detectado
       │
       ├── ¿Es crítico? (exploit/sql/flood/ddos/scan)
       │         │ Sí
       │         ├── ¿Detección ML? → confianza ≥ 70%
       │         │         │ Sí → puede_bloquear = True
       │         └── ¿Heurística? → puede_bloquear = True siempre
       │
       └── ¿modo_ips_autonomo?
                 ├── True → Bloqueo real via MikroTik API
                 └── False → Alerta Semi-autónoma (solo log/telegram)
```

> [!WARNING]
> El umbral de confianza ML del 70% para bloqueo es adecuado, pero la **detección heurística bloquea sin restricción de confianza**. Un ataque de Port Scan legítimo (auditoría interna) podría bloquearse automáticamente.

---

## 6. Fortalezas del Sistema

1. **🏆 Arquitectura híbrida:** Combina detección ML (flujos completos, alta precisión) con heurística (instantánea, sin latencia de 5s).

2. **📊 Dataset sólido:** CIC-IDS2017/2018 son estándares de facto en investigación de IDS. El preprocesamiento de 10 fases es completo y correcto.

3. **⚖️ Balanceo con SMOTE:** Aplicado correctamente solo en training — evita data leakage. Es especialmente crítico para `Inyeccion_SQL` (clase muy minoritaria).

4. **🔄 Ensamble multi-modelo:** La combinación RF+XGB+CatBoost cubre distintas superficies de decisión.

5. **📡 EWMA dinámico:** Los umbrales adaptativos evitan falsos positivos durante picos de tráfico legítimo.

6. **🔔 Notificaciones asíncronas:** Las alertas Telegram se envían en thread separado — no bloquean el sniffing.

7. **💾 Persistencia SQLite:** Registro histórico de ataques y bloqueos para auditoría.

---

## 7. Debilidades y Riesgos

### 7.1 Críticos

| # | Problema | Impacto | Archivo |
|---|---------|---------|---------|
| 1 | **Feature mismatch v2 vs v3** | Ensamble v2 inutilizable en producción | `flujos_red.py` vs `selected_features.pkl` |
| 2 | **Sin métricas del modelo v3** | No hay evidencia de rendimiento del modelo real en producción | `CEREBRO.py` |
| 3 | **SMOTE desactivado en v3** | Desbalanceo no corregido para clases pequeñas en modelo productivo | `CEREBRO.py` line 176 |
| 4 | **RF max_depth=20** | Riesgo de overfitting severo en RandomForest | `entrenar_rapido.py` |

### 7.2 Moderados

| # | Problema | Impacto |
|---|---------|---------|
| 5 | Timeout de 5s en FlowTracker | Ataques rápidos (<5s) pueden no clasificarse por ML |
| 6 | Pesos del ensamble no optimizados | Ensamble underperforms vs XGBoost solo |
| 7 | Regex de SQL Injection demasiado simple | Alta tasa de falsos negativos para SQLi ofuscado |
| 8 | Sin evaluación de curvas de aprendizaje | No se sabe si el modelo está sobreajustado |
| 9 | alpha_ewma=0.1 muy lento | Reacción lenta ante cambios bruscos de tráfico |

### 7.3 Menores

| # | Problema |
|---|---------|
| 10 | `xgboost` sin `use_label_encoder=False` (deprecado en versiones nuevas) |
| 11 | No hay logging estructurado (solo print) |
| 12 | `conn = sqlite3.connect(..., check_same_thread=False)` — uso compartido sin mutex explícito |

---

## 8. Métricas de Efectividad Global

```
┌─────────────────────────────────────────────────┐
│         SCORECARD DEL SISTEMA IDS/IPS           │
├────────────────────────┬───────────────┬────────┤
│ Dimensión              │ Valor         │ Nota   │
├────────────────────────┼───────────────┼────────┤
│ Accuracy global        │ 98.20%        │ 🟢 A+  │
│ F1-macro (balance)     │ 90.15%        │ 🟡 B+  │
│ Kappa (concordancia)   │ 93.98%        │ 🟢 A   │
│ Recall (no perder atq) │ 93.99%        │ 🟢 A   │
│ Precision (evitar FP)  │ 87.68%        │ 🟡 B+  │
│ Detección SYN Flood    │ 96.04%        │ 🟢 A   │
│ Detección DDoS         │ 95.76%        │ 🟢 A   │
│ Detección Port Scan    │ 99.55%        │ 🟢 A+  │
│ Detección SQL Inject.  │ 85.09%        │ 🟡 B   │
│ Detección Exploit      │ 84.77%        │ 🟡 B   │
│ Detección UDP Flood    │ 97.81%        │ 🟢 A   │
│ Consistencia modelo    │ ⚠️ v2≠v3     │ 🔴 D   │
│ Cobertura en real-time │ Parcial       │ 🟡 C+  │
└────────────────────────┴───────────────┴────────┘
```

---

## 9. Recomendaciones de Mejora (Priorizadas)

### 🔴 Alta Prioridad

1. **Unificar modelos v2 y v3:** Asegurar que las features del ensamble v2 sean exactamente las que calcula `flujos_red.py`. Actualizar `flujos_red.py` para incluir `Idle Mean/Max/Min`, `Subflow Bwd Packets`, `Down/Up Ratio`.

2. **Evaluar el modelo v3 en producción:** Ejecutar `classification_report` sobre el `pipeline_catboost_v3.pkl` con datos de test y guardar métricas en `metricas_modelo_v3.json`.

3. **Re-activar SMOTE en CEREBRO.py (v3):** Descomentar la línea de SMOTE para corregir el desbalanceo en `Inyeccion_SQL` y `Posible_Exploit`.

### 🟡 Media Prioridad

4. **Optimizar pesos del ensamble:** Usar `GridSearchCV` sobre los pesos o directamente usar `StackingClassifier` con meta-learner logístico.

5. **Reemplazar ANOVA F por Mutual Information:** `SelectKBest(mutual_info_classif)` para features de red no normales.

6. **Reducir `max_depth` de RF a 12-15:** Para reducir riesgo de overfitting sin pérdida significativa de rendimiento.

7. **Aumentar alpha_ewma a 0.2-0.3:** Reacción más rápida a cambios de tráfico.

### 🟢 Mejoras Futuras

8. **Agregar detección de anomalías:** Un modelo Isolation Forest o Autoencoder para detectar ataques desconocidos (zero-day).

9. **Implementar curvas ROC por clase:** Para ajustar umbrales de decisión por tipo de ataque según el costo de los errores.

10. **Agregar métricas de latencia:** Medir cuánto tiempo tarda el sistema en detectar desde el primer paquete del ataque.

---

## 10. Resumen Ejecutivo

El sistema IDS/IPS de UNIPAZ es **técnicamente sólido y funcionalmente correcto** para un entorno académico. Las métricas del ensamble v2 son excelentes (98.2% accuracy, 93.98% Kappa), especialmente para Port Scanner, UDP Flood y tráfico Normal.

Las áreas de mejora más urgentes son:
- **Resolver la inconsistencia entre el modelo evaluado (v2) y el modelo en producción (v3)**
- **Documentar las métricas del modelo v3** que es el que realmente opera
- **Mejorar la detección de Inyección SQL y Posible Exploit** (recall ~85%)

El diseño híbrido (heurística + ML) es la decisión más acertada del sistema, permitiendo detección inmediata de ataques obvios y clasificación precisa de flujos complejos.

---
*Análisis generado con skills: `scikit-learn`, `machine-learning`, `senior-data-scientist`, `pandas-pro`*
