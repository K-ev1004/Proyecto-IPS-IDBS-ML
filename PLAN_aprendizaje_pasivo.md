# Plan: Aprendizaje Pasivo de Tráfico Normal — Modelo v6 Evolutivo

**Proyecto:** IPS-IDBS-ML — UNIPAZ  
**Fecha:** 2026-09-01  
**Estado:** Propuesta (no implementada)  
**Autor:** Asistente de Desarrollo

---

## 1. Problema Actual

El modelo CatBoost v5 se entrenó exclusivamente con datasets académicos (CIC-IDS2017, CSE-CIC-IDS2018, CIC-DDoS2019) y es **estático**:

- Nunca aprende del tráfico real de la red UNIPAZ
- No conoce los patrones "normales" del campus (ARP masivo, mDNS, MikroTik, etc.)
- Genera falsos positivos porque el tráfico legítimo del campus no existe en los datasets de entrenamiento
- No detecta amenazas nuevas que no estén en las 7 clases predefinidas

### Modelos actuales

| Modelo | Archivo | Propósito |
|--------|---------|-----------|
| v5 (multiclase) | `pipeline_catboost_v5.pkl` | Clasifica flujos en 7 clases |
| SQLiGuard (binario) | `sqli_guard.pkl` | Confirma/niega SQLi (2ª etapa) |

### 7 clases actuales

```
Normal, DDoS_Distribuido, SYN_Flood, UDP_Flood,
Port_Scanner, Posible_Exploit, Inyeccion_SQL
```

---

## 2. Objetivo

Implementar un sistema de **aprendizaje pasivo** que permita al modelo aprender del tráfico normal de la red institucional, reduciendo falsos positivos y detectando anomalías que el modelo actual no conoce.

### Resultados esperados

- **v5 permanece intacto** — nunca se modifica ni sobrescribe
- **v6 se crea como modelo nuevo** — combina conocimiento académico + tráfico local
- **Clase nueva "Anómalo_Local"** — para tráfico que no es ataque conocido pero tampoco es totalmente normal
- **Captura flexible** — CLI + interfaz gráfica, horarios pico/no-pico configurables
- **Reentrenamiento manual** — el admin decide cuándo reentrenar

---

## 3. Arquitectura General

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CAPTURA DE TRÁFICO                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   capturar_trafico.py              interfasc.py (botón)             │
│     ├── CLI: --duracion 1800         ├── Capturar Tráfico Normal    │
│     │         --modo pico            ├── Duración: 15m/30m/1h/2h   │
│     └── Captura Scapy en vivo        └── Modo: pico/no_pico/auto   │
│              │                                                        │
│              ▼                                                        │
│   FlowTracker (flujos_red.py)                                        │
│     └── Extrae 23 features CIC por flujo                             │
│              │                                                        │
│              ▼                                                        │
│   Clasificación con v5 actual                                        │
│     ├── Normal (confianza ≥ 0.85) → guardar en trafico_normal       │
│     ├── Anómalo_Local (Isolation Forest) → trafico_normal (anómalo)  │
│     └── Ataque → guardar_ataque() (flujo existente)                  │
│              │                                                        │
│              ▼                                                        │
│   SQLite: tabla trafico_normal                                       │
│     ├── id, timestamp, ip_src, ip_dst, puerto_dst, protocolo        │
│     ├── features_json (23 features)                                  │
│     └── es_anomalo (0=normal, 1=anómalo)                            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                       REENTRENAMIENTO (MANUAL)                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   reentrenar_modelo.py           interfasc.py (botón)               │
│     ├── Carga dataset académico    ├── Reentrenar Modelo v6         │
│     ├── Carga trafico_normal       ├── Solo si ≥ 1000 registros    │
│     ├── Divide pico / no_pico      └── Muestra progreso + métricas │
│     ├── Isolation Forest → Anómalo_Local                            │
│     ├── Mezcla equilibrada                                           │
│     └── Guarda v6 (v5 intacto)                                       │
│              │                                                        │
│              ▼                                                        │
│   Modelos_Entrenados/                                                │
│     ├── pipeline_catboost_v5.pkl     ← INTACTO                      │
│     ├── label_encoder_v5.pkl         ← INTACTO                      │
│     ├── selected_features_v5.pkl     ← INTACTO                      │
│     ├── pipeline_catboost_v6.pkl     ← NUEVO (se crea al reentrenar)│
│     ├── label_encoder_v6.pkl         ← NUEVO                        │
│     ├── selected_features_v6.pkl     ← NUEVO                        │
│     └── metricas_v6.txt              ← NUEVO (comparativa)          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                         PREDICCIÓN (EN VIVO)                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   ids.py: on_flow_ready()                                           │
│     │                                                                │
│     ├── ¿Existe v6?                                                 │
│     │   ├── SÍ → Cargar v6 (modelo evolutivo)                      │
│     │   └── NO → Cargar v5 (fallback seguro)                       │
│     │                                                                │
│     ├── Predicción con el modelo cargado                            │
│     │   ├── SQLiGuard confirma → Inyeccion_SQL                      │
│     │   ├── Clase ≠ Normal AND confianza ≥ 0.85 → Ataque           │
│     │   ├── Clase = Normal → guardar en trafico_normal              │
│     │   └── Confianza < 0.85 → descartar                           │
│     │                                                                │
│     └── Modelo v6 ahora reconoce 8 clases:                          │
│         Normal, DDoS_Distribuido, SYN_Flood, UDP_Flood,             │
│         Port_Scanner, Posible_Exploit, Inyeccion_SQL,               │
│         Anómalo_Local                                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. Nuevos Archivos y Modificaciones

### 4.1 Archivos a crear

| Archivo | Tipo | Descripción |
|---------|------|-------------|
| `capturar_trafico.py` | Nuevo | Captura de tráfico en vivo + detección de anomalías con Isolation Forest |
| `reentrenar_modelo.py` | Nuevo | Script de reentrenamiento que combina datos académicos + locales |
| `PLAN_aprendizaje_pasivo.md` | Nuevo | Este documento |

### 4.2 Archivos a modificar

| Archivo | Cambio |
|---------|--------|
| `ids.py` | +tabla `trafico_normal`, +INSERT en `on_flow_ready()`, +carga de v6 con fallback a v5 |
| `interfasc.py` | +2 botones en `setup_settings_page()` (Capturar Tráfico + Reentrenar Modelo) |

### 4.3 Archivos que NO se modifican

| Archivo | Razón |
|---------|-------|
| `CEREBRO_V5.py` | Se mantiene como script de entrenamiento original de v5 |
| `Modelos_Entrenados/pipeline_catboost_v5.pkl` | Modelo original, nunca se sobrescribe |
| `Modelos_Entrenados/label_encoder_v5.pkl` | Encoder original, nunca se sobrescribe |
| `Modelos_Entrenados/selected_features_v5.pkl` | Features originales, nunca se sobrescriben |
| `entrenar_sqli_guard.py` | SQLiGuard se mantiene independiente |
| `flujos_red.py` | Sin cambios (ya extrae las 23 features necesarias) |

---

## 5. Especificación de Componentes

### 5.1 Tabla SQLite: `trafico_normal`

```sql
CREATE TABLE IF NOT EXISTS trafico_normal (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT,
    ip_src        TEXT,
    ip_dst        TEXT,
    puerto_dst    INTEGER,
    protocolo     TEXT,
    features_json TEXT,          -- Las 23 features CIC en JSON
    es_anomalo    INTEGER DEFAULT 0   -- 0=normal, 1=anómalo (Isolation Forest)
)
```

**Límites de almacenamiento:**
- Máximo 100,000 registros
- DELETE los más antiguos al exceder el límite
- Evitar duplicados: misma tupla (ip_src, ip_dst, puerto_dst, protocolo) en últimos 60 segundos

### 5.2 `capturar_trafic.py` — Capturador de Tráfico

**Uso CLI:**
```bash
# Capturar 30 minutos de tráfico pico
python capturar_trafico.py --duracion 1800 --modo pico

# Capturar 1 hora de tráfico no pico
python capturar_trafico.py --duracion 3600 --modo no_pico

# Captura automática (detecta horario pico/no-pico)
python capturar_trafico.py --duracion 3600 --modo auto
```

**Parámetros:**

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `--duracion` | int | 1800 | Duración de la captura en segundos |
| `--modo` | str | `auto` | `pico`, `no_pico`, o `auto` |
| `--interfaz` | str | Ninguna | Interfaz de captura (default: auto-detectar) |
| `--min-samples` | int | 100 | Mínimo de flujos para entrenar Isolation Forest |

**Flujo interno:**

```
1. Iniciar captura Scapy (AsyncSniffer, modo promiscuo)
2. Alimentar FlowTracker con cada paquete
3. Cuando un flujo expira (5s timeout):
   a. Extraer 23 features con get_features_dict()
   b. Clasificar con v5 actual
   c. Si "Normal" (confianza ≥ 0.85):
      - Guardar en trafico_normal (es_anomalo=0)
   d. Si confianza < 0.85:
      - Guardar temporalmente para análisis posterior
4. Al finalizar la captura:
   a. Entrenar Isolation Forest sobre los flujos "Normales"
   b. Marcar flujos temporales anómalos (es_anomalo=1)
   c. Guardar en trafico_normal
5. Generar resumen: total flujos, normales, anómalos
```

**Detección de anomalías con Isolation Forest:**

```python
from sklearn.ensemble import IsolationForest

# Entrenar sobre flujos normales capturados
iso_forest = IsolationForest(
    contamination=0.05,    # 5% esperado como anómalo
    random_state=42,
    n_estimators=100
)
iso_forest.fit(X_normal)

# Predecir anomalías
predicciones = iso_forest.predict(X_temporal)
# -1 = anómalo, 1 = normal
```

### 5.3 `reentrenar_modelo.py` — Reentrenamiento

**Uso CLI:**
```bash
python reentrenar_modelo.py --min-samples 1000
```

**Parámetros:**

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `--min-samples` | int | 1000 | Mínimo de registros en `trafico_normal` para reentrenar |
| `--output` | str | `Modelos_Entrenados/` | Carpeta de salida |
| `--ratio-normal` | float | 0.3 | Proporción del dataset total que debe ser tráfico normal |

**Flujo interno:**

```
1. Verificar que hay ≥ min_samples en trafico_normal
2. Cargar dataset académico original:
   - Dataset_Limpio/dataset_global_unipaz_v5.csv
   - Todas las filas, todas las clases
3. Cargar registros de trafico_normal desde SQLite:
   - Dividir por horario: pico (08:00-17:00) vs no_pico (resto)
   - Tomar muestra equilibrada de cada periodo
   - Los registros con es_anomalo=1 → clase "Anómalo_Local"
   - Los registros con es_anomalo=0 → clase "Normal"
4. Combinar datasets:
   - Académico completo (ataques)
   - Normal capturado (refuerza clase Normal)
   - Anómalos capturados (nueva clase Anómalo_Local)
5. Entrenar pipeline CatBoost:
   - Mismas 23 features (FEATURES_V4)
   - 8 clases (7 originales + Anómalo_Local)
   - SMOTE para balancear Anómalo_Local si es necesario
6. Evaluar:
   - Comparar métricas v5 vs v6 en test set
   - Verificar que v5 no empeora en detección de ataques
7. Guardar:
   - pipeline_catboost_v6.pkl (NUEVO)
   - label_encoder_v6.pkl (NUEVO)
   - selected_features_v6.pkl (NUEVO)
   - metricas_v6.txt (comparativa)
8. NO tocar ningún archivo de v5
```

**8 clases del modelo v6:**

```python
CLASES_V6 = [
    'Normal',              # Tráfico legítimo (reforzado con tráfico local)
    'DDoS_Distribuido',    # Ataques DDoS
    'SYN_Flood',           # Ataques SYN Flood
    'UDP_Flood',           # Ataques UDP Flood
    'Port_Scanner',        # Escaneo de puertos
    'Posible_Exploit',     # Intentos de explotación
    'Inyeccion_SQL',       # Inyección SQL (confirmado por SQLiGuard)
    'Anómalo_Local'        # NUEVO: Tráfico anómalo del campus
]
```

### 5.4 `ids.py` — Cambios en Predicción

**Carga de modelo (reemplazar líneas 188-196):**

```python
# === CARGA DE MODELO (v6 preferido, fallback a v5) ===
v6_model_path = os.path.join(MODELOS_FOLDER, 'pipeline_catboost_v6.pkl')
v6_le_path = os.path.join(MODELOS_FOLDER, 'label_encoder_v6.pkl')
v6_features_path = os.path.join(MODELOS_FOLDER, 'selected_features_v6.pkl')

if os.path.exists(v6_model_path):
    try:
        modelo_ml = joblib.load(v6_model_path)
        tipo_ataque_encoder = joblib.load(v6_le_path)
        features_seleccionadas = joblib.load(v6_features_path)
        print("[OK] Modelo v6 (UNIPAZ-Adaptado) cargado correctamente.")
    except Exception as e:
        print(f"[X] Error cargando modelo v6: {e}, intentando v5...")
        modelo_ml = joblib.load(model_path)
        tipo_ataque_encoder = joblib.load(le_path)
        features_seleccionadas = joblib.load(features_path)
else:
    try:
        modelo_ml = joblib.load(model_path)
        tipo_ataque_encoder = joblib.load(le_path)
        features_seleccionadas = joblib.load(features_path)
        print("[OK] Modelo v5 (Original) cargado correctamente.")
    except Exception as e:
        print(f"[X] Error cargando modelo v5: {e}")
        modelo_ml = None
```

**Inserción en `on_flow_ready()` (agregar en la rama `else` ~línea 372):**

```python
else:
    # Flujo clasificado como Normal
    metricas_trafico['riesgo_global'] = max(0.0, metricas_trafico['riesgo_global'] - 0.5)
    
    # Guardar tráfico normal para aprendizaje pasivo
    if confianza_v5 >= 0.85:
        try:
            cursor.execute('''
                INSERT INTO trafico_normal (timestamp, ip_src, ip_dst, puerto_dst,
                                           protocolo, features_json, es_anomalo)
                VALUES (?, ?, ?, ?, ?, ?, 0)
            ''', (timestamp, ip_src, ip_dst, features_dict.get('Dst Port', 0),
                  'TCP/UDP', json.dumps(features_dict)))
            conn.commit()
        except Exception:
            pass
```

### 5.5 `interfasc.py` — Botones en Settings

**En `setup_settings_page()`, agregar después de los controles existentes:**

```python
# === SECCIÓN: Aprendizaje Pasivo ===
self lbl_aprendizaje = BodyLabel("Aprendizaje Pasivo")
self btn_capturar_trafico = PrimaryPushButton("Capturar Tráfico Normal")
self.btn_capturar_trafico.clicked.connect(self.iniciar_captura_trafico)

self.btn_reentrenar = PrimaryPushButton("Reentrenar Modelo v6")
self.btn_reentrenar.clicked.connect(self.reentrenar_modelo)
self.btn_reentrenar.setEnabled(False)  # Solo si hay suficientes datos
```

**Métodos a agregar:**

```python
def iniciar_captura_trafico(self):
    """Abre diálogo de captura y ejecuta en QThread."""
    # Diálogo con opciones: duración, modo (pico/no_pico/auto)
    # Ejecutar capturar_trafico.py en QThread
    pass

def reentrenar_modelo(self):
    """Ejecuta reentrenar_modelo.py en QThread."""
    # Verificar min_samples en trafico_normal
    # Ejecutar reentrenamiento
    # Mostrar métricas comparativas
    pass

def actualizar_estado_reentrenamiento(self):
    """Habilita/deshabilita botón según registros disponibles."""
    # Contar registros en trafico_normal
    # Habilitar btn_reentrenar si ≥ 1000
    pass
```

---

## 6. Flujo de Datos Completo

### 6.1 Captura (pasivo)

```
Paquete en red
    │
    ▼
Scapy (AsyncSniffer, promiscuo)
    │
    ▼
FlowTracker.procesar_paquete()
    │
    ▼
Flujo expira (5s timeout)
    │
    ▼
get_features_dict() → 23 features CIC
    │
    ▼
Modelo v5 predice
    │
    ├── "Normal" (confianza ≥ 0.85)
    │       │
    │       ▼
    │   Guardar en trafico_normal (es_anomalo=0)
    │
    ├── Baja confianza (< 0.85)
    │       │
    │       ▼
    │   Guardar temporalmente → Isolation Forest
    │       │
    │       ├── Anómalo → trafico_normal (es_anomalo=1)
    │       └── Normal → trafico_normal (es_anomalo=0)
    │
    └── Ataque detectado
            │
            ▼
        guardar_ataque() (flujo existente)
```

### 6.2 Reentrenamiento (manual)

```
Admin hace clic en "Reentrenar Modelo v6"
    │
    ▼
reentrenar_modelo.py
    │
    ├── 1. Cargar dataset académico (CIC-IDS2017/2018/2019)
    │       └── ~3.7M registros, 7 clases
    │
    ├── 2. Cargar trafico_normal desde SQLite
    │       ├── Dividir: pico (08:00-17:00) vs no_pico
    │       ├── Muestra equilibrada de cada periodo
    │       └── es_anomalo=1 → clase "Anómalo_Local"
    │
    ├── 3. Combinar datasets
    │       ├── Académico completo (ataques)
    │       ├── Normal local (refuerza Normal)
    │       └── Anómalos locales (nueva clase)
    │
    ├── 4. Entrenar CatBoost
    │       ├── 23 features (FEATURES_V4)
    │       ├── 8 clases
    │       └── SMOTE para Anómalo_Local si necesario
    │
    ├── 5. Evaluar y comparar con v5
    │
    ├── 6. Guardar v6 (archivos nuevos)
    │       ├── pipeline_catboost_v6.pkl
    │       ├── label_encoder_v6.pkl
    │       ├── selected_features_v6.pkl
    │       └── metricas_v6.txt
    │
    └── 7. v5 permanece intacto
```

---

## 7. Consideraciones Técnicas

### 7.1 Seguridad del Modelo Original

- **v5 nunca se modifica**: Los archivos `*_v5.pkl` son de solo lectura
- **Fallback automático**: Si v6 falla al cargar, el sistema usa v5
- **Versionado**: Cada reentrenamiento crea archivos nuevos (`*_v6.pkl`), nunca sobrescribe

### 7.2 Balanceo de Datos

| Fuente | Registros esperados | Proporción |
|--------|-------------------|------------|
| Académico (CIC-IDS) | ~3.7M | ~70% |
| Normal local (pico) | ~50K-200K | ~15% |
| Normal local (no_pico) | ~50K-200K | ~15% |
| Anómalo_Local | ~5K-10K | ~1-2% |

### 7.3 Requisitos de Hardware para Captura

- **CPU**: Mínimo 2 cores disponibles para Scapy + Isolation Forest
- **RAM**: ~500MB adicionales durante captura de 1 hora
- **Disco**: ~100MB por hora de captura (features JSON)
- **Red**: La captura no afecta el rendimiento de la red (modo promiscuo pasivo)

### 7.4 Seguridad de Datos

- Los registros en `trafico_normal` contienen solo features numéricos, no payloads
- No se almacenan contenidos de paquetes, solo estadísticas de flujos
- Los datos se eliminan automáticamente al exceder 100,000 registros

---

## 8. Interfaz de Usuario

### 8.1 Botones en Settings

```
┌─────────────────────────────────────────────┐
│  Configuración                              │
├─────────────────────────────────────────────┤
│  ... (controles existentes) ...             │
│                                             │
│  ── Aprendizaje Pasivo ──────────────────   │
│                                             │
│  [Capturar Tráfico Normal]                  │
│    → Abre diálogo de captura                │
│                                             │
│  [Reentrenar Modelo v6]  (deshabilitado)    │
│    → Solo se habilita con ≥ 1000 registros  │
│                                             │
│  Registros disponibles: 0 / 100,000         │
│  Modelo activo: v5 (Original)               │
│                                             │
└─────────────────────────────────────────────┘
```

### 8.2 Diálogo de Captura

```
┌─────────────────────────────────────────────┐
│  Capturar Tráfico Normal                    │
├─────────────────────────────────────────────┤
│                                             │
│  Duración:  [30 min ▼]                      │
│  Modo:      [Automático ▼]                  │
│  Interfaz:  [Auto-detectar ▼]               │
│                                             │
│  □ Incluir análisis de anomalías            │
│    (Isolation Forest)                       │
│                                             │
│  [Iniciar Captura]    [Cancelar]            │
│                                             │
│  Progreso: ████████░░░░░░ 50%               │
│  Flujos capturados: 1,234                   │
│  Tiempo restante: 15:00                     │
│                                             │
└─────────────────────────────────────────────┘
```

---

## 9. Métricas de Éxito

| Métrica | v5 (Actual) | v6 (Esperado) |
|---------|-------------|---------------|
| Falsos positivos en tráfico normal UNIPAZ | ~15-20% | < 5% |
| Detección de ataques conocidos | ~95% | ≥ 95% (no empeora) |
| Detección de anomalías nuevas | 0% | ~60-80% (clase Anómalo_Local) |
| Tiempo de reentrenamiento | N/A | ~5-15 min (depende de datos) |

---

## 10. Pasos de Implementación (Futuros)

1. **Fase 1 — Colección pasiva** (2-3 días)
   - Crear tabla `trafico_normal` en SQLite
   - Modificar `on_flow_ready()` para guardar flujos normales
   - Actualizar carga de modelo en `ids.py` para soportar v6

2. **Fase 2 — Capturador de tráfico** (3-4 días)
   - Crear `capturar_trafico.py` con CLI
   - Integrar Isolation Forest para detección de anomalías
   - Agregar botón de captura en `interfasc.py`

3. **Fase 3 — Reentrenamiento** (2-3 días)
   - Crear `reentrenar_modelo.py`
   - Implementar lógica de mezcla equilibrada (académico + local)
   - Agregar botón de reentrenamiento en `interfasc.py`

4. **Fase 4 — Pruebas y validación** (2-3 días)
   - Probar captura en horario pico y no-pico
   - Validar que v6 se crea sin tocar v5
   - Verificar reducción de falsos positivos
   - Confirmar que detección de ataques no empeora

**Tiempo estimado total: 9-13 días**

---

## 11. Preguntas Abiertas (Para Futura Implementación)

1. ¿Qué umbral de confianza usar para guardar flujos como "Normal" en `trafico_normal`? (Actual propuesta: 0.85)
2. ¿Cuántos registros como mínimo para que el reentrenamiento sea efectivo? (Actual propuesta: 1,000)
3. ¿Debe haber un límite de tiempo para los registros en `trafico_normal`? (Actual propuesta: sin límite de tiempo, solo límite de cantidad)
4. ¿Se debe generar un reporte/correo al admin cuando el reentrenamiento termine?
5. ¿Se debe permitir revertir a v5 desde la interfaz si v6 no funciona bien?
