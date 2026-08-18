# 📊 Viabilidad del Dataset CSE-CIC-IDS2018 — Análisis Completo

> [!WARNING] Documento histórico
> Análisis previo al pipeline unificado v5. El pipeline actual (`generador_dataset_global.py`)
> combina **CIC-IDS2017 + CSE-CIC-IDS2018 + CIC-DDoS2019** y recupera los ataques web 2017
> perdidos por el bug de encoding U+FFFD (ver [`../adr/0001-pipeline-datos-v5.md`](../adr/0001-pipeline-datos-v5.md)).
> La escasez de SQLi aquí descrita se resolvió con el detector binario **SQLiGuard**.

> **Fecha:** 2 de junio de 2026  
> **Dataset en disco:** `c:\IDS-IPS\Proyecto-IPS-IDBS-ML\CSE-CIC-IDS2018\`  
> **Muestra analizada:** 200,000 filas por archivo (2,000,000 total)

---

## 1. Resumen por Archivo

| Archivo | Tamaño | Columnas | Features v3 | NaN | Inf | Clases Presentes |
|---------|--------|----------|-------------|-----|-----|-----------------|
| 02-14-2018.csv | 342 MB | 80 | ✅ 23/23 | 5 | 5 | FTP-BruteForce (90%), SSH-Bruteforce (10%) |
| 02-15-2018.csv | 359 MB | 80 | ✅ 23/23 | 701 | 1,683 | Benign (74%), DoS-GoldenEye (21%), Slowloris (5%) |
| 02-16-2018.csv | 318 MB | 80 | ✅ 23/23 | 0 | 0 | SlowHTTPTest (46%), Hulk (34%), Benign (21%) |
| **02-20-2018.csv** | **3,867 MB** | **84** ⚠️ | ✅ 23/23 | 0 | 0 | DDoS LOIC-HTTP (99.9%) |
| 02-21-2018.csv | 314 MB | 80 | ✅ 23/23 | 0 | 0 | DDoS HOIC (98%), LOIC-UDP (1%) |
| 02-22-2018.csv | 365 MB | 80 | ✅ 23/23 | 766 | 1,558 | Benign (99.8%), Web Brute (0.1%), XSS (0.04%), **SQL (0.02%)** |
| 02-23-2018.csv | 365 MB | 80 | ✅ 23/23 | 778 | 1,530 | Benign (99.7%), Web Brute (0.2%), XSS (0.08%), **SQL (0.03%)** |
| 02-28-2018.csv | 200 MB | 80 | ✅ 23/23 | 1,280 | 2,658 | Benign (100%) |
| 03-01-2018.csv | 103 MB | 80 | ✅ 23/23 | 1,161 | 2,523 | Benign (73%), Infiltration (27%) |
| 03-02-2018.csv | 336 MB | 80 | ✅ 23/23 | 106 | 246 | Bot (82%), Benign (19%) |
| **TOTAL** | **6.4 GB** | | | **6,102** | **14,456** | **15 tipos de ataque** |

---

## 2. Hallazgos Críticos

### 🔴 Hallazgo 1 — Archivo gigante con esquema diferente

```
02-20-2018.csv  →  3,867 MB  (59% del dataset total)
                →  84 columnas  (vs 80 en los demás)
```

Este archivo es casi **4 veces más grande** que cualquier otro y tiene **4 columnas extras**. Si no se maneja correctamente, al concatenar con los demás se generarán columnas con `NaN` masivos o errores de parsing. `CEREBRO.py` ya maneja esto cargando solo `FEATURES_ESPERADAS` con `usecols`, lo que evita el problema — **pero hay que verificarlo**.

### 🔴 Hallazgo 2 — SQL Injection críticamente escasa

```
SQL Injection encontrados en 2,000,000 filas muestreadas:
  02-22-2018.csv →  34 registros  (0.017% del archivo)
  02-23-2018.csv →  53 registros  (0.027% del archivo)
  TOTAL muestra  →  87 registros de SQL Injection
```

> [!CAUTION]
> Con solo **~87 registros en 2M de filas muestreadas**, en el dataset completo habría aproximadamente **400–600 registros reales de SQL Injection** de ~16 millones de filas totales. Esto es **insuficiente para entrenar un clasificador confiable**. El modelo tendrá recall bajo en esta clase (confirmado: 85% en métricas v2).

### 🔴 Hallazgo 3 — NaN e Inf en 7 de 10 archivos

```
Archivos con valores problemáticos:
  02-14-2018.csv →    5 NaN,    5 Inf  ← leve
  02-15-2018.csv →  701 NaN,  1,683 Inf ← moderado
  02-22-2018.csv →  766 NaN,  1,558 Inf ← moderado
  02-23-2018.csv →  778 NaN,  1,530 Inf ← moderado
  02-28-2018.csv → 1,280 NaN, 2,658 Inf ← alto (archivo 100% Benign)
  03-01-2018.csv → 1,161 NaN, 2,523 Inf ← alto
  03-02-2018.csv →   106 NaN,   246 Inf ← leve
```

Los `Inf` provienen típicamente de divisiones por cero en features como `Flow Byts/s` o `Flow Pkts/s` cuando la duración del flujo es 0. Son **normales en CIC-IDS2018** y el pipeline ya los maneja con `replace([np.inf, -np.inf], np.nan)` seguido de `dropna()`. ✅

### 🟡 Hallazgo 4 — Desbalanceo extremo entre clases

```
Distribución en muestra de 2,000,000 filas:

  Benign              973,140  (48.7%)  ← casi la mitad
  DDoS LOIC-HTTP      199,894  (10.0%)
  DDoS HOIC           196,055  ( 9.8%)
  FTP-BruteForce      179,244  ( 9.0%)
  Bot                 162,906  ( 8.1%)
  DoS SlowHTTPTest     91,434  ( 4.6%)
  DoS Hulk             67,350  ( 3.4%)
  Infiltration         54,311  ( 2.7%)
  DoS GoldenEye        41,508  ( 2.1%)
  SSH-Bruteforce       20,490  ( 1.0%)
  DoS Slowloris        10,990  ( 0.6%)
  LOIC-UDP              1,730  ( 0.09%)
  Brute Force Web         611  ( 0.03%)
  Brute Force XSS         230  ( 0.01%)
  SQL Injection            87  ( 0.004%) ← CRÍTICO
```

Razón máxima de desbalance: **Benign (973K) vs SQL Injection (87)** = **11,184:1**

### 🟡 Hallazgo 5 — `02-28-2018.csv` es solo Benign

El archivo de 200 MB del 28 de febrero contiene **100% tráfico benigno**. Es valioso para entrenar la clase Normal, pero no aporta diversidad de ataques.

---

## 3. ¿Son viables los datasets?

```
╔══════════════════════════════════════════════════════════════╗
║              VEREDICTO FINAL DE VIABILIDAD                  ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  ✅ SÍ, el dataset CSE-CIC-IDS2018 es VIABLE para           ║
║     entrenar el modelo IDS/IPS de UNIPAZ                    ║
║                                                              ║
║  ⚠️  CON CONDICIONES — Requiere tratamiento previo          ║
║     en 4 áreas antes de entrenar                            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

| Criterio | Estado | Detalle |
|---------|--------|---------|
| Features del modelo presentes | ✅ Todas | 23/23 en todos los archivos |
| Volumen suficiente | ✅ Sí | ~16M filas estimadas totales |
| Columna Label presente | ✅ Sí | En todos los archivos |
| NaN / Inf manejables | ✅ Sí | Pipeline ya los corrige |
| Cobertura de tipos de ataque | 🟡 Parcial | 15 tipos → 6 clases UNIPAZ |
| SQL Injection representada | 🔴 Escasa | ~87 muestras / 2M = insuficiente |
| Esquema uniforme | ⚠️ Casi | 02-20 tiene 84 cols vs 80 |
| Desbalanceo | ⚠️ Alto | 11,000:1 — requiere SMOTE obligatorio |

---

## 4. Plan de Corrección Antes de Entrenar

### Paso 1 — Activar SMOTE en CEREBRO.py (obligatorio)

```python
# CEREBRO.py, línea 176 — Descomentar esto:
pipeline = ImbPipeline([
    ('scaler', StandardScaler()),
    ('smote', SMOTE(random_state=42, k_neighbors=3)),  # ← ACTIVAR
    ('clf', cat)
])
```
Sin SMOTE, el modelo aprenderá a ignorar `SQL Injection` porque representa 0.004% del dataset.

### Paso 2 — Aumentar muestra de SQL Injection (recomendado)

En `CEREBRO.py`, cambiar la estrategia de sampling para NO reducir las clases minoritarias:

```python
# Actual (reduce todo el tráfico Benign al 10%):
benignos = benignos.sample(frac=0.10, random_state=42)

# Mejorado (mantiene el 100% de clases con < 5,000 muestras):
if label == 'Benign':
    sub = chunk_label.sample(frac=0.10, random_state=42)
elif len(chunk_label) < 5000:
    sub = chunk_label  # Guardar todo lo que haya
else:
    sub = chunk_label.sample(frac=0.50, random_state=42)
```

### Paso 3 — Manejar el archivo gigante (02-20-2018.csv)

Ese archivo tiene 3.8 GB y casi el 100% es DDoS LOIC-HTTP. Para evitar que sesgue el modelo:

```python
# En CEREBRO.py, después de cargar el chunk, limitar DDoS LOIC-HTTP:
if 'DDoS attacks-LOIC-HTTP' in chunk['Label'].values:
    loic = chunk[chunk['Label'] == 'DDoS attacks-LOIC-HTTP']
    otros = chunk[chunk['Label'] != 'DDoS attacks-LOIC-HTTP']
    loic = loic.sample(min(len(loic), 50000), random_state=42)
    chunk = pd.concat([loic, otros])
```

### Paso 4 — Augmentar SQL Injection con datos externos

Dado que SQL Injection es críticamente escasa, se recomienda complementar con:

| Fuente adicional | Tipo | URL |
|-----------------|------|-----|
| UNSW-NB15 | Dataset público | research.unsw.edu.au |
| KDD Cup 1999 | Clásico | kdd.ics.uci.edu |
| CICIDS-2017 | Complementario | ya lo tienes disponible |

O bien, aplicar **data augmentation** sobre los ~400 registros de SQL Injection usando `SMOTE` con `k_neighbors=3` (menos vecinos para evitar interpolación inválida con tan pocos datos).

---

## 5. Estimación del Dataset Real Completo

| Clase (mapeo UNIPAZ) | Filas estimadas totales | Viabilidad |
|---------------------|------------------------|-----------|
| Normal (Benign) | ~8–9 millones | ✅ Excelente |
| DDoS_Distribuido | ~3–4 millones | ✅ Excelente |
| SYN_Flood (DoS) | ~800K–1M | ✅ Bueno |
| Posible_Exploit | ~400K–600K | ✅ Bueno |
| UDP_Flood | ~50K–80K | 🟡 Suficiente |
| Port_Scanner | ~0 | 🔴 **AUSENTE** |
| Inyeccion_SQL | ~400–800 | 🔴 **Crítico** |

> [!IMPORTANT]
> **Port_Scanner (PortScan) NO está en CSE-CIC-IDS2018.** Solo existe en **CIC-IDS2017**. Si entrenas exclusivamente con 2018, el modelo **no aprenderá a detectar escaneos de puertos**. Se recomienda combinar ambos datasets o añadir los días de PortScan del 2017.

---

## 6. Conclusión

**El dataset CSE-CIC-IDS2018 es viable pero incompleto por sí solo.**

- ✅ Cubre bien: DDoS, SYN Flood, BruteForce, Bot, DoS
- 🔴 No cubre: Port Scanner (requiere CIC-IDS2017)
- 🔴 Cubre mal: SQL Injection (muy pocas muestras)
- ⚠️ Requiere: SMOTE activado, cap de DDoS LOIC-HTTP, preservación de clases minoritarias

**Solución óptima:** Combinar **CIC-IDS2017 + CSE-CIC-IDS2018** en el pipeline de limpieza, tal como lo hace `limpiar_dataset.py` (que sí incluía PortScan del 2017).

---
*Análisis ejecutado con 2,000,000 filas muestreadas de 10 archivos (200K/archivo)*
