# -*- coding: utf-8 -*-
"""
test_masivo.py — Bateria de tests masivos del subsistema ML IDS/IPS (UNIPAZ)
=============================================================================
Verifica el funcionamiento END-TO-END usando datos REALES y las MISMAS rutas
de codigo de produccion (ids.py, flujos_red.py, entrenar_sqli_guard.py y el
exportador de logs).

Secuencia:
  T1. Modelo v5 (multiclase) sobre una muestra grande del dataset v5.
  T2. SQLiGuard (produccion, via `_features_sqli_guard`) sobre los 57 K flujos
      de D2 (Zenodo): precision/recall/F1 y tasa de falsos positivos.
  T3. Cadena completa `on_flow_ready` (v5 + SQLiGuard + umbrales unificados +
      trazabilidad) sobre un lote amplio, usando una BD TEMPORAL (no toca la
      BD de produccion) y desactivando alertas/Telegram.
  T4. Exportador de logs (`log_exporter`): comprobacion de escritura .log.
"""

import os
import sys
import time
import json
import tempfile
import sqlite3

import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

print("=" * 70)
print(" TEST MASIVO — SUBSISTEMA ML IDS/IPS (UNIPAZ)")
print("=" * 70)

RESULTADOS = {}

# ---------------------------------------------------------------------------
# Utils: convertir una fila NetFlow (Zenodo D2) en dict CIC que consume la
# cadena de produccion. Ejercita exactamente el codigo real.
# ---------------------------------------------------------------------------
def netflow_a_cic_fecha(row):
    dv = abs(float(row['last']) - float(row['first']))
    dur_ms = max(dv, 1e-6)
    prot = int(row.get('prot', 0))
    flags = int(row.get('tcp_flags', 0))
    def cnt(bit):
        return 1 if flags & bit else 0
    total_pkts = int(row.get('dpkts', 0))
    total_bytes = int(row.get('doctets', 0))
    dur_s = dur_ms / 1000.0
    feat = {
        'Src Port': float(row.get('srcport', 0)),
        'Dst Port': float(row.get('dstport', 0)),
        'Protocol': prot,
        'Flow Duration': dur_ms * 1000.0,          # us (como CIC)
        'Tot Fwd Pkts': total_pkts, 'Tot Bwd Pkts': 0,
        'TotLen Fwd Pkts': total_bytes, 'TotLen Bwd Pkts': 0,
        'Flow Byts/s': total_bytes / dur_s,
        'Flow Pkts/s': total_pkts / dur_s,
        'FIN Flag Cnt': cnt(1), 'SYN Flag Cnt': cnt(2),
        'RST Flag Cnt': cnt(4), 'PSH Flag Cnt': cnt(8),
        'ACK Flag Cnt': cnt(16), 'URG Flag Cnt': cnt(32),
        '_y': 1 if int(row.get('Label', 0)) == 1 else 0,
    }
    return feat

# ---------------------------------------------------------------------------
# T1. Modelo v5 sobre muestra grande del dataset global
# ---------------------------------------------------------------------------
print("\n[T1] Modelo v5 (multiclase) sobre muestra grande del dataset v5...")
import ids
try:
    dfv5 = pd.read_csv(os.path.join(BASE_DIR, "Dataset_Limpio", "dataset_global_unipaz_v5.csv"),
                       nrows=150000)
    X = dfv5[ids.features_seleccionadas].fillna(0)
    y_true = ids.tipo_ataque_encoder.transform(dfv5['Label_UNIPAZ'])
    t0 = time.time()
    y_pred = ids.modelo_ml.predict(X)
    probs = ids.modelo_ml.predict_proba(X)
    t_pred = time.time() - t0
    from sklearn.metrics import (accuracy_score, classification_report,
                                 f1_score, confusion_matrix)
    acc = accuracy_score(y_true, y_pred)
    f1m = f1_score(y_true, y_pred, average='macro')
    reporte = classification_report(y_true, y_pred, target_names=ids.tipo_ataque_encoder.classes_,
                                    zero_division=0, output_dict=True)
    RESULTADOS['T1'] = {
        'total_flujos': len(X),
        'accuracy': round(acc, 4),
        'f1_macro': round(f1m, 4),
        'tiempo_pred_s': round(t_pred, 2),
        'clases': len(ids.tipo_ataque_encoder.classes_),
    }
    # Precisión/recall de Inyeccion_SQL según el modelo v5 (referencia)
    idx_sql = int(ids.tipo_ataque_encoder.transform(['Inyeccion_SQL'])[0])
    cm = confusion_matrix(y_true, y_pred)
    neg_classes = [i for i in range(len(cm)) if i != idx_sql]
    tp_sql = cm[idx_sql, idx_sql]
    fp_sql = sum(cm[i, idx_sql] for i in neg_classes)
    fn_sql = sum(cm[idx_sql, j] for j in neg_classes)
    prec_sql5 = tp_sql / (tp_sql + fp_sql) if (tp_sql + fp_sql) > 0 else 0
    rec_sql5 = tp_sql / (tp_sql + fn_sql) if (tp_sql + fn_sql) > 0 else 0
    RESULTADOS['T1']['sql_prec_v5'] = round(prec_sql5, 4)
    RESULTADOS['T1']['sql_rec_v5'] = round(rec_sql5, 4)
    print(f"      flujos={len(X)}  acc={acc:.4f}  f1_macro={f1m:.4f}  "
          f"pred={t_pred:.2f}s")
    print(f"      v5 SQLi -> precision={prec_sql5:.4f} recall={rec_sql5:.4f}")
except Exception as e:
    import traceback; traceback.print_exc()
    RESULTADOS['T1'] = {'error': str(e)}
    print(f"      [ERROR] {e}")

# ---------------------------------------------------------------------------
# T2. SQLiGuard de produccion sobre todos los flujos de D2 (57 K)
# ---------------------------------------------------------------------------
print("\n[T2] SQLiGuard (ruta de produccion) sobre D2 (57 K flujos reales)...")
try:
    d2 = pd.read_csv(os.path.join(BASE_DIR, "datasets", "SQLi_Zenodo", "D2_test.csv"))
    feats = ids.SQLI_GUARD_FEATURES
    guard_rows = []
    y_guard = []
    for _, r in d2.iterrows():
        cic = netflow_a_cic_fecha(r)
        guard_rows.append([ids._features_sqli_guard(cic)[k] for k in feats])
        y_guard.append(cic['_y'])
    G = pd.DataFrame(guard_rows, columns=feats)
    t0 = time.time()
    prob_guard = ids.sqli_guard.predict_proba(G)[:, 1]
    t_guard = time.time() - t0
    pred_guard = (prob_guard >= ids.UMBRAL_SQLI_GUARD).astype(int)
    y_guard = np.array(y_guard)
    tn = int(((pred_guard == 0) & (y_guard == 0)).sum())
    fp = int(((pred_guard == 1) & (y_guard == 0)).sum())
    fn = int(((pred_guard == 0) & (y_guard == 1)).sum())
    tp = int(((pred_guard == 1) & (y_guard == 1)).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    RESULTADOS['T2'] = {
        'total_flujos': len(G),
        'precision': round(prec, 4),
        'recall': round(rec, 4),
        'f1': round(f1, 4),
        'tn': tn, 'fp': fp, 'fn': fn, 'tp': tp,
        'tasa_fp_benigno': round(fp / (fp + tn), 5) if (fp + tn) else 0,
        'tiempo_pred_s': round(t_guard, 2),
        'umbral': ids.UMBRAL_SQLI_GUARD,
    }
    print(f"      flujos={len(G)}  precision={prec:.4f}  recall={rec:.4f}  f1={f1:.4f}")
    print(f"      TN={tn} FP={fp} FN={fn} TP={tp} | FP sobre benigno={fp/(fp+tn):.3%}")
    print(f"      prediccion ({len(G)} flujos): {t_guard:.2f}s")
except Exception as e:
    import traceback; traceback.print_exc()
    RESULTADOS['T2'] = {'error': str(e)}
    print(f"      [ERROR] {e}")

# ---------------------------------------------------------------------------
# T3. Cadena completa on_flow_ready con BD temporal (no toca produccion)
# ---------------------------------------------------------------------------
print("\n[T3] Cadena completa on_flow_ready (lote amplio, BD TEMPORAL)...")
try:
    # --- Redirigir a BD temporal y silenciar alertas/Telegram ---
    ids.conn.close()
    tmp_db = tempfile.mktemp(suffix='.db')
    ids.ruta_bd = tmp_db
    ids.conn = sqlite3.connect(tmp_db, check_same_thread=False)
    ids.cursor = ids.conn.cursor()
    ids.cursor.execute('''CREATE TABLE IF NOT EXISTS ataques (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, tipo_ataque TEXT,
        ip_src TEXT, protocolo TEXT, puerto INTEGER,
        confianza_ml REAL DEFAULT 0.0, features_json TEXT)''')
    ids.conn.commit()
    ids._enviar_alerta_async = lambda msg: None   # no spamear Telegram
    ids.ips_activo = False

    # Muestra balanceada de D2: 3000 benignos + 3000 SQLi
    d2 = pd.read_csv(os.path.join(BASE_DIR, "datasets", "SQLi_Zenodo", "D2_test.csv"))
    mue = d2[d2['Label'] == 0].sample(3000, random_state=1)
    mua = d2[d2['Label'] == 1].sample(3000, random_state=1)
    lote = pd.concat([mue, mua]).sample(frac=1, random_state=1).reset_index(drop=True)

    n_guard_conf = 0
    n_sqli_persistidos = 0
    t0 = time.time()
    for i, (_, r) in enumerate(lote.iterrows()):
        cic = netflow_a_cic_fecha(r)
        ip = f"TEST.IP.{i}.{r['Label']}"
        ids.on_flow_ready(ip, "10.0.0.5", cic)
        n_guard_conf += int((ids._features_sqli_guard(cic) is not None))
    t_cadena = time.time() - t0

    rows = ids.cursor.execute(
        "SELECT tipo_ataque, ip_src, confianza_ml, features_json FROM ataques").fetchall()
    n_sqli_persistidos = sum(1 for x in rows if 'Inyeccion_SQL' in x[0])
    con_trazabilidad = sum(1 for x in rows if x[3])
    # Recomputo exacto: precision/recall de la cadena (el ip guarda el label)
    import collections
    marcados = collections.defaultdict(int)
    for t, ip, conf, _ in rows:
        marcados[ip] = 1 if 'Inyeccion_SQL' in t else 0
    RESULTADOS['T3'] = {
        'flujos_procesados': len(lote),
        'sql_persistidos': n_sqli_persistidos,
        'con_trazabilidad_features_json': con_trazabilidad,
        'tiempo_cadena_s': round(t_cadena, 2),
        'filas_en_bd_tmp': len(rows),
    }
    tp3 = sum(1 for ip, m in marcados.items() if m == 1 and ip.endswith('.1'))
    fp3 = sum(1 for ip, m in marcados.items() if m == 1 and ip.endswith('.0'))
    fn3 = 3000 - tp3
    prec3 = tp3 / (tp3 + fp3) if (tp3 + fp3) else 0
    rec3 = tp3 / (tp3 + fn3) if (tp3 + fn3) else 0
    RESULTADOS['T3'].update({'precision_cadena': round(prec3, 4),
                             'recall_cadena': round(rec3, 4),
                             'tp': tp3, 'fp': fp3, 'fn': fn3})
    print(f"      flujos={len(lote)}  SQLi persistidos={n_sqli_persistidos} / 3000")
    print(f"      precision_cadena={prec3:.4f} recall_cadena={rec3:.4f} (tp={tp3} fp={fp3} fn={fn3})")
    print(f"      con trazabilidad features_json={con_trazabilidad}")
    print(f"      tiempo cadena ({len(lote)} flujos): {t_cadena:.2f}s")
    ids.conn.close()
    os.remove(tmp_db)
except Exception as e:
    import traceback; traceback.print_exc()
    RESULTADOS['T3'] = {'error': str(e)}
    print(f"      [ERROR] {e}")

# ---------------------------------------------------------------------------
# T4. Exportador de logs
# ---------------------------------------------------------------------------
print("\n[T4] Exportador de logs (log_exporter)...")
try:
    from log_exporter import registrar_bloqueo_log
    ip_prueba = "203.0.113.199"
    registrar_bloqueo_log(ip_prueba, "BLOQUEO_TEST_MASIVO", 24)
    # Verificar que existe un log .log reciente con la linea
    # registrar_bloqueo_log escribe en logs_ciberseguridad/logs_bloqueos.log
    logs_dir = os.path.join(BASE_DIR, "logs_ciberseguridad")
    ruta_bloqueos = os.path.join(logs_dir, "logs_bloqueos.log")
    encontrado = False
    if os.path.exists(ruta_bloqueos):
        contenido = open(ruta_bloqueos, encoding='utf-8', errors='ignore').read()
        encontrado = ip_prueba in contenido and 'TEST_MASIVO' in contenido
    archivos = [f for f in os.listdir(logs_dir) if f.endswith('.log')]
    RESULTADOS['T4'] = {
        'archivos_log': archivos,
        'linea_bloqueo_escrita': encontrado,
        'ruta_bloqueos': ruta_bloqueos,
    }
    print(f"      archivos .log: {len(archivos)} | linea test en logs_bloqueos.log: {encontrado}")
except Exception as e:
    import traceback; traceback.print_exc()
    RESULTADOS['T4'] = {'error': str(e)}
    print(f"      [ERROR] {e}")

# ---------------------------------------------------------------------------
# Resumen
# ---------------------------------------------------------------------------
print("\n" + "=" * 70)
print(" RESUMEN RESULTADOS")
print("=" * 70)
for k, v in RESULTADOS.items():
    print(f"\n  {k}:")
    for kk, vv in v.items():
        print(f"      {kk}: {vv}")

# Guardar informe para referencia
out = os.path.join(BASE_DIR, "informe_test_masivo.json")
with open(out, 'w', encoding='utf-8') as f:
    json.dump(RESULTADOS, f, ensure_ascii=False, indent=2)
print(f"\n  Informe guardado: {out}")
print("\n[FIN] Tests masivos ejecutados.")