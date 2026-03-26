# =============================================================================
# CEREBRO.PY — Módulo principal de entrenamiento y predicción del modelo IDS
# Sistema de Detección de Intrusiones (IDS) basado en Machine Learning
# =============================================================================

# --- BLOQUE DE IMPORTACIONES ---
# pandas: Librería para manipulación y análisis de datos en estructuras tipo tabla (DataFrame)
import pandas as pd

# numpy: Librería para operaciones matemáticas y manejo de arreglos numéricos multidimensionales
import numpy as np

# socket: Módulo estándar de Python para operaciones de red; aquí se usa para validar IPs
import socket

# struct: Módulo estándar para convertir datos binarios a tipos de Python (bytes ↔ enteros)
import struct

# joblib: Librería para serializar/deserializar objetos Python (guardar/cargar modelos entrenados)
import joblib

# warnings: Módulo estándar para controlar mensajes de advertencia del sistema
import warnings

# train_test_split: Función para dividir el dataset en conjuntos de entrenamiento y prueba
from sklearn.model_selection import train_test_split

# Métricas de evaluación del modelo de clasificación
from sklearn.metrics import (
    classification_report,  # Reporte detallado por clase (precision, recall, f1)
    accuracy_score,          # Porcentaje global de predicciones correctas
    f1_score,                # Media armónica entre precisión y recall (útil con clases desbalanceadas)
    confusion_matrix         # Matriz que muestra verdaderos/falsos positivos y negativos
)

# LabelEncoder: Convierte etiquetas de texto a valores numéricos enteros (ej: "TCP" → 0)
# StandardScaler: Normaliza los datos restando la media y dividiendo entre la desviación estándar
from sklearn.preprocessing import LabelEncoder, StandardScaler

# SelectKBest + f_classif: Selección de las K mejores características usando análisis de varianza (ANOVA F-test)
from sklearn.feature_selection import SelectKBest, f_classif

# Pipeline de scikit-learn: Encadena pasos de transformación + modelo en una sola unidad
from sklearn.pipeline import Pipeline

# ImbPipeline: Versión de Pipeline compatible con técnicas de balanceo de clases (imblearn)
from imblearn.pipeline import Pipeline as ImbPipeline

# SMOTE: Synthetic Minority Over-sampling Technique — genera muestras sintéticas de clases minoritarias
from imblearn.over_sampling import SMOTE

# RandomForestClassifier: Ensamble de árboles de decisión con votación por mayoría
# VotingClassifier: Combina múltiples clasificadores y toma decisiones por votación
from sklearn.ensemble import RandomForestClassifier, VotingClassifier

# MLPClassifier: Red neuronal artificial (Multi-Layer Perceptron) para clasificación
from sklearn.neural_network import MLPClassifier

# XGBClassifier: Algoritmo de Gradient Boosting extremo; alta precisión en datos tabulares
from xgboost import XGBClassifier

# matplotlib y seaborn: Librerías de visualización de datos y gráficas estadísticas
import matplotlib.pyplot as plt
import seaborn as sns

# Silencia advertencias de versiones y parámetros deprecados para una salida más limpia
warnings.filterwarnings("ignore")


# =============================================================================
# FUNCIÓN: ip_to_int
# Propósito: Convierte una dirección IP en formato string a su representación entera
# Motivo: Los modelos ML no trabajan con strings; necesitan valores numéricos continuos
# Ejemplo: "192.168.1.1" → 3232235777
# =============================================================================
def ip_to_int(ip):
    try:
        # socket.inet_aton: Convierte la IP string a 4 bytes en formato binario de red
        # struct.unpack("!I", ...): Interpreta esos 4 bytes como un entero de 32 bits sin signo
        # "!" = big-endian (orden de red), "I" = unsigned int de 32 bits
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except socket.error:
        # Si la IP es inválida o está malformada, retorna 0 para no interrumpir el flujo
        return 0


# =============================================================================
# FASE 1: CARGA Y PREPROCESAMIENTO DE DATOS
# =============================================================================
print("[*] Cargando y preprocesando datos...")

# Carga el archivo CSV del dataset de tráfico de red
# encoding='latin-1': Maneja caracteres especiales que UTF-8 no puede procesar
# on_bad_lines='skip': Ignora filas con formato incorrecto en lugar de lanzar error
df = pd.read_csv('Dataset/escanerpuertos.csv', encoding='latin-1', on_bad_lines='skip')

# Elimina todas las filas que contengan al menos un valor NaN
# Evita errores en transformaciones y entrenamiento por datos incompletos
df = df.dropna()

# Aplica la función ip_to_int a cada valor de las columnas de IP
# apply(): ejecuta una función sobre cada elemento de una Serie (columna)
# Resultado: nuevas columnas numéricas listas para el modelo
df['src_ip_int'] = df['src_ip'].apply(ip_to_int)
df['dst_ip_int'] = df['dst_ip'].apply(ip_to_int)

# --- CODIFICACIÓN DE VARIABLES CATEGÓRICAS ---
# Se instancian tres encoders independientes para poder guardarlos y reutilizarlos
protocol_encoder = LabelEncoder()   # Para la columna 'protocol' (ej: TCP, UDP, ICMP)
flag_encoder = LabelEncoder()       # Para la columna 'flag' (ej: S, A, F, R, P)
tipo_ataque_encoder = LabelEncoder()  # Para la columna objetivo 'tipo_ataque'

# fit_transform(): Aprende el mapeo de etiquetas y transforma la columna en una sola operación
# Ejemplo de resultado: {'DDoS':0, 'Normal':1, 'Port Scan':2, 'SYN Flood':3}
df['protocol_encoded'] = protocol_encoder.fit_transform(df['protocol'])
df['flag_encoded'] = flag_encoder.fit_transform(df['flag'])
df['tipo_ataque_encoded'] = tipo_ataque_encoder.fit_transform(df['tipo_ataque'])

# --- EXTRACCIÓN DE CARACTERÍSTICAS TEMPORALES ---
# Convierte la columna timestamp a tipo datetime de pandas
# errors='coerce': Si un valor no puede convertirse, lo convierte en NaT (Not a Time) en lugar de error
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

# Extrae solo la hora del día (0-23) como nueva característica
# .dt.hour: Accede al atributo de hora del tipo datetime
# .fillna(0): Reemplaza NaT con 0 para no perder registros
# .astype(int): Garantiza tipo entero para compatibilidad con el modelo
df['hour'] = df['timestamp'].dt.hour.fillna(0).astype(int)

# --- SERIALIZACIÓN DE ENCODERS ---
# Guarda los encoders en archivos .pkl (pickle) para poder usarlos en producción
# sin necesidad de reentrenar; garantiza consistencia en la transformación de nuevos datos
joblib.dump(protocol_encoder, 'protocol_encoder.pkl')
joblib.dump(flag_encoder, 'flag_encoder.pkl')
joblib.dump(tipo_ataque_encoder, 'tipo_ataque_encoder.pkl')


# =============================================================================
# FASE 2: INGENIERÍA DE CARACTERÍSTICAS Y PREPARACIÓN DE DATOS
# =============================================================================

# Define el vector de características (features) que usará el modelo
# Se excluyen columnas originales de texto y se usan solo versiones numéricas
features = ['src_ip_int', 'dst_ip_int', 'dst_port', 'protocol_encoded', 'flag_encoded', 'hour']

# X_raw: Matriz de características (variables independientes)
X_raw = df[features]

# y_raw: Vector objetivo (variable dependiente a predecir)
y_raw = df['tipo_ataque_encoded']

# --- AGRUPACIÓN DE CLASES MINORITARIAS ---
# Las clases con muy pocas muestras dificultan el aprendizaje del modelo
# Se reemplazan las clases 0, 2, 3 (minoritarias) mapeándolas a la clase 9 (grupo "Otros")
# Esto reduce el desbalance extremo y mejora la generalización
y_raw = y_raw.replace({0: 9, 2: 9, 3: 9})

# Se recrea el encoder con las clases finales después del agrupamiento
# Es necesario reajustar porque el mapping anterior cambió la distribución de clases
tipo_ataque_encoder = LabelEncoder()
tipo_ataque_encoder.fit(y_raw)
joblib.dump(tipo_ataque_encoder, 'tipo_ataque_encoder.pkl')  # Sobreescribe el anterior


# =============================================================================
# FASE 3: SELECCIÓN DE CARACTERÍSTICAS (Feature Selection)
# =============================================================================

# SelectKBest con f_classif: Aplica ANOVA F-test para medir la relación estadística
# entre cada característica y la variable objetivo
# k=6: Selecciona las 6 características más relevantes estadísticamente
# (en este caso k=6 equivale a todas las features disponibles)
selector = SelectKBest(score_func=f_classif, k=6)

# fit_transform: Calcula los scores de relevancia y filtra las columnas seleccionadas
X_selected = selector.fit_transform(X_raw, y_raw)

# Recupera los nombres de las columnas que pasaron el filtro
# get_support(indices=True): retorna los índices enteros de las features seleccionadas
selected_features = X_raw.columns[selector.get_support(indices=True)]


# =============================================================================
# FASE 4: DIVISIÓN DEL DATASET — TRAIN/TEST SPLIT
# =============================================================================

# Divide los datos en 80% entrenamiento y 20% prueba
# test_size=0.2: 20% de los datos reservados para evaluación
# stratify=y_raw: Mantiene la proporción original de clases en ambas particiones (evita sesgo)
# random_state=42: Semilla fija para reproducibilidad (mismos resultados en cada ejecución)
X_train, X_test, y_train, y_test = train_test_split(
    pd.DataFrame(X_selected, columns=selected_features),
    y_raw,
    test_size=0.2,
    stratify=y_raw,
    random_state=42
)


# =============================================================================
# FASE 5: CONSTRUCCIÓN DEL MODELO ENSAMBLE
# =============================================================================

# VotingClassifier: Combina tres modelos distintos bajo una estrategia de votación suave
# Cada submodelo genera probabilidades por clase; se promedian para la decisión final
ensemble_model = VotingClassifier(
    estimators=[
        # Random Forest: Robusto ante overfitting, maneja variables no lineales
        # class_weight='balanced': Ajusta pesos internamente para compensar clases desbalanceadas
        ('rf', RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)),

        # Red Neuronal MLP: Captura relaciones complejas y no lineales entre características
        # hidden_layer_sizes=(64,64): Dos capas ocultas de 64 neuronas cada una
        # early_stopping=True: Detiene el entrenamiento si la validación no mejora (evita sobreajuste)
        ('mlp', MLPClassifier(hidden_layer_sizes=(64, 64), max_iter=300, early_stopping=True, random_state=42)),

        # XGBoost: Gradient Boosting optimizado; alta precisión en clasificación tabular
        # eval_metric='mlogloss': Función de pérdida log-loss para clasificación multiclase
        ('xgb', XGBClassifier(eval_metric='mlogloss', use_label_encoder=False, random_state=42))
    ],
    voting='soft',  # Usa probabilidades promediadas en lugar de votos directos (más preciso)
    n_jobs=-1       # Usa todos los núcleos del CPU disponibles para paralelizar el entrenamiento
)

# Pipeline final: Encadena tres pasos en orden obligatorio
# 1. SMOTE: Genera muestras sintéticas de clases minoritarias para balancear el entrenamiento
# 2. StandardScaler: Normaliza los datos (media=0, desv.estándar=1); requerido por MLP y mejora XGB/RF
# 3. clf: El clasificador ensamble que aprende sobre los datos transformados
pipeline = ImbPipeline([
    ('smote', SMOTE(random_state=42)),
    ('scaler', StandardScaler()),
    ('clf', ensemble_model)
])


# =============================================================================
# FASE 6: ENTRENAMIENTO Y EVALUACIÓN
# =============================================================================
print("[+] Entrenando modelo...")

# .fit(): Ejecuta el pipeline completo sobre los datos de entrenamiento
# Internamente: aplica SMOTE → escala → entrena el ensamble
pipeline.fit(X_train, y_train)

print("[~] Evaluando modelo en test...")

# .predict(): Genera predicciones sobre el conjunto de prueba (datos no vistos durante entrenamiento)
y_pred = pipeline.predict(X_test)

# accuracy_score: Proporción de predicciones correctas sobre el total
print(f"Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")

# f1_score con average='macro': Calcula F1 por clase y promedia sin ponderar por frecuencia
# Útil para datasets desbalanceados donde el accuracy puede ser engañoso
print(f"F1-macro: {f1_score(y_test, y_pred, average='macro')*100:.2f}%")

# classification_report: Muestra precisión, recall y F1 por cada clase del modelo
# zero_division=1: Evita errores de división por cero en clases con pocas muestras
print(classification_report(y_test, y_pred, zero_division=1))

# --- GUARDADO DEL MODELO ENTRENADO ---
# Serializa el pipeline completo (incluye SMOTE, scaler y ensamble) en un archivo .pkl
joblib.dump(pipeline, 'modelo_ensamble_optimizado.pkl')

# Guarda la lista de features seleccionadas para garantizar consistencia en predicciones futuras
joblib.dump(selected_features.tolist(), 'features_seleccionadas.pkl')


# =============================================================================
# FUNCIÓN: preprocesar_datos
# Propósito: Transforma datos crudos de una conexión de red al formato que espera el modelo
# Parámetros:
#   ip_src     — IP de origen de la conexión
#   ip_dst     — IP de destino de la conexión
#   puerto     — Puerto de destino (número entero)
#   protocolo  — Protocolo de red (ej: "TCP", "UDP")
#   flag       — Bandera TCP (ej: "S", "A", "F")
#   hora       — Hora del paquete (0-23)
# Retorna: Lista ordenada de valores numéricos lista para alimentar al modelo
# =============================================================================
def preprocesar_datos(ip_src, ip_dst, puerto, protocolo, flag, hora):
    # Carga los encoders previamente entrenados para garantizar el mismo mapeo
    protocol_encoder = joblib.load('protocol_encoder.pkl')
    flag_encoder = joblib.load('flag_encoder.pkl')

    # Carga el orden exacto de features que el modelo espera como entrada
    selected_features = joblib.load('features_seleccionadas.pkl')

    # Convierte IPs a enteros usando la misma función del preprocesamiento original
    src_ip_int = ip_to_int(ip_src)
    dst_ip_int = ip_to_int(ip_dst)

    # Codifica el protocolo; si es desconocido asigna -1 para no interrumpir la predicción
    try:
        protocolo_encoded = protocol_encoder.transform([protocolo])[0]
    except ValueError:
        print(f"[!] Protocolo '{protocolo}' no reconocido, asignando valor -1")
        protocolo_encoded = -1

    # Codifica el flag; si es desconocido asigna -1 con el mismo criterio
    try:
        flag_encoded = flag_encoder.transform([flag])[0]
    except ValueError:
        print(f"[!] Flag '{flag}' no reconocido, asignando valor -1")
        flag_encoded = -1

    # Construye un diccionario con todos los valores transformados
    datos = {
        'src_ip_int': src_ip_int,
        'dst_ip_int': dst_ip_int,
        'dst_port': puerto,
        'protocol_encoded': protocolo_encoded,
        'flag_encoded': flag_encoded,
        'hour': hora
    }

    # Verificación de integridad: detecta si falta alguna característica requerida
    faltantes = set(selected_features) - set(datos.keys())
    if faltantes:
        print(f"[X] Faltan características: {faltantes}")
        return []

    # Ordena los valores según el orden exacto que espera el modelo entrenado
    # Esto es crítico: el modelo fue entrenado con las features en un orden específico
    datos_ordenados = [datos[feature] for feature in selected_features]
    return datos_ordenados


# =============================================================================
# BLOQUE DE PRUEBA — Ejemplo de predicción con datos sintéticos
# =============================================================================

# Simula una conexión HTTP normal desde 192.168.1.1 hacia 192.168.1.2, puerto 80, hora 15
datos_prueba = preprocesar_datos("192.168.1.1", "192.168.1.2", 80, "TCP", "S", 15)
print("Datos preprocesados para predicción:", datos_prueba)

if datos_prueba:
    # Carga el pipeline completo desde disco
    modelo_cargado = joblib.load('modelo_ensamble_optimizado.pkl')

    # .predict(): Recibe una lista de vectores; se envuelve en lista para representar un solo sample
    prediccion = modelo_cargado.predict([datos_prueba])
    print("Predicción para nuevos datos:", prediccion)
else:
    print("[X] No se pudo generar datos válidos para la predicción.")

# =============================================================================
# FIN DEL SCRIPT — CEREBRO.PY
# =============================================================================
