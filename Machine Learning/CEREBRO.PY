import pandas as pd
import numpy as np
import socket
import struct
import joblib
import warnings
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.pipeline import Pipeline
from imblearn.pipeline import Pipeline as ImbPipeline
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
import matplotlib.pyplot as plt
import seaborn as sns

warnings.filterwarnings("ignore")

# --- Función para convertir IP a entero ---
def ip_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except socket.error:
        return 0

# --- 1) Cargar CSV original y preprocesar ---
print("📥 Cargando y preprocesando datos...")

df = pd.read_csv('Dataset/escanerpuertos.csv', encoding='latin-1', on_bad_lines='skip')
df = df.dropna()

# Convertir IPs a enteros
df['src_ip_int'] = df['src_ip'].apply(ip_to_int)
df['dst_ip_int'] = df['dst_ip'].apply(ip_to_int)

# Codificar columnas categóricas
protocol_encoder = LabelEncoder()
flag_encoder = LabelEncoder()
tipo_ataque_encoder = LabelEncoder()

df['protocol_encoded'] = protocol_encoder.fit_transform(df['protocol'])
df['flag_encoded'] = flag_encoder.fit_transform(df['flag'])
df['tipo_ataque_encoded'] = tipo_ataque_encoder.fit_transform(df['tipo_ataque'])

# Extraer hora del timestamp
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
df['hour'] = df['timestamp'].dt.hour.fillna(0).astype(int)

# Guardar encoders para uso futuro
joblib.dump(protocol_encoder, 'protocol_encoder.pkl')
joblib.dump(flag_encoder, 'flag_encoder.pkl')
joblib.dump(tipo_ataque_encoder, 'tipo_ataque_encoder.pkl')

# Ingeniería de características extra (si quieres puedes añadir la de puerto y hora_categoria aquí)

# Variables para entrenamiento
features = ['src_ip_int', 'dst_ip_int', 'dst_port', 'protocol_encoded', 'flag_encoded', 'hour']
X_raw = df[features]
y_raw = df['tipo_ataque_encoded']

# Agrupar clases minoritarias (opcional)
y_raw = y_raw.replace({0: 9, 2: 9, 3: 9})

# Ajustar el encoder SOLO con las clases finales
tipo_ataque_encoder = LabelEncoder()
tipo_ataque_encoder.fit(y_raw)
joblib.dump(tipo_ataque_encoder, 'tipo_ataque_encoder.pkl')

# Selección de características
selector = SelectKBest(score_func=f_classif, k=6)  # Usa k=6 porque tienes 6 features
X_selected = selector.fit_transform(X_raw, y_raw)
selected_features = X_raw.columns[selector.get_support(indices=True)]

# División train-test
X_train, X_test, y_train, y_test = train_test_split(
    pd.DataFrame(X_selected, columns=selected_features),
    y_raw, test_size=0.2, stratify=y_raw, random_state=42
)

# Modelo ensamble
ensemble_model = VotingClassifier(estimators=[
    ('rf', RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)),
    ('mlp', MLPClassifier(hidden_layer_sizes=(64, 64), max_iter=300, early_stopping=True, random_state=42)),
    ('xgb', XGBClassifier(eval_metric='mlogloss', use_label_encoder=False, random_state=42))
], voting='soft', n_jobs=-1)

# Pipeline final con SMOTE y escalado
pipeline = ImbPipeline([
    ('smote', SMOTE(random_state=42)),
    ('scaler', StandardScaler()),
    ('clf', ensemble_model)
])

# Entrenar modelo
print("🚀 Entrenando modelo...")
pipeline.fit(X_train, y_train)

# Evaluar modelo
print("📊 Evaluando modelo en test...")
y_pred = pipeline.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
print(f"F1-macro: {f1_score(y_test, y_pred, average='macro')*100:.2f}%")
print(classification_report(y_test, y_pred, zero_division=1))

# Guardar modelo y features seleccionadas
joblib.dump(pipeline, 'modelo_ensamble_optimizado.pkl')
joblib.dump(selected_features.tolist(), 'features_seleccionadas.pkl')

# Función para preprocesar datos nuevos usando encoders y selección
def preprocesar_datos(ip_src, ip_dst, puerto, protocolo, flag, hora):
    # Cargar encoders
    protocol_encoder = joblib.load('protocol_encoder.pkl')
    flag_encoder = joblib.load('flag_encoder.pkl')
    selected_features = joblib.load('features_seleccionadas.pkl')

    # Convertir IP a int
    src_ip_int = ip_to_int(ip_src)
    dst_ip_int = ip_to_int(ip_dst)

    # Codificar protocolo y flag
    try:
        protocolo_encoded = protocol_encoder.transform([protocolo])[0]
    except ValueError:
        print(f"⚠ Protocolo '{protocolo}' no reconocido, asignando valor -1")
        protocolo_encoded = -1

    try:
        flag_encoded = flag_encoder.transform([flag])[0]
    except ValueError:
        print(f"⚠ Flag '{flag}' no reconocido, asignando valor -1")
        flag_encoded = -1

    datos = {
        'src_ip_int': src_ip_int,
        'dst_ip_int': dst_ip_int,
        'dst_port': puerto,
        'protocol_encoded': protocolo_encoded,
        'flag_encoded': flag_encoded,
        'hour': hora
    }

    faltantes = set(selected_features) - set(datos.keys())
    if faltantes:
        print(f"❌ Faltan características: {faltantes}")
        return []

    datos_ordenados = [datos[feature] for feature in selected_features]
    return datos_ordenados

# Ejemplo de predicción con nuevos datos
datos_prueba = preprocesar_datos("192.168.1.1", "192.168.1.2", 80, "TCP", "S", 15)
print("Datos preprocesados para predicción:", datos_prueba)

if datos_prueba:
    modelo_cargado = joblib.load('modelo_ensamble_optimizado.pkl')
    prediccion = modelo_cargado.predict([datos_prueba])
    print("Predicción para nuevos datos:", prediccion)
else:
    print("❌ No se pudo generar datos válidos para la predicción.")
# --- Fin del script ---