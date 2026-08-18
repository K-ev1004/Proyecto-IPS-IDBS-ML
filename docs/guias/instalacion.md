# Guía de instalación

Guía paso a paso para poner en marcha el sistema IDS/IPS en **Windows** (entorno objetivo).

## 1. Requisitos del sistema

| Componente | Mínimo recomendado |
|---|---|
| SO | Windows 10/11 (64 bits) |
| Python | 3.10+ (64 bits) en `PATH` |
| Npcap | Última versión estable (instalar como Administrador) |
| GPU | Opcional: NVIDIA + drivers CUDA para entrenar con `task_type='GPU'` |
| Disco | ~1.5 GB libres (modelos + datasets) |

## 2. Instalar dependencias

```powershell
# Entorno virtual (recomendado)
python -m venv venv
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

`requirements.txt` incluye: `catboost`, `pandas`, `numpy`, `scikit-learn`,
`imbalanced-learn`, `joblib`, `tqdm`, `PyQt5`, `PyQt-Fluent-Widgets`, `matplotlib`,
`scapy`, `paramiko`, `requests`.

> [!TIP]
> Si el entrenamiento no dispone de GPU, cambiar `task_type='GPU'` por `'CPU'` en
> `CEREBRO_V5.py` / `entrenar_sqli_guard.py`.

## 3. Verificar la captura

El motor usa Scapy con `conf.use_pcap = True`, por lo que necesita **Npcap** instalado y
preferiblemente ejecución con permisos de administrador:

```powershell
sc query npcap
```

Si la captura no ve paquetes en tu interfaz, comprueba la interfaz activa y ajusta `iface`
en `ids.iniciar_monitoreo()`.

## 4. Comprobar los modelos

El proyecto espera estos artefactos en `Modelos_Entrenados/`:

- `pipeline_catboost_v5.pkl`, `selected_features_v5.pkl`, `label_encoder_v5.pkl`
- `sqli_guard.pkl`, `sql_guard_features.pkl`

Si clonaste el repo y los `.pkl` no bajaron (Git LFS):

```powershell
git lfs pull
```

> [!NOTE]
> Si faltan los modelos, el IDS seguirá funcionando con **detección heurística** únicamente
> (se imprime un aviso en consola).

## 5. Primer arranque

```powershell
python interfasc.py
```

En la GUI puedes iniciar/detener el monitoreo desde la pestaña correspondiente y ajustar
los umbrales ML en `Configuración → Umbrales del Motor ML`.

## Solución de problemas

| Síntoma | Causa probable | Acción |
|---|---|---|
| No se captura tráfico | Npcap ausente / interfaz incorrecta | Reinstalar Npcap, revisar `iface` |
| `ImportError: qfluentwidgets` | Falta PyQt-Fluent-Widgets | `pip install PyQt-Fluent-Widgets` |
| Modelo no se carga | `.pkl` no presentes | `git lfs pull` |
| Bloques siempre "simulado" | Sin acceso SSH al MikroTik | Revisar credenciales en `mikrotik_api.py` o modo semi-autónomo |
