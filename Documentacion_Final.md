# Documentación de Mejoras: Sistema de Detección y Prevención de Intrusiones (IDS/IPS) UNIPAZ

Este documento resume todas las correcciones, mejoras visuales y de arquitectura implementadas en el proyecto del IDS/IPS basado en Python, Scapy y Machine Learning.

---

## 1. Captura de Tráfico en Windows (Scapy)
El sistema originalmente no detectaba ningún paquete en la interfaz porque Windows y Scapy tienen dificultades para leer tráfico de Capa 3 de forma nativa.
* **Solución:** Se forzó el uso del driver de bajo nivel agregando `conf.use_pcap = True` en `ids.py`.
* **Beneficio:** El sniffer ahora captura correctamente todos los paquetes (TCP/UDP/ICMP) en tiempo real usando Npcap.

---

## 2. Ajuste de Umbrales Heurísticos
Los umbrales originales del IDS causaban dos problemas: o eran muy altos para la simulación de prueba, o muy bajos provocando **falsos positivos** con tráfico normal de navegación (ej. viendo YouTube o descargando archivos).
* **Solución:** Se ajustaron los umbrales en `ids.py`:
  - `THRESHOLD_SYN_FLOOD = 10` (Bajo, porque los paquetes SYN puros son raros en tráfico normal).
  - `THRESHOLD_DDOS = 500` (Alto, para no confundirlo con tráfico pesado legítimo).
  - `PORT_SCAN_THRESHOLD = 10` (Bajo, buscar en 10 puertos distintos en un segundo es una clara señal de escaneo).
  - `THRESHOLD_UDP_FLOOD = 500` (Alto, para soportar tráfico DNS/Streaming intenso).

---

## 3. Mejora del Panel SOC de Respuesta Activa (IPS)
La pestaña original del IPS era muy básica (solo 3 columnas) y no ofrecía información vital en tiempo real.
* **Solución:** Se reescribió por completo la función `setup_ips_tab()` en `interfasc.py`:
  - **Tabla de 7 columnas:** Hora, IP Bloqueada, Tipo de Ataque, Severidad, Acción Aplicada, Estado y Tiempo Restante.
  - **Badges de Resumen:** Indicadores visuales en la parte superior (Total, Activos, Expirados, Último ataque).
  - **Countdown en Vivo:** Se implementó un `QTimer` que restaula segundos visualmente en la tabla. Al llegar a 0, la fila cambia a "Expirado" de forma automática.
  - **Tracking Visual:** Ahora el botón "Desbloquear" no borra la fila, sino que la marca de azul como "Desbloqueado", manteniendo un historial visible.
  - **Manejo de Permisos (Bloqueo Simulado):** Si el programa no se ejecuta como Administrador y el Firewall de Windows rechaza el comando, el panel ya no falla silenciosamente; en su lugar, indica "Bloqueo simulado" en la tabla para seguir monitoreando.

---

## 4. Corrección de la Lógica de Bloqueo (IDS vs ML)
Existía un error de diseño donde el IPS **se negaba a bloquear una IP** si la Inteligencia Artificial tenía una confianza menor al 70%, ignorando por completo que las reglas heurísticas ya habían confirmado el ataque al 100%.
* **Solución:** Modificamos la función temporal en `ids.py`. Ahora el IDS obedece la siguiente regla:
  - Si el modelo ML clasifica el ataque con **alta confianza (>= 70%)**, usa el veredicto del ML y bloquea.
  - Si el ML está inseguro (**< 70%**), cede el control a la heurística. Si la regla heurística dicta que es un ataque crítico (Exploit, SYN Flood, etc.), el sistema **bloquea inmediatamente la IP** asegurando la protección.

---

## 5. Entrenamiento del Modelo de Machine Learning (IA)
El código en `CEREBRO.py` estaba preparado para usar un modelo de Ensamble (Random Forest + Redes Neuronales MLP + XGBoost), pero los archivos de entrenamiento (`.pkl`) no existían porque faltaba el dataset base.
* **Solución:** 
  1. Creamos `generar_dataset.py`, un script que sintetizó un archivo CSV (`escanerpuertos.csv`) con **20,000 registros de tráfico de red realista**, compuesto por 60% tráfico interactivo normal y 40% de 6 diferentes ataques severos (incluyendo inyecciones SQL y UDP Floods).
  2. Ejecutamos el pipeline de `CEREBRO.py` con herramientas profesionales de balanceo de clases (`SMOTE`).
  3. **Resultado:** El modelo alcanzó un **Accuracy (Precisión) del 91.90%**. Los archivos de predicciones fueron generados, y ahora la tabla de "Tráfico en Vivo" muestra directamente las deducciones con confirmación en porcentajes: `(ML: 98.4%)`.

---

## 6. Simulador Avanzado de Ataques Red (Pentesting)
El script original de pruebas enviaba paquetes uno a uno usando la IP local de la computadora, lo cual era ignorado por el IDS (ya que el IDS descarta ataques cuyo origen es la máquina local para evitar bucles) y además era inyectado directamentente a Capa 3, haciéndolo invisible para el monitor de Windows.
* **Solución:** 
  - Se programó un nuevo script interactivo unificado: **`simular_varios_ataques.py`**.
  - Este envía tramas en Capa 2 puras (Ethernet) con `sendp()`, lo que garantiza que Scapy capture los paquetes en sistemas Windows.
  - **4 Modos de ataque a elegir:** Port Scan, DDoS (Botnet de IPs), UDP Flood y Exploits (FTP/SSH/SMB).
  - Incluye **generación de IPs falsas** (IP Spoofing) aleatorias en cada ejecución. Esto arregló el "misterio" final donde la interfaz parecía dejar de bloquear ataques, cuando en realidad la IP hardcodeada ya estaba bloqueada (por ende, el IPS la ignoraba silenciosamente).

---
---

## 7. Glosario de Amenazas (Modelado ML)
Para facilitar la interpretación de los resultados en el Dashboard, se ha estandarizado el siguiente glosario de anomalías:

*   **Inyección SQL (Tipo 1):** Intentos de inyectar comandos maliciosos en peticiones HTTP para extraer o borrar datos de la base de datos.
*   **Posible Exploit (Tipo 4):** Tráfico dirigido a puertos sensibles (21, 22, 445, 3389) que indica un intento de aprovechar una vulnerabilidad de software.
*   **SYN Flood (Tipo 5):** Ataque de denegación de servicio que busca agotar las conexiones del servidor enviando paquetes de inicio (SYN) sin completarlos.
*   **UDP Flood (Tipo 6):** Saturación de la red mediante el envío masivo de paquetes UDP, común en ataques volumétricos.
*   **Anomalías Tipo 9 (Otros/Varios):** Una categoría especial que agrupa el tráfico normal y ataques que, debido a su baja frecuencia o agrupación en el preprocesamiento, se identifican como "comportamiento inusual general".

---
*Hecho por Antigravity AI.*
