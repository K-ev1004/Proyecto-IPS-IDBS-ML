# Documento del Proyecto: Sistema de Detección y Prevención de Intrusiones con Machine Learning (IDBS-IPS-ML)

---

## 1. INTRODUCCIÓN

La transformación digital en las instituciones educativas ha traído consigo un aumento significativo en la superficie de ataque cibernético. Las universidades, por su naturaleza abierta y su alta densidad de dispositivos conectados, se han convertido en blancos frecuentes de ciberataques como escaneo de puertos, ataques de denegación de servicio (DoS/DDoS), inyecciones SQL y explotación de vulnerabilidades. Según el informe de amenazas cibernéticas de Educause (2024), el sector educativo es uno de los más atacados a nivel global, solo superado por el sector salud y el gubernamental.

La Universidad Popular del Cesar (UNIPAZ), ubicada en Valledupar, Colombia, cuenta con una población estudiantil de aproximadamente 2,915 estudiantes distribuidos en tres bloques principales (Aulas, Biblioteca y Salones Externos), con una concurrencia simultánea de entre 1,100 y 1,750 dispositivos en horas pico. Su infraestructura de red está segmentada por VLANs y utiliza equipos como firewalls Sophos XGS 3300, routers MikroTik CCR, switches Raisecom y TP-Link Omada, y puntos de acceso UniFi/Ruckus. Sin embargo, la institución carece de un sistema de detección y prevención de intrusiones (IDS/IPS) dedicado que analice el tráfico interno más allá del firewall perimetral.

El presente proyecto propone el desarrollo e implementación de un Sistema de Detección y Prevención de Intrusiones basado en Machine Learning (IDBS-IPS-ML), diseñado específicamente para operar en el entorno de red de UNIPAZ. El sistema integra captura de tráfico en tiempo real mediante Scapy con Npcap, detección heurística de seis tipos de ataques (SYN Flood, DDoS Distribuido, Port Scanner, Posible Exploit, Inyección SQL y UDP Flood), clasificación mediante un modelo CatBoost con precisión del 91.9%, un módulo de respuesta activa (IPS) que bloquea IPs maliciosas vía firewall de Windows y MikroTik RouterOS, y un panel de control SOC (Security Operations Center) en tiempo real con interfaz PyQt5 Fluent Design.

---

## 2. DESCRIPCIÓN DEL PRODUCTO O SERVICIO

### 2.1 Nombre del Sistema
**IDBS-IPS-ML** (Intrusion Detection and Blocking System con Machine Learning)

### 2.2 Tipo de Producto
Sistema híbrido de Detección y Prevención de Intrusiones (IDS/IPS) de red basado en software libre, diseñado para operar en plataforma Windows con capacidad de bloqueo activo sobre infraestructura MikroTik.

### 2.3 Componentes del Sistema

| Componente | Descripción | Tecnología |
|---|---|---|
| Motor de Captura | Captura pasiva de paquetes mediante port mirroring (SPAN) | Scapy + Npcap |
| Analizador Heurístico | Detección por reglas de umbrales para 6 tipos de ataque | Python puro con contadores por IP |
| Motor de Flujos | Agrupación de paquetes en flujos bidireccionales con extracción de 22 características CIC-IDS2018 | `flujos_red.py` |
| Clasificador ML | Modelo de clasificación de tráfico en 7 categorías | CatBoost (91.9% accuracy) |
| Módulo IPS | Bloqueo activo de IPs maliciosas | Firewall de Windows (netsh/PowerShell) + SSH a MikroTik RouterOS |
| Panel de Control | Dashboard SOC en tiempo real con 4 pestañas | PyQt5 + qfluentwidgets + Matplotlib |
| Sistema de Alertas | Notificaciones push de ataques detectados | Telegram Bot API |
| Persistencia | Almacenamiento local de eventos y bloqueos | SQLite + CSV |

### 2.4 Funcionalidades Principales

1. **Captura de tráfico en tiempo real**: Monitoreo continuo de la interfaz de red seleccionada, capturando paquetes TCP, UDP e ICMP.
2. **Detección heurística multicapa**: Seis detectores independientes con umbrales configurables que identifican patrones de ataque inmediatamente.
3. **Clasificación inteligente por Machine Learning**: El modelo CatBoost analiza flujos de tráfico y clasifica cada uno en una de 7 categorías (Normal, SYN Flood, DDoS Distribuido, Port Scanner, Posible Exploit, Inyección SQL, UDP Flood).
4. **Lógica de decisión híbrida**: Combinación inteligente de heuristicas y ML — si el ML tiene alta confianza (≥70%), su veredicto prevalece; si no, las reglas heurísticas toman el control para garantizar la detección.
5. **Bloqueo activo de IPs**: Ejecución automática de reglas de bloqueo en el firewall de Windows y envío de comandos SSH al router MikroTik para añadir IPs a la lista negra.
6. **Dashboard SOC interactivo**: Visualización en tiempo real de eventos, tráfico, estadísticas avanzadas y controles IPS con temporizadores de desbloqueo.
7. **Alertas por Telegram**: Notificaciones instantáneas al personal de seguridad cuando se detecta un ataque crítico.

### 2.5 Usuarios Destinatarios

- **Personal de seguridad informática** de UNIPAZ (administradores de red, equipo de sistemas).
- **Estudiantes de último semestre** del programa de Ingeniería de Sistemas como proyecto de grado.

---

## 3. JUSTIFICACIÓN DEL PROYECTO

### 3.1 Problemática

La red de UNIPAZ atiende a aproximadamente 2,915 estudiantes con una infraestructura que, aunque correctamente segmentada y equipada con un firewall perimetral Sophos XGS 3300, carece de visibilidad sobre el tráfico interno entre VLANs y subredes. El firewall perimetral protege el perímetro, pero no detecta amenazas internas como:

- Escaneos de puertos entre estaciones de trabajo.
- Propagación de malware dentro del campus.
- Intentos de explotación de vulnerabilidades en servidores internos.
- Ataques de denegación de servicio originados desde dispositivos infectados dentro de la misma red.
- Inyecciones SQL dirigidas a bases de datos locales.

Además, el personal de sistemas de UNIPAZ no tiene acceso a los equipos de red (switches, routers, firewall) para implementar bloqueos manuales rápidos, lo que hace necesario un sistema automatizado que aplique contramedidas en tiempo real.

### 3.2 Importancia de los IDS/IPS en Instituciones Educativas

Los institutos educativos presentan características que los hacen particularmente vulnerables:

- **Alta densidad de dispositivos**: Cientos de dispositivos personales (laptops, smartphones) se conectan diariamente sin supervisión.
- **Red abierta por naturaleza**: El acceso a internet y la colaboración son pilares de la educación, lo que choca con modelos de seguridad restrictivos.
- **Recursos limitados**: La mayoría de las instituciones educativas, especialmente en países en desarrollo, no cuentan con presupuesto para soluciones comerciales de ciberseguridad.
- **Datos sensibles**: Se manejan datos personales de estudiantes, docentes y personal administrativo, así como sistemas críticos como notas y matrículas.

Un sistema IDS/IPS basado en software libre y Machine Learning representa una solución viable y escalable que permite a instituciones como UNIPAZ tener capacidades de detección y respuesta a intrusiones sin incurrir en costos de licenciamiento.

### 3.3 Brecha Tecnológica

Actualmente no existe en UNIPAZ un sistema de monitoreo continuo de tráfico de red con capacidades de detección por Machine Learning. La implementación de este proyecto llena ese vacío, proporcionando:

- Visibilidad en tiempo real del tráfico de red.
- Detección temprana de amenazas antes de que escalen.
- Respuesta automatizada para mitigar ataques en curso.
- Generación de evidencia forense para análisis posterior.
- Base para futuras mejoras en la postura de seguridad institucional.

---

## 4. ESTADO DEL ARTE DE LA INNOVACIÓN Y EL DESARROLLO TECNOLÓGICO

### 4.1 Sistemas IDS/IPS Tradicionales

La detección de intrusiones en redes tiene sus orígenes en el trabajo de Dorothy Denning (1987) con el modelo de detección de intrusiones en tiempo real. Desde entonces, han surgido herramientas ampliamente adoptadas:

- **Snort** (1998): Sistema IDS/IPS de código abierto basado en reglas, creado por Martin Roesch. Utiliza firmas para detectar patrones de ataque conocidos. Es el estándar de facto en IDS basados en firmas, pero tiene limitaciones frente a ataques desconocidos (zero-day).

- **Suricata** (2010): Desarrollado por la Open Information Security Foundation (OISF). Soporta multi-hilo, inspección de protocolos y detección basada en firmas y anomalías. Puede utilizar hardware de aceleración (AF_PACKET, CUDA).

- **Zeek** (antes Bro, 1995): Sistema de monitoreo de seguridad que se enfoca en análisis de tráfico de red y generación de logs estructurados, más que en bloqueo en tiempo real.

### 4.2 Machine Learning aplicado a la Ciberseguridad

La aplicación de Machine Learning en IDS ha evolucionado significativamente en la última década:

- **Random Forest**: Utilizado por Zhang et al. (2021) para clasificación de tráfico malicioso en redes SDN, alcanzando precisiones superiores al 95% en datasets como CIC-IDS2017.

- **Redes Neuronales Profundas (DNN)**: Vinayakumar et al. (2019) demostraron la efectividad de DNNs para detección de intrusiones a escala, con mejor rendimiento que métodos tradicionales de ML en datasets como NSL-KDD y CIC-IDS2017.

- **CatBoost**: Desarrollado por Yandex (2017), es un algoritmo de gradient boosting que maneja de forma nativa características categóricas y soporta aceleración por GPU. Estudios recientes (Hwang et al., 2020; Alqahtani et al., 2022) muestran que CatBoost supera a XGBoost y LightGBM en precisión y velocidad en tareas de clasificación de tráfico de red.

- **Autoencoders y Aprendizaje No Supervisado**: Utilizados para detección de anomalías, donde el modelo aprende el comportamiento "normal" de la red y señala desviaciones como potenciales ataques.

### 4.3 Datasets de Referencia

- **KDD Cup 1999 / NSL-KDD**: Dataset histórico, hoy considerado desactualizado pero útil como línea base.
- **CIC-IDS2017 / CSE-CIC-IDS2018**: Desarrollados por el Canadian Institute for Cybersecurity (CIC). Contienen tráfico realista con ataques modernos (DDoS, Brute Force, Infiltración, Web Attacks). Son los datasets más utilizados en investigación actual de IDS/ML.
- **CIC-DDoS2019**: Enfocado específicamente en ataques DDoS actuales (incluyendo reflexión/amplificación).

### 4.4 Soluciones Comerciales

- **Cisco Secure Network Analytics** (antes Stealthwatch): Utiliza ML para análisis de comportamiento de red.
- **Darktrace**: Plataforma de ciberseguridad basada en IA que utiliza algoritmos de aprendizaje auto-supervisado.
- **Fortinet FortiGate**: Firewalls de nueva generación con capacidades IDS/IPS integradas.

### 4.5 Posicionamiento del Proyecto

A diferencia de las soluciones comerciales (costosas y cerradas) y de las herramientas open source tradicionales como Snort (basadas en firmas), **IDBS-IPS-ML** ofrece:

| Característica | Snort | Suricata | Darktrace | IDBS-IPS-ML |
|---|---|---|---|---|
| Código abierto | Sí | Sí | No | Sí |
| ML para detección | No | Limitado | Sí | Sí (CatBoost) |
| Bloqueo automatizado | Sí | Sí | No | Sí (FW + MikroTik) |
| Interfaz SOC moderna | Limitada | Limitada | Sí | Sí (PyQt5 Fluent) |
| Costo | Gratuito | Gratuito | Alto | Gratuito |
| Alertas Telegram | No | No | Sí | Sí |
| Diseñado para Windows | No | Limitado | No | Sí |

---

## 5. METODOLOGÍA SCRUMBAN

### 5.1 Principios de Scrumban

Scrumban es una metodología híbrida que combina la estructura de Scrum con la flexibilidad y el enfoque de flujo continuo de Kanban. Fue formalizada por Corey Ladas en su libro *Scrumban: Essays on Kanban Systems for Lean Software Development* (2009). Los principios fundamentales aplicados a este proyecto son:

#### 1. Planificación por Demanda (Pull System)
No se planifica por sprints rígidos; las tareas se toman del backlog cuando hay capacidad disponible. Esto permite responder ágilmente a cambios en los requisitos del proyecto, como la necesidad de ajustar umbrales de detección o incorporar nuevos tipos de ataque.

#### 2. Límites de Trabajo en Progreso (WIP Limits)
Se establecen límites máximos de tareas en cada columna del tablero Kanban para evitar la sobrecarga del equipo (en este caso, un desarrollador individual). Ejemplo: máximo 2 tareas en "En Progreso" y 3 en "Revisión".

#### 3. Flujo Continuo con Retroalimentación
A diferencia de Scrum, no hay sprints con duración fija; el trabajo fluye de manera continua. Sin embargo, se mantienen reuniones periódicas de revisión (cada 1-2 semanas) para ajustar prioridades y revisar avances.

#### 4. Mejora Continua (Kaizen)
Al finalizar cada bloque de trabajo, se realiza una retrospectiva para identificar cuellos de botella y oportunidades de mejora. Por ejemplo, después de implementar el módulo heurístico se identificó la necesidad de ajustar umbrales, lo que se incorporó rápidamente al flujo.

#### 5. Visualización del Flujo de Trabajo
Todas las actividades se visualizan en un tablero Kanban con columnas que reflejan el estado de cada tarea, permitiendo identificar bloqueos y priorizar esfuerzos de forma transparente.

#### 6. Iteraciones Basadas en Entregas
Se definen hitos de entrega en lugar de sprints temporales. Cada hito representa un incremento funcional del sistema, por ejemplo: Hito 1 → Captura de tráfico funcional, Hito 2 → Detección heurística, Hito 3 → Integración del modelo ML, Hito 4 → Módulo IPS, Hito 5 → Dashboard SOC.

#### 7. Eventos de Scrum Adaptados
- **Daily Standup (adaptado)**: Revisión rápida diaria del tablero (equipo individual: auto-revisión).
- **Revisión del Backlog**: Cada 2 semanas se refinan las prioridades del backlog.
- **Retrospectiva**: Al completar cada hito de entrega.

### 5.2 Backlog del Proyecto

El backlog prioriza las actividades restantes y completadas del proyecto, organizadas por módulo:

#### MÓDULO 1: CAPTURA DE TRÁFICO ✅ (Completado)
| ID | Actividad | Prioridad | Estado |
|---|---|---|---|
| CAP-01 | Implementar captura con Scapy + Npcap en Windows | Alta | ✅ Completado |
| CAP-02 | Configurar modo SPAN en switch (simulado) | Alta | ✅ Completado |
| CAP-03 | Filtrado de tráfico local para evitar bucles | Media | ✅ Completado |
| CAP-04 | Pruebas de rendimiento en horarios pico | Media | 🔄 Pendiente |

#### MÓDULO 2: DETECCIÓN HEURÍSTICA ✅ (Completado)
| ID | Actividad | Prioridad | Estado |
|---|---|---|---|
| HEU-01 | Detector SYN Flood | Alta | ✅ Completado |
| HEU-02 | Detector DDoS Distribuido | Alta | ✅ Completado |
| HEU-03 | Detector Port Scanner | Alta | ✅ Completado |
| HEU-04 | Detector Posible Exploit | Alta | ✅ Completado |
| HEU-05 | Detector Inyección SQL | Alta | ✅ Completado |
| HEU-06 | Detector UDP Flood | Alta | ✅ Completado |
| HEU-07 | Ajuste de umbrales (calibración) | Alta | ✅ Completado |
| HEU-08 | Pruebas con tráfico real universitario | Media | 🔄 Pendiente |

#### MÓDULO 3: MACHINE LEARNING (Completado)
| ID | Actividad | Prioridad | Estado |
|---|---|---|---|
| ML-01 | Generación de dataset sintético (20,000 registros) | Alta | ✅ Completado |
| ML-02 | Limpieza y balanceo con SMOTE | Alta | ✅ Completado |
| ML-03 | Selección de características (SelectKBest, 22 features) | Alta | ✅ Completado |
| ML-04 | Entrenamiento de CatBoost v3 | Alta | ✅ Completado |
| ML-05 | Evaluación del modelo (91.9% accuracy) | Alta | ✅ Completado |
| ML-06 | Integración del modelo predictivo en flujo en vivo | Alta | ✅ Completado |
| ML-07 | Lógica de decisión híbrida (ML ≥70% / heurística) | Alta | ✅ Completado |

#### MÓDULO 4: IPS - BLOQUEO ACTIVO (EN PROCESO)
| ID | Actividad | Prioridad | Estado |
|---|---|---|---|
| IPS-01 | Bloqueo por Firewall de Windows (netsh) | Alta | ✅ Completado |
| IPS-02 | Temporizador de desbloqueo automático | Alta | ✅ Completado |
| IPS-03 | Integración SSH con MikroTik RouterOS | Alta | ✅ Completado |
| IPS-04 | Manejo de permisos (bloqueo simulado sin Admin) | Alta | ✅ Completado |
| IPS-05 | **Lista blanca de IPs críticas (servidores UNIPAZ)** | **Alta** | **🔄 Por terminar** |
| IPS-06 | **Bloqueo selectivo por VLAN (autónomo vs semi-autónomo)** | **Alta** | **🔄 Por terminar** |
| IPS-07 | **Modo híbrido: automático para externos, manual para internos** | **Media** | **🔄 Por terminar** |
| IPS-08 | Log de acciones de bloqueo con exportación | Media | ✅ Completado |
| IPS-09 | Pruebas de integración MikroTik (producción) | Alta | ❌ Pendiente |

#### MÓDULO 5: DASHBOARD SOC (Completado)
| ID | Actividad | Prioridad | Estado |
|---|---|---|---|
| UI-01 | Tablero SOC con tabla de eventos en vivo | Alta | ✅ Completado |
| UI-02 | Pestaña IPS con tabla de bloqueos y countdown | Alta | ✅ Completado |
| UI-03 | Estadísticas avanzadas (gráfico de torta, área, top IPs) | Alta | ✅ Completado |
| UI-04 | Panel de configuración (interfaz, umbrales, inicio/parada) | Alta | ✅ Completado |
| UI-05 | Badges de resumen en pestaña IPS | Media | ✅ Completado |
| UI-06 | Gráfico de área en tiempo real | Media | ✅ Completado |

#### MÓDULO 6: ALERTAS Y NOTIFICACIONES (Completado)
| ID | Actividad | Prioridad | Estado |
|---|---|---|---|
| AL-01 | Integración con Telegram Bot API | Alta | ✅ Completado |
| AL-02 | Formato de alertas con detalles del ataque | Media | ✅ Completado |
| AL-03 | Alertas selectivas por severidad | Media | ✅ Completado |

#### MÓDULO 7: DOCUMENTACIÓN Y TESIS (EN PROCESO)
| ID | Actividad | Prioridad | Estado |
|---|---|---|---|
| DOC-01 | Documentación de mejora del sistema | Alta | ✅ Completado |
| DOC-02 | **Documentación de arquitectura de red UNIPAZ** | **Alta** | **🔄 Por terminar** |
| DOC-03 | **Capítulos de tesis (Introducción, Justificación, etc.)** | **Alta** | **🔄 Por terminar** |
| DOC-04 | Manual de usuario | Media | ❌ Pendiente |
| DOC-05 | Manual de instalación y despliegue | Alta | ❌ Pendiente |

---

### 5.3 Tablero Kanban de Actividades

El tablero Kanban refleja el estado actual del proyecto, con énfasis en las actividades del módulo IPS que están por finalizar:

```plaintext
┌─────────────────────────────────────────────────────────────────────────────┐
│                     TABLERO KANBAN - IDBS-IPS-ML                           │
├──────────────┬──────────────┬──────────────┬──────────────┬────────────────┤
│   BACKLOG    │    POR HACER │ EN PROGRESO  │   REVISIÓN   │    HECHO       │
│  (Pendiente) │  (Siguiente) │  (WIP: 2)    │  (WIP: 3)    │                │
├──────────────┼──────────────┼──────────────┼──────────────┼────────────────┤
│              │              │              │              │                │
│ ML: Pruebas  │ IPS-07:     │ IPS-05:      │ IPS-06:      │ CAP-01 al 03   │
│ con tráfico  │ Modo híbrido│ Lista blanca │ Bloqueo      │ HEU-01 al 07   │
│ real         │ automático/ │ de IPs       │ selectivo    │ ML-01 al 07    │
│              │ manual      │ críticas     │ por VLAN     │ IPS-01,02,03,04│
│ DOC-04:      │              │ (Servidores  │              │ IPS-08         │
│ Manual de    │ DOC-03:     │ UNIPAZ)      │ CAP-04:      │ UI-01 al 06    │
│ usuario      │ Capítulos   │              │ Pruebas      │ AL-01,02,03    │
│              │ de tesis    │              │ rendimiento  │ DOC-01,02      │
│ DOC-05:      │              │              │              │                │
│ Manual de    │ IPS-09:     │              │ DOC-03:      │                │
│ instalación  │ Pruebas     │              │ Capítulos    │                │
│              │ MikroTik    │              │ de tesis     │                │
│              │ producción  │              │ (borrador)   │                │
│              │              │              │              │                │
├──────────────┴──────────────┴──────────────┴──────────────┴────────────────┤
│                                                                             │
│  WIP (Trabajo en Progreso): Máximo 2 tareas simultáneas en "En Progreso"   │
│                                                                             │
│  Flujo actual: BACKLOG → POR HACER → EN PROGRESO → REVISIÓN → HECHO       │
│                                                                             │
│  Hito actual: Módulo IPS (bloqueo activo) - 80% completado                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.4 Actividades del Módulo IPS - Detalle de Finalización

Las siguientes actividades del módulo IPS están actualmente en proceso de finalización:

#### IPS-05: Lista Blanca de IPs Críticas
- **Descripción**: Implementar una lista blanca configurable de IPs de servidores críticos (sistema de notas, matrículas, aulas virtuales, bases de datos administrativas) que nunca deben ser bloqueadas por el IPS, incluso si generan tráfico sospechoso.
- **Archivo afectado**: `respuesta_activa.py`
- **Criterio de aceptación**: Las IPs en whitelist son ignoradas por el módulo de bloqueo; cualquier intento de bloqueo se registra en log pero no se ejecuta.

#### IPS-06: Bloqueo Selectivo por VLAN
- **Descripción**: Implementar lógica que identifique la VLAN de origen del tráfico malicioso (mediante el tag 802.1Q) y determine si el bloqueo debe ser automático o requiere autorización manual, basado en la procedencia (externo vs interno).
- **Archivo afectado**: `ids.py`, `respuesta_activa.py`
- **Criterio de aceptación**: El sistema distingue tráfico de VLANs externas (bloqueo automático) vs internas (alerta sin bloqueo automático).

#### IPS-07: Modo Híbrido Autónomo/Semi-autónomo
- **Descripción**: Implementar un selector de modo en la interfaz de configuración que permita al administrador elegir entre bloqueo completamente automático (para ataques volumétricos externos) o semi-autónomo (para tráfico interno sospechoso, donde solo se genera alerta).
- **Archivo afectado**: `interfasc.py`, `ids.py`
- **Criterio de aceptación**: El modo se configura desde el panel de Settings y afecta el comportamiento del bloqueo.

---

## 6. REFERENCIAS

### 6.1 Libros y Textos Académicos

1. **Ladas, C. (2009).** *Scrumban: Essays on Kanban Systems for Lean Software Development*. Modus Cooperandi Press. — Libro fundamental sobre la metodología Scrumban utilizada en este proyecto.

2. **Stallings, W. (2018).** *Cryptography and Network Security: Principles and Practice* (7th ed.). Pearson. — Referencia clave sobre principios de seguridad en redes, incluyendo IDS y firewalls.

3. **Scarfone, K., & Mell, P. (2007).** *Guide to Intrusion Detection and Prevention Systems (IDPS)*. NIST Special Publication 800-94. National Institute of Standards and Technology. — Guía técnica oficial del NIST para la implementación de sistemas IDS/IPS.

4. **Northcutt, S., & Novak, J. (2002).** *Network Intrusion Detection: An Analyst's Handbook* (3rd ed.). New Riders Publishing. — Manual clásico para analistas de detección de intrusiones en redes.

5. **Chandola, V., Banerjee, A., & Kumar, V. (2009).** *Anomaly Detection: A Survey*. ACM Computing Surveys, 41(3), 1-58. — Survey exhaustivo sobre técnicas de detección de anomalías.

6. **Bishop, C. M. (2006).** *Pattern Recognition and Machine Learning*. Springer. — Texto de referencia en Machine Learning, aplicable al desarrollo del clasificador CatBoost.

7. **Provost, F., & Fawcett, T. (2013).** *Data Science for Business: What You Need to Know about Data Mining and Data-Analytic Thinking*. O'Reilly Media. — Enfoque práctico de ciencia de datos aplicada a problemas de negocio, incluyendo detección de fraude y seguridad.

### 6.2 Artículos Científicos y Técnicos

8. **Denning, D. E. (1987).** *An Intrusion-Detection Model*. IEEE Transactions on Software Engineering, SE-13(2), 222-232. — Artículo fundacional que establece el modelo teórico de detección de intrusiones.

9. **Zhang, Y., et al. (2021).** *Network Intrusion Detection Based on Random Forest and Deep Learning*. IEEE Access, 9, 115732-115745.

10. **Hwang, S., et al. (2020).** *CatBoost-Based Intrusion Detection System for IoT Networks*. Sensors, 20(22), 6528.

11. **Alqahtani, H., et al. (2022).** *Comparative Analysis of Gradient Boosting Algorithms for Network Intrusion Detection*. Computers, Materials & Continua, 71(2), 3129-3145.

12. **Vinayakumar, R., et al. (2019).** *Deep Learning Approach for Intelligent Intrusion Detection System*. IEEE Access, 7, 41525-41550.

13. **Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018).** *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. ICISSP 2018, 108-116. — Artículo que presenta el dataset CIC-IDS2017, utilizado para entrenar el modelo ML del proyecto.

14. **Ring, M., et al. (2019).** *A Survey of Network-based Intrusion Detection Data Sets*. Computers & Security, 86, 147-167. — Survey de datasets disponibles para detección de intrusiones en redes.

### 6.3 Documentación Técnica y Estándares

15. **NIST (2011).** *NIST SP 800-94 Rev. 1: Guide to Intrusion Detection and Prevention Systems (IDPS)*. https://csrc.nist.gov/publications/detail/sp/800-94/rev-1/final

16. **Canadian Institute for Cybersecurity (2018).** *CSE-CIC-IDS2018 Dataset*. https://www.unb.ca/cic/datasets/ids-2018.html

17. **Yandex (2017).** *CatBoost Documentation*. https://catboost.ai/docs/

18. **OISF (2010).** *Suricata User Guide*. https://suricata.readthedocs.io/

19. **Cisco Systems (2020).** *Cisco Secure Network Analytics*. https://www.cisco.com/c/en/us/products/security/secure-network-analytics/

20. **Darktrace (2013).** *Darktrace Enterprise Immune System*. https://darktrace.com/

### 6.4 Recursos sobre Ciberseguridad en Educación

21. **Educause (2024).** *EDUCAUSE 2024 Cybersecurity Report*. https://www.educause.edu/ — Reporte anual sobre el estado de la ciberseguridad en instituciones educativas.

22. **ENISA (2023).** *ENISA Threat Landscape 2023*. European Union Agency for Cybersecurity. https://www.enisa.europa.eu/ — Panorama de amenazas cibernéticas a nivel europeo, incluyendo sector educativo.

23. **ISC2 (2023).** *ISC2 Cybersecurity Workforce Study*. https://www.isc2.org/ — Estudio sobre la fuerza laboral en ciberseguridad, relevante para justificar la necesidad de herramientas automatizadas ante la escasez de personal calificado.

### 6.5 Metodología Scrumban

24. **Anderson, D. J. (2010).** *Kanban: Successful Evolutionary Change for Your Technology Business*. Blue Hole Press. — Libro fundamental sobre Kanban, complementario a Scrumban.

25. **Kniberg, H., & Skarin, M. (2010).** *Kanban and Scrum: Making the Most of Both*. InfoQ Enterprise Software Development Series. — Comparativa práctica entre Scrum y Kanban.

---

## 7. ANEXOS (TRABAJO FUTURO)

- Integración con AbuseIPDB para verificación de reputación de IPs.
- Dashboard web interactivo con Flask/Node.js para acceso remoto.
- Expansión del dataset con tráfico real de UNIPAZ para reentrenamiento del modelo.
- Implementación de autoencoders para detección de anomalías zero-day.
- App móvil para notificaciones y monitoreo rápido.
