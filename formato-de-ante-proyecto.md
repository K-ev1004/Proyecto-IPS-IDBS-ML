System Prompt & Context Blueprint para la Generación del Anteproyecto de Grado (UNIPAZ)
1. Variables de Entorno y Datos Maestro Contextuales
La otra IA debe usar estrictamente estas variables en todo el documento:

Institución: Instituto Universitario de la Paz (UNIPAZ).

Ubicación: Barrancabermeja, Santander, Colombia.

Año del Proyecto: 2026.

Autor: Kevin Abner Rojas Gomez.

Modalidad de Grado: Trabajo de Grado Alterno (según Acuerdo CAC No. 053-19).

Unidad Académica: Escuela de Ciencias - Programa de Ingeniería de Sistemas.

Línea de Investigación Institucional: Línea 8: Aprovechamiento de los recursos potenciales del Magdalena Medio en procesos transdisciplinarios de las ciencias y las ingenierías.

Normativa de Formato Obligatoria: NTC 1486 (Presentación), NTC 6166 (Referencias Bibliográficas), NTC 4430 (Fuentes Electrónicas).

Presupuesto del Proyecto: Cero (0) COP (Sujeto estrictamente a software open-source/libre).

2. Ficha Técnica de la Infraestructura de Red Objeto de Estudio
El diseño del sistema debe acoplarse obligatoriamente a esta topología de tres capas:

Capa Perimetral (Frontera): Next-Generation Firewall (NGFW) Sophos XGS 3300 (Inspección profunda de firmas, control de capa 7, inspección SSL, bloqueos perimetrales).

Capa Core (Núcleo Central): Routers industriales MikroTik Cloud Core (CCR2004-1G-12S+2XS y CCR1009-7G-1C-1S+) corriendo RouterOS. Administran el enrutamiento inter-VLAN y actúan como servidores DHCP centrales.

Capa de Distribución: Switch Carrier-Class Raisecom ISCOM S3600 (Centraliza la fibra óptica del nodo principal y la distribuye a los edificios).

Capa de Acceso Local (Edificios): Switches gestionables PoE+ TP-Link Omada SG2428P y TL-SG1428PE.

Capa Inalámbrica: Puntos de acceso Ubiquiti UniFi 6 Long Range (U6-LR) y Ruckus Wireless distribuidos por pisos, emitiendo SSIDs segmentados por VLAN (Estudiantes, Docentes, Administrativos).

Distribución Física del Tráfico: * Bloque de Aulas (Nodo SR1): Bajadas por cable UTP Categoría 6 independientes a Pisos 4, 3, 2 y 1.

Biblioteca (Nodo SR2): Conexión UTP a Primer y Segundo piso (Área de alta densidad de usuarios).

Salones Externos (Nodo SR3): Cableado hacia Cafetería 2, Semilleros de Investigación y aulas 10, 12, 13, 14, 15 y 17.

3. Especificaciones del Stack Tecnológico del Proyecto (NIDS/NIPS)
Entorno de Ejecución: Host nativo Windows operando 24/7 de forma ininterrumpida.

Hardware Dedicado: CPU multinúcleo, RAM expandida y GPU NVIDIA dedicada aprovechando los drivers de arquitectura CUDA para acelerar los hilos de inferencia en tiempo real.

Motor de Inteligencia Artificial: Algoritmo CatBoost (Gradient Boosting sobre árboles de decisión categóricos).

Dataset de Entrenamiento: CIC-IDS2017 (Filtrado para procesar ataques volumétricos: DDoS, Port Scanning, Fuerza Bruta SSH/FTP e intentos de movimiento lateral).

Lógica de Captura: Modo pasivo SPAN/Port Mirror mediante el controlador Npcap en Windows para analizar metadatos de las capas 2, 3 y 4 (IPs, puertos, flags TCP, tamaños de trama, tags 802.1Q). Prohibida la inspección profunda de datos privados (DPI).

Lógica de Mitigación (IPS): Sistema reactivo Out-of-Line. Al detectar una amenaza, el script en Windows envía comandos remotos automáticos vía API/SSH de RouterOS a los MikroTik Core para banear la IP del atacante de inmediato.

Salvaguarda Crítica: Implementación de una Lista Blanca (Whitelist) inmutable dentro del código para evitar falsos positivos que bloqueen los servicios esenciales de UNIPAZ (Plataforma de notas, sistema de matrículas y servidores administrativos).

4. Instrucciones Estructurales de Generación (Sección por Sección)
La otra IA debe estructurar el documento final basándose exactamente en los siguientes 12 bloques constructivos, aplicando un tono académico, técnico y formal:

1. Portada y 2. Contraportada
Instrucción: Generar el bloque de texto centrado respetando las jerarquías de la norma NTC 1486. Usar el título: "Diseño e Implementación de un Sistema de Detección y Prevención de Intrusiones (NIDS/NIPS) Basado en Machine Learning (CatBoost) bajo Entorno Windows para la Infraestructura de Red Segmentada del Instituto Universitario de la Paz (UNIPAZ)".

3. Tabla de Contenido y 4. Listas Especiales
Instrucción: Crear los esquemas de tablas dinámicas de contenido, índice de figuras (donde irá la topología), índice de tablas y anexos de acuerdo a los requerimientos del manual de UNIPAZ.

5. Planteamiento del Problema
Instrucción: Desarrollar la redacción bajo la técnica del embudo (de lo macro a lo micro).

Contexto: Crecimiento de redes académicas y sofisticación de ataques de día cero.

Foco Institucional: Describir la infraestructura de UNIPAZ. Explicar que aunque existe un firewall perimetral Sophos XGS 3300 robusto, este opera principalmente por firmas tradicionales orientadas al tráfico norte-sur (exterior-interior) y no inspecciona el tráfico este-oeste (interno) entre las VLANs de los diferentes pisos de Aulas, Biblioteca y Salones externos.

Brecha Técnica: Describir las dificultades de desplegar soluciones IDS/IPS comerciales (costo prohibitivo/presupuesto cero) y las limitaciones de rendimiento y pérdida de tramas (packet dropping) asociadas a arquitecturas de captura bajo entornos Windows en horas pico (concurrencia de 1,100 a 1,750 usuarios simultáneos). Mencionar el riesgo de VLAN stripping por parte de drivers comerciales de Windows que borran la etiqueta 802.1Q.

Pregunta problema: Formular la pregunta de investigación enfocada en la viabilidad técnica de CatBoost + Windows + API MikroTik.

6. Justificación
Instrucción: Redactar los impactos divididos en tres dimensiones:

Justificación Técnica: La necesidad de usar modelos heurísticos adaptativos (CatBoost) frente a ráfagas de tráfico atípico estudiantil (Data Drift) y la protección proactiva de la capa de acceso local (Switches TP-Link Omada) antes de comprometer el Core.

Justificación Económica: Demostrar el valor de una solución soberana de costo cero basada en Python, Npcap y software libre.

Justificación Académica e Institucional: Alinear el proyecto con la Línea 8 de investigación de UNIPAZ y enriquecer el repositorio institucional con soluciones transdisciplinarias de ingeniería.

7. Objetivos (General y Específicos)
Instrucción: Redactar textualmente los siguientes objetivos, asegurando consistencia gramatical (verbos en infinitivo):

General: Desarrollar un sistema de detección y prevención de intrusiones (NIDS/NIPS) basado en el modelo de Machine Learning CatBoost para entorno Windows, que permita identificar y mitigar de forma autónoma amenazas de red en la infraestructura segmentada de UNIPAZ.

Específicos:

Analizar el tráfico de red de las subredes de UNIPAZ (Aulas, Biblioteca, Externos) mediante capturas pasivas con Npcap para identificar los patrones de comportamiento y los tags VLAN (802.1Q).

Entrenar y validar el modelo de Machine Learning utilizando el algoritmo CatBoost y el dataset CIC-IDS2017, optimizando la inferencia mediante aceleración por hardware (GPU NVIDIA CUDA).

Desarrollar el módulo de prevención (NIPS) en Windows para automatizar la inyección de reglas de bloqueo dinámicas en los routers Core MikroTik (CCR2004/CCR1009) a través de su API/SSH.

Diseñar un dashboard web interactivo en tiempo real para la visualización del estado de riesgo por subredes y el histórico de mitigaciones.

8. Marco Referencial
Instrucción: Desarrollar de manera exhaustiva y profunda los siguientes cuatro sub-marcos:

Marco Teórico: Sistemas de detección de intrusiones, seguridad perimetral, algoritmos de ensamble (Gradient Boosting), y redes jerárquicas empresariales.

Marco Conceptual: Definición rigurosa de Port Mirroring (SPAN), Modo Promiscuo, Encapsulamiento IEEE 802.1Q, Data Drift, Falsos Positivos, e Inferencia en Tiempo Real.

Marco Tecnológico y Científico: Estado del arte de los equipos Sophos XGS 3300, MikroTik RouterOS, Raisecom ISCOM S3600 y el ecosistema Omada de TP-Link. Analizar por qué CatBoost procesa mejor las variables categóricas de red (puertos, protocolos) frente a otras arquitecturas de Machine Learning.

Marco Histórico/Actual: Diagnóstico de la ciberseguridad en redes universitarias de la región del Magdalena Medio y los retos de la transición hacia Wi-Fi 6 (UniFi 6 LR).

9. Diseño Metodológico
Instrucción: Detallar detalladamente la metodología de desarrollo de software e investigación, estructurada en 4 fases correlacionadas directamente con los objetivos específicos:

Fase 1: Configuración del entorno de captura en los switches TP-Link Omada/Raisecom. Procesamiento de tramas etiquetadas mediante Npcap y aislamiento de campos IP/Puertos/Flags TCP.

Fase 2: Balanceo y normalización del dataset CIC-IDS2017, proceso de tuning de hiperparámetros de CatBoost y configuración de hilos de ejecución con aceleración por GPU (CUDA).

Fase 3: Desarrollo de scripts en Python para la automatización del IPS. Integración del canal de comunicación socket API/SSH con los routers MikroTik Core para inyección de la cadena /ip firewall filter. Programación del algoritmo de exclusión estricta (Whitelist) para proteger los servidores de notas y matrículas.

Fase 4: Diseño de la arquitectura del Dashboard en tiempo real (utilizando frameworks livianos compatibles con Windows como Streamlit o Dash/Flask) segmentado por los nodos del campus (Bloque Aulas por pisos, Biblioteca por pisos, Salones externos).

10. Cronograma de Actividades
Instrucción: Diseñar una estructura de tabla o diagrama de Gantt planificada a lo largo de las semanas de desarrollo disponibles, apuntando a las ventanas de validación técnica previas a las ceremonias oficiales de grado fijadas para el calendario académico vigente de 2026.

11. Presupuesto
Instrucción: Estructurar una matriz financiera detallada de costos indexados (aunque el proyecto sea de presupuesto cero para la universidad). Dividir en:

Hardware: Estación de trabajo Windows de alta gama con GPU NVIDIA CUDA (valor comercial estimado).

Software: Declarar costo de 0 USD para Python, CatBoost, Npcap y RouterOS API (Licencias Open-Source/Gratuitas).

Recurso Humano: Valorar el costo de horas de ingeniería del investigador principal (Kevin Abner Rojas Gomez).

12. Bibliografía
Instrucción: Generar un listado de referencias bibliográficas de alta calidad científica (artículos de IEEE, Springer, ACM, y manuales oficiales de Sophos/MikroTik) estructuradas de forma impecable bajo la norma NTC 6166 y NTC 4430 para recursos web.

5. Criterios de Evaluación Obligatorios para la IA
[!CAUTION]
Regla de Validación del Consejo de Escuela: Los tres calificadores de UNIPAZ evaluarán este documento basándose en la coherencia estricta. La otra IA debe asegurar que cada fase del Diseño Metodológico responda exactamente a un Objetivo Específico, y que cada Objetivo Específico sea una pieza necesaria para solucionar el problema planteado en el Planteamiento del Problema. Si hay inconsistencias, el proyecto será rechazado.