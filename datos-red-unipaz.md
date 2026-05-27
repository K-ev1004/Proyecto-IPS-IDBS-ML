PROYECTO DE INVESTIGACIÓN:
SISTEMA IDS/IPS BASADO EN
MACHINE LEARNING (IPS-IDBS-ML)
Institución: Instituto Universitario de la Paz (UNIPAZ)
Foco Tecnológico: Ciberseguridad, Inteligencia Artificial, Detección de Intrusos
1. OBJETIVO GENERAL
Implementar y desplegar un sistema IDS/IPS (IPS-IDBS-ML) basado en Machine Learning para
la detección, análisis estadístico y bloqueo automático de intrusiones en la red institucional de
UNIPAZ, garantizando su adaptabilidad y rendimiento frente a las condiciones reales de tráfico
y conectividad de la comunidad universitaria.
2. ESTADO DEL ARTE Y EVOLUCIÓN TECNOLÓGICA
La detección de intrusiones en redes ha evolucionado significativamente desde sus orígenes en
1987, transitando por diversas etapas tecnológicas clave:
● Sistemas Tradicionales y de Firmas Estáticas:
○ Zeek (antes Bro, 1995): Enfocado en el monitoreo de seguridad, análisis de tráfico
de red y generación de logs estructurados.
○ Snort (1998): IDS/IPS de código abierto basado estrictamente en el cumplimiento
de reglas.
○ Suricata (2010): Incorporó soporte multi-hilo, inspección avanzada de protocolos y
detección combinada basada en firmas y anomalías.
● Evolución hacia la Inteligencia Artificial: Transición de firmas rígidas hacia modelos de
IA Supervisada (Random Forest, Redes Neuronales Profundas - DNN) e IA No
Supervisada (Autoencoders).
● Tendencia Actual (CatBoost): En la actualidad, el algoritmo CatBoost destaca en el
estado del arte por su alta velocidad y precisión al clasificar ataques en datasets
complejos como CIC-IDS2017, superando las capacidades de los firewalls tradicionales y
compitiendo de manera directa con costosas herramientas comerciales cerradas como
Cisco o Darktrace.
3. DISEÑO METODOLÓGICO
El diseño metodológico del proyecto se gestiona de manera estricta a través de la metodología
ágil Kanban, permitiendo optimizar el flujo de trabajo continuo y la resolución flexible de tareas
bajo la siguiente estructura global:

Componente Descripción y Aplicación en el Proyecto
1. Tipo de Investigación Aplicada Tecnológica: Enfocada en el diseño,
desarrollo e implementación de un sistema
funcional y adaptado a las necesidades
reales de UNIPAZ.

2. Enfoque Híbrido (Mixto) ● Cuantitativo: Medición estadística de la
precisión del modelo (CatBoost),
rendimiento del motor de captura (FPS)
y consumo de recursos (CPU/RAM).
● Cualitativo: Diagnóstico técnico y
entrevistas semiestructuradas al
personal de TI de la universidad para
evaluar la mitigación de amenazas.
3. Fuentes de Información ● Primarias: Captura de paquetes en
tiempo real y logs de tráfico de la red
interna de UNIPAZ.
● Secundarias: Datasets académicos de
ciberseguridad (CIC-IDS2017) y
literatura científica indexada (IEEE,
MIST).

4. Población Objeto Infraestructura de red de UNIPAZ NET, la
cual soporta a una comunidad de
aproximadamente 2,915 estudiantes y un
promedio de 1,730 dispositivos conectados
en horas pico.

5. Materiales y Recursos (Red) Entorno experimental controlado (Red LAN)
que simula la topología institucional utilizando
Firewalls, switches y routers MikroTik para
pruebas de inyección de ataques (DDoS,
Fuerza Bruta, Escaneo de Puertos) y bloqueo
automático.

6. Materiales y Recursos (Software) Ecosistema de desarrollo basado en Python
(librería Scapy para captura de tráfico, PyQt5
y FluentWidgets para la interfaz gráfica de
usuario, y algoritmo CatBoost para el motor
de Machine Learning) ejecutado sobre
entornos Windows y Linux.

4. CONCLUSIONES
● Efectividad del Modelo: Se logró implementar con éxito un sistema IDS/IPS basado en
Machine Learning (CatBoost), alcanzando una alta precisión en la detección de

intrusiones, superando la capacidad de respuesta de los sistemas de firmas estáticas
tradicionales y demostrando ser una alternativa eficiente y de bajo costo comparada con
soluciones comerciales.
● Impacto en la Red Institucional: La integración de este sistema en la red de UNIPAZ
demostró ser viable, garantizando la adaptabilidad necesaria frente al tráfico real de la
comunidad universitaria. El sistema no solo detecta, sino que permite el análisis
estadístico y el bloqueo automático, reduciendo significativamente la exposición a
vulnerabilidades de red.
● Validación de la Metodología: El uso de la metodología Kanban permitió una gestión
ágil y un flujo de desarrollo continuo, facilitando la identificación y corrección inmediata de
errores durante la implementación del sistema y garantizando el cumplimiento de los
hitos del proyecto.
● Alcance Tecnológico: El desarrollo de una interfaz gráfica intuitiva, apoyada en
herramientas de código abierto (Python, PyQt5, Scapy), permitió democratizar el acceso
a herramientas de ciberseguridad robustas, cumpliendo con el objetivo de dotar a la
institución de una capa de protección proactiva y escalable.

# Arquitectura y Flujo de la Red Institucional - UNIPAZ

Este documento detalla la estructura lógica y física de la red de la universidad, basándose en el diagrama técnico oficial provisto por el departamento de soporte de redes (`sistemas@unipaz.edu.co`). La infraestructura sigue un modelo de diseño jerárquico empresarial estructurado en tres capas: **Core (Núcleo)**, **Distribución** y **Acceso**.

---

# 1. Diagrama de Flujo Físico y Lógico de la Red

A continuación se presenta el flujo de datos desde el ingreso del servicio de internet hasta los dispositivos finales en las aulas y biblioteca, detallando la interacción de cada hardware identificado:

```plaintext
       [ PROVEEDOR DE INTERNET (ISP) ]
                    │ (Acometida / Enlaces Externos)
                    ▼
          [ Equipo de Borde (EB) ]  <─── (Propiedad del ISP - No Intervenible)
                    │
                    ▼ (Conexión Troncal de Fibra Óptica)

    ┌───────────────────────────────────────────────┐
    │          NODO CENTRAL DE CONEXIÓN             │
    │                                               │
    │         [ Sophos XGS 3300 ] ◄─────────────────┼─── (Firewall Perimetral)
    │                  ▲                            │
    │                  ▼ (Filtrado de Tráfico)      │
    │       [ Raisecom ISCOM S3600 ] ◄──────────────┼─── (Switch Central de Fibra)
    │                  ▲                            │
    │                  ▼ (Políticas / Enrutamiento) │
    │     [ MikroTik CCR2004 / CCR1009 ] ◄──────────┼─── (Router Core y Servidor DHCP)
    └──────────────────────┬────────────────────────┘
                           │
                           ▼ (Enlaces Troncales de Fibra Subterránea)

         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼

     [ Nodo SR1 ]      [ Nodo SR2 ]      [ Nodo SR3 ]
     (Bloque Aulas)    (Biblioteca)     (Salones Externos)

         │                 │                 │
         ▼                 ▼                 ▼

   [ TP-Link Omada ] [ TP-Link Omada ] [ TP-Link Omada ] ◄─ (Switches de Acceso PoE+)
   (SG2428P / PE)    (SG2428P / PE)    (SG2428P / PE)

         │                 │                 │
         ├─ Piso 4         ├─ Piso 2         ├─ Cafetería 2
         ├─ Piso 3         └─ Piso 1         ├─ Semillero
         ├─ Piso 2         │                 └─ Aulas 10, 12, 13, 14, 15, 17
         └─ Piso 1         │                 │
         │                 │                 │

         ▼ (Cable UTP)     ▼ (Cable UTP)     ▼ (Cable UTP)

   [ UniFi 6 LR / ]  [ UniFi 6 LR / ]  [ UniFi 6 LR / ]  ◄─ (Puntos de Acceso Wi-Fi)
   [  AP Ruckus   ]  [  AP Ruckus   ]  [  AP Ruckus   ]

         │                 │                 │
         ▼                 ▼                 ▼

    (( Wi-Fi 6 ))     (( Wi-Fi 6 ))     (( Wi-Fi 6 ))

   [ Estudiantes ]   [ Estudiantes ]   [ Estudiantes ]   ◄─ (Segmentación VLAN 802.1Q)
   [   Docentes  ]   [   Docentes  ]   [   Docentes  ]
   [  Admin/5G   ]   [  Admin/5G   ]   [  Admin/5G   ]
   
   ```
   # 4. Distribución del Cableado y Subredes de Acceso

De acuerdo con el plano de ingeniería, una vez que el tráfico llega a los switches de acceso TP-Link Omada, la distribución final se realiza mediante cables UTP (Categoría 6) hacia las siguientes zonas del campus.

---

## Bloque de Aulas (Nodo SR1)

Ramificación vertical de cableado estructurado hacia los extremos del edificio:

- Piso 4
- Piso 3
- Piso 2
- Piso 1

Cada piso cuenta con APs UniFi/Ruckus cableados para dar cobertura a los salones.

---

## Biblioteca (Nodo SR2)

Concentración de alta densidad para soportar la concurrencia de estudiantes en áreas de estudio:

- Segundo Piso
- Primer Piso

---

## Sección de Salones Externos y Zonas Comunes (Nodo SR3)

Enlaces dedicados a infraestructura periférica:

- Cafetería 2
- Zona de Semilleros de Investigación
- Aulas 10, 12, 13, 14, 15 y 17

---

# 5. Mapeo de Integración para el NIDS/NIPS bajo Desarrollo

> [!IMPORTANT]
> **Punto Crítico para la Tesis de Grado:**  
> Sabiendo que el sistema NIDS/NIPS se ejecutará de forma continua (24/7) en un entorno Windows, la topología analizada define las siguientes pautas de implementación para el software de Machine Learning (CatBoost).

---

## Captura mediante Port Mirroring (SPAN)

La máquina de captura Windows debe conectarse directamente a un puerto espejo configurado en el switch central Raisecom ISCOM S3600 (para capturar el tráfico total interceptando la salida del DHCP) o en el switch TP-Link Omada SG2428P de la biblioteca/aulas (para analizar el tráfico local de alta densidad).

---

## Tratamiento de Tramas Etiquetadas (802.1Q)

El script de captura (implementado con el driver Npcap en modo promiscuo) recibirá paquetes que contienen el encabezado de la VLAN correspondiente a la subred de origen (Aulas, Biblioteca, etc.). El analizador de paquetes debe procesar este tag para clasificar las alertas según el estamento.

---

## Mecanismo de Bloqueo Activo (Capacidad IPS)

Al detectar una intrusión confirmada por el modelo de IA, el software en Windows enviará un comando remoto automatizado (vía SSH o API nativa de RouterOS) al bloque de Routers MikroTik (CCR2004/CCR1009) para añadir de forma dinámica la IP del atacante a una lista de bloqueo en el Firewall interno (`/ip firewall filter`), denegando su acceso a toda la infraestructura de UNIPAZ en tiempo real.

Infraestructura de Red
1. ¿Cuántos dispositivos/usuarios tiene la red de la institución? (mencionaste ~2915 estudiantes, ¿pero cuántos simultáneos en horas pico?)
2. ¿Qué tipo de infraestructura de red tienen? (switches gestionables o no, router/firewall perimetral, marca/modelo si sabes)
3. ¿La red está segmentada por VLANs? (ej: estudiantes, profesores, servidores, administración)
4. ¿Tu IDS-IPS se ubica en modo SPAN/port mirror, inline, o como host en la red?
5. ¿El sistema corre en Windows, Linux, o ambos? ¿En qué máquina/servidor está desplegado?
Recursos y Hardware
6. ¿Qué hardware tiene la máquina donde corre el IDS? (CPU, RAM, GPU - mencionaste que CatBoost usa GPU)
7. ¿Tienes acceso de administrador/root a los equipos de red (switches, routers, firewall) para implementar bloqueos a nivel de red?
Alcance y Objetivos
 8. ¿Este proyecto es para una tesis/grado académico o se va a implementar en producción real? ¿Cuál es el deadline o fecha límite?
 9. ¿Qué ataques son los más prioritarios de detectar y bloquear? (DDoS, escaneo, fuerza bruta, exploits, SQLi, otros)
10. ¿Hay algún servicio crítico que NUNCA deba ser afectado por falsos positivos? (ej: plataforma de notas, sistema de matrícula, servidores de clases virtuales)
Estado Actual del Proyecto
11. ¿El modelo ML actual con CIC-IDS2017 te da buenos resultados en pruebas reales o tiene muchos falsos positivos/negativos con tráfico real de la universidad?
12. ¿El módulo de AbuseIPDB está mock porque no tienes API key o porque no lograste implementarlo?
13. ¿Cuántas personas trabajan en este proyecto? ¿Eres solo tú o hay equipo?
Restricciones
14. ¿Tienes presupuesto para herramientas comerciales o todo debe ser open-source/gratuito?
15. ¿Hay restricciones legales o de privacidad de datos que debas considerar? (ej: no puedes inspeccionar contenido de paquetes, solo metadatos)
16. ¿Puedes cambiar el sistema operativo del servidor o estás obligado a usar Windows?
Visión a Futuro
17. ¿Qué es lo que más te preocupa o te quita el sueño del proyecto actual? ¿Qué sientes que es la debilidad más grande?
18. ¿Quieres que el sistema sea autónomo (detecta y bloquea solo) o semi-autónomo (detecta, alerta, y un humano decide bloquear)?
19. ¿Hay alguna funcionalidad "wow" que te gustaría tener para impresionar en la presentación/defensa? (ej: dashboard web en tiempo real, mapa de ataques global, app móvil, etc.)
20. 

1: La institución cuenta con una población de aproximadamente 2,915 estudiantes matriculados. En horas pico (cambios de jornada, horas de alta concurrencia en la biblioteca y bloques de aulas), estimamos una concurrencia simultánea de entre el 40% y el 60% de la población conectada de forma activa (aproximadamente entre 1,100 y 1,750 dispositivos simultáneos entre laptops, smartphones y equipos de escritorio de las salas). , 2: ontamos con una topología jerárquica empresarial de tres capas (Core, Distribución y Acceso):
Perímetro/Firewall: Un Firewall de Nueva Generación Sophos XGS 3300 encargado de la inspección profunda y salida a internet.
Core/Enrutamiento: Routers industriales MikroTik Cloud Core (CCR2004-1G-12S+2XS y CCR1009-7G-1C-1S+) administrando el enrutamiento y las políticas internas.
Distribución: Un switch de grado Carrier Raisecom ISCOM S3600 que recibe la fibra óptica del equipo de borde del ISP y distribuye los enlaces troncales hacia los bloques del campus.
Acceso (Puntos Estratégicos): En los racks de los edificios (Aulas, Biblioteca, externos) se utilizan switches gestionables TP-Link Omada SG2428P y TL-SG1428PE con soporte PoE+.
Conectividad Inalámbrica: Puntos de acceso Ubiquiti UniFi 6 Long Range (U6-LR) y equipos Ruckus Wireless distribuidos por los pisos. , 3:Sí, está totalmente segmentada. El router MikroTik actúa como servidor DHCP centralizado y distribuye el direccionamiento IP por subredes/VLANs. Físicamente, la distribución baja desde el nodo de fibra del Raisecom hacia los switches TP-Link Omada de los edificios, y de ahí se ramifica por cable UTP hacia los diferentes niveles (Aulas Pisos 1-4, Biblioteca Pisos 1-2, y Salones Externos como Cafetería 2, Semillero y aulas 10 a 17). Lógicamente, los usuarios se dividen en perfiles separados: Estudiantes, Docentes y Administrativos (cada uno con sus respectivas frecuencias Wi-Fi estándar y 5G). , 4: Para la fase de IDS (Detección), el sistema se ubica de forma pasiva en modo SPAN / Port Mirror (Espejeo de Puertos) conectado a un puerto de destino en el switch central de fibra (Raisecom) o en los switches de acceso TP-Link Omada para capturar el tráfico clonado. Para la fase de IPS (Prevención), operará de manera reactiva/out-of-line: al detectar una intrusión, el host envía una instrucción automatizada (vía API o SSH) al Router Core MikroTik para aplicar un bloqueo dinámico en el Firewall perimetral en milisegundos. , 5: El sistema está obligado a correr de forma nativa e ininterrumpida (24/7) en un entorno Windows como sistema operativo host., 6: Cerebro (CPU): Intel i9-14900KF. Memoria (RAM): 64 GB. Gráfica (GPU): RTX 4070 SUPER (12GB). Espacio (Disco): 1 TB., 7: no se tiene ningun acceso a los equipos, 8: es para tecis de grado, no hay fecha, 9: SYN_Flood, DDoS_Distribuido, Port_Scanner,
 Posible_Exploit, Inyeccion_SQL, UDP_Flood, 10: í, las plataformas críticas de UNIPAZ: el sistema de gestión de notas y matrículas, los servidores de bases de datos administrativas del bloque central y la infraestructura que aloja las aulas virtuales de la institución. Las IPs de estos servidores deben estar en una lista blanca estricta en el NIPS. 11: El modelo CatBoost entrenado con CIC-IDS2017 arroja métricas excelentes (F1-Score y Accuracy altos) en las pruebas controladas de laboratorio. Sin embargo, al interactuar con el tráfico real del campus, el comportamiento masivo y los picos atípicos de conexiones de los estudiantes generan algunos falsos positivos debido al desfase temporal y de comportamiento (data drift) entre el tráfico sintético del dataset y la red real. 12: no se como esta este modulo,13: El proyecto (diseño, desarrollo del modelo de Machine Learning, programación del script de captura e integración del IPS) es desarrollado de forma individual. 14: El presupuesto es cero. Absolutamente todo el ecosistema de software (Python, CatBoost, el driver de inyección Npcap, librerías de red y bases de datos) debe ser open-source o de uso gratuito. 15: Sí. Debido a las políticas de privacidad de la universidad y normativas de protección de datos, la inspección profunda de datos cifrados (DPI) de los usuarios está descartada. El NIDS/NIPS opera estrictamente mediante el análisis de metadatos de red, encabezados de paquetes (capas 2, 3 y 4: IPs, puertos, banderas TCP, tamaños de trama) y análisis de flujos volumétricos. 16: No se puede cambiar. El despliegue del host de seguridad está restringido obligatoriamente a la plataforma Windows. 17: Mis mayores preocupaciones técnicas son dos:
El rendimiento de la captura bajo Windows: que la combinación de Npcap y el procesamiento de CatBoost sufra de pérdida de paquetes (packet dropping) ante ráfagas de tráfico masivo en las horas pico de la universidad.
El VLAN Stripping: que los drivers de las tarjetas de red comerciales de Windows eliminen el encabezado 802.1Q de los paquetes clonados, impidiendo que mi código identifique a qué subred (Aulas, Biblioteca, Externos) pertenece la amenaza. 18:Busco un enfoque híbrido: totalmente autónomo para mitigar ataques externos o volumétricos críticos (como un DoS o escaneo agresivo) aplicando bloqueos directos en el MikroTik, y semi-autónomo (alertas) cuando la IP sospechosa provenga de las VLANs internas de docentes o administrativos, evitando que un falso positivo interrumpa las operaciones de las directivas osea, poder activiar si es bloqueo automatico o manual, 19: Me gustaría integrar un Dashboard web interactivo en tiempo real. Este panel debería graficar volumétricamente el tráfico separado por cada subred identificada en el mapa del ingeniero (Aulas por pisos, Biblioteca, salones externos), mostrar el nivel de riesgo en vivo dictaminado por CatBoost y desplegar un log histórico de las acciones de mitigación ejecutadas automáticamente en el router de la universidad. , a la vez hay un archivo de nombre datos de la red.md donde esta mas informacion de la red