# =============================================================================
# interfasc.py — Interfaz Gráfica del IDS (Sistema de Detección de Intrusiones)
# Construida con PyQt5 + Matplotlib. Muestra eventos en tiempo real,
# tráfico en vivo, métricas SOC, gráficos y controles de monitoreo
# =============================================================================

# Módulos estándar
import sys       # sys.exit() para cierre limpio de la app Qt
import os        # Rutas de archivos y directorios
import time      # Timestamps para métricas (PPS, uptime)
import csv       # Exportación de eventos a CSV
import logging   # Sistema de logs en archivo para depuración
import re        # Expresiones regulares para extracción de IPs del warnbox

# Estructuras de datos de alto rendimiento
from collections import Counter, deque  # Counter: frecuencia; deque: buffer circular
from datetime import datetime           # Formateo de timestamps para nombres de archivos
from threading import Lock              # Mutex para acceso thread-safe a datos compartidos

# PyQt5: Framework de interfaz gráfica multiplataforma
from PyQt5.QtWidgets import (
    QApplication,     # Núcleo de la aplicación Qt (event loop)
    QWidget,          # Widget base para ventanas y contenedores
    QVBoxLayout,      # Layout vertical (apila widgets de arriba a abajo)
    QHBoxLayout,      # Layout horizontal (coloca widgets lado a lado)
    QPushButton,      # Botón interactivo con texto
    QLabel,           # Etiqueta de texto no editable
    QTableWidget,     # Tabla con filas/columnas para eventos detectados
    QTableWidgetItem, # Celda individual de la tabla
    QHeaderView,      # Control de cabeceras de tabla
    QFileDialog,      # Diálogo nativo del SO para seleccionar archivos
    QSplitter,        # Divisor redimensionable entre dos paneles
    QTabWidget,       # Contenedor de pestañas para múltiples vistas
    QGroupBox,        # Caja agrupadora con título (panel visual)
    QStatusBar,       # Barra de estado en la parte inferior
    QSpinBox,         # Campo numérico con flechas arriba/abajo
    QCheckBox,        # Casilla de verificación booleana
    QPlainTextEdit,   # Área de texto de solo lectura (más eficiente que QTextEdit)
    QMessageBox,      # Diálogos modales de mensajes
    QComboBox,        # Lista desplegable de opciones
    QLineEdit,        # Campo de texto de una línea para búsqueda
)
from PyQt5.QtCore import (
    QTimer,      # Timer de Qt integrado con el event loop (no usa hilos)
    Qt,          # Constantes globales de Qt (alineaciones, flags, atributos)
    QThread,     # Clase base para hilos Qt con soporte de señales
    pyqtSignal,  # Decorador para definir señales Qt personalizadas
)
from PyQt5.QtGui import (
    QFont,   # Fuentes tipográficas (familia, tamaño, bold)
    QColor,  # Representación de colores RGB/hex para celdas
    QBrush,  # Pincel para colores de fondo/texto en QTableWidget
)

# Matplotlib embebido en Qt5 para gráficos dentro de la ventana
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure          # Figura contenedora del gráfico
from matplotlib import style                  # Estilos predefinidos de Matplotlib
from matplotlib import cm                     # Colormaps para paletas automáticas
from matplotlib import colors as mcolors      # Utilidades de conversión de colores

# Módulo interno para verificación de reputación IP en AbuseIPDB
from abuseipdb_module import GestorAbuseIPDB

# BASE_DIR: Ruta absoluta al directorio del proyecto
# Necesario para cargar recursos (imagen de fondo, logs) de forma portátil
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Importación condicional del motor IDS — si falla, la UI arranca sin monitoreo
try:
    import ids
    import respuesta_activa  # Para desbloqueo manual desde la UI
except Exception as _e:
    ids = None
    respuesta_activa = None
    logging.error("No se pudo importar 'ids' o 'respuesta_activa'. Detalle: %s", _e)

# Activa el tema oscuro de Matplotlib para los gráficos embebidos
style.use('dark_background')


# =============================================================================
# CONSTANTES DE RENDIMIENTO
# Controlan límites de memoria y frecuencia de actualización de la UI
# =============================================================================
MAX_EVENTOS_TABLA   = 1000   # Filas visibles máximas en la tabla (evita lag de scroll)
MAX_EVENTOS_MEMORIA = 10000  # Límite total en el deque global (evita memory leak)
MAX_TRAFICO_LINEAS  = 500    # Líneas máximas en el panel "Tráfico en Vivo"
UPDATE_BATCH_SIZE   = 50     # Eventos procesados por ciclo del DataProcessor


# =============================================================================
# ATTACK_STYLE: Mapa de tipos de ataque → color de resaltado en la tabla
# Cada tipo tiene un color distintivo para identificación visual rápida (SOC)
# =============================================================================
ATTACK_STYLE = {
    "Inyección SQL":  {"color": "#ff5370"},  # Rojo
    "PORT scanner":   {"color": "#bb86fc"},  # Violeta
    "DDOS":           {"color": "#00eaff"},  # Cian
    "SYN FLOOD":      {"color": "#82b1ff"},  # Azul claro
    "UDP Flood":      {"color": "#ffa000"},  # Naranja
}


# =============================================================================
# FUNCIÓN: colors_for_labels
# Propósito: Asigna un color a cada etiqueta de ataque para el gráfico de pastel
# Respeta ATTACK_STYLE para tipos conocidos; usa colormap para los demás
# Parámetros:
#   labels    — Lista de strings con los tipos de ataque detectados
#   cmap_name — Nombre del colormap de Matplotlib (default: "tab20")
# Retorna: Lista de strings de color hexadecimal en el mismo orden que labels
# =============================================================================
def colors_for_labels(labels, cmap_name="tab20"):
    # cm.get_cmap(): Obtiene el objeto colormap con N colores discretos
    cmap = cm.get_cmap(cmap_name, 20)
    out = []
    for lab in labels:
        st = ATTACK_STYLE.get(lab, {})
        if st.get("color"):
            out.append(st["color"])  # Color definido manualmente
        else:
            # Color determinista por hash: mismo tipo → mismo color siempre
            # abs(hash(lab)) % cmap.N: Mapea el string a un índice del colormap
            idx = abs(hash(lab)) % cmap.N
            out.append(mcolors.to_hex(cmap(idx)))  # Convierte RGBA → hex string
    return out


# =============================================================================
# ESTRUCTURAS DE DATOS GLOBALES
# deque(maxlen=N): Buffer circular — al llenarse, descarta los más antiguos
# Lock(): Mutex para garantizar consistencia al acceder desde múltiples hilos
# =============================================================================
eventos_detectados = deque(maxlen=MAX_EVENTOS_MEMORIA)  # Eventos del IDS
advertencias_cont  = {}                                  # Conteo de alertas por IP
trafico_buffer     = deque(maxlen=MAX_TRAFICO_LINEAS)   # Líneas de tráfico en vivo
data_lock          = Lock()  # Protege las estructuras anteriores contra race conditions


# =============================================================================
# CLASE: DataProcessor (QThread)
# Propósito: Procesa eventos en un hilo de background para no bloquear la UI
# Patrón: Producer-Consumer — ids.py produce eventos; DataProcessor los consume
# =============================================================================
class DataProcessor(QThread):
    # pyqtSignal(list): Señal emitida cuando un lote de eventos está listo para la UI
    data_ready  = pyqtSignal(list)
    # pyqtSignal(dict): Señal emitida con estadísticas actualizadas del sistema
    stats_ready = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.running       = False
        self.pending_events = deque()  # Cola interna de eventos sin procesar

    def add_events(self, events):
        # Extiende la cola interna con nuevos eventos — thread-safe por el GIL de Python
        self.pending_events.extend(events)

    def run(self):
        # Método principal del hilo — se ejecuta cuando se llama a .start()
        self.running = True
        while self.running:
            if self.pending_events:
                # Procesa hasta UPDATE_BATCH_SIZE eventos por ciclo (evita sobrecarga)
                batch = []
                for _ in range(min(UPDATE_BATCH_SIZE, len(self.pending_events))):
                    if self.pending_events:
                        batch.append(self.pending_events.popleft())

                if batch:
                    # Emite señal con el lote → la UI lo recibe en su hilo principal
                    self.data_ready.emit(batch)

                    # Calcula estadísticas sobre los últimos 100 eventos
                    with data_lock:
                        stats = {
                            'total_eventos': len(eventos_detectados),
                            'ips_unicas':    len(advertencias_cont),
                            # Counter sobre índice 6 (tipo de ataque) de los últimos 100 eventos
                            'tipos_ataques': dict(Counter([e[6] for e in list(eventos_detectados)[-100:]]))
                        }
                    self.stats_ready.emit(stats)

            self.msleep(100)  # Pausa 100ms entre ciclos para no saturar CPU

    def stop(self):
        # Señaliza el bucle para que termine y espera a que el hilo concluya
        self.running = False
        self.quit()
        self.wait()


# =============================================================================
# CLASE: IDSInterface (QWidget)
# Ventana principal de la aplicación — construida con layouts anidados
# =============================================================================
class IDSInterface(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDS UNIPAZ - Interfaz de Monitoreo")
        self.setGeometry(100, 100, 1200, 800)  # Posición x,y y tamaño inicial
        self.setObjectName("mainWindow")  # ID para selector de QSS (CSS de Qt)
        self.modo_oscuro = True

        # --- ATRIBUTOS DE CONTROL DE RENDIMIENTO ---
        self.last_table_update     = 0      # Timestamp del último refresco de tabla
        self.last_graph_update     = 0      # Timestamp del último refresco de gráfico
        self.update_pending        = False  # Bandera: hay actualización de tabla pendiente
        self.graph_update_pending  = False  # Bandera: hay actualización de gráfico pendiente
        self.auto_scroll_enabled   = True   # Scroll automático al último evento
        self.show_all_events       = False  # Muestra todos vs. solo MAX_EVENTOS_TABLA

        # Inicia el hilo procesador y conecta sus señales a métodos de la UI
        self.data_processor = DataProcessor()
        self.data_processor.data_ready.connect(self.process_event_batch)
        self.data_processor.stats_ready.connect(self.update_stats)
        self.data_processor.start()  # Arranca el QThread

        self.setup_styles()   # Aplica hojas de estilo QSS y carga imagen de fondo
        self.setFont(QFont("Segoe UI", 10))
        self.last_hover_row = -1  # Fila con hover actual (para efectos visuales)

        # Construye toda la estructura de widgets de la ventana
        self.setup_ui()

        # Métricas SOC (Security Operations Center)
        self._pps_count  = 0          # Paquetes por segundo (contador instantáneo)
        self._alert_ts   = deque(maxlen=5000)  # Timestamps de alertas para calcular alertas/min
        self._start_time = None       # Tiempo de inicio para cálculo de uptime

        # Debounce para resize: espera 60ms inactivo antes de recalcular proporciones
        # Evita repintado continuo mientras el usuario arrastra el borde de la ventana
        self._resize_timer = QTimer(self)
        self._resize_timer.setSingleShot(True)  # Se dispara una sola vez por activación
        self._resize_timer.timeout.connect(self._apply_table_proportions)

        self.setup_timers()   # Crea y configura todos los QTimers del sistema
        self.setup_signals()  # Conecta señales de ids.py con slots de la interfaz

    def agregar_evento_deprecated(self, evento):
        # Versión obsoleta de agregar_evento — reemplazada por agregar_evento_()
        # Conservada por compatibilidad pero no se usa en el flujo principal
        with data_lock:
            eventos_detectados.append(evento)
            try:
                self._alert_ts.append(time.time())
            except Exception:
                pass
            ip = evento[1]
            advertencias_cont[ip] = advertencias_cont.get(ip, 0) + 1
            if self._es_ip_externa(ip):
                self.ips_a_verificar_cola.add(ip)
        self.data_processor.add_events([evento])

    def _es_ip_externa(self, ip):
        """Verifica si una IP es externa (no privada/reservada)."""
        # Limpieza defensiva del string antes de procesar
        ip_limpia = str(ip).strip()
        if not ip_limpia:
            return False

        # Validación básica de formato IPv4 (debe tener exactamente 4 octetos)
        partes = ip_limpia.split('.')
        if len(partes) != 4:
            return False

        try:
            octeto1 = int(partes[0])
            octeto2 = int(partes[1])

            # Exclusión de rangos privados y especiales según RFC 1918 y IANA:
            if octeto1 == 10: return False                               # 10.0.0.0/8
            if octeto1 == 172 and 16 <= octeto2 <= 31: return False     # 172.16.0.0/12
            if octeto1 == 192 and octeto2 == 168: return False          # 192.168.0.0/16
            if octeto1 == 127 or octeto1 == 0 or octeto1 >= 224: return False  # Loopback/Multicast
            return True
        except:
            return False

    def verificar_ips_abuse(self):
        """Verifica IPs externas contra la API de AbuseIPDB."""
        ips_encontradas = set()

        # Prioridad 1: Extraer IPs del cuadro de advertencias con regex
        try:
            texto_adv = self.advertencias.toPlainText()
            if texto_adv:
                patron_ip = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"  # Regex para IPv4
                for ip in re.findall(patron_ip, texto_adv):
                    if self._es_ip_externa(ip):
                        ips_encontradas.add(ip)
        except Exception as e:
            logging.error(f"Error extrayendo IPs del warnbox: {e}")

        # Prioridad 2: Buscar en columnas IP Origen (col 1) e IP Destino (col 2) de la tabla
        if not ips_encontradas and hasattr(self, "table"):
            try:
                for fila in range(self.table.rowCount()):
                    for col in (1, 2):
                        item = self.table.item(fila, col)
                        if item and item.text().strip():
                            ip = item.text().strip()
                            if self._es_ip_externa(ip):
                                ips_encontradas.add(ip)
            except Exception as e:
                logging.error(f"Error extrayendo IPs de la tabla: {e}")

        # Prioridad 3: Usar la cola acumulada de IPs detectadas
        if not ips_encontradas and self.ips_a_verificar_cola:
            ips_encontradas = set(self.ips_a_verificar_cola)

        if not ips_encontradas:
            self.status.showMessage("No se encontraron IPs externas para verificar", 3000)
            self.ips_a_verificar_cola.clear()
            return

        ips_lista = list(ips_encontradas)
        self.status.showMessage(f"Verificando {len(ips_lista)} IPs en AbuseIPDB...", 5000)

        # Lanza la verificación asíncrona — los callbacks actualizan la UI al completar
        self.gestor_abuse.verificar_ips(
            ips_lista,
            callback_resultado=self.mostrar_resultado_abuse,
            callback_error=self.mostrar_error_abuse
        )

    def mostrar_resultado_abuse(self, resultado):
        # resultado: dict con ip, abuse_score (0-100), riesgo, total_reports, pais
        ip      = resultado['ip']
        score   = resultado['abuse_score']
        riesgo  = resultado['riesgo']
        reports = resultado['total_reports']
        pais    = resultado['pais']

        # Prepend: Inserta el nuevo resultado arriba del texto existente
        linea = f"\n🔍 AbuseIPDB | {ip} | Score: {score}% | {riesgo} | Reports: {reports} | {pais}"
        texto_actual = self.advertencias.toPlainText()
        self.advertencias.setPlainText(linea + "\n" + texto_actual)

        # Alerta visual adicional para IPs con riesgo crítico
        if "CRÍTICO" in riesgo:
            self.status.showMessage(f"[!]️ IP CRÍTICA DETECTADA: {ip}", 5000)

    def mostrar_error_abuse(self, error_msg):
        logging.error(f"Error AbuseIPDB: {error_msg}")
        linea = f"\n[X] AbuseIPDB Error: {error_msg}"
        self.advertencias.setPlainText(linea + "\n" + self.advertencias.toPlainText())

    def exportar_reporte_abuse(self):
        # QFileDialog.getSaveFileName(): Abre diálogo nativo del OS para elegir ruta
        ruta, _ = QFileDialog.getSaveFileName(
            self, "Guardar Reporte AbuseIPDB", "reporte_abuse.json", "JSON Files (*.json)"
        )
        if ruta:
            self.gestor_abuse.exportar_reporte(ruta)
            self.status.showMessage(f"Reporte guardado: {ruta}", 5000)

    def setup_styles(self):
        """Aplica QSS (CSS de Qt) e inicializa el gestor AbuseIPDB."""
        imagen_fondo = os.path.join(BASE_DIR, 'aed04dd0-dcaa-4ac2-8c8f-3bfca505b67f.png')
        if os.path.exists(imagen_fondo):
            # replace('\\', '/'): Qt espera barras / en rutas dentro de QSS en Windows
            imagen_fondo_qt = imagen_fondo.replace("\\", "/")
            self.setStyleSheet(
                self.estilo_moderno() + f"""
                #mainWindow {{
                    background-image: url('{imagen_fondo_qt}');
                    background-repeat: no-repeat;
                    background-position: center;
                }}
                """
            )
        else:
            self.setStyleSheet(self.estilo_moderno())  # Solo estilos sin imagen

        # Inicializa el gestor de AbuseIPDB con la API key
        self.api_key_abuse = "31b904b493a50236fd7bd08163d01b562ce7a5127dc3968ef589d808232696ce3ea1b68e695323d4"
        self.gestor_abuse       = GestorAbuseIPDB(self.api_key_abuse)
        self.ips_a_verificar_cola = set()  # Cola de IPs pendientes de verificar

    def setup_ui(self):
        """Construye la estructura completa de la interfaz con layouts anidados."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Título de la ventana
        header = QLabel("IDS UNIPAZ - Sistema de Detección de Intrusiones")
        header.setAlignment(Qt.AlignCenter)  # Qt.AlignCenter: centrado horizontal y vertical
        header.setFont(QFont("Segoe UI", 16, QFont.Bold))
        layout.addWidget(header)

        # --- BARRA SUPERIOR SOC (métricas + filtros) ---
        topbar = QHBoxLayout()
        topbar.setSpacing(10)

        # Badge de interfaz — muestra nombre de interfaz y estado running/stopped
        self.iface_badge = QLabel("Interfaz: N/A | ○ Stopped")
        self.iface_badge.setObjectName("ifaceBadge")
        self.iface_badge.setStyleSheet("""
            QLabel#ifaceBadge {
                padding: 4px 10px; border: 1px solid #03dac6;
                border-radius: 10px; font-size: 10px;
                color: #e0e0e0; background: rgba(0,0,0,0.35);
            }
        """)
        topbar.addWidget(self.iface_badge)

        # Métricas en tiempo real: PPS, alertas por minuto, uptime
        self.lbl_pps = QLabel("PPS: 0")
        self.lbl_pps.setStyleSheet("padding:4px 8px; border:1px solid #333; border-radius:10px; font-size:10px;")
        topbar.addWidget(self.lbl_pps)

        self.lbl_alerts_min = QLabel("Alertas/min: 0")
        self.lbl_alerts_min.setStyleSheet("padding:4px 8px; border:1px solid #333; border-radius:10px; font-size:10px;")
        topbar.addWidget(self.lbl_alerts_min)

        self.lbl_uptime = QLabel("Uptime: 00:00:00")
        self.lbl_uptime.setStyleSheet("padding:4px 8px; border:1px solid #333; border-radius:10px; font-size:10px;")
        topbar.addWidget(self.lbl_uptime)

        topbar.addStretch()  # Espacio flexible que empuja los filtros a la derecha

        # Campo de búsqueda en tiempo real — filtra filas visibles de la tabla
        topbar.addWidget(QLabel("Buscar:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("ip / tipo / puerto / protocolo ...")
        self.search_input.setMinimumWidth(260)
        # lambda _: ignora el parámetro del texto actual (no se necesita)
        self.search_input.textChanged.connect(lambda _: self.apply_filters())
        topbar.addWidget(self.search_input)

        # Filtro de severidad — muestra solo eventos de un nivel de criticidad
        topbar.addWidget(QLabel("Severidad:"))
        self.sev_filter = QComboBox()
        self.sev_filter.addItems(["Todos", "CRÍTICA", "ALTA", "MEDIA", "BAJA"])
        self.sev_filter.currentIndexChanged.connect(lambda _: self.apply_filters())
        topbar.addWidget(self.sev_filter)
        layout.addLayout(topbar)

        # --- CONTROLES DE RENDIMIENTO ---
        controls_layout = QHBoxLayout()

        # Selector de interfaz de red captura (Ethernet, Wi-Fi, etc.)
        controls_layout.addWidget(QLabel("Interfaz:"))
        self.combo_iface = QComboBox()
        self.combo_iface.setMinimumWidth(220)
        self.combo_iface.addItems(self.listar_interfaces_captura())
        # Al cambiar interfaz, actualiza el badge de estado
        self.combo_iface.currentIndexChanged.connect(lambda _: self._set_running_state(self.monitoreo_activo))
        controls_layout.addWidget(self.combo_iface)

        # QCheckBox para auto-scroll: toggled emite bool con el nuevo estado
        self.auto_scroll_cb = QCheckBox("Auto-scroll")
        self.auto_scroll_cb.setChecked(True)
        self.auto_scroll_cb.toggled.connect(self.toggle_auto_scroll)
        controls_layout.addWidget(self.auto_scroll_cb)

        # QCheckBox para mostrar todos los eventos (puede ser lento con >10k eventos)
        self.show_all_cb = QCheckBox("Mostrar todos los eventos")
        self.show_all_cb.toggled.connect(self.toggle_show_all)
        controls_layout.addWidget(self.show_all_cb)

        # QSpinBox para ajustar el límite de filas en la tabla dinámicamente
        controls_layout.addWidget(QLabel("Máx. eventos tabla:"))
        self.max_events_spin = QSpinBox()
        self.max_events_spin.setRange(100, 5000)
        self.max_events_spin.setValue(MAX_EVENTOS_TABLA)
        self.max_events_spin.valueChanged.connect(self.change_max_events)
        controls_layout.addWidget(self.max_events_spin)

        # QCheckBox para Activar Modo IPS (Respuesta Activa)
        self.ips_activo_cb = QCheckBox("MODO IPS (Bloqueo Automático)")
        self.ips_activo_cb.setStyleSheet("color: #ff3b30; font-weight: bold; margin-left: 20px;")
        self.ips_activo_cb.toggled.connect(self.toggle_ips_mode)
        controls_layout.addWidget(self.ips_activo_cb)

        controls_layout.addStretch()
        layout.addLayout(controls_layout)

        # --- SPLITTER PRINCIPAL: divide la ventana en panel izquierdo y derecho ---
        # QSplitter: El usuario puede redimensionar los paneles arrastrando el divisor
        splitter = QSplitter(Qt.Horizontal)
        left  = QWidget()
        right = QWidget()
        self.setup_left_panel(left)
        self.setup_right_panel(right)
        splitter.addWidget(left)
        splitter.addWidget(right)
        # setStretchFactor: Define la proporción de expansión (4:6 → izq 40%, der 60%)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 6)
        splitter.setSizes([480, 720])  # Tamaños iniciales en píxeles
        layout.addWidget(splitter)

        # Barra de estado en la parte inferior de la ventana
        self.status = QStatusBar()
        layout.addWidget(self.status)

    def setup_left_panel(self, left):
        """Panel izquierdo: tabla de eventos + caja de advertencias."""
        vi = QVBoxLayout(left)
        lbl = QLabel("Eventos Detectados")
        lbl.setFont(QFont("Segoe UI", 13, QFont.Bold))
        vi.addWidget(lbl)

        # Tabla optimizada — ver método crear_tabla_eventos_optimizada()
        self.table = self.crear_tabla_eventos_optimizada()
        self.table.itemSelectionChanged.connect(self.update_detail_panel)
        vi.addWidget(self.table)

        # QTimer.singleShot(0, ...): Ejecuta en el próximo ciclo del event loop
        # Garantiza que el widget ya tiene tamaño asignado al aplicar proporciones
        QTimer.singleShot(0, self._apply_table_proportions)

        # Panel de advertencias — QPlainTextEdit es más eficiente que QTextEdit
        # para texto de solo lectura con muchas actualizaciones
        advert_box = QGroupBox("Advertencias")
        advert_box.setObjectName("warnBox")  # ID para selector QSS
        adv_layout = QVBoxLayout()
        self.advertencias = QPlainTextEdit()
        self.advertencias.setObjectName("warnText")
        self.advertencias.setReadOnly(True)
        self.advertencias.setFont(QFont("Segoe UI", 10, QFont.Bold))
        # setMaximumBlockCount: Limita el historial a 100 líneas sin acumular en memoria
        self.advertencias.document().setMaximumBlockCount(100)
        adv_layout.addWidget(self.advertencias)
        advert_box.setLayout(adv_layout)
        vi.addWidget(advert_box)

    def setup_right_panel(self, right):
        """Panel derecho: detalle del evento, tráfico en vivo, gráfico y botones."""
        vd = QVBoxLayout(right)

        # Panel de detalle SOC — muestra info completa del evento seleccionado
        detalle_box = QGroupBox("Detalle del Evento")
        detalle_box.setObjectName("detailBox")
        detalle_layout = QVBoxLayout()
        self.detalle_text = QPlainTextEdit()
        self.detalle_text.setReadOnly(True)
        self.detalle_text.setFont(QFont("Segoe UI", 9))
        self.detalle_text.document().setMaximumBlockCount(200)
        self.detalle_text.setPlainText("Seleccione una alerta para ver el detalle.")
        detalle_layout.addWidget(self.detalle_text)
        detalle_box.setLayout(detalle_layout)
        vd.addWidget(detalle_box)

        # Panel de tráfico en vivo — feed de todos los paquetes capturados
        trafico_box = QGroupBox("Tráfico en Vivo")
        trafico_box.setObjectName("trafficBox")
        trafico_layout = QVBoxLayout()
        self.trafico_en_vivo = QPlainTextEdit()
        self.trafico_en_vivo.setObjectName("trafficText")
        self.trafico_en_vivo.setReadOnly(True)
        self.trafico_en_vivo.setFont(QFont("Segoe UI", 9))
        self.trafico_en_vivo.document().setMaximumBlockCount(MAX_TRAFICO_LINEAS)
        trafico_layout.addWidget(self.trafico_en_vivo)
        trafico_box.setLayout(trafico_layout)
        vd.addWidget(trafico_box)

        # QTabWidget con gráfico de distribución de ataques y tabla de bloqueos
        self.tabs = QTabWidget()
        
        # Pestaña 1: Gráfico
        self.canvas_pie  = FigureCanvas(Figure(figsize=(5, 4)))
        self.axes_pie    = self.canvas_pie.figure.subplots()
        self.tabs.addTab(self.canvas_pie, "GRAFICO ESTADÍSTICO")
        
        # Pestaña 2: Gestión de Bloqueos (IPS)
        self.setup_ips_tab()

        vd.addWidget(self.tabs)

        self.setup_buttons(vd)  # Botones de control al fondo del panel

    def setup_buttons(self, layout):
        """Crea y agrega los botones de control al layout dado."""
        btns = QHBoxLayout()
        btns.setSpacing(8)
        btns.setContentsMargins(0, 8, 0, 0)

        # crear_boton(): Helper que instancia QPushButton y conecta la señal clicked
        self.boton_iniciar         = self.crear_boton("Iniciar",             self.iniciar_monitoreo,   True)
        self.boton_detener         = self.crear_boton("Detener",             self.detener_monitoreo,   False)
        self.boton_limpiar         = self.crear_boton("Limpiar",             self.limpiar_tabla,       True)
        self.boton_exportar        = self.crear_boton("Exportar CSV",        self.exportar_csv,        True)
        self.boton_evidencia       = self.crear_boton("Evidencia",           self.generar_evidencia,   True)
        self.boton_verificar_abuse = self.crear_boton("Verificar AbuseIPDB", self.verificar_ips_abuse, True)
        self.boton_tema            = self.crear_boton("Modo Claro",          self.cambiar_tema,        True)

        for b in [self.boton_iniciar, self.boton_detener, self.boton_limpiar,
                  self.boton_exportar, self.boton_evidencia,
                  self.boton_verificar_abuse, self.boton_tema]:
            btns.addWidget(b)
        layout.addLayout(btns)

    def setup_timers(self):
        """Crea todos los QTimers — se inician en iniciar_monitoreo()."""
        self.timer       = QTimer()  # Actualización de tabla (cada 3s al monitorear)
        self.timer.timeout.connect(self.actualizar_tabla_optimizada)

        self.graf_timer  = QTimer()  # Actualización de gráfico (cada 10s)
        self.graf_timer.timeout.connect(self.actualizar_grafico_auto)

        self.pps_timer   = QTimer()  # PPS (paquetes/segundo) cada 1s
        self.pps_timer.timeout.connect(self._tick_pps)

        self.uptime_timer = QTimer()  # Uptime (tiempo activo) cada 1s
        self.uptime_timer.timeout.connect(self._tick_uptime)

        self.alerts_timer = QTimer()  # Alertas/minuto cada 5s
        self.alerts_timer.timeout.connect(self._tick_alerts_per_min)

        # Timer para countdown de bloqueos IPS (cada 1 segundo)
        self.bloqueos_timer = QTimer()
        self.bloqueos_timer.timeout.connect(self._tick_bloqueos_timer)
        self.bloqueos_timer.start(1000)  # Siempre activo para actualizar expirados

        self.monitoreo_activo = False

        # Timers de guardado diario automático (24h en milisegundos)
        self.timer_guardar_diario = QTimer()
        self.timer_guardar_diario.timeout.connect(self.guardar_grafico_pie_diario)
        self.timer_guardar_diario.start(24 * 60 * 60 * 1000)

        self.timer_guardar_csv_diario = QTimer()
        self.timer_guardar_csv_diario.timeout.connect(self.guardar_csv_diario)
        self.timer_guardar_csv_diario.start(24 * 60 * 60 * 1000)

    def setup_signals(self):
        """Conecta señales del módulo ids.py con métodos de esta interfaz."""
        self.table.setMouseTracking(False)  # Deshabilita hover tracking (reduce eventos Qt)

        # Conexión de señales del motor IDS al UI — puente entre hilos
        if ids and hasattr(ids, 'comunicador'):
            try:
                ids.comunicador.nuevo_evento.connect(self.agregar_evento_)
                ids.comunicador.nuevo_trafico.connect(self.agregar_trafico_)
                ids.comunicador.nuevo_bloqueo.connect(self.actualizar_tabla_bloqueos_signal)
            except Exception as e:
                logging.error(f"No se pudieron conectar señales de 'ids': {e}")

    def crear_tabla_eventos_optimizada(self):
        """Crea la tabla de eventos con optimizaciones de rendimiento."""
        table = QTableWidget()
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "Sev", "Hora", "IP Origen", "IP Destino",
            "Puerto", "Protocolo", "Flag", "Tipo"
        ])

        header_h = table.horizontalHeader()
        header_v = table.verticalHeader()

        # QHeaderView.Fixed: Los anchos de columna son controlados programáticamente
        # (evita que Qt los recalcule en cada inserción, lo que causaría lag)
        header_h.setSectionResizeMode(QHeaderView.Fixed)
        header_h.setStretchLastSection(False)
        header_v.setSectionResizeMode(QHeaderView.Fixed)
        header_v.setDefaultSectionSize(25)  # Alto de cada fila en píxeles
        header_v.hide()  # Oculta numeración de filas para limpiar la UI

        # Optimizaciones críticas:
        table.setWordWrap(False)             # Evita cálculos de altura de línea
        table.setSortingEnabled(False)       # El sorting dispara redibujado costoso
        table.setAlternatingRowColors(True)  # Alternado de colores para legibilidad
        table.setShowGrid(False)             # Sin grilla = menos píxeles a dibujar
        table.setEditTriggers(QTableWidget.NoEditTriggers)   # Tabla de solo lectura
        table.setSelectionBehavior(QTableWidget.SelectRows)  # Selecciona fila completa
        table.setSelectionMode(QTableWidget.SingleSelection) # Solo una fila a la vez

        # ScrollPerPixel: Scroll suave en vez de por filas enteras
        table.setVerticalScrollMode(QTableWidget.ScrollPerPixel)
        table.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)

        # Anchos iniciales en píxeles (serán recalculados por _apply_table_proportions)
        for i, ancho in enumerate([120, 140, 140, 70, 90, 70, 220]):
            table.setColumnWidth(i, ancho)

        return table

    def agregar_evento_(self, evento):
        """Versión optimizada: agrega a estructuras y delega el UI al DataProcessor."""
        print(f"DEBUG - Evento recibido: {evento}")
        with data_lock:
            eventos_detectados.append(evento)
            try:
                self._alert_ts.append(time.time())
            except Exception:
                pass
            ip = evento[1]
            advertencias_cont[ip] = advertencias_cont.get(ip, 0) + 1
        # No actualiza la UI directamente — usa batch processing para mejor rendimiento
        self.data_processor.add_events([evento])

    def agregar_trafico_(self, mensaje):
        """Agrega línea al buffer de tráfico y actualiza el panel cada 10 mensajes."""
        try:
            self._pps_count += 1
        except Exception:
            self._pps_count = 1
        trafico_buffer.append(mensaje)
        if len(trafico_buffer) % 10 == 0:  # Batch: actualiza cada 10 mensajes
            self.actualizar_trafico_batch()

    def setup_ips_tab(self):
        """Crea la pestaña profesional de Respuesta Activa IPS con tabla de 7 columnas,
        badges de resumen en tiempo real y countdown de expiración."""
        self.ips_tab = QWidget()
        layout = QVBoxLayout(self.ips_tab)
        layout.setSpacing(8)

        # --- TÍTULO DEL PANEL ---
        lbl_titulo = QLabel("RESPUESTA ACTIVA IPS — IPs Bloqueadas en Tiempo Real")
        lbl_titulo.setFont(QFont("Segoe UI", 12, QFont.Bold))
        lbl_titulo.setStyleSheet("color: #ff3b30; padding: 4px;")
        layout.addWidget(lbl_titulo)

        # --- BADGES DE RESUMEN (indicadores SOC) ---
        badges_layout = QHBoxLayout()
        badges_layout.setSpacing(12)

        badge_style = (
            "padding: 6px 14px; border: 1px solid {color}; border-radius: 8px;"
            "font-size: 11px; font-weight: bold; color: {color}; background: rgba(0,0,0,0.4);"
        )

        self.lbl_total_bloqueadas = QLabel("Total: 0")
        self.lbl_total_bloqueadas.setStyleSheet(badge_style.format(color="#03dac6"))
        badges_layout.addWidget(self.lbl_total_bloqueadas)

        self.lbl_bloqueos_activos = QLabel("Activos: 0")
        self.lbl_bloqueos_activos.setStyleSheet(badge_style.format(color="#ff3b30"))
        badges_layout.addWidget(self.lbl_bloqueos_activos)

        self.lbl_bloqueos_expirados = QLabel("Expirados: 0")
        self.lbl_bloqueos_expirados.setStyleSheet(badge_style.format(color="#ffd60a"))
        badges_layout.addWidget(self.lbl_bloqueos_expirados)

        self.lbl_ultimo_ataque = QLabel("Ultimo ataque: —")
        self.lbl_ultimo_ataque.setStyleSheet(badge_style.format(color="#bb86fc"))
        badges_layout.addWidget(self.lbl_ultimo_ataque)

        badges_layout.addStretch()
        layout.addLayout(badges_layout)

        # --- TABLA DE BLOQUEOS (7 columnas profesionales) ---
        self.table_bloqueos = QTableWidget()
        self.table_bloqueos.setColumnCount(7)
        self.table_bloqueos.setHorizontalHeaderLabels([
            "Hora", "IP Bloqueada", "Tipo de Ataque",
            "Severidad", "Accion Aplicada", "Estado", "Tiempo Restante"
        ])
        header = self.table_bloqueos.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        self.table_bloqueos.verticalHeader().hide()
        self.table_bloqueos.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table_bloqueos.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_bloqueos.setSelectionMode(QTableWidget.SingleSelection)
        self.table_bloqueos.setAlternatingRowColors(True)
        self.table_bloqueos.setShowGrid(False)
        self.table_bloqueos.setStyleSheet("""
            QTableWidget { background-color: #0a0a0a; gridline-color: #222; }
            QHeaderView::section {
                background-color: #1a1a1a; color: #ff3b30;
                padding: 5px; border: 1px solid #333;
                font-weight: bold; font-size: 10px;
            }
        """)
        layout.addWidget(self.table_bloqueos)

        # --- BOTÓN DE DESBLOQUEO MANUAL ---
        btn_unblock = QPushButton("Desbloquear IP Seleccionada")
        btn_unblock.setStyleSheet(
            "background-color: #292929; color: #4CAF50; border: 1px solid #4CAF50;"
            "border-radius: 4px; padding: 6px 14px; font-weight: bold;"
        )
        btn_unblock.clicked.connect(self.desbloquear_ip_manual)
        layout.addWidget(btn_unblock)

        self.tabs.addTab(self.ips_tab, "RESPUESTA ACTIVA (IPS)")

        # --- ESTRUCTURA INTERNA: lista de metadatos de bloqueos para countdown ---
        # Cada entrada: {'ip': str, 'tipo': str, 'expiry': float (epoch), 'row': int}
        self._bloqueos_data = []

    def toggle_ips_mode(self, enabled):
        """Habilita/Deshabilita el modo IPS en el motor de detección."""
        if ids:
            ids.ips_activo = enabled
            estado = "ACTIVADO" if enabled else "DESACTIVADO"
            self.status.showMessage(f"Modo IPS (Respuesta Activa) {estado}", 5000)
            print(f"DEBUG: Modo IPS {estado}")

    def actualizar_tabla_bloqueos_signal(self, datos_bloqueo):
        """Slot que recibe la señal nuevo_bloqueo desde ids.py y la muestra en la tabla.
        Formato esperado: [ip, accion, duracion, tipo_ataque, severidad]
        Compatible con formato antiguo de 3 elementos."""
        try:
            # Compatibilidad: soporta tanto formato viejo (3) como nuevo (5)
            if len(datos_bloqueo) >= 5:
                ip, accion, duracion, tipo_ataque, severidad = datos_bloqueo[:5]
            elif len(datos_bloqueo) >= 3:
                ip, accion, duracion = datos_bloqueo[:3]
                tipo_ataque = "Desconocido"
                severidad = "ALTA"
            else:
                return

            hora = time.strftime("%H:%M:%S")
            accion_texto = "Bloqueo automatico"
            estado = "Activo"
            expiry_epoch = time.time() + (duracion * 60)  # Epoch de expiración

            # Colores por severidad para la tabla
            colores_sev = {
                "CRITICA": "#ff3b30", "ALTA": "#ff9500",
                "MEDIA": "#ffd60a", "BAJA": "#0a84ff"
            }
            color_sev = colores_sev.get(severidad, "#ff9500")

            # Inserta nueva fila en la tabla
            row = self.table_bloqueos.rowCount()
            self.table_bloqueos.insertRow(row)

            # Valores de cada columna
            valores = [hora, ip, tipo_ataque, severidad, accion_texto, estado, f"{duracion}:00"]

            for col, val in enumerate(valores):
                item = QTableWidgetItem(str(val))
                item.setForeground(QBrush(QColor("#e0e0e0")))
                # Columna Severidad: color según nivel
                if col == 3:
                    item.setForeground(QBrush(QColor(color_sev)))
                # Columna Estado: verde para Activo
                if col == 5:
                    item.setForeground(QBrush(QColor("#4CAF50")))
                self.table_bloqueos.setItem(row, col, item)

            # Guarda metadatos para el countdown
            self._bloqueos_data.append({
                'ip': ip, 'tipo': tipo_ataque, 'expiry': expiry_epoch,
                'row': row, 'estado': 'Activo'
            })

            # Actualiza badges de resumen
            self._actualizar_resumen_bloqueos()
            self.lbl_ultimo_ataque.setText(f"Ultimo ataque: {tipo_ataque}")

            self.status.showMessage(f"[IPS] IP BLOQUEADA: {ip} | {tipo_ataque} | {severidad}", 5000)
        except Exception as e:
            logging.error(f"Error actualizando tabla de bloqueos: {e}")

    def _tick_bloqueos_timer(self):
        """Timer de 1 segundo: actualiza el countdown y estado de cada bloqueo activo."""
        try:
            ahora = time.time()
            cambio = False

            for entry in self._bloqueos_data:
                row = entry['row']
                if entry['estado'] != 'Activo':
                    continue

                restante = entry['expiry'] - ahora
                if restante <= 0:
                    # Bloqueo expirado: actualiza estado y color
                    entry['estado'] = 'Expirado'
                    estado_item = self.table_bloqueos.item(row, 5)
                    tiempo_item = self.table_bloqueos.item(row, 6)
                    if estado_item:
                        estado_item.setText("Expirado")
                        estado_item.setForeground(QBrush(QColor("#ffd60a")))
                    if tiempo_item:
                        tiempo_item.setText("00:00")
                        tiempo_item.setForeground(QBrush(QColor("#666666")))
                    cambio = True
                else:
                    # Countdown activo: formato mm:ss
                    mins = int(restante // 60)
                    secs = int(restante % 60)
                    tiempo_item = self.table_bloqueos.item(row, 6)
                    if tiempo_item:
                        tiempo_item.setText(f"{mins:02d}:{secs:02d}")
                        # Rojo parpadeante cuando queda menos de 1 minuto
                        if restante < 60:
                            tiempo_item.setForeground(QBrush(QColor("#ff3b30")))
                        else:
                            tiempo_item.setForeground(QBrush(QColor("#03dac6")))

            if cambio:
                self._actualizar_resumen_bloqueos()
        except Exception as e:
            logging.error(f"Error en tick bloqueos: {e}")

    def _actualizar_resumen_bloqueos(self):
        """Recalcula y actualiza los badges de resumen del panel IPS."""
        total = len(self._bloqueos_data)
        activos = sum(1 for b in self._bloqueos_data if b['estado'] == 'Activo')
        expirados = sum(1 for b in self._bloqueos_data if b['estado'] != 'Activo')
        self.lbl_total_bloqueadas.setText(f"Total: {total}")
        self.lbl_bloqueos_activos.setText(f"Activos: {activos}")
        self.lbl_bloqueos_expirados.setText(f"Expirados: {expirados}")

    def desbloquear_ip_manual(self):
        """Desbloquea manualmente una IP seleccionada en la tabla IPS."""
        items = self.table_bloqueos.selectedItems()
        if not items:
            QMessageBox.information(self, "Info", "Seleccione una fila para desbloquear.")
            return

        row = items[0].row()
        ip_item = self.table_bloqueos.item(row, 1)  # Columna 1 = IP Bloqueada
        if not ip_item:
            return
        ip = ip_item.text()

        if respuesta_activa and respuesta_activa.desbloquear_ip(ip):
            # Actualiza estado visual en vez de eliminar la fila (mantiene historial)
            estado_item = self.table_bloqueos.item(row, 5)
            tiempo_item = self.table_bloqueos.item(row, 6)
            if estado_item:
                estado_item.setText("Desbloqueado")
                estado_item.setForeground(QBrush(QColor("#0a84ff")))
            if tiempo_item:
                tiempo_item.setText("—")
            # Actualiza metadatos internos
            for entry in self._bloqueos_data:
                if entry['row'] == row:
                    entry['estado'] = 'Desbloqueado'
            self._actualizar_resumen_bloqueos()
            self.status.showMessage(f"[OK] IP Desbloqueada manualmente: {ip}", 5000)
        else:
            QMessageBox.warning(self, "Error", f"No se pudo desbloquear la IP {ip}")

    def actualizar_trafico_batch(self):
        """Actualiza el panel de tráfico con los últimos 20 mensajes del buffer."""
        if not trafico_buffer:
            return
        mensajes = list(trafico_buffer)[-20:]
        self.trafico_en_vivo.setPlainText('\n'.join(mensajes))
        if self.auto_scroll_enabled:
            # scrollToBottom: Mueve el scroll al final para ver los eventos más recientes
            self.trafico_en_vivo.verticalScrollBar().setValue(
                self.trafico_en_vivo.verticalScrollBar().maximum()
            )

    def process_event_batch(self, events):
        """Callback del DataProcessor — activa actualización de tabla con debounce."""
        if not self.update_pending:
            self.update_pending = True
            # singleShot(100ms): Retrasa la actualización para agrupar múltiples eventos
            QTimer.singleShot(100, self.actualizar_tabla_optimizada)

    def update_stats(self, stats):
        """Muestra estadísticas globales en la barra de estado."""
        self.status.showMessage(
            f"Eventos: {stats['total_eventos']} | IPs únicas: {stats['ips_unicas']}"
        )

    def _hash_muestra_eventos(self, eventos):
        """
        Hash ligero sobre las últimas 50 filas para detectar cambios de contenido.
        Evita redibujar la tabla si los datos no han cambiado.
        """
        muestra = eventos[-50:] if len(eventos) > 50 else eventos
        try:
            key = tuple(tuple(ev) for ev in muestra)
            return hash(key)
        except Exception:
            # Fallback si los elementos no son hasheables
            return hash(tuple(sorted(Counter([e[6] for e in muestra]).items())))

    def _compute_severity(self, tipo_texto: str):
        """Mapea tipo de ataque a nivel de severidad SOC con color asociado."""
        t = (tipo_texto or "").lower()
        if "posible exploit" in t or "exploit" in t:
            return "CRÍTICA", "#ff3b30"   # Rojo: máxima urgencia
        if "ddos" in t or "syn flood" in t or "udp flood" in t:
            return "ALTA",    "#ff9500"   # Naranja: requiere atención inmediata
        if "escaneo" in t or "port" in t or "scan" in t:
            return "MEDIA",   "#ffd60a"   # Amarillo: reconocimiento
        if "sql injection" in t or "sqli" in t:
            return "ALTA",    "#ff9500"   # Naranja: compromiso potencial de datos
        return "BAJA",    "#0a84ff"       # Azul: informativo

    def _row_matches_filters(self, row_values):
        """Retorna True si una fila cumple los filtros activos de severidad y búsqueda."""
        sev_filter = self.sev_filter.currentText() if hasattr(self, "sev_filter") else "Todos"
        if sev_filter != "Todos" and row_values.get("sev") != sev_filter:
            return False

        q = (self.search_input.text() if hasattr(self, "search_input") else "").strip().lower()
        if not q:
            return True

        # Concatena todos los valores de la fila en un string para búsqueda global
        haystack = " ".join(str(v).lower() for v in row_values.values())
        return q in haystack

    def apply_filters(self):
        """Oculta/muestra filas de la tabla según los filtros activos."""
        try:
            for r in range(self.table.rowCount()):
                # Extrae texto de cada celda de la fila (o string vacío si es None)
                sev    = self.table.item(r, 0).text() if self.table.item(r, 0) else ""
                hora   = self.table.item(r, 1).text() if self.table.item(r, 1) else ""
                ip_src = self.table.item(r, 2).text() if self.table.item(r, 2) else ""
                ip_dst = self.table.item(r, 3).text() if self.table.item(r, 3) else ""
                puerto = self.table.item(r, 4).text() if self.table.item(r, 4) else ""
                proto  = self.table.item(r, 5).text() if self.table.item(r, 5) else ""
                flag   = self.table.item(r, 6).text() if self.table.item(r, 6) else ""
                tipo   = self.table.item(r, 7).text() if self.table.item(r, 7) else ""

                row_ok = self._row_matches_filters({
                    "sev": sev, "hora": hora, "ip_src": ip_src, "ip_dst": ip_dst,
                    "puerto": puerto, "proto": proto, "flag": flag, "tipo": tipo,
                })
                # setRowHidden: Oculta la fila sin eliminarla (preserva los datos)
                self.table.setRowHidden(r, not row_ok)
        except Exception as e:
            logging.error(f"Error aplicando filtros: {e}")

    def listar_interfaces_captura(self):
        """Lista interfaces de red disponibles para captura (Windows con Scapy/Npcap)."""
        ifaces = []
        try:
            from scapy.arch.windows import get_windows_if_list
            for i in get_windows_if_list():
                name = i.get("name") or ""
                desc = (i.get("description") or "").lower()
                ips  = i.get("ips") or []

                # Filtra interfaces de captura virtuales (WFP, Npcap loopback, etc.)
                nlow = name.lower()
                if "-wfp" in nlow or "-npcap" in nlow or "-filter" in nlow:
                    continue
                if "loopback" in desc or "wi-fi direct" in desc:
                    continue

                # Solo incluye interfaces con IPv4 activa
                if not any("." in ip for ip in ips):
                    continue
                ifaces.append(name)
        except Exception as e:
            logging.error(f"No se pudieron listar interfaces: {e}")

        if not ifaces:
            ifaces = ["Ethernet", "Wi-Fi"]  # Fallback con nombres estándar

        # Prioriza Ethernet sobre Wi-Fi (más estable para captura)
        if "Ethernet" in ifaces:
            ifaces = ["Ethernet"] + [x for x in ifaces if x != "Ethernet"]

        return ifaces

    def _set_running_state(self, running: bool):
        """Actualiza el badge de interfaz con el estado actual del monitoreo."""
        iface  = self.combo_iface.currentText() if hasattr(self, "combo_iface") else "N/A"
        estado = "● Running" if running else "○ Stopped"
        self.iface_badge.setText(f"Interfaz: {iface} | {estado}")

    def _tick_pps(self):
        """Actualiza el label PPS con el contador del último segundo y lo resetea."""
        try:
            pps = getattr(self, "_pps_count", 0)
            self.lbl_pps.setText(f"PPS: {pps}")
            self._pps_count = 0  # Reset para el siguiente segundo
        except Exception as e:
            logging.error(f"Error PPS tick: {e}")

    def _tick_uptime(self):
        """Calcula y muestra el tiempo transcurrido desde que inició el monitoreo."""
        try:
            if not getattr(self, "_start_time", None):
                self.lbl_uptime.setText("Uptime: 00:00:00")
                return
            delta = int(time.time() - self._start_time)
            # Desglose en horas, minutos y segundos con formato HH:MM:SS
            h = delta // 3600
            m = (delta % 3600) // 60
            s = delta % 60
            self.lbl_uptime.setText(f"Uptime: {h:02d}:{m:02d}:{s:02d}")
        except Exception as e:
            logging.error(f"Error uptime tick: {e}")

    def _tick_alerts_per_min(self):
        """Cuenta alertas en la ventana del último minuto (60 segundos)."""
        try:
            dq    = getattr(self, "_alert_ts", None)
            ahora = time.time()
            # Descarta timestamps más viejos de 60 segundos (ventana deslizante)
            while dq and (ahora - dq[0]) > 60:
                dq.popleft()
            self.lbl_alerts_min.setText(f"Alertas/min: {len(dq)}")
        except Exception as e:
            logging.error(f"Error alert/min tick: {e}")

    def update_detail_panel(self):
        """Muestra información detallada del evento seleccionado en la tabla."""
        try:
            items = self.table.selectedItems()
            if not items:
                self.detalle_text.setPlainText("Seleccione una alerta para ver el detalle.")
                return

            row   = items[0].row()  # Índice de la fila seleccionada
            sev   = self.table.item(row, 0).text() if self.table.item(row, 0) else ""
            hora  = self.table.item(row, 1).text() if self.table.item(row, 1) else ""
            ip_src = self.table.item(row, 2).text() if self.table.item(row, 2) else ""
            ip_dst = self.table.item(row, 3).text() if self.table.item(row, 3) else ""
            puerto = self.table.item(row, 4).text() if self.table.item(row, 4) else ""
            proto  = self.table.item(row, 5).text() if self.table.item(row, 5) else ""
            flag   = self.table.item(row, 6).text() if self.table.item(row, 6) else ""
            tipo   = self.table.item(row, 7).text() if self.table.item(row, 7) else ""

            # Genera evidencia contextual según el tipo de ataque detectado
            evidencia = [f"- Protocolo/Flag: {proto}/{flag}"]
            if "syn flood"   in tipo.lower(): evidencia.append("- Indicador: volumen alto de SYN en ventana corta")
            if "ddos"        in tipo.lower(): evidencia.append("- Indicador: volumen alto hacia destino (posible DDoS)")
            if "escaneo"     in tipo.lower(): evidencia.append("- Indicador: múltiples puertos probados desde una misma IP")
            if "sql"         in tipo.lower(): evidencia.append("- Indicador: patrón de payload compatible con SQLi")

            # Formato de reporte SOC estructurado para análisis e incidentes
            txt = (
                f"SEVERIDAD: {sev}\nHORA: {hora}\nTIPO: {tipo}\n"
                f"IP ORIGEN: {ip_src}\nIP DESTINO: {ip_dst}\nPUERTO: {puerto}\n\n"
                f"EVIDENCIA (resumen):\n" + "\n".join(evidencia) + "\n\n"
                f"ACCIONES SUGERIDAS:\n"
                f"- llamar al profesor Jhoni si la alarma persiste\n"
                f"- Revisar logs del servicio en puerto destino\n"
                f"- Bloquear/limitar si es recurrente\n"
            )
            self.detalle_text.setPlainText(txt)
        except Exception as e:
            logging.error(f"Error actualizando detalle: {e}")

    def actualizar_tabla_optimizada(self):
        """Refresca la tabla con los eventos más recientes aplicando hash diff."""
        self.update_pending = False
        try:
            with data_lock:
                max_eventos     = self.max_events_spin.value()
                eventos_a_mostrar = (
                    list(eventos_detectados)[-max_eventos:]
                    if not self.show_all_events
                    else list(eventos_detectados)
                )

            self.table.setRowCount(len(eventos_a_mostrar))

            # Hash diff: solo redibuja si el contenido de las últimas 50 filas cambió
            nuevo_hash = self._hash_muestra_eventos(eventos_a_mostrar)
            contenido_cambio = (getattr(self, "_last_cnt_hash", None) != nuevo_hash)
            self._last_cnt_hash = nuevo_hash

            # setUpdatesEnabled(False): Suspende el redibujado durante la actualización
            # Evita parpadeos y mejora significativamente el rendimiento
            self.table.setUpdatesEnabled(False)
            try:
                if contenido_cambio:
                    bg_color = "#000000"
                    fg_color = "#ab0df5" if self.modo_oscuro else "#ffffff"

                    for i, ev in enumerate(eventos_a_mostrar):
                        try:
                            hora, ip_src, ip_dst, puerto, protocolo, flag, tipo = ev
                        except Exception:
                            lst = list(ev) + [""] * 7
                            hora, ip_src, ip_dst, puerto, protocolo, flag, tipo = lst[:7]

                        sev_txt, sev_color = self._compute_severity(str(tipo))
                        cols = [sev_txt, hora, ip_src, ip_dst, puerto, protocolo, flag, tipo]

                        for j, v in enumerate(cols):
                            it = self.table.item(i, j)
                            if not it:
                                it = QTableWidgetItem()
                                self.table.setItem(i, j, it)

                            it.setText(str(v))
                            it.setBackground(QBrush(QColor(bg_color)))

                            if j == 0:
                                # Columna Severidad: color según nivel de criticidad
                                it.setForeground(QBrush(QColor(sev_color)))
                            elif j == 7:
                                # Columna Tipo: color del ATTACK_STYLE si existe
                                st = ATTACK_STYLE.get(tipo, {})
                                it.setForeground(QBrush(QColor(st.get("color", "#f54f13"))))
                            else:
                                it.setForeground(QBrush(QColor(fg_color)))
            finally:
                self.table.setUpdatesEnabled(True)  # Reactiva el redibujado siempre

            self.apply_filters()

            if self.auto_scroll_enabled and eventos_a_mostrar:
                self.table.scrollToBottom()

            self.actualizar_advertencias_optimizada()

        except Exception as e:
            logging.error(f"Error actualizando tabla optimizada: {e}")

    def actualizar_advertencias_optimizada(self):
        """Reconstruye el panel de advertencias con las Top 100 IPs más activas."""
        try:
            with data_lock:
                # sorted + reverse=True: IPs con más advertencias primero
                items_sorted = sorted(advertencias_cont.items(), key=lambda x: x[1], reverse=True)[:100]
            texto = '\n'.join(f"[!] -> {ip}: {cnt} advertencia(s)" for ip, cnt in items_sorted)
            self.advertencias.setPlainText(texto)
        except Exception as e:
            logging.error(f"Error actualizando advertencias: {e}")

    def toggle_auto_scroll(self, enabled):
        self.auto_scroll_enabled = enabled

    def toggle_show_all(self, show_all):
        self.show_all_events = show_all
        self.actualizar_tabla_optimizada()

    def change_max_events(self, value):
        global MAX_EVENTOS_TABLA
        MAX_EVENTOS_TABLA = value
        self.actualizar_tabla_optimizada()
        self._apply_table_proportions()

    def cambiar_tema(self):
        """Alterna entre modo oscuro y claro actualizando estilos, tabla y gráficos."""
        self.modo_oscuro = not self.modo_oscuro
        self.boton_tema.setText("Modo Claro" if self.modo_oscuro else "Modo Oscuro")
        self.aplicar_tema()
        self.actualizar_tabla_optimizada()
        self.actualizar_grafico_auto()
        self.status.showMessage(
            f"Tema cambiado a modo {'oscuro' if self.modo_oscuro else 'claro'}", 3000
        )

    def aplicar_tema(self):
        """Aplica el stylesheet correspondiente al modo actual."""
        imagen_fondo = os.path.join(BASE_DIR, 'aed04dd0-dcaa-4ac2-8c8f-3bfca505b67f.png')
        if self.modo_oscuro:
            if os.path.exists(imagen_fondo):
                imagen_fondo_qt = imagen_fondo.replace("\\", "/")
                self.setStyleSheet(
                    self.estilo_moderno() + f"""
                    #mainWindow {{ background-image: url('{imagen_fondo_qt}'); background-repeat: no-repeat; background-position: center; }}
                    """
                )
            else:
                self.setStyleSheet(self.estilo_moderno())
        else:
            self.setStyleSheet(self.estilo_claro())

    def iniciar_monitoreo(self):
        """Arranca el monitoreo: habilita sniffer, timers y botones."""
        self.boton_iniciar.setEnabled(False)
        self.boton_detener.setEnabled(True)
        self.monitoreo_activo = True
        if hasattr(self, "combo_iface"):
            self.combo_iface.setEnabled(False)  # Bloquea cambio de interfaz mientras monitorea

        # Reset de métricas SOC al inicio de cada sesión
        self._pps_count  = 0
        self._alert_ts.clear()
        self._start_time = time.time()  # Marca el inicio para el uptime

        iface = self.combo_iface.currentText() if hasattr(self, "combo_iface") else None

        if ids and hasattr(ids, 'iniciar_monitoreo'):
            try:
                # Advertencia para interfaces virtuales o de solo host
                iface_lower = iface.lower()
                if "virtualbox" in iface_lower or "host-only" in iface_lower or "local*" in iface_lower:
                    QMessageBox.warning(
                        self, "Advertencia de Interfaz",
                        f"La interfaz seleccionada ({iface}) parece ser una red virtual o de solo host.\n\n"
                        "Es probable que NO detecte tráfico de internet. Si no ve actividad, "
                        "intente seleccionar su interfaz física (ej: Wi-Fi o Ethernet)."
                    )
                
                ids.iniciar_monitoreo(iface)  # Inicia el AsyncSniffer con la interfaz elegida
            except Exception as e:
                logging.error(f"Error al iniciar monitoreo en 'ids': {e}")

        self._set_running_state(True)

        # Tiempos conservadores para no saturar la UI durante captura activa
        self.timer.start(3000)        # Tabla: cada 3 segundos
        self.graf_timer.start(10000)  # Gráfico: cada 10 segundos

        # Métricas SOC: actualizaciones más frecuentes
        self.pps_timer.start(1000)
        self.uptime_timer.start(1000)
        self.alerts_timer.start(5000)

    def detener_monitoreo(self):
        """Detiene el monitoreo: para sniffer y todos los timers."""
        self.monitoreo_activo = False

        if ids and hasattr(ids, 'detener_monitoreo'):
            try:
                ids.detener_monitoreo()
            except Exception as e:
                logging.error(f"Error al detener monitoreo en 'ids': {e}")

        # Detiene todos los timers de actualización
        for timer in [self.timer, self.graf_timer, self.pps_timer,
                      self.uptime_timer, self.alerts_timer]:
            timer.stop()

        if hasattr(self, "combo_iface"):
            self.combo_iface.setEnabled(True)  # Permite cambiar interfaz nuevamente

        self._set_running_state(False)
        self.boton_iniciar.setEnabled(True)
        self.boton_detener.setEnabled(False)

    def limpiar_tabla(self):
        """Borra todos los datos de memoria y limpia los widgets visuales."""
        with data_lock:
            eventos_detectados.clear()
            advertencias_cont.clear()
            trafico_buffer.clear()

        self.table.setRowCount(0)  # Elimina todas las filas de la tabla
        self.advertencias.clear()
        self.trafico_en_vivo.clear()
        self.axes_pie.clear()
        self.canvas_pie.draw()  # Fuerza redibujado del canvas de Matplotlib
        self.status.showMessage("Interfaz limpia", 3000)

    def actualizar_grafico_auto(self):
        """Actualiza el gráfico de distribución de ataques con los últimos 500 eventos."""
        if self.graph_update_pending:
            return  # Evita actualización concurrente si ya hay una en progreso

        self.graph_update_pending = True
        try:
            with data_lock:
                if not eventos_detectados:
                    return
                eventos_muestra = list(eventos_detectados)[-500:]

            # Counter sobre índice 6 (tipo_ataque) para distribución de categorías
            cnt = Counter([e[6] for e in eventos_muestra])
            if not cnt:
                return

            labels = list(cnt.keys())
            values = list(cnt.values())
            colors = colors_for_labels(labels)  # Un color por tipo de ataque

            bg_color   = "#121212" if self.modo_oscuro else "#FFFFFF"
            text_color = "#ffffff" if self.modo_oscuro else "#000000"

            # Dibuja gráfico de torta con etiquetas y porcentajes
            self.axes_pie.clear()
            self.axes_pie.pie(
                values, labels=labels, colors=colors,
                autopct='%1.1f%%',  # Formato de porcentaje con 1 decimal
                textprops={'color': text_color, 'fontsize': 8}
            )
            self.axes_pie.set_title("Distribución de Ataques", color=text_color, fontsize=10)
            self.axes_pie.axis('equal')  # Asegura que el pastel sea circular
            self.axes_pie.set_facecolor(bg_color)
            self.canvas_pie.figure.patch.set_facecolor(bg_color)
            self.canvas_pie.figure.tight_layout()
            self.canvas_pie.draw_idle()  # draw_idle: solo redibuja si el canvas está visible

        except Exception as e:
            logging.error(f"Error actualizando gráfico: {e}")
        finally:
            self.graph_update_pending = False  # Siempre libera el flag

    def _apply_table_proportions(self):
        """Ajusta anchos de columna proporcionales al ancho visible de la tabla."""
        if not hasattr(self, "table"):
            return

        total = max(200, self.table.viewport().width())

        # Proporciones relativas al ancho total (suman ~1.0):
        # Sev=8%, Hora=12%, IP Origen=16%, IP Destino=16%, Puerto=8%, Proto=10%, Flag=8%, Tipo=22%
        ratios = [0.08, 0.12, 0.16, 0.16, 0.08, 0.10, 0.08, 0.22]
        mins   = [60,   80,   120,  120,  60,   80,   60,  200]  # Mínimos por columna

        self.table.setUpdatesEnabled(False)
        try:
            for i, r in enumerate(ratios):
                w = max(mins[i], int(total * r))
                # Solo aplica si el cambio supera 2px — evita parpadeo por cambios mínimos
                if abs(self.table.columnWidth(i) - w) > 2:
                    self.table.setColumnWidth(i, w)
        finally:
            self.table.setUpdatesEnabled(True)

    def resizeEvent(self, event):
        """Sobrescribe el evento de resize para aplicar debounce de 60ms."""
        if hasattr(self, "_resize_timer"):
            self._resize_timer.start(60)  # Reinicia el timer en cada resize
        super().resizeEvent(event)

    def estilo_moderno(self):
        """Retorna el stylesheet QSS para el modo oscuro de la interfaz."""
        return """
        QWidget { background-color: #121212; color: #e0e0e0; font-family: 'Segoe UI'; }
        QGroupBox#warnBox { border: 1px solid #ffab40; border-radius: 4px; margin-top: 8px; background-color: #1a1a1a; }
        QGroupBox#warnBox::title { subcontrol-origin: margin; subcontrol-position: top center; padding: 0 5px; color: #ffeb3b; font-size: 10px; font-weight: bold; }
        QPlainTextEdit#warnText { background: transparent; border: none; color: #ffffff; font-size: 10px; padding: 4px; }
        QGroupBox#trafficBox { border: 1px solid #00eaff; border-radius: 4px; margin-top: 8px; background-color: #1a1a1a; }
        QGroupBox#trafficBox::title { subcontrol-origin: margin; subcontrol-position: top center; padding: 0 5px; color: #00eaff; font-size: 12px; font-weight: bold; }
        QPlainTextEdit#trafficText { background: transparent; border: none; color: #ffffff; padding: 4px; }
        QLabel { font-weight: bold; color: #03dac6; font-size: 12px; margin: 2px; }
        QPushButton { background-color: #292929; color: #ffffff; border: 1px solid #03dac6; border-radius: 4px; padding: 6px 10px; font-weight: bold; font-size: 10px; }
        QPushButton:hover { background-color: #03dac6; color: #121212; }
        QTableWidget { background-color: #000; border: none; gridline-color: #333; alternate-background-color: #111; }
        QHeaderView::section { background-color: #2a2a2a; color: #fff; padding: 6px; border: 1px solid #444; font-size: 10px; }
        """

    def estilo_claro(self):
        """Retorna el stylesheet QSS para el modo claro de la interfaz."""
        return """
        QWidget { background-color: #E0E0E0; color: #000000; font-family: 'Segoe UI'; }
        QGroupBox#warnBox { border: 1px solid #FF0000; border-radius: 4px; margin-top: 8px; background-color: #ffffff; }
        QGroupBox#warnBox::title { subcontrol-origin: margin; subcontrol-position: top center; padding: 0 5px; color: #FF0000; font-size: 10px; font-weight: bold; }
        QLabel { font-weight: bold; color: #0093FF; font-size: 12px; margin: 2px; }
        QPushButton { background-color: #ffffff; color: #212121; border: 1px solid #0093FF; border-radius: 4px; padding: 6px 10px; font-weight: bold; font-size: 10px; }
        QPushButton:hover { background-color: #0093FF; color: #ffffff; }
        QTableWidget { background-color: #ffffff; border: none; gridline-color: #e0e0e0; alternate-background-color: #fafafa; }
        QHeaderView::section { background-color: #e0e0e0; color: #212121; padding: 6px; border: 1px solid #bdbdbd; font-size: 10px; font-weight: bold; }
        """

    def crear_boton(self, texto, funcion, habil=True):
        """Factory de botones: crea QPushButton y conecta el slot en una línea."""
        boton = QPushButton(texto)
        boton.clicked.connect(funcion)
        boton.setEnabled(habil)
        return boton

    def exportar_csv(self):
        """Exporta todos los eventos actuales a un archivo CSV elegido por el usuario."""
        with data_lock:
            if not eventos_detectados:
                return
            eventos_copia = list(eventos_detectados)

        ruta, _ = QFileDialog.getSaveFileName(
            self, "Guardar CSV", "Eventos_ids.csv", "CSV Files (*.csv)"
        )
        if ruta:
            try:
                with open(ruta, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Hora", "IP Origen", "IP Destino", "Puerto", "Protocolo", "Flag", "Tipo"])
                    writer.writerows(eventos_copia)  # writerows: escribe todas las filas de una vez
                self.status.showMessage(f"CSV guardado: {ruta}", 5000)
            except Exception as e:
                logging.error(f"Error exportando CSV: {e}")

    def generar_evidencia(self):
        """Guarda el gráfico de pastel como imagen PNG en la carpeta 'evidencia'."""
        try:
            carpeta = os.path.join(BASE_DIR, 'evidencia')
            if not os.path.exists(carpeta):
                os.makedirs(carpeta)

            timestamp  = datetime.now().strftime('%Y%m%d_%H%M%S')
            ruta_pie   = os.path.join(carpeta, f"grafico_pie_{timestamp}.png")
            # savefig: Guarda la figura en disco con 100 DPI, ajustando al contenido
            self.canvas_pie.figure.savefig(ruta_pie, dpi=100, bbox_inches='tight')
            self.status.showMessage(f"Evidencia generada en {carpeta}", 5000)
        except Exception as e:
            logging.error(f"Error generando evidencia: {e}")

    def guardar_grafico_pie_diario(self):
        """Guardado automático diario del gráfico de pastel."""
        try:
            carpeta = os.path.join(BASE_DIR, 'evidencia')
            if not os.path.exists(carpeta):
                os.makedirs(carpeta)
            nombre  = f"grafica_pie_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            self.canvas_pie.figure.savefig(os.path.join(carpeta, nombre), dpi=100, bbox_inches='tight')
            self.status.showMessage(f"Gráfica (pie) guardada: {nombre}", 5000)
        except Exception as e:
            logging.error(f"Error guardando gráfica diaria: {e}")

    def guardar_csv_diario(self):
        """Guardado automático diario del dataset de eventos en CSV."""
        try:
            with data_lock:
                if not eventos_detectados:
                    self.status.showMessage("No hay eventos para guardar.", 3000)
                    return
                eventos_copia = list(eventos_detectados)

            carpeta = os.path.join(BASE_DIR, 'evidencia')
            if not os.path.exists(carpeta):
                os.makedirs(carpeta)

            nombre = f"eventos_ids_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(os.path.join(carpeta, nombre), 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Hora", "IP Origen", "IP Destino", "Puerto", "Protocolo", "Flag", "Tipo"])

                # Escritura en chunks de 1000: eficiente para archivos grandes (>100k filas)
                chunk_size = 1000
                for i in range(0, len(eventos_copia), chunk_size):
                    writer.writerows(eventos_copia[i:i + chunk_size])

            self.status.showMessage(f"CSV guardado: {nombre}", 5000)
        except Exception as e:
            logging.error(f"Error guardando CSV diario: {e}")

    def closeEvent(self, event):
        """Sobrescribe el evento de cierre para limpieza ordenada de recursos."""
        try:
            self.gestor_abuse.limpiar()  # Cancela requests pendientes de AbuseIPDB

            if self.monitoreo_activo:
                self.detener_monitoreo()  # Para el AsyncSniffer limpiamente

            # Detiene todos los timers para evitar callbacks tras cierre
            for t in [self.timer, self.graf_timer,
                      self.timer_guardar_diario, self.timer_guardar_csv_diario]:
                t.stop()

            self.data_processor.stop()  # Espera a que el QThread termine su ciclo

            # Libera memoria de las estructuras globales
            with data_lock:
                eventos_detectados.clear()
                advertencias_cont.clear()
                trafico_buffer.clear()

        except Exception as e:
            logging.error(f"Error en closeEvent: {e}")
        finally:
            super().closeEvent(event)  # Siempre llama al closeEvent del padre


# =============================================================================
# FUNCIONES AUXILIARES GLOBALES
# =============================================================================

def configurar_logging():
    """Configura el sistema de logs para escribir en archivo y consola simultáneamente."""
    logging.basicConfig(
        level=logging.ERROR,  # Solo errores (reduce ruido en producción)
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(BASE_DIR, 'ids_interface.log')),  # Archivo rotativo en BASE_DIR
            logging.StreamHandler()                    # Consola
        ]
    )

def limpiar_memoria_periodica():
    """Limpia estructuras globales cuando superan los límites configurados."""
    global eventos_detectados, advertencias_cont
    with data_lock:
        # Si supera el límite: conserva solo la mitad más reciente
        if len(eventos_detectados) > MAX_EVENTOS_MEMORIA:
            eventos_list = list(eventos_detectados)
            eventos_detectados.clear()
            eventos_detectados.extend(eventos_list[-MAX_EVENTOS_MEMORIA//2:])

        # Limita el diccionario de advertencias a las 500 IPs con más actividad
        if len(advertencias_cont) > 1000:
            items_sorted = sorted(advertencias_cont.items(), key=lambda x: x[1], reverse=True)
            advertencias_cont.clear()
            advertencias_cont.update(dict(items_sorted[:500]))


# =============================================================================
# PUNTO DE ENTRADA DE LA APLICACIÓN
# =============================================================================
if __name__ == "__main__":
    configurar_logging()

    app = QApplication(sys.argv)
    # Atributos de rendimiento Qt: evita widgets nativos anidados y oculta íconos en menús
    app.setAttribute(Qt.AA_DontCreateNativeWidgetSiblings, True)
    app.setAttribute(Qt.AA_DontShowIconsInMenus, True)

    # Timer de limpieza de memoria cada 60 segundos
    cleanup_timer = QTimer()
    cleanup_timer.timeout.connect(limpiar_memoria_periodica)
    cleanup_timer.start(60000)

    try:
        ventana = IDSInterface()
        ventana.show()
        print("IDS Interface Optimizada iniciada")
        print(f"Límites: Tabla={MAX_EVENTOS_TABLA} | Memoria={MAX_EVENTOS_MEMORIA} | Tráfico={MAX_TRAFICO_LINEAS}")
        sys.exit(app.exec_())  # Inicia el event loop de Qt — bloquea hasta cierre
    except Exception as e:
        logging.error(f"Error crítico en la aplicación: {e}")
        sys.exit(1)

# =============================================================================
# FIN DEL SCRIPT — interfasc.py
# =============================================================================
