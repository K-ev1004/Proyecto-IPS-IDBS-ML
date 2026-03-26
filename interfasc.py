import sys
import os
import time
import csv
import logging
import re
from collections import Counter, deque
from datetime import datetime
from threading import Lock

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog, QSplitter,
    QTabWidget, QGroupBox, QStatusBar, QSpinBox, QCheckBox, QPlainTextEdit,
    QMessageBox, QComboBox, QLineEdit,
)
from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QBrush

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from matplotlib import style
from matplotlib import cm
from matplotlib import colors as mcolors
from abuseipdb_module import GestorAbuseIPDB

# BASE_DIR: carpeta base del proyecto

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    import ids
except Exception as _e:
    ids = None
    logging.error("No se pudo importar 'ids'. Funciones de monitoreo deshabilitadas. Detalle: %s", _e)

style.use('dark_background')


# CONFIGURACIÓN DE RENDIMIENTO

MAX_EVENTOS_TABLA = 1000        # Límite de eventos en tabla
MAX_EVENTOS_MEMORIA = 10000     # Límite total en memoria
MAX_TRAFICO_LINEAS = 500        # Límite de líneas de tráfico
UPDATE_BATCH_SIZE = 50          # Procesar eventos en lotes


# Estilo para los distintos tipos de ataque en la tabla

ATTACK_STYLE = {
    "Inyección SQL": {"color": "#ff5370"},
    "PORT scanner":  {"color": "#bb86fc"},
    "DDOS":           {"color": "#00eaff"},
    "SYN FLOOD":      {"color": "#82b1ff"},
    "UDP Flood":      {"color": "#ffa000"},
}

def colors_for_labels(labels, cmap_name="tab20"):
    """
    Devuelve una lista de colores para cada etiqueta.
    - Si la etiqueta está en ATTACK_STYLE y tiene 'color', se respeta.
    - Si no, se toma un color determinista del colormap (tab20 por defecto).
    """
    cmap = cm.get_cmap(cmap_name, 20)
    out = []
    for lab in labels:
        st = ATTACK_STYLE.get(lab, {})
        if st.get("color"):
            out.append(st["color"])
        else:
            idx = abs(hash(lab)) % cmap.N
            out.append(mcolors.to_hex(cmap(idx)))
    return out

# Usar deque para mejor rendimiento en operaciones de cola

eventos_detectados = deque(maxlen=MAX_EVENTOS_MEMORIA)
advertencias_cont = {}
trafico_buffer = deque(maxlen=MAX_TRAFICO_LINEAS)

# Lock para thread safety
data_lock = Lock()


# Worker Thread para procesamiento en background

class DataProcessor(QThread):
    data_ready = pyqtSignal(list)   # eventos procesados
    stats_ready = pyqtSignal(dict)  # estadísticas

    def __init__(self):
        super().__init__()
        self.running = False
        self.pending_events = deque()

    def add_events(self, events):
        self.pending_events.extend(events)

    def run(self):
        self.running = True
        while self.running:
            if self.pending_events:
                # Procesar eventos en lotes
                batch = []
                for _ in range(min(UPDATE_BATCH_SIZE, len(self.pending_events))):
                    if self.pending_events:
                        batch.append(self.pending_events.popleft())

                if batch:
                    self.data_ready.emit(batch)

                    # Calcular estadísticas
                    with data_lock:
                        stats = {
                            'total_eventos': len(eventos_detectados),
                            'ips_unicas': len(advertencias_cont),
                            'tipos_ataques': dict(Counter([e[6] for e in list(eventos_detectados)[-100:]]))
                        }
                    self.stats_ready.emit(stats)

            self.msleep(100)  # 100ms entre procesamiento

    def stop(self):
        self.running = False
        self.quit()
        self.wait()


# Clase de la interfaz gráfica optimizada

class IDSInterface(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDS UNIPAZ - Interfaz de Monitoreo")
        self.setGeometry(100, 100, 1200, 800)
        self.setObjectName("mainWindow")
        self.modo_oscuro = True

        
        # INICIALIZAR ATRIBUTOS DE RENDIMIENTO
        
        self.last_table_update = 0
        self.last_graph_update = 0
        self.update_pending = False
        self.graph_update_pending = False
        self.auto_scroll_enabled = True
        self.show_all_events = False

        # Processor thread
        self.data_processor = DataProcessor()
        self.data_processor.data_ready.connect(self.process_event_batch)
        self.data_processor.stats_ready.connect(self.update_stats)
        self.data_processor.start()

        
        # CARGAR IMAGEN DE FONDO (optimizada)
        
        self.setup_styles()

        
        # INICIALIZAR ATRIBUTOS
        
        self.setFont(QFont("Segoe UI", 10))
        self.last_hover_row = -1

        
        # ESTRUCTURA PRINCIPAL DE LAYOUT
        
        self.setup_ui()
        # SOC métricas (PPS/Alertas/Uptime)
        self._pps_count = 0
        self._alert_ts = deque(maxlen=5000)
        self._start_time = None


        # Debounce para resize de tabla (evita lag)
        self._resize_timer = QTimer(self)
        self._resize_timer.setSingleShot(True)
        self._resize_timer.timeout.connect(self._apply_table_proportions)

        
        # CONFIGURAR TIMERS S
        
        self.setup_timers()

        
        # CONECTAR SEÑALES
        
        self.setup_signals()

    def agregar_evento_deprecated(self, evento):
        with data_lock:
            eventos_detectados.append(evento)
            try:
                self._alert_ts.append(time.time())
            except Exception:
                pass
            ip = evento[1]  # IP origen
            advertencias_cont[ip] = advertencias_cont.get(ip, 0) + 1
            
            # Agregar IP a cola de verificación si es externa (no privada)
            if self._es_ip_externa(ip):
                self.ips_a_verificar_cola.add(ip)

        self.data_processor.add_events([evento])

    def _es_ip_externa(self, ip):
        """
        Verifica si una IP es externa (no privada).
        Incluye limpieza de string para robustez.
        """
        
        # 🚨 FIX CRÍTICO: Aseguramos que es un string y eliminamos cualquier espacio.
        ip_limpia = str(ip).strip() 
        
        # Si está vacía o es nula DESPUÉS de limpiar, descartar inmediatamente.
        if not ip_limpia or ip_limpia == "":
            return False
        
        # Validación básica de formato
        partes = ip_limpia.split('.')
        if len(partes) != 4:
            return False
        
        try:
            octeto1 = int(partes[0])
            octeto2 = int(partes[1])
            
            # Exclusión de rangos privados (RFC 1918) y rangos especiales/reservados:
            
            # 10.0.0.0/8
            if octeto1 == 10:
                return False
            # 172.16.0.0/12 (172.16 a 172.31)
            if octeto1 == 172 and 16 <= octeto2 <= 31:
                return False
            # 192.168.0.0/16
            if octeto1 == 192 and octeto2 == 168:
                return False
            # Loopback (127.0.0.0/8), Reservadas (0.0.0.0/8) y Multicast/Experimental (>= 224)
            if octeto1 == 127 or octeto1 == 0 or octeto1 >= 224:
                return False
            
            # Es pública/externa
            return True
        except:
            # Captura errores si los octetos no se pueden convertir a int
            return False
        
    def verificar_ips_abuse(self):
        """
        Verifica IPs contra AbuseIPDB.

        Prioridad:
        1) IPs externas encontradas en el cuadro de Advertencias (warnbox).
        2) IPs externas de las columnas IP Origen / IP Destino de la tabla.
        3) IPs externas ya acumuladas en self.ips_a_verificar_cola.
        """
        ips_encontradas = set()

        # 1) Buscar IPs en el cuadro de advertencias (warnbox)
        try:
            texto_adv = self.advertencias.toPlainText()
            if texto_adv:
                patron_ip = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
                for ip in re.findall(patron_ip, texto_adv):
                    if self._es_ip_externa(ip):
                        ips_encontradas.add(ip)
        except Exception as e:
            logging.error(f"Error extrayendo IPs del warnbox: {e}")

        # 2) Si no hay IPs desde el warnbox, mirar en la tabla de eventos
        if not ips_encontradas and hasattr(self, "table"):
            try:
                filas = self.table.rowCount()
                for fila in range(filas):
                    # Columna 1 = IP Origen, Columna 2 = IP Destino
                    for col in (1, 2):
                        item = self.table.item(fila, col)
                        if item is None:
                            continue
                        ip = item.text().strip()
                        if ip and self._es_ip_externa(ip):
                            ips_encontradas.add(ip)
            except Exception as e:
                logging.error(f"Error extrayendo IPs de la tabla: {e}")

        # 3) Como último recurso, usar la cola existente
        if not ips_encontradas and self.ips_a_verificar_cola:
            ips_encontradas = set(self.ips_a_verificar_cola)

        # Si sigue vacío, no hay nada que verificar
        if not ips_encontradas:
            self.status.showMessage("No se encontraron IPs externas para verificar", 3000)
            self.ips_a_verificar_cola.clear()
            return

        ips_lista = list(ips_encontradas)
        self.status.showMessage(f"Verificando {len(ips_lista)} IPs en AbuseIPDB...", 5000)

        # Lanzar la verificación en el thread de AbuseIPDB
        self.gestor_abuse.verificar_ips(
            ips_lista,
            callback_resultado=self.mostrar_resultado_abuse,
            callback_error=self.mostrar_error_abuse
        )

    def mostrar_resultado_abuse(self, resultado):

        ip = resultado['ip']
        score = resultado['abuse_score']
        riesgo = resultado['riesgo']
        reports = resultado['total_reports']
        pais = resultado['pais']

        linea = f"\n🔍 AbuseIPDB | {ip} | Score: {score}% | {riesgo} | Reports: {reports} | {pais}"

        texto_actual = self.advertencias.toPlainText()
        self.advertencias.setPlainText(linea + "\n" + texto_actual)

        if "CRÍTICO" in riesgo:
            self.status.showMessage(f"⚠️ IP CRÍTICA DETECTADA: {ip}", 5000)

    def mostrar_error_abuse(self, error_msg):
        logging.error(f"Error AbuseIPDB: {error_msg}")
        linea = f"\n❌ AbuseIPDB Error: {error_msg}"
        texto_actual = self.advertencias.toPlainText()
        self.advertencias.setPlainText(linea + "\n" + texto_actual)

    def exportar_reporte_abuse(self):

        ruta, _ = QFileDialog.getSaveFileName(
            self, "Guardar Reporte AbuseIPDB", "reporte_abuse.json", "JSON Files (*.json)"
        )
        if ruta:
            self.gestor_abuse.exportar_reporte(ruta)
            self.status.showMessage(f"Reporte guardado: {ruta}", 5000)

    def setup_styles(self):
        """Configuración optimizada de estilos"""
        imagen_fondo = os.path.join(BASE_DIR, 'aed04dd0-dcaa-4ac2-8c8f-3bfca505b67f.png')
        if os.path.exists(imagen_fondo):
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
            self.setStyleSheet(self.estilo_moderno())

            # Inicializar gestor AbuseIPDB
        self.api_key_abuse = "31b904b493a50236fd7bd08163d01b562ce7a5127dc3968ef589d808232696ce3ea1b68e695323d4"  # Configurar con tu clave
        self.gestor_abuse = GestorAbuseIPDB(self.api_key_abuse)
        self.ips_a_verificar_cola = set()

    def setup_ui(self):
        """Configuración de la interfaz de usuario"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Header
        header = QLabel("IDS UNIPAZ - Sistema de Detección de Intrusiones")
        header.setAlignment(Qt.AlignCenter)
        header.setFont(QFont("Segoe UI", 16, QFont.Bold))
        layout.addWidget(header)

        # ==========================
        # SOC Top Bar (Estado + Filtros)
        # ==========================
        topbar = QHBoxLayout()
        topbar.setSpacing(10)

        # Estado / interfaz
        self.iface_badge = QLabel("Interfaz: N/A | ○ Stopped")
        self.iface_badge.setObjectName("ifaceBadge")
        self.iface_badge.setStyleSheet("""
            QLabel#ifaceBadge {
                padding: 4px 10px;
                border: 1px solid #03dac6;
                border-radius: 10px;
                font-size: 10px;
                color: #e0e0e0;
                background: rgba(0,0,0,0.35);
            }
        """)
        topbar.addWidget(self.iface_badge)

        self.lbl_pps = QLabel("PPS: 0")
        self.lbl_pps.setStyleSheet("padding:4px 8px; border:1px solid #333; border-radius:10px; font-size:10px;")
        topbar.addWidget(self.lbl_pps)

        self.lbl_alerts_min = QLabel("Alertas/min: 0")
        self.lbl_alerts_min.setStyleSheet("padding:4px 8px; border:1px solid #333; border-radius:10px; font-size:10px;")
        topbar.addWidget(self.lbl_alerts_min)

        self.lbl_uptime = QLabel("Uptime: 00:00:00")
        self.lbl_uptime.setStyleSheet("padding:4px 8px; border:1px solid #333; border-radius:10px; font-size:10px;")
        topbar.addWidget(self.lbl_uptime)

        topbar.addStretch()

        # Filtros
        topbar.addWidget(QLabel("Buscar:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("ip / tipo / puerto / protocolo ...")
        self.search_input.setMinimumWidth(260)
        self.search_input.textChanged.connect(lambda _: self.apply_filters())
        topbar.addWidget(self.search_input)

        topbar.addWidget(QLabel("Severidad:"))
        self.sev_filter = QComboBox()
        self.sev_filter.addItems(["Todos", "CRÍTICA", "ALTA", "MEDIA", "BAJA"])
        self.sev_filter.currentIndexChanged.connect(lambda _: self.apply_filters())
        topbar.addWidget(self.sev_filter)

        layout.addLayout(topbar)

        # Controles de rendimiento
        controls_layout = QHBoxLayout()

        # Selector de interfaz (UX)
        controls_layout.addWidget(QLabel("Interfaz:"))
        self.combo_iface = QComboBox()
        self.combo_iface.setMinimumWidth(220)
        self.combo_iface.addItems(self.listar_interfaces_captura())
        self.combo_iface.currentIndexChanged.connect(lambda _: self._set_running_state(self.monitoreo_activo))
        controls_layout.addWidget(self.combo_iface)



        self.auto_scroll_cb = QCheckBox("Auto-scroll")
        self.auto_scroll_cb.setChecked(True)
        self.auto_scroll_cb.toggled.connect(self.toggle_auto_scroll)
        controls_layout.addWidget(self.auto_scroll_cb)

        self.show_all_cb = QCheckBox("Mostrar todos los eventos")
        self.show_all_cb.toggled.connect(self.toggle_show_all)
        controls_layout.addWidget(self.show_all_cb)

        controls_layout.addWidget(QLabel("Máx. eventos tabla:"))
        self.max_events_spin = QSpinBox()
        self.max_events_spin.setRange(100, 5000)
        self.max_events_spin.setValue(MAX_EVENTOS_TABLA)
        self.max_events_spin.valueChanged.connect(self.change_max_events)
        controls_layout.addWidget(self.max_events_spin)

        controls_layout.addStretch()
        layout.addLayout(controls_layout)

        # Splitter principal
        splitter = QSplitter(Qt.Horizontal)
        left = QWidget()
        right = QWidget()

        # Panel IZQUIERDO
        self.setup_left_panel(left)

        # Panel DERECHO
        self.setup_right_panel(right)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 6)
        splitter.setSizes([480, 720])
        layout.addWidget(splitter)

        # Barra de estado
        self.status = QStatusBar()
        layout.addWidget(self.status)

    def setup_left_panel(self, left):
        """Configurar panel izquierdo"""
        vi = QVBoxLayout(left)

        lbl = QLabel("Eventos Detectados")
        lbl.setFont(QFont("Segoe UI", 13, QFont.Bold))
        vi.addWidget(lbl)

        self.table = self.crear_tabla_eventos_optimizada()
        self.table.itemSelectionChanged.connect(self.update_detail_panel)

        vi.addWidget(self.table)

        # Primera aplicación de proporciones cuando ya existe el widget
        QTimer.singleShot(0, self._apply_table_proportions)

        # Advertencias optimizadas (QPlainTextEdit real)
        advert_box = QGroupBox("Advertencias")
        advert_box.setObjectName("warnBox")
        adv_layout = QVBoxLayout()
        self.advertencias = QPlainTextEdit()
        self.advertencias.setObjectName("warnText")
        self.advertencias.setReadOnly(True)
        self.advertencias.setFont(QFont("Segoe UI", 10, QFont.Bold))
        # Limitar líneas mediante el documento (más eficiente)
        self.advertencias.document().setMaximumBlockCount(100)
        adv_layout.addWidget(self.advertencias)
        advert_box.setLayout(adv_layout)
        vi.addWidget(advert_box)

    def setup_right_panel(self, right):
        """Configurar panel derecho """
        vd = QVBoxLayout(right)

        # Detalle del evento (SOC)
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

        # Tráfico en vivo  (QPlainTextEdit para menos overhead)
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

        # Tabs con gráficos: dos canvases (barras y pastel)
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(
            "QTabWidget::pane { border:1px solid #333; }"
            "QTabBar::tab { background:#3A84BD; padding:6px; }"
        )

        # Canvas para pastel
        self.canvas_pie = FigureCanvas(Figure(figsize=(5, 4)))
        self.axes_pie = self.canvas_pie.figure.subplots()
        self.tabs.addTab(self.canvas_pie, "GRAFICO")

        vd.addWidget(self.tabs)

        # Botones
        self.setup_buttons(vd)

    def setup_buttons(self, layout):
        """Configurar botones de control"""
        btns = QHBoxLayout()
        btns.setSpacing(8)
        btns.setContentsMargins(0, 8, 0, 0)

        self.boton_iniciar        = self.crear_boton("Iniciar",      self.iniciar_monitoreo, True)
        self.boton_detener        = self.crear_boton("Detener",      self.detener_monitoreo, False)
        self.boton_limpiar        = self.crear_boton("Limpiar",      self.limpiar_tabla, True)
        self.boton_exportar       = self.crear_boton("Exportar CSV", self.exportar_csv, True)
        self.boton_evidencia      = self.crear_boton("Evidencia", self.generar_evidencia, True)
        self.boton_verificar_abuse = self.crear_boton("Verificar AbuseIPDB", self.verificar_ips_abuse, True)
        self.boton_tema           = self.crear_boton("Modo Claro", self.cambiar_tema, True)
        for b in [
            self.boton_iniciar, self.boton_detener,
            self.boton_limpiar, self.boton_exportar,
            self.boton_evidencia, self.boton_verificar_abuse,
            self.boton_tema
        ]:
            btns.addWidget(b)
        layout.addLayout(btns)
        

    def setup_timers(self):
        """Configuración optimizada de timers"""
        # Timer para actualización de tabla (menos frecuente)
        self.timer = QTimer()
        self.timer.timeout.connect(self.actualizar_tabla_optimizada)

        # Timer para gráfico (aún menos frecuente)
        self.graf_timer = QTimer()
        self.graf_timer.timeout.connect(self.actualizar_grafico_auto)

        # Timer PPS (paquetes por segundo)
        self.pps_timer = QTimer()
        self.pps_timer.timeout.connect(self._tick_pps)

        # Timer uptime
        self.uptime_timer = QTimer()
        self.uptime_timer.timeout.connect(self._tick_uptime)

        # Timer alertas/min
        self.alerts_timer = QTimer()
        self.alerts_timer.timeout.connect(self._tick_alerts_per_min)


        self.monitoreo_activo = False

        # Timers diarios (s)
        self.timer_guardar_diario = QTimer()
        self.timer_guardar_diario.timeout.connect(self.guardar_grafico_pie_diario)
        self.timer_guardar_diario.start(24 * 60 * 60 * 1000)

        self.timer_guardar_csv_diario = QTimer()
        self.timer_guardar_csv_diario.timeout.connect(self.guardar_csv_diario)
        self.timer_guardar_csv_diario.start(24 * 60 * 60 * 1000)

    def setup_signals(self):
        """Configurar señales y conexiones"""
        # Deshabilitar hover tracking para mejor rendimiento
        self.table.setMouseTracking(False)

        # Conectar señales del módulo ids ()
        if ids and hasattr(ids, 'comunicador'):
            try:
                ids.comunicador.nuevo_evento.connect(self.agregar_evento_)
                ids.comunicador.nuevo_trafico.connect(self.agregar_trafico_)
            except Exception as e:
                logging.error(f"No se pudieron conectar señales de 'ids': {e}")

    def crear_tabla_eventos_optimizada(self):
        """Crear tabla optimizada para mejor rendimiento y responsiva por proporciones"""
        table = QTableWidget()
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "Sev", "Hora", "IP Origen", "IP Destino",
            "Puerto", "Protocolo", "Flag", "Tipo"
        ])

        # Optimizaciones críticas de rendimiento
        header_h = table.horizontalHeader()
        header_v = table.verticalHeader()

        header_h.setSectionResizeMode(QHeaderView.Fixed)   # controlamos nosotros los anchos
        header_h.setStretchLastSection(False)
        header_v.setSectionResizeMode(QHeaderView.Fixed)
        header_v.setDefaultSectionSize(25)
        header_v.hide()  # Ocultar números de fila para mayor rendimiento

        table.setWordWrap(False)
        table.setSortingEnabled(False)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setSelectionMode(QTableWidget.SingleSelection)

        table.setVerticalScrollMode(QTableWidget.ScrollPerPixel)
        table.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)

        # Anchos iniciales (se recalcularán por proporciones en _apply_table_proportions)
        anchos = [120, 140, 140, 70, 90, 70, 220]
        for i, ancho in enumerate(anchos):
            table.setColumnWidth(i, ancho)

        return table

    
    # Métodos s de manejo de eventos
    

    def agregar_evento_(self, evento):
        """Versión optimizada para agregar eventos"""
        print(f"DEBUG - Evento recibido: {evento}")
        print(f"DEBUG - Tipo: {type(evento)}")
        print(f"DEBUG - Largo: {len(evento) if hasattr(evento, '__len__') else 'N/A'}")
        with data_lock:
            eventos_detectados.append(evento)
            try:
                self._alert_ts.append(time.time())
            except Exception:
                pass
            ip = evento[1]
            advertencias_cont[ip] = advertencias_cont.get(ip, 0) + 1

        # No actualizar inmediatamente, usar batch processing
        self.data_processor.add_events([evento])
        

    def agregar_trafico_(self, mensaje):
        """Versión optimizada para tráfico"""
        try:
            self._pps_count += 1
        except Exception:
            self._pps_count = 1
        trafico_buffer.append(mensaje)
        if len(trafico_buffer) % 10 == 0:  # Actualizar cada 10 mensajes
            self.actualizar_trafico_batch()

    def actualizar_trafico_batch(self):
        """Actualizar tráfico en lotes"""
        if not trafico_buffer:
            return

        # Tomar últimos mensajes
        mensajes = list(trafico_buffer)[-20:]  # Solo últimos 20
        texto = '\n'.join(mensajes)

        self.trafico_en_vivo.setPlainText(texto)
        if self.auto_scroll_enabled:
            self.trafico_en_vivo.verticalScrollBar().setValue(
                self.trafico_en_vivo.verticalScrollBar().maximum()
            )

    def process_event_batch(self, events):
        """Procesar lote de eventos en UI thread"""
        if not self.update_pending:
            self.update_pending = True
            QTimer.singleShot(100, self.actualizar_tabla_optimizada)  # Delayed update

    def update_stats(self, stats):
        """Actualizar estadísticas"""
        self.status.showMessage(
            f"Eventos: {stats['total_eventos']} | IPs únicas: {stats['ips_unicas']}"
        )

    def _hash_muestra_eventos(self, eventos):
        """
        Calcula un hash ligero sobre una muestra de las últimas 50 filas
        para detectar cambios de contenido sin recorrer toda la tabla.
        """
        muestra = eventos[-50:] if len(eventos) > 50 else eventos
        try:
            # Convertir a tuplas inmutables para hashear
            key = tuple(tuple(ev) for ev in muestra)
            return hash(key)
        except Exception:
            # Fallback: conteo por tipo
            return hash(tuple(sorted(Counter([e[6] for e in muestra]).items())))

    
    # --------------------------
    # UX helpers (SOC-style)
    # --------------------------
    def _compute_severity(self, tipo_texto: str):
        """Mapea tipo de evento a severidad SOC."""
        t = (tipo_texto or "").lower()
        if "posible exploit" in t or "exploit" in t:
            return "CRÍTICA", "#ff3b30"
        if "ddos" in t or "syn flood" in t or "udp flood" in t:
            return "ALTA", "#ff9500"
        if "escaneo" in t or "port" in t or "scan" in t:
            return "MEDIA", "#ffd60a"
        if "sql injection" in t or "sqli" in t:
            return "ALTA", "#ff9500"
        return "BAJA", "#0a84ff"

    def _row_matches_filters(self, row_values):
        """Aplica filtro por severidad y búsqueda textual."""
        # row_values: dict con claves 'sev','hora','ip_src','ip_dst','puerto','proto','flag','tipo'
        sev_filter = self.sev_filter.currentText() if hasattr(self, "sev_filter") else "Todos"
        if sev_filter != "Todos" and row_values.get("sev") != sev_filter:
            return False

        q = (self.search_input.text() if hasattr(self, "search_input") else "").strip().lower()
        if not q:
            return True

        haystack = " ".join(str(v).lower() for v in row_values.values())
        return q in haystack

    def apply_filters(self):
        """Oculta/mostrar filas según filtros (simple y efectivo con QTableWidget)."""
        try:
            for r in range(self.table.rowCount()):
                sev = self.table.item(r, 0).text() if self.table.item(r, 0) else ""
                hora = self.table.item(r, 1).text() if self.table.item(r, 1) else ""
                ip_src = self.table.item(r, 2).text() if self.table.item(r, 2) else ""
                ip_dst = self.table.item(r, 3).text() if self.table.item(r, 3) else ""
                puerto = self.table.item(r, 4).text() if self.table.item(r, 4) else ""
                proto = self.table.item(r, 5).text() if self.table.item(r, 5) else ""
                flag = self.table.item(r, 6).text() if self.table.item(r, 6) else ""
                tipo = self.table.item(r, 7).text() if self.table.item(r, 7) else ""
                # quitar ícono del tipo si existe
                tipo_clean = tipo.split(" ", 1)[1] if tipo.startswith(("🚨", "🟠", "🔴", "🟡", "🔵", "⚠", "🔎", "🧨", "🛑", "💥")) and " " in tipo else tipo

                row_ok = self._row_matches_filters({
                    "sev": sev,
                    "hora": hora,
                    "ip_src": ip_src,
                    "ip_dst": ip_dst,
                    "puerto": puerto,
                    "proto": proto,
                    "flag": flag,
                    "tipo": tipo_clean,
                })
                self.table.setRowHidden(r, not row_ok)
        except Exception as e:
            logging.error(f"Error aplicando filtros: {e}")

    
    def listar_interfaces_captura(self):
        """Lista interfaces recomendadas para captura (Windows)."""
        ifaces = []
        try:
            from scapy.arch.windows import get_windows_if_list
            for i in get_windows_if_list():
                name = i.get("name") or ""
                desc = (i.get("description") or "").lower()
                ips = i.get("ips") or []

                # descartar filtros/capas
                nlow = name.lower()
                if "-wfp" in nlow or "-npcap" in nlow or "-filter" in nlow:
                    continue
                if "loopback" in desc or "wi-fi direct" in desc:
                    continue

                # incluir solo interfaces con IPv4
                if not any("." in ip for ip in ips):
                    continue

                ifaces.append(name)
        except Exception as e:
            logging.error(f"No se pudieron listar interfaces: {e}")

        # fallback
        if not ifaces:
            ifaces = ["Ethernet", "Wi-Fi"]

        # ordenar: Ethernet primero si existe
        if "Ethernet" in ifaces:
            ifaces = ["Ethernet"] + [x for x in ifaces if x != "Ethernet"]

        return ifaces

    def _set_running_state(self, running: bool):
        """Actualiza el badge de interfaz + estado."""
        iface = self.combo_iface.currentText() if hasattr(self, "combo_iface") else "N/A"
        estado = "● Running" if running else "○ Stopped"
        self.iface_badge.setText(f"Interfaz: {iface} | {estado}")

    
    def _tick_pps(self):
        try:
            pps = getattr(self, "_pps_count", 0)
            self.lbl_pps.setText(f"PPS: {pps}")
            self._pps_count = 0
        except Exception as e:
            logging.error(f"Error PPS tick: {e}")

    def _tick_uptime(self):
        try:
            if not getattr(self, "_start_time", None):
                self.lbl_uptime.setText("Uptime: 00:00:00")
                return
            delta = int(time.time() - self._start_time)
            h = delta // 3600
            m = (delta % 3600) // 60
            s = delta % 60
            self.lbl_uptime.setText(f"Uptime: {h:02d}:{m:02d}:{s:02d}")
        except Exception as e:
            logging.error(f"Error uptime tick: {e}")

    def _tick_alerts_per_min(self):
        try:
            dq = getattr(self, "_alert_ts", None)
            if dq is None:
                self.lbl_alerts_min.setText("Alertas/min: 0")
                return
            ahora = time.time()
            while dq and (ahora - dq[0]) > 60:
                dq.popleft()
            self.lbl_alerts_min.setText(f"Alertas/min: {len(dq)}")
        except Exception as e:
            logging.error(f"Error alert/min tick: {e}")

    def update_detail_panel(self):
        """Actualiza panel de detalle con la fila seleccionada."""
        try:
            items = self.table.selectedItems()
            if not items:
                self.detalle_text.setPlainText("Seleccione una alerta para ver el detalle.")
                return

            row = items[0].row()
            sev = self.table.item(row, 0).text() if self.table.item(row, 0) else ""
            hora = self.table.item(row, 1).text() if self.table.item(row, 1) else ""
            ip_src = self.table.item(row, 2).text() if self.table.item(row, 2) else ""
            ip_dst = self.table.item(row, 3).text() if self.table.item(row, 3) else ""
            puerto = self.table.item(row, 4).text() if self.table.item(row, 4) else ""
            proto = self.table.item(row, 5).text() if self.table.item(row, 5) else ""
            flag = self.table.item(row, 6).text() if self.table.item(row, 6) else ""
            tipo = self.table.item(row, 7).text() if self.table.item(row, 7) else ""

            # evidencia simple (para enriquecer después con contadores reales)
            evidencia = []
            evidencia.append(f"- Protocolo/Flag: {proto}/{flag}")
            if "syn flood" in tipo.lower():
                evidencia.append("- Indicador: volumen alto de SYN en ventana corta")
            if "ddos" in tipo.lower():
                evidencia.append("- Indicador: volumen alto hacia destino (posible DDoS)")
            if "escaneo" in tipo.lower():
                evidencia.append("- Indicador: múltiples puertos probados desde una misma IP")
            if "sql" in tipo.lower():
                evidencia.append("- Indicador: patrón de payload compatible con SQLi")

            txt = (
                f"SEVERIDAD: {sev}\n"
                f"HORA: {hora}\n"
                f"TIPO: {tipo}\n"
                f"IP ORIGEN: {ip_src}\n"
                f"IP DESTINO: {ip_dst}\n"
                f"PUERTO: {puerto}\n\n"
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
        """Actualización optimizada de la tabla (con severidad + filtros)."""
        self.update_pending = False

        try:
            with data_lock:
                max_eventos = self.max_events_spin.value()
                eventos_a_mostrar = (
                    list(eventos_detectados)[-max_eventos:]
                    if not self.show_all_events
                    else list(eventos_detectados)
                )

            row_count = len(eventos_a_mostrar)
            self.table.setRowCount(row_count)

            nuevo_hash = self._hash_muestra_eventos(eventos_a_mostrar)
            contenido_cambio = (getattr(self, "_last_cnt_hash", None) != nuevo_hash)
            self._last_cnt_hash = nuevo_hash

            self.table.setUpdatesEnabled(False)
            try:
                if contenido_cambio:
                    # Colores según el tema
                    if self.modo_oscuro:
                        bg_color = "#000000"
                        fg_color = "#ab0df5"
                    else:
                        bg_color = "#000000"
                        fg_color = "#ffffff"

                    for i, ev in enumerate(eventos_a_mostrar):
                        # ev esperado: [hora, ip_src, ip_dst, puerto, protocolo, flag, tipo]
                        try:
                            hora, ip_src, ip_dst, puerto, protocolo, flag, tipo = ev
                        except Exception:
                            lst = list(ev) + [""] * 7
                            hora, ip_src, ip_dst, puerto, protocolo, flag, tipo = lst[:7]

                        sev_txt, sev_color = self._compute_severity(str(tipo))
                        cols = [sev_txt, hora, ip_src, ip_dst, puerto, protocolo, flag, tipo]

                        for j, v in enumerate(cols):
                            item_text = str(v)
                            it = self.table.item(i, j)
                            if not it:
                                it = QTableWidgetItem()
                                self.table.setItem(i, j, it)

                            if j == 0:
                                it.setForeground(QBrush(QColor(sev_color)))
                                it.setText(item_text)
                            elif j == 7:
                                st = ATTACK_STYLE.get(tipo, {})
                                if st.get("icon"):
                                    item_text = f"{st['icon']} {tipo}"
                                it.setForeground(QBrush(QColor(st.get("color", "#f54f13"))))
                                it.setText(item_text)
                            else:
                                it.setForeground(QBrush(QColor(fg_color)))
                                it.setText(item_text)

                            it.setBackground(QBrush(QColor(bg_color)))
            finally:
                self.table.setUpdatesEnabled(True)

            # Aplicar filtros UX (búsqueda/severidad)
            self.apply_filters()

            if self.auto_scroll_enabled and eventos_a_mostrar:
                self.table.scrollToBottom()

            self.actualizar_advertencias_optimizada()

        except Exception as e:
            logging.error(f"Error actualizando tabla optimizada: {e}")


    def actualizar_advertencias_optimizada(self):
        """Reconstrucción completa y eficiente de advertencias (Top 100)"""
        try:
            with data_lock:
                items_sorted = sorted(advertencias_cont.items(), key=lambda x: x[1], reverse=True)[:100]
            texto = '\n'.join(f"⚠ -> {ip}: {cnt} advertencia(s)" for ip, cnt in items_sorted)
            self.advertencias.setPlainText(texto)
        except Exception as e:
            logging.error(f"Error actualizando advertencias: {e}")
    
    # Métodos de control s
    

    def toggle_auto_scroll(self, enabled):
        """Alternar auto-scroll"""
        self.auto_scroll_enabled = enabled

    def toggle_show_all(self, show_all):
        """Alternar mostrar todos los eventos"""
        self.show_all_events = show_all
        self.actualizar_tabla_optimizada()

    def change_max_events(self, value):
        """Cambiar máximo de eventos en tabla"""
        global MAX_EVENTOS_TABLA
        MAX_EVENTOS_TABLA = value
        self.actualizar_tabla_optimizada()
        # Aplicar proporciones de nuevo ante cambio fuerte de filas
        self._apply_table_proportions()

    def cambiar_tema(self):
        """Alternar entre modo claro y oscuro"""
        self.modo_oscuro = not self.modo_oscuro
        
        # Cambiar el texto del botón
        if self.modo_oscuro:
            self.boton_tema.setText("Modo Claro")
        else:
            self.boton_tema.setText("Modo Oscuro")
        
        # Aplicar el estilo correspondiente
        self.aplicar_tema()
        
        # Actualizar tabla con los nuevos colores
        self.actualizar_tabla_optimizada()
        
        # Actualizar gráficos
        self.actualizar_grafico_auto()
        
        self.status.showMessage(
            f"Tema cambiado a modo {'oscuro' if self.modo_oscuro else 'claro'}", 
            3000
        )

    def aplicar_tema(self):
        """Aplicar el tema seleccionado"""
        imagen_fondo = os.path.join(BASE_DIR, 'aed04dd0-dcaa-4ac2-8c8f-3bfca505b67f.png')
        
        if self.modo_oscuro:
            # Modo oscuro (actual)
            if os.path.exists(imagen_fondo):
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
                self.setStyleSheet(self.estilo_moderno())
        else:
            # Modo claro
            self.setStyleSheet(self.estilo_claro())

    def iniciar_monitoreo(self):
        """Iniciar monitoreo con configuración optimizada"""
        self.boton_iniciar.setEnabled(False)
        self.boton_detener.setEnabled(True)
        self.monitoreo_activo = True
        if hasattr(self, "combo_iface"):
            self.combo_iface.setEnabled(False)

        # Reset métricas
        self._pps_count = 0
        self._alert_ts.clear()
        self._start_time = time.time()

        iface = self.combo_iface.currentText() if hasattr(self, "combo_iface") else None

        if ids and hasattr(ids, 'iniciar_monitoreo'):
            try:
                # ✅ pasar interfaz elegida al motor IDS
                ids.iniciar_monitoreo(iface)
            except Exception as e:
                logging.error(f"Error al iniciar monitoreo en 'ids': {e}")

        self._set_running_state(True)

        # Timers menos agresivos para mejor rendimiento
        self.timer.start(3000)        # 3 segundos para tabla
        self.graf_timer.start(10000)  # 10 segundos para gráfico

        # SOC timers
        self.pps_timer.start(1000)     # PPS cada 1s
        self.uptime_timer.start(1000)  # Uptime cada 1s
        self.alerts_timer.start(5000)  # Alertas/min cada 5s


    def detener_monitoreo(self):
        """Detener monitoreo"""
        self.monitoreo_activo = False

        if ids and hasattr(ids, 'detener_monitoreo'):
            try:
                ids.detener_monitoreo()
            except Exception as e:
                logging.error(f"Error al detener monitoreo en 'ids': {e}")

        self.timer.stop()
        self.graf_timer.stop()
        self.pps_timer.stop()
        self.uptime_timer.stop()
        self.alerts_timer.stop()

        if hasattr(self, "combo_iface"):
            self.combo_iface.setEnabled(True)

        self._set_running_state(False)

        self.boton_iniciar.setEnabled(True)
        self.boton_detener.setEnabled(False)

    def limpiar_tabla(self):
        """Limpiar tabla """
        with data_lock:
            eventos_detectados.clear()
            advertencias_cont.clear()
            trafico_buffer.clear()

        self.table.setRowCount(0)
        self.advertencias.clear()
        self.trafico_en_vivo.clear()
        # Limpiar ambas gráficas
        self.axes_pie.clear()
        self.canvas_pie.draw()
        self.status.showMessage("Interfaz limpia", 3000)

    def actualizar_grafico_auto(self):
        """Actualizar gráfica con colores según tema"""
        if self.graph_update_pending:
            return

        self.graph_update_pending = True
        try:
            with data_lock:
                if not eventos_detectados:
                    return
                eventos_muestra = list(eventos_detectados)[-500:]

            cnt = Counter([e[6] for e in eventos_muestra])
            if not cnt:
                return

            labels = list(cnt.keys())
            values = list(cnt.values())
            colors = colors_for_labels(labels)

            # Colores según tema
            if self.modo_oscuro:
                bg_color = "#121212"
                text_color = "#ffffff"
            else:
                bg_color = "#FFFFFF"
                text_color = "#000000"

            # Pastel
            self.axes_pie.clear()
            self.axes_pie.pie(
                values, labels=labels, colors=colors,
                autopct='%1.1f%%',
                textprops={'color': text_color, 'fontsize': 8}
            )
            self.axes_pie.set_title("Distribución de Ataques", color=text_color, fontsize=10)
            self.axes_pie.axis('equal')
            
            self.axes_pie.set_facecolor(bg_color)
            self.canvas_pie.figure.patch.set_facecolor(bg_color)
            self.canvas_pie.figure.tight_layout()
            self.canvas_pie.draw_idle()

        except Exception as e:
            logging.error(f"Error actualizando gráfico: {e}")
        finally:
            self.graph_update_pending = False

    
    # Responsive sin lag para la tabla
    
    def _apply_table_proportions(self):
        """Ajusta anchos de columna por proporciones del ancho visible, sin lag."""
        if not hasattr(self, "table"):
            return

        vp = self.table.viewport()
        total = max(200, vp.width())  # salvaguarda

        # Proporciones por columna (suman ~1.0):
        # Sev, Hora, Origen, Destino, Puerto, Protocolo, Flag, Tipo
        ratios = [0.08, 0.12, 0.16, 0.16, 0.08, 0.10, 0.08, 0.22]

        # Mínimos razonables para no romper legibilidad
        mins =   [ 60,   80,  120,  120,  60,   80,   60,  200]

        # Evitar repintados innecesarios:
        self.table.setUpdatesEnabled(False)
        try:
            for i, r in enumerate(ratios):
                w = max(mins[i], int(total * r))
                # Sólo aplicar si el cambio es significativo para evitar parpadeo
                if abs(self.table.columnWidth(i) - w) > 2:
                    self.table.setColumnWidth(i, w)
        finally:
            self.table.setUpdatesEnabled(True)

    def resizeEvent(self, event):
        """Debounce de resize para recalcular proporciones sin saturar el UI thread."""
        if hasattr(self, "_resize_timer"):
            self._resize_timer.start(60)  # debounce corto: fluido y sin lag
        super().resizeEvent(event)

    
    # Métodos auxiliares (conservados pero s)
    

    def estilo_moderno(self):
        """Estilo  sin efectos pesados"""
        return """
        QWidget { 
            background-color: #121212; 
            color: #e0e0e0; 
            font-family: 'Segoe UI'; 
        }

        QGroupBox#warnBox {
            border: 1px solid #ffab40;
            border-radius: 4px;
            margin-top: 8px;
            background-color: #1a1a1a;
        }
        QGroupBox#warnBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top center;
            padding: 0 5px;
            color: #ffeb3b; 
            font-size: 10px; 
            font-weight: bold;
        }
        QPlainTextEdit#warnText {
            background: transparent; 
            border: none;
            color: #ffffff; 
            font-size: 10px; 
            padding: 4px;
        }

        QGroupBox#trafficBox {
            border: 1px solid #00eaff;
            border-radius: 4px;
            margin-top: 8px;
            background-color: #1a1a1a;
        }
        QGroupBox#trafficBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top center;
            padding: 0 5px;
            color: #00eaff; 
            font-size: 12px; 
            font-weight: bold;
        }
        QPlainTextEdit#trafficText {
            background: transparent; 
            border: none;
            color: #ffffff; 
            padding: 4px;
        }

        QLabel { 
            font-weight: bold; 
            color: #03dac6; 
            font-size: 12px; 
            margin: 2px; 
        }
        
        QPushButton {
            background-color: #292929; 
            color: #ffffff;
            border: 1px solid #03dac6; 
            border-radius: 4px;
            padding: 6px 10px; 
            font-weight: bold;
            font-size: 10px;
        }
        QPushButton:hover { 
            background-color: #03dac6; 
            color: #121212; 
        }

        QPlainTextEdit, QTextEdit { 
            background-color: #1f1f1f; 
            border: 1px solid #444; 
            border-radius: 4px; 
            padding: 4px; 
            font-size: 10px; 
        }

        QTableWidget {
            background-color: #000; 
            border: none; 
            gridline-color: #333;
            alternate-background-color: #111;
        }
        QHeaderView::section {
            background-color: #2a2a2a;
            color: #fff; 
            padding: 6px; 
            border: 1px solid #444;
            font-size: 10px;
        }
        QTableWidget::item {
            background-color: #000; 
            color: #fff; 
            padding: 4px; 
            border: none;
        }
        QTableWidget::item:alternate {
            background-color: #111;
        }
        QTableWidget::item:selected { 
            background-color: #333; 
        }
        """

    def estilo_claro(self):
        """Estilo modo claro"""
        return """
        QWidget { 
            background-color: #E0E0E0; 
            color: #000000; 
            font-family: 'Segoe UI'; 
        }

        QGroupBox#warnBox {
            border: 1px solid #FF0000;
            border-radius: 4px;
            margin-top: 8px;
            background-color: #ffffff;
        }
        QGroupBox#warnBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top center;
            padding: 0 5px;
            color: #FF0000; 
            font-size: 10px; 
            font-weight: bold;
        }
        QPlainTextEdit#warnText {
            background: transparent; 
            border: none;
            color: #000000; 
            font-size: 10px; 
            padding: 4px;
        }

        QGroupBox#trafficBox {
            border: 1px solid #0288d1;
            border-radius: 4px;
            margin-top: 8px;
            background-color: #ffffff;
        }
        QGroupBox#trafficBox::title {
            subcontrol-origin: margin;
            subcontrol-position: top center;
            padding: 0 5px;
            color: #0277bd; 
            font-size: 12px; 
            font-weight: bold;
        }
        QPlainTextEdit#trafficText {
            background: transparent; 
            border: none;
            color: #424242; 
            padding: 4px;
        }

        QLabel { 
            font-weight: bold; 
            color: #0093FF; 
            font-size: 12px; 
            margin: 2px; 
        }
        
        QPushButton {
            background-color: #ffffff; 
            color: #212121;
            border: 1px solid #0093FF; 
            border-radius: 4px;
            padding: 6px 10px; 
            font-weight: bold;
            font-size: 10px;
        }
        QPushButton:hover { 
            background-color: #0093FF; 
            color: #ffffff; 
        }

        QPlainTextEdit, QTextEdit { 
            background-color: #ffffff; 
            border: 1px solid #bdbdbd; 
            border-radius: 4px; 
            padding: 4px; 
            font-size: 10px; 
            color: #212121;
        }

        QTableWidget {
            background-color: #ffffff; 
            border: none; 
            gridline-color: #e0e0e0;
            alternate-background-color: #fafafa;
        }
        QHeaderView::section {
            background-color: #e0e0e0;
            color: #212121; 
            padding: 6px; 
            border: 1px solid #bdbdbd;
            font-size: 10px;
            font-weight: bold;
        }
        QTableWidget::item {
            background-color: #ffffff; 
            color: #212121; 
            padding: 4px; 
            border: none;
        }
        QTableWidget::item:alternate {
            background-color: #fafafa;
        }
        QTableWidget::item:selected { 
            background-color: #b2dfdb; 
        }
        
        QStatusBar {
            background-color: #e0e0e0;
            color: #212121;
        }
        
        QCheckBox {
            color: #212121;
        }
        
        QSpinBox {
            background-color: #ffffff;
            color: #212121;
            border: 1px solid #bdbdbd;
            border-radius: 4px;
            padding: 2px;
        }
        
        QTabWidget::pane { 
            border: 1px solid #bdbdbd; 
            background-color: #ffffff;
        }
        QTabBar::tab { 
            background: #e0e0e0; 
            padding: 6px;
            color: #212121;
            border: 1px solid #bdbdbd;
        }
        QTabBar::tab:selected {
            background: #ffffff;
            border-bottom-color: #ffffff;
        }
        """

    def crear_boton(self, texto, funcion, habil=True):
        """Crear botón """
        boton = QPushButton(texto)
        boton.clicked.connect(funcion)
        boton.setEnabled(habil)
        return boton

    def exportar_csv(self):
        """Exportar CSV """
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
                    writer.writerows(eventos_copia)
                self.status.showMessage(f"CSV guardado: {ruta}", 5000)
            except Exception as e:
                logging.error(f"Error exportando CSV: {e}")
                self.status.showMessage("Error exportando CSV", 5000)

    def mostrar_grafico_pie(self):
        """Cambiar a pestaña de pastel"""
        if hasattr(self, "tabs"):
            self.tabs.setCurrentIndex(1)
        self.actualizar_grafico_auto()

    def generar_evidencia(self):
        """Guardar las dos gráficas en carpeta evidencia"""
        try:
            carpeta = os.path.join(BASE_DIR, 'evidencia')
            if not os.path.exists(carpeta):
                os.makedirs(carpeta)

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            # Guardar pastel
            ruta_pie = os.path.join(carpeta, f"grafico_pie_{timestamp}.png")
            self.canvas_pie.figure.savefig(ruta_pie, dpi=100, bbox_inches='tight')

            self.status.showMessage(f"Evidencia generada en {carpeta}", 5000)
        except Exception as e:
            logging.error(f"Error generando evidencia: {e}")
            self.status.showMessage("Error generando evidencia", 5000)

    def guardar_grafico_pie_diario(self):
        """Guardar gráfico de pastel diario (usa el canvas_pie)"""
        try:
            carpeta = os.path.join(BASE_DIR, 'evidencia')
            if not os.path.exists(carpeta):
                os.makedirs(carpeta)

            nombre_archivo = f"grafica_pie_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            ruta_completa = os.path.join(carpeta, nombre_archivo)

            # Guardar el pastel actual
            self.canvas_pie.figure.savefig(ruta_completa, dpi=100, bbox_inches='tight')
            self.status.showMessage(f"Gráfica (pie) guardada: {nombre_archivo}", 5000)

        except Exception as e:
            logging.error(f"Error guardando gráfica diaria: {e}")
            self.status.showMessage("Error guardando gráfica diaria", 5000)

    def guardar_csv_diario(self):
        """Guardar CSV diario """
        try:
            with data_lock:
                if not eventos_detectados:
                    self.status.showMessage("No hay eventos para guardar.", 3000)
                    return
                eventos_copia = list(eventos_detectados)

            carpeta = os.path.join(BASE_DIR, 'evidencia')
            if not os.path.exists(carpeta):
                os.makedirs(carpeta)

            nombre_archivo = f"eventos_ids_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            ruta_completa = os.path.join(carpeta, nombre_archivo)

            # Guardar en chunk para archivos grandes
            with open(ruta_completa, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Hora", "IP Origen", "IP Destino", "Puerto", "Protocolo", "Flag", "Tipo"])

                # Procesar en lotes para archivos grandes
                chunk_size = 1000
                for i in range(0, len(eventos_copia), chunk_size):
                    chunk = eventos_copia[i:i + chunk_size]
                    writer.writerows(chunk)

            self.status.showMessage(f"CSV guardado: {nombre_archivo}", 5000)

        except Exception as e:
            logging.error(f"Error guardando CSV diario: {e}")
            self.status.showMessage("Error guardando CSV diario", 5000)

    def closeEvent(self, event):
        """Cierre limpio """
        try:

            # Limpiar AbuseIPDB
            self.gestor_abuse.limpiar()
            

            # Detener monitoreo si está activo
            if self.monitoreo_activo:
                self.detener_monitoreo()

            # Detener timers
            self.timer.stop()
            self.graf_timer.stop()
            self.timer_guardar_diario.stop()
            self.timer_guardar_csv_diario.stop()

            # Detener worker thread
            self.data_processor.stop()

            # Limpiar memoria
            with data_lock:
                eventos_detectados.clear()
                advertencias_cont.clear()
                trafico_buffer.clear()

        except Exception as e:
            logging.error(f"Error en closeEvent: {e}")
        finally:
            super().closeEvent(event)



# Funciones auxiliares de optimización


def configurar_logging():
    """Configurar logging """
    logging.basicConfig(
        level=logging.ERROR,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('ids_interface.log'),
            logging.StreamHandler()
        ]
    )

def limpiar_memoria_periodica():
    """Limpiar memoria periódicamente"""
    global eventos_detectados, advertencias_cont

    with data_lock:
        # Mantener solo los eventos más recientes
        if len(eventos_detectados) > MAX_EVENTOS_MEMORIA:
            eventos_list = list(eventos_detectados)
            eventos_detectados.clear()
            eventos_detectados.extend(eventos_list[-MAX_EVENTOS_MEMORIA//2:])

        # Limpiar contadores muy antiguos (opcional)
        if len(advertencias_cont) > 1000:
            items_sorted = sorted(advertencias_cont.items(), key=lambda x: x[1], reverse=True)
            advertencias_cont.clear()
            advertencias_cont.update(dict(items_sorted[:500]))


# Punto de entrada 

if __name__ == "__main__":
    # Configurar logging
    configurar_logging()

    # Configurar aplicación para mejor rendimiento
    app = QApplication(sys.argv)
    app.setAttribute(Qt.AA_DontCreateNativeWidgetSiblings, True)
    app.setAttribute(Qt.AA_DontShowIconsInMenus, True)

    # Configurar timer para limpieza periódica de memoria
    cleanup_timer = QTimer()
    cleanup_timer.timeout.connect(limpiar_memoria_periodica)
    cleanup_timer.start(60000)  # Cada minuto

    try:
        ventana = IDSInterface()
        ventana.show()

        # Mensaje de inicio
        print("IDS Interface Optimizada iniciada")
        print(f"Límites configurados:")
        print(f"   - Eventos en tabla: {MAX_EVENTOS_TABLA}")
        print(f"   - Eventos en memoria: {MAX_EVENTOS_MEMORIA}")
        print(f"   - Líneas de tráfico: {MAX_TRAFICO_LINEAS}")

        sys.exit(app.exec_())

    except Exception as e:
        logging.error(f"Error crítico en la aplicación: {e}")
        sys.exit(1)