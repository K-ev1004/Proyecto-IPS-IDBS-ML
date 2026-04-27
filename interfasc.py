# =============================================================================
# interfasc.py — Interfaz Gráfica del IDS (Sistema de Detección de Intrusiones)
# Refactorizada con PyQt-Fluent-Widgets siguiendo Fluent Design (Windows 11)
# =============================================================================

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
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
    QTableWidgetItem, QHeaderView, QFileDialog, QSplitter,
    QMessageBox
)
from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal, QSettings
from PyQt5.QtGui import QFont, QColor, QBrush

# qfluentwidgets para diseño moderno
from qfluentwidgets import (
    FluentWindow, NavigationItemPosition, InfoBar, InfoBarPosition,
    PrimaryPushButton, TransparentPushButton, TableWidget,
    ComboBox, LineEdit, SpinBox, CheckBox, PlainTextEdit,
    SubtitleLabel, BodyLabel, TitleLabel, Theme, setTheme, FluentIcon as FIF
)

# Matplotlib
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from matplotlib import style
from matplotlib import cm
from matplotlib import colors as mcolors

# Módulo interno
from abuseipdb_module import GestorAbuseIPDB

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    import ids
    import respuesta_activa
except Exception as _e:
    ids = None
    respuesta_activa = None
    logging.error("No se pudo importar 'ids' o 'respuesta_activa'. Detalle: %s", _e)

style.use('dark_background')

# CONSTANTES DE RENDIMIENTO
MAX_EVENTOS_TABLA   = 1000
MAX_EVENTOS_MEMORIA = 10000
MAX_TRAFICO_LINEAS  = 500
UPDATE_BATCH_SIZE   = 50

FLUENT_COLORS = ['#0078D4', '#00BCF2', '#107C10', '#D83B01', '#E81123', '#5C2D91']

def colors_for_labels(labels):
    return [FLUENT_COLORS[i % len(FLUENT_COLORS)] for i in range(len(labels))]

eventos_detectados = deque(maxlen=MAX_EVENTOS_MEMORIA)
advertencias_cont  = {}
trafico_buffer     = deque(maxlen=MAX_TRAFICO_LINEAS)
data_lock          = Lock()

class DataProcessor(QThread):
    data_ready  = pyqtSignal(list)
    stats_ready = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.running       = False
        self.pending_events = deque()

    def add_events(self, events):
        self.pending_events.extend(events)

    def run(self):
        self.running = True
        while self.running:
            if self.pending_events:
                batch = []
                for _ in range(min(UPDATE_BATCH_SIZE, len(self.pending_events))):
                    if self.pending_events:
                        batch.append(self.pending_events.popleft())

                if batch:
                    self.data_ready.emit(batch)
                    with data_lock:
                        stats = {
                            'total_eventos': len(eventos_detectados),
                            'ips_unicas':    len(advertencias_cont),
                            'tipos_ataques': dict(Counter([e[6] for e in list(eventos_detectados)[-100:]]))
                        }
                    self.stats_ready.emit(stats)

            self.msleep(100)

    def stop(self):
        self.running = False
        self.quit()
        self.wait()

class IDSInterface(FluentWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IDS UNIPAZ - Sistema de Detección de Intrusiones")
        self.resize(1350, 900)
        self.modo_oscuro = True
        
        self.settings = QSettings("IDS_UNIPAZ", "Configuracion")
        self._cargar_preferencias()
        
        self.last_table_update     = 0
        self.last_graph_update     = 0
        self.update_pending        = False
        self.graph_update_pending  = False
        self.auto_scroll_enabled   = True
        self.show_all_events       = False

        self.history_pps = deque([0]*60, maxlen=60)
        self.history_alerts = deque([0]*60, maxlen=60)

        self.data_processor = DataProcessor()
        self.data_processor.data_ready.connect(self.process_event_batch)
        self.data_processor.stats_ready.connect(self.update_stats)
        self.data_processor.start()

        self.setup_styles()
        self.last_hover_row = -1

        self.setup_ui()

        self._pps_count  = 0
        self._alert_ts   = deque(maxlen=5000)
        self._start_time = None

        self._resize_timer = QTimer(self)
        self._resize_timer.setSingleShot(True)
        self._resize_timer.timeout.connect(self._apply_table_proportions)

        self.setup_timers()
        self.setup_signals()

    def _cargar_preferencias(self):
        if ids:
            try:
                # Carga los valores de QSettings, con fallback a los valores originales de ids.py
                ids.THRESHOLD_SYN_FLOOD = int(self.settings.value("thresh_syn", ids.THRESHOLD_SYN_FLOOD))
                ids.THRESHOLD_DDOS = int(self.settings.value("thresh_ddos", ids.THRESHOLD_DDOS))
                ids.THRESHOLD_UDP_FLOOD = int(self.settings.value("thresh_udp", ids.THRESHOLD_UDP_FLOOD))
                ids.PORT_SCAN_THRESHOLD = int(self.settings.value("thresh_scan", ids.PORT_SCAN_THRESHOLD))
            except Exception as e:
                logging.error(f"Error cargando preferencias: {e}")

    def _update_threshold(self, key, attr, value):
        if ids:
            setattr(ids, attr, value)
        self.settings.setValue(key, value)

    def mostrar_mensaje(self, titulo, mensaje, tipo="info"):
        if tipo == "info":
            InfoBar.info(title=titulo, content=mensaje, position=InfoBarPosition.TOP, duration=3000, parent=self)
        elif tipo == "success":
            InfoBar.success(title=titulo, content=mensaje, position=InfoBarPosition.TOP, duration=3000, parent=self)
        elif tipo == "warning":
            InfoBar.warning(title=titulo, content=mensaje, position=InfoBarPosition.TOP, duration=5000, parent=self)
        elif tipo == "error":
            InfoBar.error(title=titulo, content=mensaje, position=InfoBarPosition.TOP, duration=5000, parent=self)

    def setup_styles(self):
        self.api_key_abuse = "31b904b493a50236fd7bd08163d01b562ce7a5127dc3968ef589d808232696ce3ea1b68e695323d4"
        self.gestor_abuse = GestorAbuseIPDB(self.api_key_abuse)
        self.ips_a_verificar_cola = set()

    def aplicar_estilos_badges(self):
        bg = "#272727" if self.modo_oscuro else "#ffffff"
        border = "#3e3e42" if self.modo_oscuro else "#e1dfdd"

        def b_style(color):
            return f"padding: 10px 16px; border-radius: 6px; font-weight: 500; font-size: 13px; background-color: {bg}; color: {color}; border: 1px solid {border}; border-left: 4px solid {color};"

        c_blue = "#4daafc" if self.modo_oscuro else "#0078d4"
        c_green = "#6ccb5f" if self.modo_oscuro else "#107c10"
        c_red = "#ff99a4" if self.modo_oscuro else "#d13438"
        c_orange = "#ffb38f" if self.modo_oscuro else "#d83b01"
        c_purple = "#b4a0ff" if self.modo_oscuro else "#5c2d91"

        if hasattr(self, 'iface_badge'):
            self.iface_badge.setStyleSheet(b_style(c_blue))
            self.lbl_pps.setStyleSheet(b_style(c_purple))
            self.lbl_alerts_min.setStyleSheet(b_style(c_red))
            self.lbl_uptime.setStyleSheet(b_style(c_green))
            self.lbl_stats.setStyleSheet(b_style(c_orange))

        if hasattr(self, 'lbl_total_bloqueadas'):
            self.lbl_total_bloqueadas.setStyleSheet(b_style(c_blue))
            self.lbl_bloqueos_activos.setStyleSheet(b_style(c_red))
            self.lbl_bloqueos_expirados.setStyleSheet(b_style(c_green))
            self.lbl_ultimo_ataque.setStyleSheet(b_style(c_orange))

    def setup_ui(self):
        self.page_dashboard = QWidget()
        self.page_dashboard.setObjectName("page_dashboard")
        self.setup_dashboard_page()

        self.page_ips = QWidget()
        self.page_ips.setObjectName("page_ips")
        self.setup_ips_page()

        self.page_stats = QWidget()
        self.page_stats.setObjectName("page_stats")
        self.setup_stats_page()

        self.page_settings = QWidget()
        self.page_settings.setObjectName("page_settings")
        self.setup_settings_page()

        self.addSubInterface(self.page_dashboard, FIF.HOME, "Dashboard")
        self.addSubInterface(self.page_ips, FIF.VPN, "Respuesta Activa (IPS)")
        self.addSubInterface(self.page_stats, FIF.PIE_SINGLE, "Estadísticas Avanzadas")
        self.addSubInterface(self.page_settings, FIF.SETTING, "Configuración", NavigationItemPosition.BOTTOM)

        self.aplicar_estilos_badges()

    def setup_dashboard_page(self):
        layout = QVBoxLayout(self.page_dashboard)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        header_layout = QHBoxLayout()
        header = TitleLabel("Monitoreo SOC en Tiempo Real")
        header_layout.addStretch()
        header_layout.addWidget(header)
        header_layout.addStretch()
        
        btn_tema = TransparentPushButton(FIF.PALETTE, "Alternar Modo Claro/Oscuro")
        btn_tema.clicked.connect(self.cambiar_tema)
        header_layout.addWidget(btn_tema)
        
        layout.addLayout(header_layout)

        badges_layout = QHBoxLayout()
        badges_layout.setSpacing(15)

        self.iface_badge = BodyLabel("Interfaz: N/A | ○ Stopped")
        self.lbl_pps = BodyLabel("PPS: 0")
        self.lbl_alerts_min = BodyLabel("Alertas/min: 0")
        self.lbl_uptime = BodyLabel("Uptime: 00:00:00")
        self.lbl_stats = BodyLabel("Eventos: 0 | IPs únicas: 0")
        
        for lbl in [self.iface_badge, self.lbl_pps, self.lbl_alerts_min, self.lbl_uptime, self.lbl_stats]:
            lbl.setAlignment(Qt.AlignCenter)
            badges_layout.addWidget(lbl)
            
        layout.addLayout(badges_layout)

        filtros_layout = QHBoxLayout()
        filtros_layout.setSpacing(12)
        filtros_layout.addStretch()

        filtros_layout.addWidget(SubtitleLabel("Buscar:"))
        self.search_input = LineEdit()
        self.search_input.setPlaceholderText("IP, tipo, puerto, protocolo...")
        self.search_input.setMinimumWidth(280)
        self.search_input.textChanged.connect(lambda _: self.apply_filters())
        filtros_layout.addWidget(self.search_input)

        filtros_layout.addWidget(SubtitleLabel("Severidad:"))
        self.sev_filter = ComboBox()
        self.sev_filter.addItems(["Todos", "CRÍTICA", "ALTA", "MEDIA", "BAJA"])
        self.sev_filter.currentIndexChanged.connect(lambda _: self.apply_filters())
        filtros_layout.addWidget(self.sev_filter)

        layout.addLayout(filtros_layout)

        splitter = QSplitter(Qt.Horizontal)
        
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 10, 0)
        
        self.table = self.crear_tabla_eventos_optimizada()
        self.table.itemSelectionChanged.connect(self.update_detail_panel)
        left_layout.addWidget(SubtitleLabel("Registro de Eventos Detectados"))
        left_layout.addWidget(self.table)
        
        self.advertencias = PlainTextEdit()
        self.advertencias.setReadOnly(True)
        self.advertencias.document().setMaximumBlockCount(100)
        left_layout.addWidget(SubtitleLabel("Log de Advertencias (Top 100)"))
        left_layout.addWidget(self.advertencias)

        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(10, 0, 0, 0)

        self.detalle_text = PlainTextEdit()
        self.detalle_text.setReadOnly(True)
        self.detalle_text.setPlainText("Seleccione una alerta en la tabla para inspeccionar los metadatos y recomendaciones.")
        right_layout.addWidget(SubtitleLabel("Inspección Forense del Evento"))
        right_layout.addWidget(self.detalle_text)

        self.trafico_en_vivo = PlainTextEdit()
        self.trafico_en_vivo.setReadOnly(True)
        self.trafico_en_vivo.document().setMaximumBlockCount(MAX_TRAFICO_LINEAS)
        right_layout.addWidget(SubtitleLabel("Captura de Tráfico Raw (Live)"))
        right_layout.addWidget(self.trafico_en_vivo)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 6)
        splitter.setStretchFactor(1, 4)

        layout.addWidget(splitter)

    def setup_ips_page(self):
        layout = QVBoxLayout(self.page_ips)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        header_layout = QHBoxLayout()
        header = TitleLabel("Panel de Respuesta Activa (IPS)")
        header_layout.addStretch()
        header_layout.addWidget(header)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        badges_layout = QHBoxLayout()
        badges_layout.setSpacing(15)
        
        self.lbl_total_bloqueadas = BodyLabel("Total: 0")
        self.lbl_bloqueos_activos = BodyLabel("Activos: 0")
        self.lbl_bloqueos_expirados = BodyLabel("Expirados: 0")
        self.lbl_ultimo_ataque = BodyLabel("Último ataque: —")

        for lbl in [self.lbl_total_bloqueadas, self.lbl_bloqueos_activos, self.lbl_bloqueos_expirados, self.lbl_ultimo_ataque]:
            lbl.setAlignment(Qt.AlignCenter)
            badges_layout.addWidget(lbl)
            
        layout.addLayout(badges_layout)

        self.table_bloqueos = TableWidget()
        self.table_bloqueos.setColumnCount(7)
        self.table_bloqueos.setHorizontalHeaderLabels([
            "Hora", "IP Bloqueada", "Tipo de Ataque",
            "Severidad", "Acción Aplicada", "Estado", "Tiempo Restante"
        ])
        self.table_bloqueos.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_bloqueos.verticalHeader().hide()
        self.table_bloqueos.setEditTriggers(TableWidget.NoEditTriggers)
        self.table_bloqueos.setSelectionBehavior(TableWidget.SelectRows)
        self.table_bloqueos.setSelectionMode(TableWidget.SingleSelection)
        self.table_bloqueos.setAlternatingRowColors(True)
        self.table_bloqueos.setShowGrid(False)
        self.table_bloqueos.setBorderVisible(True)
        self.table_bloqueos.setBorderRadius(8)
        
        layout.addWidget(self.table_bloqueos)

        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(15)

        btn_unblock = PrimaryPushButton(FIF.UNPIN, "Desbloquear IP")
        btn_unblock.clicked.connect(self.desbloquear_ip_manual)
        controls_layout.addWidget(btn_unblock)

        self.input_manual_ip = LineEdit()
        self.input_manual_ip.setPlaceholderText("IP a bloquear (ej. 192.168.1.50)")
        self.input_manual_ip.setMinimumWidth(200)
        controls_layout.addWidget(self.input_manual_ip)
        
        self.spin_manual_time = SpinBox()
        self.spin_manual_time.setRange(1, 1440)
        self.spin_manual_time.setValue(30)
        self.spin_manual_time.setSuffix(" min")
        controls_layout.addWidget(self.spin_manual_time)

        btn_block_manual = TransparentPushButton(FIF.PIN, "Bloquear Manual")
        btn_block_manual.clicked.connect(self.bloquear_ip_manual_ui)
        controls_layout.addWidget(btn_block_manual)

        controls_layout.addStretch()

        btn_clear_expired = TransparentPushButton(FIF.DELETE, "Limpiar Inactivos")
        btn_clear_expired.clicked.connect(self.limpiar_ips_expirados)
        controls_layout.addWidget(btn_clear_expired)

        btn_export_ips = TransparentPushButton(FIF.DOCUMENT, "Exportar Reglas (CSV)")
        btn_export_ips.clicked.connect(self.exportar_reglas_ips)
        controls_layout.addWidget(btn_export_ips)

        layout.addLayout(controls_layout)

        self._bloqueos_data = []

    def setup_stats_page(self):
        layout = QVBoxLayout(self.page_stats)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)
        
        header_layout = QHBoxLayout()
        header = TitleLabel("Análisis Avanzado de Amenazas")
        header_layout.addStretch()
        header_layout.addWidget(header)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        self.canvas_stats = FigureCanvas(Figure(figsize=(10, 8)))
        self.fig_stats = self.canvas_stats.figure
        
        gs = self.fig_stats.add_gridspec(2, 2, height_ratios=[1, 1])
        
        self.ax_pie = self.fig_stats.add_subplot(gs[0, 0])
        self.ax_bar = self.fig_stats.add_subplot(gs[0, 1])
        self.ax_line = self.fig_stats.add_subplot(gs[1, :])
        
        layout.addWidget(self.canvas_stats)

    def setup_settings_page(self):
        layout = QVBoxLayout(self.page_settings)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)

        header_layout = QHBoxLayout()
        header = TitleLabel("Configuración y Operaciones del Sistema")
        header_layout.addStretch()
        header_layout.addWidget(header)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        controls_layout = QVBoxLayout()
        controls_layout.setSpacing(20)

        red_box = QHBoxLayout()
        red_box.addWidget(SubtitleLabel("Interfaz de Red:"))
        self.combo_iface = ComboBox()
        self.combo_iface.setMinimumWidth(300)
        self.combo_iface.addItems(self.listar_interfaces_captura())
        self.combo_iface.currentIndexChanged.connect(lambda _: self._set_running_state(self.monitoreo_activo))
        red_box.addWidget(self.combo_iface)
        red_box.addStretch()
        controls_layout.addLayout(red_box)

        vista_box = QHBoxLayout()
        vista_box.setSpacing(15)
        self.auto_scroll_cb = CheckBox("Scroll Automático")
        self.auto_scroll_cb.setChecked(True)
        self.auto_scroll_cb.toggled.connect(self.toggle_auto_scroll)
        vista_box.addWidget(self.auto_scroll_cb)

        self.show_all_cb = CheckBox("Mostrar historial completo")
        self.show_all_cb.toggled.connect(self.toggle_show_all)
        vista_box.addWidget(self.show_all_cb)

        vista_box.addWidget(SubtitleLabel("Límite de filas en UI:"))
        self.max_events_spin = SpinBox()
        self.max_events_spin.setRange(100, 5000)
        self.max_events_spin.setValue(MAX_EVENTOS_TABLA)
        self.max_events_spin.valueChanged.connect(self.change_max_events)
        vista_box.addWidget(self.max_events_spin)
        
        vista_box.addStretch()
        controls_layout.addLayout(vista_box)

        self.ips_activo_cb = CheckBox("MODO IPS (Habilitar Bloqueo Automático)")
        self.ips_activo_cb.toggled.connect(self.toggle_ips_mode)
        controls_layout.addWidget(self.ips_activo_cb)

        layout.addLayout(controls_layout)

        # --- SECCIÓN DE UMBRALES DE DETECCIÓN ---
        layout.addWidget(SubtitleLabel("Umbrales de Detección (Sensibilidad)"))
        
        info_umbrales = BodyLabel(
            "Recomendaciones según el tamaño de la red (a menor número, mayor sensibilidad):\n"
            "• Redes pequeñas/Pruebas (Tu PC o WiFi de casa):  SYN Flood: 20-50 | DDoS: 100-200 | UDP Flood: 200-300 | Port Scan: 15-20\n"
            "• Redes Universitarias/Empresariales (Tráfico masivo):  SYN Flood: 100+ | DDoS: 1000+ | UDP Flood: 2000+ | Port Scan: 50+"
        )
        info_umbrales.setWordWrap(True)
        # Usamos un estilo directo para darle un toque sutil y diferenciado
        info_umbrales.setStyleSheet("color: #888888; font-size: 13px; font-style: italic;")
        layout.addWidget(info_umbrales)

        umbrales_layout = QHBoxLayout()
        umbrales_layout.setSpacing(15)

        # SYN Flood
        box_syn = QVBoxLayout()
        box_syn.addWidget(BodyLabel("SYN Flood (pkts/0.5s):"))
        self.spin_syn = SpinBox()
        self.spin_syn.setRange(5, 5000)
        self.spin_syn.setValue(ids.THRESHOLD_SYN_FLOOD)
        self.spin_syn.valueChanged.connect(lambda v: self._update_threshold('thresh_syn', 'THRESHOLD_SYN_FLOOD', v))
        box_syn.addWidget(self.spin_syn)
        umbrales_layout.addLayout(box_syn)

        # DDoS
        box_ddos = QVBoxLayout()
        box_ddos.addWidget(BodyLabel("DDoS (pkts/1s):"))
        self.spin_ddos = SpinBox()
        self.spin_ddos.setRange(10, 10000)
        self.spin_ddos.setValue(ids.THRESHOLD_DDOS)
        self.spin_ddos.valueChanged.connect(lambda v: self._update_threshold('thresh_ddos', 'THRESHOLD_DDOS', v))
        box_ddos.addWidget(self.spin_ddos)
        umbrales_layout.addLayout(box_ddos)

        # UDP Flood
        box_udp = QVBoxLayout()
        box_udp.addWidget(BodyLabel("UDP Flood (pkts/1s):"))
        self.spin_udp = SpinBox()
        self.spin_udp.setRange(10, 10000)
        self.spin_udp.setValue(ids.THRESHOLD_UDP_FLOOD)
        self.spin_udp.valueChanged.connect(lambda v: self._update_threshold('thresh_udp', 'THRESHOLD_UDP_FLOOD', v))
        box_udp.addWidget(self.spin_udp)
        umbrales_layout.addLayout(box_udp)

        # Port Scan
        box_scan = QVBoxLayout()
        box_scan.addWidget(BodyLabel("Escaneo (puertos/IP):"))
        self.spin_scan = SpinBox()
        self.spin_scan.setRange(5, 500)
        self.spin_scan.setValue(ids.PORT_SCAN_THRESHOLD)
        self.spin_scan.valueChanged.connect(lambda v: self._update_threshold('thresh_scan', 'PORT_SCAN_THRESHOLD', v))
        box_scan.addWidget(self.spin_scan)
        umbrales_layout.addLayout(box_scan)

        layout.addLayout(umbrales_layout)
        # --- FIN SECCIÓN UMBRALES ---

        layout.addWidget(SubtitleLabel("Acciones Globales"))
        
        acciones_layout = QHBoxLayout()
        acciones_layout.setSpacing(12)
        
        self.boton_iniciar = PrimaryPushButton("Iniciar Motor")
        self.boton_iniciar.clicked.connect(self.iniciar_monitoreo)
        
        self.boton_detener = TransparentPushButton("Detener Motor")
        self.boton_detener.clicked.connect(self.detener_monitoreo)
        self.boton_detener.setEnabled(False)
        
        self.boton_limpiar = TransparentPushButton("Limpiar Registros")
        self.boton_limpiar.clicked.connect(self.limpiar_tabla)
        
        self.boton_exportar = TransparentPushButton("Exportar Eventos CSV")
        self.boton_exportar.clicked.connect(self.exportar_csv)
        
        self.boton_evidencia = TransparentPushButton("Generar Evidencia Gráfica")
        self.boton_evidencia.clicked.connect(self.generar_evidencia)
        
        self.boton_verificar_abuse = TransparentPushButton("Verificar Base de Datos AbuseIPDB")
        self.boton_verificar_abuse.clicked.connect(self.verificar_ips_abuse)
        
        self.boton_tema = TransparentPushButton("Alternar Apariencia (Dark/Light)")
        self.boton_tema.clicked.connect(self.cambiar_tema)

        for b in [self.boton_iniciar, self.boton_detener, self.boton_limpiar,
                  self.boton_exportar, self.boton_evidencia,
                  self.boton_verificar_abuse, self.boton_tema]:
            acciones_layout.addWidget(b)
            
        acciones_layout.addStretch()
        layout.addLayout(acciones_layout)
        layout.addStretch()

    def setup_timers(self):
        self.timer       = QTimer()
        self.timer.timeout.connect(self.actualizar_tabla_optimizada)

        self.graf_timer  = QTimer()
        self.graf_timer.timeout.connect(self.actualizar_grafico_auto)

        self.pps_timer   = QTimer()
        self.pps_timer.timeout.connect(self._tick_pps)

        self.uptime_timer = QTimer()
        self.uptime_timer.timeout.connect(self._tick_uptime)

        self.alerts_timer = QTimer()
        self.alerts_timer.timeout.connect(self._tick_alerts_per_min)

        self.bloqueos_timer = QTimer()
        self.bloqueos_timer.timeout.connect(self._tick_bloqueos_timer)
        self.bloqueos_timer.start(1000)

        self.monitoreo_activo = False

        self.timer_guardar_diario = QTimer()
        self.timer_guardar_diario.timeout.connect(self.guardar_grafico_pie_diario)
        self.timer_guardar_diario.start(24 * 60 * 60 * 1000)

        self.timer_guardar_csv_diario = QTimer()
        self.timer_guardar_csv_diario.timeout.connect(self.guardar_csv_diario)
        self.timer_guardar_csv_diario.start(24 * 60 * 60 * 1000)

    def setup_signals(self):
        self.table.setMouseTracking(False)
        if ids and hasattr(ids, 'comunicador'):
            try:
                ids.comunicador.nuevo_evento.connect(self.agregar_evento_)
                ids.comunicador.nuevo_trafico.connect(self.agregar_trafico_)
                ids.comunicador.nuevo_bloqueo.connect(self.actualizar_tabla_bloqueos_signal)
            except Exception as e:
                logging.error(f"No se pudieron conectar señales de 'ids': {e}")

    def crear_tabla_eventos_optimizada(self):
        table = TableWidget()
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "Sev", "Hora", "IP Origen", "IP Destino",
            "Puerto", "Protocolo", "Flag", "Tipo"
        ])

        header_h = table.horizontalHeader()
        header_v = table.verticalHeader()

        header_h.setSectionResizeMode(QHeaderView.Fixed)
        header_h.setStretchLastSection(False)
        header_v.setSectionResizeMode(QHeaderView.Fixed)
        header_v.setDefaultSectionSize(25)
        header_v.hide()

        table.setWordWrap(False)
        table.setSortingEnabled(False)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.setEditTriggers(TableWidget.NoEditTriggers)
        table.setSelectionBehavior(TableWidget.SelectRows)
        table.setSelectionMode(TableWidget.SingleSelection)

        table.setVerticalScrollMode(TableWidget.ScrollPerPixel)
        table.setHorizontalScrollMode(TableWidget.ScrollPerPixel)
        table.setBorderVisible(True)
        table.setBorderRadius(8)

        for i, ancho in enumerate([120, 140, 140, 70, 90, 70, 220]):
            table.setColumnWidth(i, ancho)

        return table

    def agregar_evento_(self, evento):
        with data_lock:
            eventos_detectados.append(evento)
            try:
                self._alert_ts.append(time.time())
            except Exception:
                pass
            ip = evento[1]
            advertencias_cont[ip] = advertencias_cont.get(ip, 0) + 1
        self.data_processor.add_events([evento])

    def agregar_trafico_(self, mensaje):
        try:
            self._pps_count += 1
        except Exception:
            self._pps_count = 1
        trafico_buffer.append(mensaje)
        if len(trafico_buffer) % 10 == 0:
            self.actualizar_trafico_batch()

    def toggle_ips_mode(self, enabled):
        if ids:
            ids.ips_activo = enabled
            estado = "ACTIVADO" if enabled else "DESACTIVADO"
            self.mostrar_mensaje("Modo IPS", f"Modo IPS {estado}", "success" if enabled else "warning")

    def actualizar_tabla_bloqueos_signal(self, datos_bloqueo):
        try:
            if len(datos_bloqueo) >= 5:
                ip, accion, duracion, tipo_ataque, severidad = datos_bloqueo[:5]
            elif len(datos_bloqueo) >= 3:
                ip, accion, duracion = datos_bloqueo[:3]
                tipo_ataque = "Desconocido"
                severidad = "ALTA"
            else:
                return

            hora = time.strftime("%H:%M:%S")
            accion_texto = "Bloqueo automático"
            estado = "Activo"
            expiry_epoch = time.time() + (duracion * 60)

            colores_sev = {
                "CRITICA": "#ff3b30", "ALTA": "#ff9500",
                "MEDIA": "#ffd60a", "BAJA": "#0a84ff"
            }
            color_sev = colores_sev.get(severidad, "#ff9500")

            row = self.table_bloqueos.rowCount()
            self.table_bloqueos.insertRow(row)

            valores = [hora, ip, tipo_ataque, severidad, accion_texto, estado, f"{duracion}:00"]

            for col, val in enumerate(valores):
                item = QTableWidgetItem(str(val))
                if col == 3:
                    item.setForeground(QBrush(QColor(color_sev)))
                if col == 5:
                    item.setForeground(QBrush(QColor("#4CAF50")))
                self.table_bloqueos.setItem(row, col, item)

            self._bloqueos_data.append({
                'ip': ip, 'tipo': tipo_ataque, 'expiry': expiry_epoch,
                'row': row, 'estado': 'Activo'
            })

            self._actualizar_resumen_bloqueos()
            self.lbl_ultimo_ataque.setText(f"Último ataque: {tipo_ataque}")
            self.mostrar_mensaje("Bloqueo IPS", f"IP BLOQUEADA: {ip} | {tipo_ataque} | {severidad}", "error")
        except Exception as e:
            logging.error(f"Error actualizando tabla de bloqueos: {e}")

    def _tick_bloqueos_timer(self):
        try:
            ahora = time.time()
            cambio = False

            for entry in self._bloqueos_data:
                row = entry['row']
                if entry['estado'] != 'Activo':
                    continue

                restante = entry['expiry'] - ahora
                if restante <= 0:
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
                    mins = int(restante // 60)
                    secs = int(restante % 60)
                    tiempo_item = self.table_bloqueos.item(row, 6)
                    if tiempo_item:
                        tiempo_item.setText(f"{mins:02d}:{secs:02d}")
                        if restante < 60:
                            tiempo_item.setForeground(QBrush(QColor("#ff3b30")))
                        else:
                            tiempo_item.setForeground(QBrush(QColor("#03dac6")))

            if cambio:
                self._actualizar_resumen_bloqueos()
        except Exception as e:
            logging.error(f"Error en tick bloqueos: {e}")

    def _actualizar_resumen_bloqueos(self):
        total = len(self._bloqueos_data)
        activos = sum(1 for b in self._bloqueos_data if b['estado'] == 'Activo')
        expirados = sum(1 for b in self._bloqueos_data if b['estado'] != 'Activo')
        self.lbl_total_bloqueadas.setText(f"Total: {total}")
        self.lbl_bloqueos_activos.setText(f"Activos: {activos}")
        self.lbl_bloqueos_expirados.setText(f"Expirados: {expirados}")

    def desbloquear_ip_manual(self):
        items = self.table_bloqueos.selectedItems()
        if not items:
            self.mostrar_mensaje("Info", "Seleccione una fila para desbloquear.", "info")
            return

        row = items[0].row()
        ip_item = self.table_bloqueos.item(row, 1)
        if not ip_item:
            return
        ip = ip_item.text()

        if respuesta_activa and respuesta_activa.desbloquear_ip(ip):
            estado_item = self.table_bloqueos.item(row, 5)
            tiempo_item = self.table_bloqueos.item(row, 6)
            if estado_item:
                estado_item.setText("Desbloqueado")
                estado_item.setForeground(QBrush(QColor("#0a84ff")))
            if tiempo_item:
                tiempo_item.setText("—")
            for entry in self._bloqueos_data:
                if entry['row'] == row:
                    entry['estado'] = 'Desbloqueado'
            self._actualizar_resumen_bloqueos()
            self.mostrar_mensaje("Desbloqueo IPS", f"IP Desbloqueada manualmente: {ip}", "success")
        else:
            self.mostrar_mensaje("Error", f"No se pudo desbloquear la IP {ip}", "error")

    def bloquear_ip_manual_ui(self):
        ip = self.input_manual_ip.text().strip()
        minutos = self.spin_manual_time.value()
        
        if not ip or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            self.mostrar_mensaje("Error de Validación", "Ingrese una dirección IPv4 válida.", "warning")
            return
            
        if respuesta_activa and respuesta_activa.bloquear_ip(ip, minutos):
            self.actualizar_tabla_bloqueos_signal([ip, "Bloqueo manual", minutos, "Prevención Manual", "ALTA"])
            self.input_manual_ip.clear()
            self.mostrar_mensaje("Bloqueo IPS", f"IP {ip} bloqueada manualmente por {minutos} minutos.", "success")
        else:
            self.mostrar_mensaje("Error", f"No se pudo ejecutar la regla de bloqueo para {ip}.", "error")
            
    def limpiar_ips_expirados(self):
        rows_to_remove = []
        for i in reversed(range(self.table_bloqueos.rowCount())):
            estado_item = self.table_bloqueos.item(i, 5)
            if estado_item and estado_item.text() in ["Expirado", "Desbloqueado"]:
                rows_to_remove.append(i)
                
        for row in rows_to_remove:
            self.table_bloqueos.removeRow(row)
            
        self._bloqueos_data = [b for b in self._bloqueos_data if b['estado'] == 'Activo']
        
        for i in range(self.table_bloqueos.rowCount()):
            ip = self.table_bloqueos.item(i, 1).text()
            for b in self._bloqueos_data:
                if b['ip'] == ip and b['estado'] == 'Activo':
                    b['row'] = i
                    
        self._actualizar_resumen_bloqueos()
        self.mostrar_mensaje("IPS", "Historial de bloqueos inactivos limpiado.", "info")

    def exportar_reglas_ips(self):
        ruta, _ = QFileDialog.getSaveFileName(self, "Exportar Reglas IPS", "reglas_ips_activas.csv", "CSV Files (*.csv)")
        if not ruta: return
        try:
            with open(ruta, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Hora", "IP Bloqueada", "Tipo de Ataque", "Severidad", "Acción Aplicada", "Estado", "Tiempo Restante"])
                for i in range(self.table_bloqueos.rowCount()):
                    row_data = [self.table_bloqueos.item(i, col).text() for col in range(7)]
                    writer.writerow(row_data)
            self.mostrar_mensaje("Exportación", f"Reglas IPS exportadas a {ruta}", "success")
        except Exception as e:
            logging.error(f"Error exportando reglas IPS: {e}")

    def actualizar_trafico_batch(self):
        if not trafico_buffer:
            return
        mensajes = list(trafico_buffer)[-20:]
        self.trafico_en_vivo.setPlainText('\n'.join(mensajes))
        if self.auto_scroll_enabled:
            self.trafico_en_vivo.verticalScrollBar().setValue(
                self.trafico_en_vivo.verticalScrollBar().maximum()
            )

    def process_event_batch(self, events):
        if not self.update_pending:
            self.update_pending = True
            QTimer.singleShot(100, self.actualizar_tabla_optimizada)

    def update_stats(self, stats):
        self.lbl_stats.setText(f"Eventos: {stats['total_eventos']} | IPs únicas: {stats['ips_unicas']}")

    def _hash_muestra_eventos(self, eventos):
        muestra = eventos[-50:] if len(eventos) > 50 else eventos
        try:
            key = tuple(tuple(ev) for ev in muestra)
            return hash(key)
        except Exception:
            return hash(tuple(sorted(Counter([e[6] for e in muestra]).items())))

    def _compute_severity(self, tipo_texto: str):
        t = (tipo_texto or "").lower()
        if "posible exploit" in t or "exploit" in t:
            return "CRÍTICA", "#E81123" if not self.modo_oscuro else "#FF99A4"
        if "ddos" in t or "syn flood" in t or "udp flood" in t:
            return "ALTA",    "#D83B01" if not self.modo_oscuro else "#FFB38F"
        if "escaneo" in t or "port" in t or "scan" in t:
            return "MEDIA",   "#D83B01" if not self.modo_oscuro else "#FFB38F"
        if "sql injection" in t or "sqli" in t:
            return "ALTA",    "#D83B01" if not self.modo_oscuro else "#FFB38F"
        return "BAJA",    "#0078D4" if not self.modo_oscuro else "#6CB8F6"

    def _row_matches_filters(self, row_values):
        sev_filter = self.sev_filter.currentText() if hasattr(self, "sev_filter") else "Todos"
        if sev_filter != "Todos" and row_values.get("sev") != sev_filter:
            return False

        q = (self.search_input.text() if hasattr(self, "search_input") else "").strip().lower()
        if not q:
            return True

        haystack = " ".join(str(v).lower() for v in row_values.values())
        return q in haystack

    def apply_filters(self):
        try:
            for r in range(self.table.rowCount()):
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
                self.table.setRowHidden(r, not row_ok)
        except Exception as e:
            logging.error(f"Error aplicando filtros: {e}")

    def listar_interfaces_captura(self):
        ifaces = []
        try:
            from scapy.arch.windows import get_windows_if_list
            for i in get_windows_if_list():
                name = i.get("name") or ""
                desc = (i.get("description") or "").lower()
                ips  = i.get("ips") or []

                nlow = name.lower()
                if "-wfp" in nlow or "-npcap" in nlow or "-filter" in nlow:
                    continue
                if "loopback" in desc or "wi-fi direct" in desc:
                    continue

                if not any("." in ip for ip in ips):
                    continue
                ifaces.append(name)
        except Exception as e:
            logging.error(f"No se pudieron listar interfaces: {e}")

        if not ifaces:
            ifaces = ["Ethernet", "Wi-Fi"]

        if "Ethernet" in ifaces:
            ifaces = ["Ethernet"] + [x for x in ifaces if x != "Ethernet"]

        return ifaces

    def _set_running_state(self, running: bool):
        iface  = self.combo_iface.currentText() if hasattr(self, "combo_iface") else "N/A"
        estado = "● Running" if running else "○ Stopped"
        self.iface_badge.setText(f"Interfaz: {iface} | {estado}")

    def _tick_pps(self):
        try:
            pps = getattr(self, "_pps_count", 0)
            self.history_pps.append(pps)
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
            dq    = getattr(self, "_alert_ts", None)
            ahora = time.time()
            while dq and (ahora - dq[0]) > 60:
                dq.popleft()
            alertas = len(dq)
            self.history_alerts.append(alertas)
            self.lbl_alerts_min.setText(f"Alertas/min: {alertas}")
        except Exception as e:
            logging.error(f"Error alert/min tick: {e}")

    def update_detail_panel(self):
        try:
            items = self.table.selectedItems()
            if not items:
                self.detalle_text.setPlainText("Seleccione una alerta en la tabla para inspeccionar los metadatos y recomendaciones.")
                return

            row   = items[0].row()
            sev   = self.table.item(row, 0).text() if self.table.item(row, 0) else ""
            hora  = self.table.item(row, 1).text() if self.table.item(row, 1) else ""
            ip_src = self.table.item(row, 2).text() if self.table.item(row, 2) else ""
            ip_dst = self.table.item(row, 3).text() if self.table.item(row, 3) else ""
            puerto = self.table.item(row, 4).text() if self.table.item(row, 4) else ""
            proto  = self.table.item(row, 5).text() if self.table.item(row, 5) else ""
            flag   = self.table.item(row, 6).text() if self.table.item(row, 6) else ""
            tipo   = self.table.item(row, 7).text() if self.table.item(row, 7) else ""

            evidencia = [f"- Protocolo/Flag: {proto}/{flag}"]
            if "syn flood"   in tipo.lower(): evidencia.append("- Indicador: volumen alto de SYN en ventana corta")
            if "ddos"        in tipo.lower(): evidencia.append("- Indicador: volumen alto hacia destino (posible DDoS)")
            if "escaneo"     in tipo.lower(): evidencia.append("- Indicador: múltiples puertos probados desde una misma IP")
            if "sql"         in tipo.lower(): evidencia.append("- Indicador: patrón de payload compatible con SQLi")

            txt = (
                f"SEVERIDAD: {sev}\nHORA: {hora}\nTIPO: {tipo}\n"
                f"IP ORIGEN: {ip_src}\nIP DESTINO: {ip_dst}\nPUERTO: {puerto}\n\n"
                f"EVIDENCIA (resumen):\n" + "\n".join(evidencia) + "\n\n"
                f"ACCIONES SUGERIDAS:\n"
                f"- Llamar al profesor Jhoni si la alarma persiste\n"
                f"- Revisar logs del servicio en el puerto destino\n"
                f"- Bloquear/limitar tráfico desde la interfaz de IPS si es recurrente\n"
            )
            self.detalle_text.setPlainText(txt)
        except Exception as e:
            logging.error(f"Error actualizando detalle: {e}")

    def actualizar_tabla_optimizada(self):
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

            nuevo_hash = self._hash_muestra_eventos(eventos_a_mostrar)
            contenido_cambio = (getattr(self, "_last_cnt_hash", None) != nuevo_hash)
            self._last_cnt_hash = nuevo_hash

            self.table.setUpdatesEnabled(False)
            try:
                if contenido_cambio:
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

                            if j == 0:
                                it.setForeground(QBrush(QColor(sev_color)))
                            elif j == 7:
                                color_val = "#0078D4" if not self.modo_oscuro else "#6CB8F6"
                                it.setForeground(QBrush(QColor(color_val)))
                            else:
                                it.setData(Qt.ForegroundRole, None)
            finally:
                self.table.setUpdatesEnabled(True)

            self.apply_filters()

            if self.auto_scroll_enabled and eventos_a_mostrar:
                self.table.scrollToBottom()

            self.actualizar_advertencias_optimizada()

        except Exception as e:
            logging.error(f"Error actualizando tabla optimizada: {e}")

    def actualizar_advertencias_optimizada(self):
        try:
            with data_lock:
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
        self.modo_oscuro = not self.modo_oscuro
        tema = Theme.DARK if self.modo_oscuro else Theme.LIGHT
        setTheme(tema)
        self.aplicar_estilos_badges()
        self.actualizar_tabla_optimizada()
        self.actualizar_grafico_auto()
        self.mostrar_mensaje("Apariencia", f"Tema cambiado a modo {'oscuro' if self.modo_oscuro else 'claro'}", "info")

    def iniciar_monitoreo(self):
        self.boton_iniciar.setEnabled(False)
        self.boton_detener.setEnabled(True)
        self.monitoreo_activo = True
        if hasattr(self, "combo_iface"):
            self.combo_iface.setEnabled(False)

        self._pps_count  = 0
        self._alert_ts.clear()
        self._start_time = time.time()

        iface = self.combo_iface.currentText() if hasattr(self, "combo_iface") else None

        if ids and hasattr(ids, 'iniciar_monitoreo'):
            try:
                iface_lower = iface.lower()
                if "virtualbox" in iface_lower or "host-only" in iface_lower or "local*" in iface_lower:
                    self.mostrar_mensaje(
                        "Advertencia de Interfaz",
                        f"La interfaz {iface} parece ser una red virtual. Puede no detectar tráfico de internet.",
                        "warning"
                    )
                ids.iniciar_monitoreo(iface)
            except Exception as e:
                logging.error(f"Error al iniciar monitoreo en 'ids': {e}")

        self._set_running_state(True)
        self.timer.start(3000)
        self.graf_timer.start(10000)
        self.pps_timer.start(1000)
        self.uptime_timer.start(1000)
        self.alerts_timer.start(5000)

    def detener_monitoreo(self):
        self.monitoreo_activo = False

        if ids and hasattr(ids, 'detener_monitoreo'):
            try:
                ids.detener_monitoreo()
            except Exception as e:
                logging.error(f"Error al detener monitoreo en 'ids': {e}")

        for timer in [self.timer, self.graf_timer, self.pps_timer,
                      self.uptime_timer, self.alerts_timer]:
            timer.stop()

        if hasattr(self, "combo_iface"):
            self.combo_iface.setEnabled(True)

        self._set_running_state(False)
        self.boton_iniciar.setEnabled(True)
        self.boton_detener.setEnabled(False)

    def limpiar_tabla(self):
        with data_lock:
            eventos_detectados.clear()
            advertencias_cont.clear()
            trafico_buffer.clear()

        self.table.setRowCount(0)
        self.advertencias.clear()
        self.trafico_en_vivo.clear()
        self.history_pps.clear()
        self.history_pps.extend([0]*60)
        
        self.ax_pie.clear()
        self.ax_bar.clear()
        self.ax_line.clear()
        self.canvas_stats.draw()
        
        self.mostrar_mensaje("Limpieza", "Interfaz y registros en memoria limpiados", "info")

    def actualizar_grafico_auto(self):
        if self.graph_update_pending:
            return

        self.graph_update_pending = True
        try:
            with data_lock:
                eventos_muestra = list(eventos_detectados)[-500:] if eventos_detectados else []
                top_ips = sorted(advertencias_cont.items(), key=lambda x: x[1], reverse=True)[:5]
            
            bg_color   = "#272727" if self.modo_oscuro else "#ffffff"
            text_color = "#ffffff" if self.modo_oscuro else "#201f1e"
            grid_color = "#3e3e42" if self.modo_oscuro else "#e1dfdd"
            accent_color = "#4daafc" if self.modo_oscuro else "#0078d4"

            self.fig_stats.patch.set_facecolor(bg_color)

            # 1. Pie Chart
            self.ax_pie.clear()
            self.ax_pie.set_facecolor(bg_color)
            if eventos_muestra:
                cnt = Counter([e[6] for e in eventos_muestra])
                if cnt:
                    labels = list(cnt.keys())
                    values = list(cnt.values())
                    colors = colors_for_labels(labels)
                    self.ax_pie.pie(
                        values, labels=labels, colors=colors,
                        autopct='%1.1f%%',
                        textprops={'color': text_color, 'fontsize': 9, 'weight': 'bold'}
                    )
            self.ax_pie.set_title("Distribución de Amenazas", color=text_color, fontsize=11, pad=15, weight='bold')
            
            # 2. Cuadro descriptivo en lugar de Bar Chart
            self.ax_bar.clear()
            self.ax_bar.set_facecolor(bg_color)
            self.ax_bar.axis('off') # Ocultar ejes
            
            description = (
                "IPS-IDBS-ML (Intrusion Prevention System)\n\n"
                "Capacidad de Detección y Bloqueo:\n"
                "• DoS / DDoS (Inundación de red)\n"
                "• Escaneo de Puertos y Reconocimiento\n"
                "• Fuerza Bruta (SSH, FTP, etc.)\n"
                "• Actividad de Malware y Botnets\n"
                "• Anomalías detectadas por Machine Learning"
            )
            
            self.ax_bar.text(
                0.5, 0.5, description,
                transform=self.ax_bar.transAxes,
                fontsize=11, color=text_color,
                ha='center', va='center', weight='bold',
                bbox=dict(facecolor=bg_color, edgecolor=accent_color, boxstyle='round,pad=1', alpha=0.8)
            )
            self.ax_bar.set_title("Protección Activa", color=text_color, fontsize=12, pad=15, weight='bold')

            # 3. Line Chart
            self.ax_line.clear()
            self.ax_line.set_facecolor(bg_color)
            x_data = list(range(len(self.history_pps)))
            self.ax_line.plot(x_data, list(self.history_pps), color=accent_color, linewidth=2.5, marker='o', markersize=4, label="Paquetes / Seg")
            self.ax_line.fill_between(x_data, list(self.history_pps), color=accent_color, alpha=0.15)
            self.ax_line.set_title("Carga de Red en Tiempo Real (Últimos 60s)", color=text_color, fontsize=11, pad=15, weight='bold')
            self.ax_line.tick_params(axis='both', colors=text_color, labelsize=9)
            for spine in self.ax_line.spines.values():
                spine.set_edgecolor(grid_color)
            self.ax_line.grid(True, linestyle='--', alpha=0.4, color=grid_color)
            self.ax_line.set_xlim(0, max(1, len(x_data) - 1))
            self.ax_line.set_ylim(bottom=0)

            self.fig_stats.tight_layout(pad=4.0)
            self.canvas_stats.draw_idle()

        except Exception as e:
            logging.error(f"Error actualizando gráficos avanzados: {e}")
        finally:
            self.graph_update_pending = False

    def _apply_table_proportions(self):
        if not hasattr(self, "table"):
            return

        total = max(200, self.table.viewport().width())
        ratios = [0.08, 0.12, 0.16, 0.16, 0.08, 0.10, 0.08, 0.22]
        mins   = [60,   80,   120,  120,  60,   80,   60,  200]

        self.table.setUpdatesEnabled(False)
        try:
            for i, r in enumerate(ratios):
                w = max(mins[i], int(total * r))
                if abs(self.table.columnWidth(i) - w) > 2:
                    self.table.setColumnWidth(i, w)
        finally:
            self.table.setUpdatesEnabled(True)

    def resizeEvent(self, event):
        if hasattr(self, "_resize_timer"):
            self._resize_timer.start(60)
        super().resizeEvent(event)

    def exportar_csv(self):
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
                self.mostrar_mensaje("Exportación", f"CSV guardado: {ruta}", "success")
            except Exception as e:
                logging.error(f"Error exportando CSV: {e}")

    def generar_evidencia(self):
        try:
            carpeta = os.path.join(BASE_DIR, 'evidencia')
            if not os.path.exists(carpeta):
                os.makedirs(carpeta)

            timestamp  = datetime.now().strftime('%Y%m%d_%H%M%S')
            ruta_pie   = os.path.join(carpeta, f"grafico_pie_{timestamp}.png")
            self.canvas_stats.figure.savefig(ruta_pie, dpi=100, bbox_inches='tight')
            self.mostrar_mensaje("Evidencia", f"Evidencia generada en {carpeta}", "success")
        except Exception as e:
            logging.error(f"Error generando evidencia: {e}")

    def guardar_grafico_pie_diario(self):
        try:
            carpeta = os.path.join(BASE_DIR, 'evidencia')
            if not os.path.exists(carpeta):
                os.makedirs(carpeta)
            nombre  = f"grafica_pie_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            self.canvas_stats.figure.savefig(os.path.join(carpeta, nombre), dpi=100, bbox_inches='tight')
            self.mostrar_mensaje("Backup", f"Gráfica (pie) guardada: {nombre}", "info")
        except Exception as e:
            logging.error(f"Error guardando gráfica diaria: {e}")

    def guardar_csv_diario(self):
        try:
            with data_lock:
                if not eventos_detectados:
                    return
                eventos_copia = list(eventos_detectados)

            carpeta = os.path.join(BASE_DIR, 'evidencia')
            if not os.path.exists(carpeta):
                os.makedirs(carpeta)

            nombre = f"eventos_ids_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(os.path.join(carpeta, nombre), 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Hora", "IP Origen", "IP Destino", "Puerto", "Protocolo", "Flag", "Tipo"])
                chunk_size = 1000
                for i in range(0, len(eventos_copia), chunk_size):
                    writer.writerows(eventos_copia[i:i + chunk_size])

            self.mostrar_mensaje("Backup", f"CSV guardado: {nombre}", "info")
        except Exception as e:
            logging.error(f"Error guardando CSV diario: {e}")

    def closeEvent(self, event):
        try:
            self.gestor_abuse.limpiar()

            if self.monitoreo_activo:
                self.detener_monitoreo()

            for t in [self.timer, self.graf_timer,
                      self.timer_guardar_diario, self.timer_guardar_csv_diario]:
                t.stop()

            self.data_processor.stop()

            with data_lock:
                eventos_detectados.clear()
                advertencias_cont.clear()
                trafico_buffer.clear()

        except Exception as e:
            logging.error(f"Error en closeEvent: {e}")
        finally:
            super().closeEvent(event)

    def _es_ip_externa(self, ip):
        ip_limpia = str(ip).strip()
        if not ip_limpia:
            return False

        partes = ip_limpia.split('.')
        if len(partes) != 4:
            return False

        try:
            octeto1 = int(partes[0])
            octeto2 = int(partes[1])

            if octeto1 == 10: return False
            if octeto1 == 172 and 16 <= octeto2 <= 31: return False
            if octeto1 == 192 and octeto2 == 168: return False
            if octeto1 == 127 or octeto1 == 0 or octeto1 >= 224: return False
            return True
        except:
            return False

    def verificar_ips_abuse(self):
        ips_encontradas = set()

        try:
            texto_adv = self.advertencias.toPlainText()
            if texto_adv:
                patron_ip = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
                for ip in re.findall(patron_ip, texto_adv):
                    if self._es_ip_externa(ip):
                        ips_encontradas.add(ip)
        except Exception as e:
            logging.error(f"Error extrayendo IPs del warnbox: {e}")

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

        if not ips_encontradas and self.ips_a_verificar_cola:
            ips_encontradas = set(self.ips_a_verificar_cola)

        if not ips_encontradas:
            self.mostrar_mensaje("Verificación", "No se encontraron IPs externas para verificar", "warning")
            self.ips_a_verificar_cola.clear()
            return

        ips_lista = list(ips_encontradas)
        self.mostrar_mensaje("AbuseIPDB", f"Verificando {len(ips_lista)} IPs en AbuseIPDB...", "info")

        self.gestor_abuse.verificar_ips(
            ips_lista,
            callback_resultado=self.mostrar_resultado_abuse,
            callback_error=self.mostrar_error_abuse
        )

    def mostrar_resultado_abuse(self, resultado):
        ip      = resultado['ip']
        score   = resultado['abuse_score']
        riesgo  = resultado['riesgo']
        reports = resultado['total_reports']
        pais    = resultado['pais']

        linea = f"\n🔍 AbuseIPDB | {ip} | Score: {score}% | {riesgo} | Reports: {reports} | {pais}"
        texto_actual = self.advertencias.toPlainText()
        self.advertencias.setPlainText(linea + "\n" + texto_actual)

        if "CRÍTICO" in riesgo:
            self.mostrar_mensaje("Alerta de Riesgo", f"IP CRÍTICA DETECTADA: {ip}", "error")

    def mostrar_error_abuse(self, error_msg):
        logging.error(f"Error AbuseIPDB: {error_msg}")
        linea = f"\n[X] AbuseIPDB Error: {error_msg}"
        self.advertencias.setPlainText(linea + "\n" + self.advertencias.toPlainText())

def configurar_logging():
    logging.basicConfig(
        level=logging.ERROR,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(BASE_DIR, 'ids_interface.log')),
            logging.StreamHandler()
        ]
    )

def limpiar_memoria_periodica():
    global eventos_detectados, advertencias_cont
    with data_lock:
        if len(eventos_detectados) > MAX_EVENTOS_MEMORIA:
            eventos_list = list(eventos_detectados)
            eventos_detectados.clear()
            eventos_detectados.extend(eventos_list[-MAX_EVENTOS_MEMORIA//2:])

        if len(advertencias_cont) > 1000:
            items_sorted = sorted(advertencias_cont.items(), key=lambda x: x[1], reverse=True)
            advertencias_cont.clear()
            advertencias_cont.update(dict(items_sorted[:500]))

if __name__ == "__main__":
    configurar_logging()
    
    # Habilitar soporte para pantallas de alta resolución (High DPI)
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
        
    # En PyQt5, es recomendable ajustar la política de escala a veces
    # os.environ["QT_ENABLE_HIGHDPI_SCALING"] = "1"
    # os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    
    app = QApplication(sys.argv)
    app.setAttribute(Qt.AA_DontCreateNativeWidgetSiblings, True)
    app.setAttribute(Qt.AA_DontShowIconsInMenus, True)
    
    setTheme(Theme.DARK)

    cleanup_timer = QTimer()
    cleanup_timer.timeout.connect(limpiar_memoria_periodica)
    cleanup_timer.start(60000)

    try:
        ventana = IDSInterface()
        ventana.show()
        print("IDS Interface Fluent Optimizada iniciada")
        print(f"Límites: Tabla={MAX_EVENTOS_TABLA} | Memoria={MAX_EVENTOS_MEMORIA} | Tráfico={MAX_TRAFICO_LINEAS}")
        sys.exit(app.exec_())
    except Exception as e:
        logging.error(f"Error en la ejecución principal: {e}")
