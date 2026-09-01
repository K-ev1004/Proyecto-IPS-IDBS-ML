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
from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal, QSettings, QObject
from PyQt5.QtGui import QFont, QColor, QBrush

# qfluentwidgets para diseño moderno
from qfluentwidgets import (
    FluentWindow, NavigationItemPosition, InfoBar, InfoBarPosition,
    PrimaryPushButton, TransparentPushButton, TableWidget,
    ComboBox, LineEdit, SpinBox, DoubleSpinBox, CheckBox, PlainTextEdit, TextEdit,
    SubtitleLabel, BodyLabel, TitleLabel, Theme, setTheme, FluentIcon as FIF,
    SimpleCardWidget
)

# Matplotlib
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from matplotlib import style
from matplotlib import cm
from matplotlib import colors as mcolors

# Módulo interno

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    import ids
    import mikrotik_api
except Exception as _e:
    ids = None
    mikrotik_api = None
    logging.error("No se pudo importar 'ids' o 'mikrotik_api'. Detalle: %s", _e)

try:
    from geolocalizacion import obtener_ubicacion_ip, generar_mapa_pixmap, clasificar_ip_unipaz
except Exception as _e:
    obtener_ubicacion_ip = None
    generar_mapa_pixmap = None
    clasificar_ip_unipaz = None
    logging.error("No se pudo importar 'geolocalizacion'. Detalle: %s", _e)

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

class GeoWorker(QObject):
    finished = pyqtSignal(dict)

    def __init__(self, ip_src, color_sev):
        super().__init__()
        self.ip_src = ip_src
        self.color_sev = color_sev

    def run(self):
        resultado = {}
        try:
            if obtener_ubicacion_ip:
                resultado["ubicacion"] = obtener_ubicacion_ip(self.ip_src)
        except Exception:
            resultado["ubicacion"] = None
        try:
            if generar_mapa_pixmap and resultado.get("ubicacion"):
                ub = resultado["ubicacion"]
                lat = ub.get("lat", 0.0)
                lon = ub.get("lon", 0.0)
                hostname = ub.get("hostname", "")
                es_privada = ub.get("status") == "private"
                geo_pais = ub.get("country", "")
                geo_ciudad = ub.get("city", "")
                resultado["pixmap"] = generar_mapa_pixmap(
                    lat, lon, self.ip_src, geo_ciudad, geo_pais,
                    self.color_sev, hostname, es_privada)
        except Exception:
            resultado["pixmap"] = None
        self.finished.emit(resultado)

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
                ids.BASE_THRESHOLD_SYN_FLOOD = int(self.settings.value("thresh_syn", ids.BASE_THRESHOLD_SYN_FLOOD))
                ids.BASE_THRESHOLD_DDOS = int(self.settings.value("thresh_ddos", ids.BASE_THRESHOLD_DDOS))
                ids.BASE_THRESHOLD_UDP_FLOOD = int(self.settings.value("thresh_udp", ids.BASE_THRESHOLD_UDP_FLOOD))
                ids.BASE_PORT_SCAN_THRESHOLD = int(self.settings.value("thresh_scan", ids.BASE_PORT_SCAN_THRESHOLD))
                # Umbrales del motor ML (unificados y SQLiGuard)
                if hasattr(ids, 'UMBRAL_ML'):
                    ids.UMBRAL_ML = float(self.settings.value("umbral_ml", ids.UMBRAL_ML))
                if hasattr(ids, 'UMBRAL_SQLI_GUARD'):
                    ids.UMBRAL_SQLI_GUARD = float(self.settings.value("umbral_sqli", ids.UMBRAL_SQLI_GUARD))
            except Exception as e:
                logging.error(f"Error cargando preferencias: {e}")

    def _update_threshold(self, key, attr, value):
        if ids:
            setattr(ids, attr, value)
        self.settings.setValue(key, value)

    def _update_umbral_ml(self, value):
        # Umbral de confianza unificado (logueo Y bloqueo) del motor ML
        if ids:
            try:
                ids.UMBRAL_ML = float(value)
            except Exception as e:
                logging.error(f"Error actualizando UMBRAL_ML: {e}")
        self.settings.setValue("umbral_ml", float(value))

    def _update_umbral_sqli(self, value):
        # Umbral de confirmación de SQLiGuard (detector binario de 2a etapa)
        if ids:
            try:
                ids.UMBRAL_SQLI_GUARD = float(value)
            except Exception as e:
                logging.error(f"Error actualizando UMBRAL_SQLI_GUARD: {e}")
        self.settings.setValue("umbral_sqli", float(value))

    def abrir_carpeta_logs(self):
        """Abre el explorador en la carpeta donde log_exporter escribe los .log"""
        try:
            from log_exporter import obtener_carpeta_logs
            carpeta = obtener_carpeta_logs()
        except Exception:
            carpeta = os.path.join(BASE_DIR, 'logs_ciberseguridad')
        if not os.path.isdir(carpeta):
            try:
                os.makedirs(carpeta, exist_ok=True)
            except Exception:
                carpeta = BASE_DIR
        try:
            if sys.platform.startswith('win'):
                os.startfile(carpeta)  # type: ignore
            else:
                import subprocess
                subprocess.Popen(['xdg-open', carpeta])
        except Exception as e:
            logging.error(f"No se pudo abrir carpeta de logs {carpeta}: {e}")
            self.mostrar_mensaje("Carpeta de Logs", carpeta, "info")

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
        self.ips_a_verificar_cola = set()

    def aplicar_estilos_badges(self):
        bg = "#272727" if self.modo_oscuro else "#ffffff"
        border = "#3e3e42" if self.modo_oscuro else "#e1dfdd"

        def b_style(color):
            return f"padding: 12px 20px; border-radius: 8px; font-weight: 600; font-size: 15px; background-color: {bg}; color: {color}; border: 1px solid {border}; border-left: 5px solid {color};"

        def simple_style():
            text_color = "#ffffff" if self.modo_oscuro else "#000000"
            bg_color = "#30373b" if self.modo_oscuro else "#f3f3f3"
            border_color = "#3e3e42" if self.modo_oscuro else "#e1dfdd"
            return f"padding: 8px 16px; border-radius: 6px; font-weight: 500; font-size: 15px; background-color: {bg_color}; color: {text_color}; border: 1px solid {border_color};"

        c_blue = "#4daafc" if self.modo_oscuro else "#0078d4"
        c_green = "#6ccb5f" if self.modo_oscuro else "#107c10"
        c_red = "#ff99a4" if self.modo_oscuro else "#d13438"
        c_orange = "#ffb38f" if self.modo_oscuro else "#d83b01"
        c_purple = "#b4a0ff" if self.modo_oscuro else "#5c2d91"

        if hasattr(self, 'iface_badge'):
            self.iface_badge.setStyleSheet(simple_style())
            self.lbl_pps.setStyleSheet(simple_style())
            self.lbl_alerts_min.setStyleSheet(simple_style())
            self.lbl_uptime.setStyleSheet(simple_style())
            self.lbl_stats.setStyleSheet(simple_style())

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
        self.lbl_pps = BodyLabel("Paquetes por segundo: 0")
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

        self.detalle_text = TextEdit()
        self.detalle_text.setReadOnly(True)
        self.detalle_text.setHtml("<p style='font-size:13px; color:#888;'>Seleccione una alerta en la tabla para inspeccionar los metadatos y recomendaciones.</p>")
        right_layout.addWidget(SubtitleLabel("Inspección Forense del Evento"))
        right_layout.addWidget(self.detalle_text)

        self.mapa_label = BodyLabel("")
        self.mapa_label.setAlignment(Qt.AlignCenter)
        self.mapa_label.setMinimumHeight(200)
        self.mapa_label.setMaximumHeight(260)
        right_layout.addWidget(self.mapa_label)

        self._geo_thread = None
        self._geo_worker = None

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
        btn_block_manual.clicked.connect(self._bloquear_desde_input)
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
        self.historial_aulas = deque(maxlen=60)
        self.historial_biblio = deque(maxlen=60)
        self.historial_externos = deque(maxlen=60)

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

        subtitle = BodyLabel("Distribución del Tráfico Analizado y Tendencias Históricas")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)

        # -- KPIs --
        kpi_layout = QHBoxLayout()
        kpi_layout.setSpacing(15)
        
        self.kpi_riesgo = TitleLabel("0.0%")
        self.kpi_eventos = TitleLabel("0")
        self.kpi_ips = TitleLabel("0")
        self.kpi_bloqueos = TitleLabel("0")
        
        for title, value_lbl in [("Riesgo Global (CatBoost)", self.kpi_riesgo), 
                                 ("Eventos Detectados", self.kpi_eventos),
                                 ("IPs Atacantes", self.kpi_ips), 
                                 ("Bloqueos Activos", self.kpi_bloqueos)]:
            card = SimpleCardWidget()
            cl = QVBoxLayout(card)
            cl.setAlignment(Qt.AlignCenter)
            t = SubtitleLabel(title)
            t.setAlignment(Qt.AlignCenter)
            value_lbl.setAlignment(Qt.AlignCenter)
            value_lbl.setStyleSheet("color: #0078d4; font-weight: bold;")
            cl.addWidget(t)
            cl.addWidget(value_lbl)
            kpi_layout.addWidget(card)
            
        layout.addLayout(kpi_layout)

        # -- Middle Panel: Pie & Top IPs --
        mid_layout = QHBoxLayout()
        mid_layout.setSpacing(15)
        
        pie_card = SimpleCardWidget()
        pie_layout = QVBoxLayout(pie_card)
        self.canvas_pie = FigureCanvas(Figure(figsize=(5, 4)))
        self.canvas_pie.setStyleSheet("background-color: transparent;")
        self.fig_pie = self.canvas_pie.figure
        self.fig_pie.patch.set_alpha(0.0)
        self.ax_pie = self.fig_pie.add_subplot(111)
        pie_layout.addWidget(self.canvas_pie)
        mid_layout.addWidget(pie_card)
        
        explicacion_tooltip = (
            "<b>Glosario de Amenazas (Machine Learning):</b><br><br>"
            "<b>• Tráfico Normal (0):</b> Conexiones regulares sin intención maliciosa.<br>"
            "<b>• Escaneo de Puertos (1):</b> Intentos de descubrir puertos abiertos y vulnerabilidades.<br>"
            "<b>• Fuerza Bruta (2):</b> Intentos repetitivos para adivinar contraseñas (ej. SSH/FTP).<br>"
            "<b>• DoS / Inundación (3):</b> Ataques de Denegación de Servicio para saturar el servidor.<br>"
            "<b>• DDoS (4):</b> Denegación de Servicio Distribuida utilizando múltiples IPs.<br>"
            "<b>• Anomalía Tipo 9:</b> Comportamiento de red inusual que no encaja en patrones conocidos."
        )
        self.canvas_pie.setToolTip(explicacion_tooltip)
        self.canvas_pie.setToolTipDuration(10000)

        top_ips_card = SimpleCardWidget()
        top_ips_layout = QVBoxLayout(top_ips_card)
        lbl_top = SubtitleLabel("Top 5 IPs Atacantes")
        lbl_top.setAlignment(Qt.AlignCenter)
        top_ips_layout.addWidget(lbl_top)
        
        self.table_top_ips = TableWidget()
        self.table_top_ips.setColumnCount(2)
        self.table_top_ips.setHorizontalHeaderLabels(["IP Origen", "Nº de Alertas"])
        self.table_top_ips.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_top_ips.verticalHeader().hide()
        self.table_top_ips.setEditTriggers(TableWidget.NoEditTriggers)
        self.table_top_ips.setShowGrid(False)
        self.table_top_ips.setBorderRadius(4)
        top_ips_layout.addWidget(self.table_top_ips)
        mid_layout.addWidget(top_ips_card)
        
        layout.addLayout(mid_layout)

        # -- Bottom Panel: Line --
        line_card = SimpleCardWidget()
        line_layout = QVBoxLayout(line_card)
        self.canvas_line = FigureCanvas(Figure(figsize=(10, 3)))
        self.canvas_line.setStyleSheet("background-color: transparent;")
        self.fig_line = self.canvas_line.figure
        self.fig_line.patch.set_alpha(0.0)
        self.ax_line = self.fig_line.add_subplot(111)
        line_layout.addWidget(self.canvas_line)
        layout.addWidget(line_card)



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
        syn_card = SimpleCardWidget()
        syn_layout = QVBoxLayout(syn_card)
        syn_layout.addWidget(BodyLabel("SYN Flood (pkts/0.5s):"))
        self.spin_syn = SpinBox()
        self.spin_syn.setRange(10, 5000)
        self.spin_syn.setValue(ids.BASE_THRESHOLD_SYN_FLOOD)
        self.spin_syn.valueChanged.connect(lambda v: self._update_threshold('thresh_syn', 'BASE_THRESHOLD_SYN_FLOOD', v))
        syn_layout.addWidget(self.spin_syn)
        box_syn.addWidget(syn_card)
        umbrales_layout.addLayout(box_syn)

        # DDoS
        box_ddos = QVBoxLayout()
        ddos_card = SimpleCardWidget()
        ddos_layout = QVBoxLayout(ddos_card)
        ddos_layout.addWidget(BodyLabel("DDoS (pkts/1s):"))
        self.spin_ddos = SpinBox()
        self.spin_ddos.setRange(100, 10000)
        self.spin_ddos.setValue(ids.BASE_THRESHOLD_DDOS)
        self.spin_ddos.valueChanged.connect(lambda v: self._update_threshold('thresh_ddos', 'BASE_THRESHOLD_DDOS', v))
        ddos_layout.addWidget(self.spin_ddos)
        box_ddos.addWidget(ddos_card)
        umbrales_layout.addLayout(box_ddos)

        # UDP Flood
        box_udp = QVBoxLayout()
        udp_card = SimpleCardWidget()
        udp_layout = QVBoxLayout(udp_card)
        udp_layout.addWidget(BodyLabel("UDP Flood (pkts/1s):"))
        self.spin_udp = SpinBox()
        self.spin_udp.setRange(100, 10000)
        self.spin_udp.setValue(ids.BASE_THRESHOLD_UDP_FLOOD)
        self.spin_udp.valueChanged.connect(lambda v: self._update_threshold('thresh_udp', 'BASE_THRESHOLD_UDP_FLOOD', v))
        udp_layout.addWidget(self.spin_udp)
        box_udp.addWidget(udp_card)
        umbrales_layout.addLayout(box_udp)

        # Port Scan
        box_scan = QVBoxLayout()
        scan_card = SimpleCardWidget()
        scan_layout = QVBoxLayout(scan_card)
        scan_layout.addWidget(BodyLabel("Escaneo (puertos/IP):"))
        self.spin_scan = SpinBox()
        self.spin_scan.setRange(5, 500)
        self.spin_scan.setValue(ids.BASE_PORT_SCAN_THRESHOLD)
        self.spin_scan.valueChanged.connect(lambda v: self._update_threshold('thresh_scan', 'BASE_PORT_SCAN_THRESHOLD', v))
        scan_layout.addWidget(self.spin_scan)
        box_scan.addWidget(scan_card)
        umbrales_layout.addLayout(box_scan)

        layout.addLayout(umbrales_layout)
        # --- FIN SECCIÓN UMBRALES ---

        # --- SECCIÓN UMBRALES DEL MOTOR ML (CONFIANZA) ---
        layout.addWidget(SubtitleLabel("Umbrales del Motor ML (Confianza)"))
        info_ml = BodyLabel(
            "El motor ML unifica logueo y bloqueo con un umbral de confianza. "
            "SQLiGuard (2ª etapa) confirma Inyección SQL a partir de su propio umbral.\n"
            "• UMBRAL ML: confianza mínima para registrar Y bloquear (def. 0.85).\n"
            "• UMBRAL SQLiGuard: probabilidad mínima para confirmar SQLi (def. 0.30).\n"
            "  Menor umbral SQLiGuard = más sensibilidad (más recall, igual precisión ~99.8%)."
        )
        info_ml.setWordWrap(True)
        info_ml.setStyleSheet("color: #888888; font-size: 13px; font-style: italic;")
        layout.addWidget(info_ml)

        umbrales_ml_layout = QHBoxLayout()
        umbrales_ml_layout.setSpacing(15)

        # UMBRAL ML (unificado)
        box_ml = QVBoxLayout()
        ml_card = SimpleCardWidget()
        ml_layout = QVBoxLayout(ml_card)
        ml_layout.addWidget(BodyLabel("Confianza ML (registrar y bloquear):"))
        self.spin_umbral_ml = DoubleSpinBox()
        self.spin_umbral_ml.setRange(0.50, 0.99)
        self.spin_umbral_ml.setSingleStep(0.01)
        self.spin_umbral_ml.setValue(float(getattr(ids, 'UMBRAL_ML', 0.85)))
        self.spin_umbral_ml.valueChanged.connect(self._update_umbral_ml)
        ml_layout.addWidget(self.spin_umbral_ml)
        box_ml.addWidget(ml_card)
        umbrales_ml_layout.addLayout(box_ml)

        # UMBRAL SQLiGuard (2ª etapa)
        box_sqli = QVBoxLayout()
        sqli_card = SimpleCardWidget()
        sqli_layout = QVBoxLayout(sqli_card)
        sqli_layout.addWidget(BodyLabel("SQLiGuard (confirmar SQLi):"))
        self.spin_umbral_sqli = DoubleSpinBox()
        self.spin_umbral_sqli.setRange(0.05, 0.99)
        self.spin_umbral_sqli.setSingleStep(0.05)
        self.spin_umbral_sqli.setValue(float(getattr(ids, 'UMBRAL_SQLI_GUARD', 0.30)))
        self.spin_umbral_sqli.valueChanged.connect(self._update_umbral_sqli)
        sqli_layout.addWidget(self.spin_umbral_sqli)
        box_sqli.addWidget(sqli_card)
        umbrales_ml_layout.addLayout(box_sqli)

        layout.addLayout(umbrales_ml_layout)
        layout.addStretch()
        # --- FIN SECCIÓN UMBRALES ML ---

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
        
        self.boton_tema = TransparentPushButton("Alternar Apariencia (Dark/Light)")
        self.boton_tema.clicked.connect(self.cambiar_tema)

        self.boton_logs = TransparentPushButton("Abrir Carpeta de Logs")
        self.boton_logs.clicked.connect(self.abrir_carpeta_logs)

        for b in [self.boton_iniciar, self.boton_detener, self.boton_limpiar,
                  self.boton_exportar, self.boton_evidencia,
                  self.boton_tema, self.boton_logs]:
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

        self.timer_log_semanal = QTimer()
        self.timer_log_semanal.timeout.connect(self.exportar_logs_semanales)
        # 7 días en milisegundos
        self.timer_log_semanal.start(7 * 24 * 60 * 60 * 1000)

    def setup_signals(self):
        self.table.setMouseTracking(False)
        if ids and hasattr(ids, 'comunicador'):
            try:
                ids.comunicador.nuevo_evento.connect(self.agregar_evento_)
                ids.comunicador.nuevo_trafico.connect(self.agregar_trafico_)
                ids.comunicador.nuevo_bloqueo.connect(self.actualizar_tabla_bloqueos_signal)
                ids.comunicador.actualizacion_dashboard.connect(self.actualizar_dashboard_en_vivo)
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
        """Desbloquea la IP seleccionada en la tabla via MikroTik."""
        items = self.table_bloqueos.selectedItems()
        if not items:
            self.mostrar_mensaje("Info", "Seleccione una fila para desbloquear.", "info")
            return

        row = items[0].row()
        ip_item = self.table_bloqueos.item(row, 1)
        if not ip_item:
            return
        ip = ip_item.text()

        self.mostrar_mensaje("Desbloqueo IPS", f"Intentando desbloquear {ip} en MikroTik...", "info")

        if mikrotik_api and mikrotik_api.desbloquear_ip_mikrotik(ip):
            # Actualizar UI
            estado_item = self.table_bloqueos.item(row, 5)
            tiempo_item = self.table_bloqueos.item(row, 6)
            if estado_item:
                estado_item.setText("Desbloqueado")
                estado_item.setForeground(QBrush(QColor("#0a84ff")))
            if tiempo_item:
                tiempo_item.setText("—")
            for entry in self._bloqueos_data:
                if entry.get('row') == row:
                    entry['estado'] = 'Desbloqueado'
            self._actualizar_resumen_bloqueos()
            self.mostrar_mensaje("Desbloqueo IPS", f"IP Desbloqueada: {ip}", "success")
        else:
            self.mostrar_mensaje("Error", f"No se pudo desbloquear la IP {ip}.", "error")

    def _bloquear_desde_input(self):
        """Toma la IP y minutos de los campos en la UI y ejecuta el bloqueo."""
        ip = self.input_manual_ip.text().strip()
        minutos = self.spin_manual_time.value()

        if not ip or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            self.mostrar_mensaje("Error", "Ingrese una dirección IPv4 válida.", "warning")
            return

        self.bloquear_ip_manual(ip, minutos)
        self.input_manual_ip.clear()

    def bloquear_ip_manual(self, ip, minutos=30):
        if mikrotik_api and mikrotik_api.bloquear_ip_mikrotik(ip, duracion_horas=round(minutos/60, 2)):
            self.mostrar_mensaje("IPS Activo", f"Regla de MikroTik añadida para bloquear {ip} por {minutos} min", "success")
            self.actualizar_tabla_bloqueos_signal([ip, "Bloqueo manual", minutos, "Prevención Manual", "ALTA"])
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
            self.lbl_pps.setText(f"Paquetes por segundo: {pps}")
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
                self.detalle_text.setHtml("<p style='font-size:13px; color:#888;'>Seleccione una alerta en la tabla para inspeccionar los metadatos y recomendaciones.</p>")
                self.mapa_label.clear()
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

            vlan_id = ""
            ttl = ""
            packet_size = ""
            try:
                with data_lock:
                    ev_list = list(eventos_detectados)
                    if row < len(ev_list):
                        ev = ev_list[row]
                        if len(ev) >= 10:
                            vlan_id = ev[7]
                            ttl = ev[8]
                            packet_size = ev[9]
            except Exception:
                pass

            evidencia = [f"<li>Protocolo/Flag: <b>{proto} / {flag}</b></li>"]
            if "syn flood"   in tipo.lower(): evidencia.append("<li>Indicador: volumen alto de SYN en ventana corta</li>")
            if "ddos"        in tipo.lower(): evidencia.append("<li>Indicador: volumen alto hacia destino (posible DDoS)</li>")
            if "escaneo"     in tipo.lower(): evidencia.append("<li>Indicador: multiples puertos probados desde una misma IP</li>")
            if "sql"         in tipo.lower(): evidencia.append("<li>Indicador: patron de payload compatible con SQLi</li>")

            color_sev = self._compute_severity(tipo)[1]
            txt_color = "#e1dfdd" if self.modo_oscuro else "#333333"

            departamento = ""
            if clasificar_ip_unipaz:
                try:
                    info_dep = clasificar_ip_unipaz(ip_src)
                    if isinstance(info_dep, dict):
                        departamento = info_dep.get("departamento", "")
                    else:
                        departamento = str(info_dep) if info_dep else ""
                except Exception:
                    departamento = ""

            ttl_str = ""
            if ttl and ttl != "":
                try:
                    ttl_int = int(ttl)
                    ttl_str = f"{ttl} ({_estimar_os(ttl_int)})"
                except Exception:
                    ttl_str = str(ttl)

            vlan_str = ""
            if vlan_id and vlan_id != "" and vlan_id != 0:
                try:
                    vlan_str = _traducir_vlan(int(vlan_id))
                except Exception:
                    vlan_str = str(vlan_id)

            device_info_html = ""
            if departamento:
                device_info_html = f"""
                <h4 style="color: #ffb400; margin-bottom: 5px;">Dispositivo UNIPAZ</h4>
                <table style="width: 100%; margin-bottom: 10px;">
                    <tr><td style="padding: 2px 0;"><b>Departamento:</b> {departamento}</td><td style="padding: 2px 0;"><b>IP:</b> {ip_src}</td></tr>
                </table>
                """

            packet_info_html = ""
            packet_rows = []
            if vlan_str:
                packet_rows.append(f"<tr><td style='padding: 2px 0;'><b>VLAN:</b> {vlan_str}</td></tr>")
            if ttl_str:
                packet_rows.append(f"<tr><td style='padding: 2px 0;'><b>TTL:</b> {ttl_str}</td></tr>")
            if packet_size and packet_size != "":
                packet_rows.append(f"<tr><td style='padding: 2px 0;'><b>Tamanio Paquete:</b> {packet_size} bytes</td></tr>")
            if packet_rows:
                packet_info_html = f"""
                <h4 style="color: #4daafc; margin-bottom: 5px;">Detalles Paquete</h4>
                <table style="width: 100%; margin-bottom: 10px;">
                    {"".join(packet_rows)}
                </table>
                """

            geo_placeholder = '<h4 style="color: #888; margin-bottom: 5px;">Ubicacion del Atacante</h4><p style="color:#888;">Cargando...</p>'

            html_txt = f"""
            <div style="font-family: 'Segoe UI', sans-serif; font-size: 13px; color: {txt_color};">
                <h3 style="color: {color_sev}; margin-top: 0; margin-bottom: 10px;">Analisis Forense: {tipo}</h3>
                <p style="margin-top: 0;"><b>Severidad:</b> <span style="color:{color_sev}; font-weight:bold;">{sev}</span> &nbsp;&nbsp;|&nbsp;&nbsp; <b>Hora:</b> {hora}</p>
                <table style="width: 100%; margin-bottom: 15px;">
                    <tr><td style="padding: 3px 0;"><b>IP Origen:</b> {ip_src}</td><td style="padding: 3px 0;"><b>IP Destino:</b> {ip_dst}</td></tr>
                    <tr><td style="padding: 3px 0;"><b>Puerto:</b> {puerto}</td><td style="padding: 3px 0;"><b>Protocolo:</b> {proto}</td></tr>
                </table>
                {geo_placeholder}
                {device_info_html}
                {packet_info_html}
                <h4 style="color: #4daafc; margin-bottom: 5px;">Evidencia Detectada</h4>
                <ul style="margin-top: 0; margin-bottom: 15px; padding-left: 20px;">
                    {"".join(evidencia)}
                </ul>
                <h4 style="color: #6ccb5f; margin-bottom: 5px;">Acciones Sugeridas</h4>
                <ul style="margin-top: 0; padding-left: 20px;">
                    <li>Llamar al profesor Jhoni si la alarma persiste.</li>
                    <li>Revisar logs del servicio en el puerto destino.</li>
                    <li>Bloquear/limitar trafico desde la interfaz de IPS si es recurrente.</li>
                </ul>
            </div>
            """
            self.detalle_text.setHtml(html_txt)

            if self._geo_thread and self._geo_thread.isRunning():
                self._geo_thread.quit()
                self._geo_thread.wait(200)

            self._geo_thread = QThread()
            self._geo_worker = GeoWorker(ip_src, color_sev)
            self._geo_worker.moveToThread(self._geo_thread)
            self._geo_worker.finished.connect(
                lambda resultado: self._on_geo_finished(
                    resultado, ip_src, html_txt, txt_color))
            self._geo_thread.started.connect(self._geo_worker.run)
            self._geo_thread.start()

        except Exception as e:
            logging.error(f"Error actualizando detalle: {e}")

    def _on_geo_finished(self, resultado, ip_src, html_base, txt_color):
        try:
            ubicacion = resultado.get("ubicacion")
            pixmap = resultado.get("pixmap")

            if pixmap:
                scaled = pixmap.scaled(480, 220, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.mapa_label.setPixmap(scaled)

            if not ubicacion:
                return

            hostname = ubicacion.get("hostname", "Dispositivo Desconocido")
            subred = ubicacion.get("subred", "Desconocida")
            es_privada = ubicacion.get("status") == "private"
            geo_pais = ubicacion.get("country", "Desconocido")
            geo_ciudad = ubicacion.get("city", "Desconocido")
            geo_region = ubicacion.get("regionName", "Desconocido")
            geo_isp = ubicacion.get("isp", "Desconocido")
            geo_org = ubicacion.get("org", "Desconocido")
            geo_as = ubicacion.get("as", "Desconocido")
            geo_lat = ubicacion.get("lat", 0.0)
            geo_lon = ubicacion.get("lon", 0.0)

            if es_privada:
                tipo_red = "Red Local (IP Privada)"
                geo_html = f"""
                <h4 style="color: #ffb400; margin-bottom: 5px;">Dispositivo del Atacante</h4>
                <table style="width: 100%; margin-bottom: 10px;">
                    <tr><td style="padding: 2px 0;"><b>Hostname:</b> {hostname}</td><td style="padding: 2px 0;"><b>IP:</b> {ip_src}</td></tr>
                    <tr><td style="padding: 2px 0;"><b>Subred:</b> {subred}</td><td style="padding: 2px 0;"><b>Tipo:</b> {tipo_red}</td></tr>
                </table>
                <h4 style="color: #d6a4ff; margin-bottom: 5px;">Ubicacion Aproximada (Router/ISP)</h4>
                <table style="width: 100%; margin-bottom: 5px;">
                    <tr><td style="padding: 2px 0;"><b>Pais:</b> {geo_pais}</td><td style="padding: 2px 0;"><b>Ciudad:</b> {geo_ciudad}</td></tr>
                    <tr><td style="padding: 2px 0;"><b>Region:</b> {geo_region}</td><td style="padding: 2px 0;"><b>Coordenadas:</b> {geo_lat:.4f}, {geo_lon:.4f}</td></tr>
                    <tr><td style="padding: 2px 0;"><b>ISP:</b> {geo_isp}</td><td style="padding: 2px 0;"><b>Org:</b> {geo_org}</td></tr>
                    <tr><td colspan="2" style="padding: 2px 0; font-style: italic; color: #888;">Nota: Ubicacion del router, no del dispositivo</td></tr>
                </table>
                """
            else:
                geo_html = f"""
                <h4 style="color: #d6a4ff; margin-bottom: 5px;">Ubicacion del Atacante</h4>
                <table style="width: 100%; margin-bottom: 5px;">
                    <tr><td style="padding: 2px 0;"><b>Hostname:</b> {hostname}</td><td style="padding: 2px 0;"><b>IP:</b> {ip_src}</td></tr>
                    <tr><td style="padding: 2px 0;"><b>Pais:</b> {geo_pais}</td><td style="padding: 2px 0;"><b>Ciudad:</b> {geo_ciudad}</td></tr>
                    <tr><td style="padding: 2px 0;"><b>Region:</b> {geo_region}</td><td style="padding: 2px 0;"><b>Coordenadas:</b> {geo_lat:.4f}, {geo_lon:.4f}</td></tr>
                    <tr><td style="padding: 2px 0;"><b>ISP:</b> {geo_isp}</td><td style="padding: 2px 0;"><b>Org:</b> {geo_org}</td></tr>
                    <tr><td colspan="2" style="padding: 2px 0;"><b>ASN:</b> {geo_as}</td></tr>
                </table>
                """

            html_actualizado = html_base.replace(
                '<h4 style="color: #888; margin-bottom: 5px;">Ubicacion del Atacante</h4><p style="color:#888;">Cargando...</p>',
                geo_html)
            self.detalle_text.setHtml(html_actualizado)

        except Exception as e:
            logging.error(f"Error en callback geo: {e}")

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
                            hora, ip_src, ip_dst, puerto, protocolo, flag, tipo, vlan_id, ttl, packet_size = ev
                        except Exception:
                            lst = list(ev) + [""] * 10
                            hora, ip_src, ip_dst, puerto, protocolo, flag, tipo, vlan_id, ttl, packet_size = lst[:10]

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
        
        if hasattr(self, 'ax_pie'):
            self.ax_pie.clear()
            self.ax_line.clear()
            self.canvas_pie.draw()
            self.canvas_line.draw()
            
        if hasattr(self, 'table_top_ips'):
            self.table_top_ips.setRowCount(0)
            self.kpi_eventos.setText("0")
            self.kpi_ips.setText("0")
            self.kpi_bloqueos.setText("0")
        
        self.mostrar_mensaje("Limpieza", "Interfaz y registros en memoria limpiados", "info")

    def actualizar_dashboard_en_vivo(self, metricas):
        try:
            if hasattr(self, 'kpi_riesgo'):
                self.kpi_riesgo.setText(f"{metricas.get('riesgo_global', 0.0):.1f}%")
            if hasattr(self, 'historial_aulas'):
                self.historial_aulas.append(metricas.get('aulas_pkts', 0))
                self.historial_biblio.append(metricas.get('biblioteca_pkts', 0))
                self.historial_externos.append(metricas.get('externos_pkts', 0))
        except Exception as e:
            logging.error(f"Error en actualizar_dashboard_en_vivo: {e}")

    def actualizar_grafico_auto(self):
        if self.graph_update_pending:
            return

        self.graph_update_pending = True
        try:
            with data_lock:
                eventos_muestra = list(eventos_detectados)[-500:] if eventos_detectados else []
                top_ips = sorted(advertencias_cont.items(), key=lambda x: x[1], reverse=True)[:5]
            
            text_color = "#ffffff" if self.modo_oscuro else "#201f1e"
            grid_color = "#3e3e42" if self.modo_oscuro else "#e1dfdd"
            accent_color = "#4daafc" if self.modo_oscuro else "#0078d4"

            # 1. Update KPIs
            self.kpi_eventos.setText(str(len(eventos_detectados)))
            self.kpi_ips.setText(str(len(advertencias_cont)))
            activos = sum(1 for b in self._bloqueos_data if b['estado'] == 'Activo') if hasattr(self, '_bloqueos_data') else 0
            self.kpi_bloqueos.setText(str(activos))

            # 2. Pie Chart
            self.fig_pie.patch.set_facecolor('none')
            self.ax_pie.clear()
            self.ax_pie.set_facecolor('none')
            if eventos_muestra:
                import re
                # Limpiar la etiqueta removiendo el texto "(ML: XX.X%)" para poder agrupar correctamente
                tipos_limpios = [re.sub(r'\s*\(ML:\s*[\d\.]+%?\)', '', str(e[6])).strip() for e in eventos_muestra]
                
                # Mapeo de clases del modelo v5 a nombres descriptivos (si llegara
                # el código numérico o la etiqueta cruda del multiclase v5).
                diccionario_ataques = {
                    "0": "Tráfico Normal",
                    "Normal": "Tráfico Normal",
                    "1": "Escaneo de Puertos",
                    "Port_Scanner": "Escaneo de Puertos",
                    "2": "Exploit / Fuerza Bruta",
                    "Posible_Exploit": "Exploit / Fuerza Bruta",
                    "3": "Inundación SYN",
                    "SYN_Flood": "Inundación SYN",
                    "4": "Inundación UDP",
                    "UDP_Flood": "Inundación UDP",
                    "5": "DDoS Distribuido",
                    "DDoS_Distribuido": "DDoS Distribuido",
                    "6": "Inyección SQL",
                    "Inyeccion_SQL": "Inyección SQL",
                }
                # Coincidencia insensible a mayúsculas sobre las claves descriptivas
                def _map(t):
                    if t in diccionario_ataques:
                        return diccionario_ataques[t]
                    for k, v in diccionario_ataques.items():
                        if t and k.isalpha() and k.lower() == t.lower():
                            return v
                    return t
                tipos_finales = [_map(t) for t in tipos_limpios]
                
                cnt = Counter(tipos_finales)
                if cnt:
                    top_items = cnt.most_common(4)
                    otros_count = sum(cnt.values()) - sum(count for item, count in top_items)
                    
                    labels = [item for item, count in top_items]
                    values = [count for item, count in top_items]
                    
                    if otros_count > 0:
                        labels.append("Otros")
                        values.append(otros_count)

                    colors = colors_for_labels(labels)
                    wedges, texts, autotexts = self.ax_pie.pie(
                        values, colors=colors,
                        autopct='%1.0f%%',
                        radius=1.0,
                        textprops={'color': text_color, 'fontsize': 8, 'weight': 'bold'},
                        pctdistance=0.7
                    )
                    self.ax_pie.legend(wedges, labels, loc="center left", bbox_to_anchor=(0.9, 0.5), facecolor=grid_color, edgecolor="none", labelcolor=text_color, fontsize=8)
            
            self.ax_pie.set_title("Distribución de Amenazas", color=text_color, fontsize=11, pad=15, weight='bold')
            self.fig_pie.subplots_adjust(left=0.0, right=0.65, top=0.85, bottom=0.1)
            self.canvas_pie.draw_idle()

            # 3. Top IPs Table
            self.table_top_ips.setRowCount(0)
            for i, (ip, count) in enumerate(top_ips):
                self.table_top_ips.insertRow(i)
                item_ip = QTableWidgetItem(ip)
                item_count = QTableWidgetItem(str(count))
                item_count.setTextAlignment(Qt.AlignCenter)
                self.table_top_ips.setItem(i, 0, item_ip)
                self.table_top_ips.setItem(i, 1, item_count)

            # 4. Gráfico Multi-línea: Segmentación de Red (VLAN)
            self.fig_line.patch.set_facecolor('none')
            self.ax_line.clear()
            self.ax_line.set_facecolor('none')
            
            h_aulas = list(self.historial_aulas)
            h_biblio = list(self.historial_biblio)
            h_ext = list(self.historial_externos)
            max_len = max(len(h_aulas), len(h_biblio), len(h_ext), 1)
            x_data = list(range(max_len))
            
            h_aulas = [0] * (max_len - len(h_aulas)) + h_aulas
            h_biblio = [0] * (max_len - len(h_biblio)) + h_biblio
            h_ext = [0] * (max_len - len(h_ext)) + h_ext
            
            self.ax_line.plot(x_data, h_aulas, color="#4daafc", linewidth=2.0, label="Aulas")
            self.ax_line.fill_between(x_data, h_aulas, color="#4daafc", alpha=0.1)
            self.ax_line.plot(x_data, h_biblio, color="#6ccb5f", linewidth=2.0, label="Biblioteca")
            self.ax_line.fill_between(x_data, h_biblio, color="#6ccb5f", alpha=0.1)
            self.ax_line.plot(x_data, h_ext, color="#ff3b30", linewidth=2.0, label="Externos")
            self.ax_line.fill_between(x_data, h_ext, color="#ff3b30", alpha=0.1)
            
            self.ax_line.set_title("Tráfico por Segmentos de Red (Últimos 60s)", color=text_color, fontsize=11, pad=15, weight='bold')
            self.ax_line.tick_params(axis='both', colors=text_color, labelsize=9)
            self.ax_line.legend(loc="upper left", facecolor=grid_color, edgecolor="none", labelcolor=text_color)
            
            for spine in self.ax_line.spines.values():
                spine.set_edgecolor(grid_color)
            self.ax_line.grid(True, linestyle='--', alpha=0.4, color=grid_color)
            self.ax_line.set_xlim(0, max(1, len(x_data) - 1))
            self.ax_line.set_ylim(bottom=0)
            self.fig_line.tight_layout(pad=1.0)
            self.canvas_line.draw_idle()

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

    def exportar_logs_semanales(self):
        try:
            from log_exporter import exportar_logs_semanales as _export
            try:
                ruta_log, ruta_sha = _export()
                msg = f"Logs exportados a: {ruta_log}"
                if ruta_sha:
                    msg += f"\nHash SHA-512: {ruta_sha}"
                self.mostrar_mensaje("Backup Semanal", msg, "info")
            except Exception as e:
                logging.error(f"Error en exportador de logs semanales: {e}")
        except Exception as e:
            logging.error(f"Error importando exportador de logs semanales: {e}")

    def closeEvent(self, event):
        try:
            if self.monitoreo_activo:
                self.detener_monitoreo()

            for t in [self.timer, self.graf_timer,
                      self.timer_guardar_diario, self.timer_guardar_csv_diario, self.timer_log_semanal]:
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


def _estimar_os(ttl):
    """Estima el OS del dispositivo basado en el TTL del paquete."""
    if ttl == 0:
        return "Desconocido"
    elif ttl <= 64:
        return "Linux / Android / macOS"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Router / Switch / Network Device"
    return f"Otro (TTL={ttl})"

def _traducir_vlan(vlan_id):
    """Traduce VLAN ID a nombre legible."""
    VLANES = {10: "Aulas", 20: "Biblioteca", 30: "Externos"}
    if vlan_id == 0:
        return "Sin VLAN"
    return VLANES.get(vlan_id, f"VLAN {vlan_id}")

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
        
        # Ejecutar exportación semanal inicial para verificar que existe la carpeta
        try:
            from log_exporter import exportar_logs_semanales as _export
            _export()
        except Exception as e:
            logging.error(f"Error inicial exportando logs: {e}")
        
        sys.exit(app.exec_())
    except Exception as e:
        logging.error(f"Error en la ejecución principal: {e}")
