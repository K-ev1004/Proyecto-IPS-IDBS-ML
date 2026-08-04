# -*- coding: utf-8 -*-
"""Verificacion definitiva - lee en UTF-8 y valida el timer en instancia."""
import io, os, sys, codecs
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from log_exporter import exportar_logs_semanales, registrar_bloqueo_log, LOGS_FOLDER

# 1. Verificar formato del logs_bloqueos.log (leer UTF-8 real)
print("== LOGS_BLOQUEOS.LOG (contenido UTF-8) ==")
path = os.path.join(LOGS_FOLDER, 'logs_bloqueos.log')
with codecs.open(path, 'r', encoding='utf-8') as f:
    for line in f:
        print(repr(line.strip()))

# 2. Verificar timer_log_semanal como atributo de instancia
print("\n== VERIFICACION TIMER EN CODIGO FUENTE ==")
src = codecs.open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'interfasc.py'), 'r', encoding='utf-8').read()
ok_timer_def = 'self.timer_log_semanal = QTimer()' in src
ok_timer_conn = 'self.timer_log_semanal.timeout.connect(self.exportar_logs_semanales)' in src
ok_timer_start = 'self.timer_log_semanal.start(7 * 24 * 60 * 60 * 1000)' in src
ok_timer_close = 'self.timer_log_semanal' in src.split('def closeEvent')[1].split(']')[0] if 'def closeEvent' in src else False
print("timer_log_semanal definido en setup_timers:", ok_timer_def)
print("timer_log_semanal conectado a exportar_logs_semanales:", ok_timer_conn)
print("timer_log_semanal iniciado con 7 dias:", ok_timer_start)
print("timer_log_semanal detenido en closeEvent:", ok_timer_close)

# 3. Verificar llamada a registrar_bloqueo_log en ids.py
print("\n== VERIFICACION IDS.PY ==")
ids_src = codecs.open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ids.py'), 'r', encoding='utf-8').read()
print("import registrar_bloqueo_log en ids.py:", 'from log_exporter import registrar_bloqueo_log' in ids_src)
print("llamada registrar_bloqueo_log en guardar_ataque:", 'registrar_bloqueo_log(ip_src,' in ids_src)

# 4. Exportar y ver contenido
print("\n== EXPORTACION SEMANAL ==")
ruta = exportar_logs_semanales()
print("Archivo generado:", os.path.basename(ruta))
with codecs.open(ruta, 'r', encoding='utf-8') as f:
    contenido = f.read()
print("Tiene encabezado SEMANA:", 'SEMANA' in contenido)
print("Total lineas:", len(contenido.splitlines()))