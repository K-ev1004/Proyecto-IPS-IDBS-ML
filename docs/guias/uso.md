# Guía de uso

Cómo operar el sistema IDS/IPS desde la GUI y desde consola.

## Operación desde la GUI (`python interfasc.py`)

### Dashboard SOC

- **Eventos en vivo:** tabla con los ataques detectados (origen, destino, puerto, protocolo,
  flag y tipo con confianza ML).
- **Tráfico:** paquetes por segundo y distribución por VLAN/segmento.
- **Estadísticas:** gráficos de torta, área y top de IPs atacantes.
- **IPS (respuesta activa):** tabla de bloqueos con severidad, estado y tiempo restante.

### Configuración

| Parámetro | Valor por defecto | Descripción |
|---|---|---|
| `ids.UMBRAL_ML` | 0.85 | Confianza mínima del modelo multiclase para loguear y bloquear |
| `ids.UMBRAL_SQLI_GUARD` | 0.30 | Probabilidad mínima de SQLiGuard para confirmar `Inyeccion_SQL` |
| Modo IPS | Semi-autónomo | Autónomo = bloquea en MikroTik; Semi = solo alerta |
| Botón "Abrir Carpeta de Logs" | — | Abre `logs_ciberseguridad/` (o `LOG_FOLDER`) |

> Los umbrales se guardan en **QSettings** y se aplican en vivo, sin reiniciar.

### Interpretación de alertas

- Tipo con `(ML: 98.4%)` → clasificación por **CatBoost v5** (y/o SQLiGuard en SQLi).
- Tipo con `(Heurística)` → detectado por reglas en tiempo real (sin esperar al flujo).
- `flag="SQLiGuard"` en BD → confirmado por el detector binario de SQLi.

## Operación desde consola

| Acción | Comando |
|---|---|
| Captura de prueba (10 s) | `python ids.py` |
| Exportar logs semanales | `python log_exporter.py` |
| Enviar alerta de prueba a Telegram | `python telegram_alert.py` |
| Batería de pruebas | `python test_masivo.py` |

## Modos del IPS

1. **Semi-autónomo (por defecto):** detecta, alerta y registra; el bloqueo real se omite.
2. **Autónomo:** además del registro, ejecuta el bloqueo real en el MikroTik
   (`/ip firewall address-list add` con timeout por defecto de 24 h) cuando el criterio se
   cumple y la IP no está en la whitelist/redes confiables.

> La whitelist (`IPS_CONFIABLES`, `RANGOS_CONFIABLES` en `ids.py`) protege IPs críticas de
> UNIPAZ (plataformas de notas, matrículas, servidores) contra falsos positivos.
