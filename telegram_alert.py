# =============================================================================
# telegram_alert.py — Módulo de notificaciones en tiempo real via Telegram
# Envía alertas del IDS a uno o varios usuarios mediante la API de Telegram Bot
# =============================================================================

# requests: Librería HTTP de terceros para realizar peticiones REST a la API de Telegram
import requests

# BOT_TOKEN: Credencial única que identifica el bot ante la API de Telegram
# Formato: "<id_numérico>:<hash_alfanumérico>"
# Se obtiene creando un bot con @BotFather en Telegram
# [!] SEGURIDAD: En producción debe cargarse desde una variable de entorno, no hardcodeado
BOT_TOKEN = "8274037275:AAGoQKHXiy-heCtVGgAT16NUagN2ck9q40s"

# CHAT_IDS: Lista de identificadores únicos de los destinatarios de las alertas
# Cada chat_id corresponde a un usuario o grupo de Telegram
# Permite enviar la misma alerta a múltiples destinatarios (administradores, SOC, etc.)
CHAT_IDS = [1016030596]  # ID del chat del administrador principal


# =============================================================================
# FUNCIÓN: enviar_alerta
# Propósito: Envía un mensaje de texto a todos los chat_ids configurados
# Parámetros:
#   mensaje — String con el contenido de la alerta a enviar
# Retorna: None (opera por efectos secundarios — HTTP POST y logs en consola)
# =============================================================================
def enviar_alerta(mensaje):
    # Construye la URL del endpoint sendMessage de la API de Telegram Bot
    # f-string embebe el BOT_TOKEN dinámicamente en la URL
    # Formato oficial: https://api.telegram.org/bot{TOKEN}/METHOD
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    # Itera sobre cada destinatario configurado en la lista
    # Permite notificación masiva: el mismo mensaje llega a todos los admins
    for chat_id in CHAT_IDS:

        # Construye el cuerpo de la petición como diccionario Python
        # chat_id: identifica al destinatario en Telegram
        # text: contenido del mensaje (soporta emojis y texto plano)
        data = {
            "chat_id": chat_id,
            "text": mensaje
        }

        try:
            # requests.post(): Envía una petición HTTP POST al endpoint de Telegram
            # La API de Telegram espera los datos como form-data (parámetro data=)
            # No se usa json= porque la API acepta application/x-www-form-urlencoded
            response = requests.post(url, data=data)

            # Verifica el código de estado HTTP de la respuesta
            # 200 OK indica que el mensaje fue recibido y encolado por Telegram
            if response.status_code == 200:
                print(f"📨 Alerta enviada a Telegram (chat_id {chat_id}) con éxito.")
            else:
                # Cualquier código diferente a 200 indica error de la API
                # response.text contiene el JSON de error de Telegram con detalles
                print(f"[X] Error al enviar alerta a {chat_id}: {response.text}")

        except Exception as e:
            # Captura errores de red: timeout, sin conexión, DNS fallido, etc.
            # Manejo defensivo para no interrumpir la detección de ataques si Telegram falla
            print(f"[X] Excepción al enviar alerta a {chat_id}: {e}")


# =============================================================================
# BLOQUE DE PRUEBA — Se ejecuta solo cuando se invoca el archivo directamente
# if __name__ == "__main__": evita que esta prueba se ejecute al importar el módulo
# =============================================================================
if __name__ == "__main__":
    # Envía un mensaje de prueba para verificar que el bot y el token funcionan
    enviar_alerta("[ALERT] Prueba de alerta desde mi bot!")

# =============================================================================
# FIN DEL SCRIPT — telegram_alert.py
# =============================================================================
