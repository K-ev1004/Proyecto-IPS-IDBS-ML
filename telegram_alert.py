import requests

BOT_TOKEN = "8274037275:AAGoQKHXiy-heCtVGgAT16NUagN2ck9q40s"

# Lista de chat_ids a los que se enviará la alerta
CHAT_IDS = [6750700630]  # Tu chat_id

def enviar_alerta(mensaje):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    for chat_id in CHAT_IDS:
        data = {
            "chat_id": chat_id,
            "text": mensaje
        }
        try:
            response = requests.post(url, data=data)
            if response.status_code == 200:
                print(f"📨 Alerta enviada a Telegram (chat_id {chat_id}) con éxito.")
            else:
                print(f"❌ Error al enviar alerta a {chat_id}: {response.text}")
        except Exception as e:
            print(f"❌ Excepción al enviar alerta a {chat_id}: {e}")

if __name__ == "__main__":
    enviar_alerta("🚨 Prueba de alerta desde mi bot!")
