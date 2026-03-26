import sqlite3

# Crear la base de datos y la tabla de ataques
def crear_bd():
    conn = sqlite3.connect("ids.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ataques (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_origen TEXT,
            tipo_ataque TEXT,
            protocolo TEXT,
            puerto INTEGER
        )
    ''')
    conn.commit()
    conn.close()

# Guardar ataques detectados en la BD
def guardar_ataque(ip, tipo, protocolo, puerto):
    conn = sqlite3.connect("ids.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO ataques (timestamp, ip_origen, tipo_ataque, protocolo, puerto) VALUES (datetime('now'), ?, ?, ?, ?)",
                   (ip, tipo, protocolo, puerto))
    conn.commit()
    conn.close()

# Crear BD si no existe
crear_bd()
