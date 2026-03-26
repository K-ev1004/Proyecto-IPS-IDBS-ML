import os
import re

def clean_file(filepath):
    """Elimina emojis y caracteres especiales propensos a errores de encoding."""
    # Rango de emojis y caracteres especiales comunes
    # Ver: https://stackoverflow.com/questions/33404752/removing-emojis-from-a-string-in-python
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Sustituciones específicas para mantener legibilidad
    content = content.replace("[OK]", "[OK]")
    content = content.replace("[X]", "[X]")
    content = content.replace("[ALERT]", "[ALERT]")
    content = content.replace("[USER]", "[USER]")
    content = content.replace("[PKG]", "[PKG]")
    content = content.replace("[PORT]", "[PORT]")
    content = content.replace("[IP]", "[IP]")
    content = content.replace("[WAIT]", "[WAIT]")
    content = content.replace("[!]", "[!]")
    
    # Eliminar cualquier otro carácter no-ASCII residual en los mensajes de print
    # que pueda causar problemas en terminales cp1252
    def remove_non_ascii(text):
        return "".join(i if ord(i) < 128 else " " for i in text)
    
    # Solo aplicamos a líneas de print o logs si es necesario, 
    # pero para simplificar lo aplicaremos a todo el archivo cuidando no romper strings vitales.
    # actually, just replacing the known emojis should be enough.
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Limpieza completada: {filepath}")

directory = r"g:\Mi unidad\Proyecto IDBS IPS ML Unipaz\Codigo IDS - sustentado_comentado"
for filename in os.listdir(directory):
    if filename.endswith(".py"):
        clean_file(os.path.join(directory, filename))
