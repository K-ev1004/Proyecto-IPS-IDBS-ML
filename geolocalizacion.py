# =============================================================================
# geolocalizacion.py — Geolocalizacion de IPs + Mapa real OSM
# Reconocimiento de redes UNIPAZ por subred + hostname + IP publica router
# =============================================================================

import time
import logging
import socket
import subprocess
import re
import ipaddress

logger = logging.getLogger(__name__)

# Cache
_cache = {}
_CACHE_TTL = 3600
_ip_publica_cache = {"ip": None, "ts": 0}


# =============================================================================
# REDES CONOCIDAS UNIPAZ
# =============================================================================
REDES_UNIPAZ = {
    "172.20.12.0/24": {"departamento": "Docentes",       "frecuencia": "2.4GHz / 5G"},
    "172.10.15.0/24": {"departamento": "Administrativo",  "frecuencia": "2.4GHz"},
    "172.10.7.0/24":  {"departamento": "Administrativo",  "frecuencia": "5GHz"},
    "172.30.10.0/24": {"departamento": "Estudiantes",     "frecuencia": "2.4GHz"},
    "172.30.9.0/24":  {"departamento": "Estudiantes",     "frecuencia": "5GHz"},
}

# Colores por departamento para el mapa
COLORES_DEPTO = {
    "Docentes":       "#4daafc",  # azul
    "Administrativo": "#6ccb5f",  # verde
    "Estudiantes":    "#ff9f43",  # naranja
}


def _hex_a_rgb(hex_color):
    h = hex_color.lstrip('#')
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


def clasificar_ip_unipaz(ip):
    """
    Clasifica una IP en una subred conocida de UNIPAZ.
    Retorna dict con departamento, frecuencia, subred o None.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return None

    for subnet_str, info in REDES_UNIPAZ.items():
        try:
            red = ipaddress.ip_network(subnet_str, strict=False)
            if ip_obj in red:
                return {
                    "departamento": info["departamento"],
                    "frecuencia": info["frecuencia"],
                    "subred": subnet_str,
                }
        except ValueError:
            continue
    return None


def _es_ip_privada_rfc1918(ip):
    """Solo detecta IPs RFC 1918 reales: 10.x, 172.16-31.x, 192.168.x"""
    if not ip:
        return False
    partes = ip.split('.')
    if len(partes) != 4:
        return False
    try:
        o1 = int(partes[0])
        o2 = int(partes[1])
        if o1 == 10:
            return True
        if o1 == 172 and 16 <= o2 <= 31:
            return True
        if o1 == 192 and o2 == 168:
            return True
        return False
    except ValueError:
        return False


# =============================================================================
# Opcion C: Hostname del dispositivo
# =============================================================================
def obtener_hostname_ip(ip):
    try:
        resultado = socket.gethostbyaddr(ip)
        return resultado[0]
    except (socket.herror, socket.gaierror, OSError):
        pass

    try:
        if __import__('platform').system() == "Windows":
            resultado = subprocess.run(
                ["arp", "-a", ip],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            for linea in resultado.stdout.splitlines():
                if ip in linea:
                    partes = linea.split()
                    for p in partes:
                        if re.match(r'^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$', p):
                            return f"Dispositivo ({p})"
        else:
            resultado = subprocess.run(
                ["arp", "-n", ip],
                capture_output=True, text=True, timeout=5
            )
            for linea in resultado.stdout.splitlines():
                if ip in linea and "noarp" not in linea.lower():
                    partes = linea.split()
                    for p in partes:
                        if re.match(r'^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$', p):
                            return f"Dispositivo ({p})"
    except Exception:
        pass

    return "Dispositivo Desconocido"


# =============================================================================
# Opcion B: IP publica del router
# =============================================================================
def obtener_ip_publica_router():
    ahora = time.time()
    if _ip_publica_cache["ip"] and (ahora - _ip_publica_cache["ts"] < 300):
        return _ip_publica_cache["ip"]

    try:
        import requests
        resp = requests.get("https://api.ipify.org", timeout=5)
        resp.raise_for_status()
        ip_pub = resp.text.strip()
        _ip_publica_cache["ip"] = ip_pub
        _ip_publica_cache["ts"] = ahora
        return ip_pub
    except Exception as e:
        logger.warning(f"No se pudo obtener IP publica del router: {e}")
        return None


# =============================================================================
# Subred del dispositivo
# =============================================================================
def obtener_subred(ip):
    partes = ip.split('.')
    if len(partes) == 4:
        return f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"
    return "Desconocida"


# =============================================================================
# Geolocalizacion principal
# =============================================================================
def obtener_ubicacion_ip(ip):
    hostname = obtener_hostname_ip(ip)
    subred = obtener_subred(ip)

    # 1) Clasificar en red UNIPAZ conocida
    info_unipaz = clasificar_ip_unipaz(ip)
    if info_unipaz:
        return {
            "status": "unipaz",
            "departamento": info_unipaz["departamento"],
            "frecuencia": info_unipaz["frecuencia"],
            "subred": info_unipaz["subred"],
            "hostname": hostname,
            "country": "Colombia",
            "regionName": "Santander",
            "city": "Bucaramanga",
            "lat": 7.069694,
            "lon": -73.745340,
            "isp": "UNIPAZ",
            "org": "Instituto Universitario de la Paz",
            "as": "Red Interna UNIPAZ",
        }

    # 2) IP privada RFC 1918 real → geolocalizar via IP publica del router
    if _es_ip_privada_rfc1918(ip):
        ip_pub = obtener_ip_publica_router()
        geo = _consultar_api_geo(ip_pub if ip_pub else ip)
        geo["hostname"] = hostname
        geo["subred"] = subred
        geo["status"] = "private"
        return geo

    # 3) IP publica → geolocalizar directo
    geo = _consultar_api_geo(ip)
    geo["hostname"] = hostname
    geo["subred"] = subred
    return geo


def _consultar_api_geo(ip):
    ahora = time.time()
    if ip in _cache:
        ts, datos = _cache[ip]
        if ahora - ts < _CACHE_TTL:
            return datos.copy()

    try:
        import requests
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,org,as"
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") == "success":
            datos = {
                "country": data.get("country", "Desconocido"),
                "regionName": data.get("regionName", "Desconocido"),
                "city": data.get("city", "Desconocido"),
                "lat": data.get("lat", 0.0),
                "lon": data.get("lon", 0.0),
                "isp": data.get("isp", "Desconocido"),
                "org": data.get("org", "Desconocido"),
                "as": data.get("as", "Desconocido")
            }
        else:
            datos = _geo_vacio()

        _cache[ip] = (ahora, datos)
        return datos.copy()

    except Exception as e:
        logger.warning(f"Error geolocalizando IP {ip}: {e}")
        return _geo_vacio()


def _geo_vacio():
    return {
        "country": "Desconocido",
        "regionName": "Desconocido",
        "city": "Desconocido",
        "lat": 0.0,
        "lon": 0.0,
        "isp": "Desconocido",
        "org": "Desconocido",
        "as": "Desconocido"
    }


# =============================================================================
# Mapa estatico OSM
# =============================================================================
def generar_mapa_pixmap(lat, lon, ip, ciudad="", pais="", color="#E81123",
                         hostname="", status="public"):
    pixmap_data = generar_mapa_datos(lat, lon, ip, ciudad, pais, color, hostname, status)
    if pixmap_data is None:
        from PyQt5.QtGui import QPixmap
        pixmap = QPixmap(480, 260)
        pixmap.fill()
        return pixmap
    return _render_pixmap_from_datos(pixmap_data)


def generar_mapa_datos(lat, lon, ip, ciudad="", pais="", color="#E81123",
                        hostname="", status="public"):
    """Retorna dict con datos para renderizar el mapa en el hilo GUI.
    Evita crear QPixmap en threads no-GUI."""
    from staticmap import StaticMap, CircleMarker

    try:
        UNIPAZ_LAT, UNIPAZ_LON = 7.069694, -73.745340

        m = StaticMap(480, 260,
                      url_template='https://tile.openstreetmap.org/{z}/{x}/{y}.png')

        if status == "unipaz":
            info = clasificar_ip_unipaz(ip)
            depto = info["departamento"] if info else "UNIPAZ"
            color_depto = COLORES_DEPTO.get(depto, "#ffffff")
            r, g, b = _hex_a_rgb(color_depto)
            m.add_marker(CircleMarker((UNIPAZ_LON, UNIPAZ_LAT), (r, g, b), 14))
            image = m.render(zoom=15)

        elif status == "private":
            m.add_marker(CircleMarker((UNIPAZ_LON, UNIPAZ_LAT), (255, 180, 0), 14))
            image = m.render(zoom=14)

        elif lat == 0.0 and lon == 0.0:
            m.add_marker(CircleMarker((UNIPAZ_LON, UNIPAZ_LAT), (128, 128, 128), 12))
            image = m.render(zoom=10)

        else:
            r, g, b = _hex_a_rgb(color)
            m.add_marker(CircleMarker((lon, lat), (r, g, b), 14))
            max_dist = max(abs(lat - UNIPAZ_LAT), abs(lon - UNIPAZ_LON))
            if max_dist < 0.5:
                zoom = 10
            elif max_dist < 2:
                zoom = 8
            elif max_dist < 10:
                zoom = 6
            elif max_dist < 50:
                zoom = 4
            else:
                zoom = 3
            image = m.render(zoom=zoom)

        buf = image.tobytes("raw", "RGB")
        return {"buf": buf, "width": image.width, "height": image.height}

    except Exception as e:
        logger.error(f"Error generando datos de mapa: {e}")
        return None


def _render_pixmap_from_datos(datos):
    """Renderiza QPixmap desde datos dict. Ejecutar en hilo GUI."""
    from PyQt5.QtGui import QPixmap, QImage
    try:
        qimg = QImage(datos["buf"], datos["width"], datos["height"],
                      QImage.Format_RGB888)
        return QPixmap.fromImage(qimg)
    except Exception:
        pixmap = QPixmap(480, 260)
        pixmap.fill()
        return pixmap
