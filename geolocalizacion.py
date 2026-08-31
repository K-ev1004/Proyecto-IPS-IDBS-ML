# =============================================================================
# geolocalizacion.py — Geolocalizacion de IPs atacantes + Mapa real OSM
# 3 opciones: hostname del dispositivo, IP publica del router, mapa OSM
# =============================================================================

import time
import logging
import socket
import subprocess
import re

logger = logging.getLogger(__name__)

# Cache
_cache = {}
_CACHE_TTL = 3600
_ip_publica_cache = {"ip": None, "ts": 0}


def _hex_a_rgb(hex_color):
    h = hex_color.lstrip('#')
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


def _es_ip_privada(ip):
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

    if _es_ip_privada(ip):
        ip_pub = obtener_ip_publica_router()
        geo = _consultar_api_geo(ip_pub if ip_pub else ip)
        geo["hostname"] = hostname
        geo["subred"] = subred
        geo["status"] = "private"
        return geo

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
                         hostname="", es_privada=False):
    from staticmap import StaticMap, CircleMarker, Line
    from PyQt5.QtGui import QPixmap, QImage

    try:
        UNIPAZ_LAT, UNIPAZ_LON = 4.7110, -74.0721

        m = StaticMap(480, 260,
                      url_template='https://tile.openstreetmap.org/{z}/{x}/{y}.png')

        r, g, b = _hex_a_rgb(color)

        if es_privada:
            m.add_marker(CircleMarker((UNIPAZ_LON, UNIPAZ_LAT), (77, 170, 252), 12))
            m.add_marker(CircleMarker((UNIPAZ_LON + 0.003, UNIPAZ_LAT + 0.002),
                                      (255, 180, 0), 14))
            image = m.render(zoom=14)
        elif lat == 0.0 and lon == 0.0:
            m.add_marker(CircleMarker((UNIPAZ_LON, UNIPAZ_LAT), (77, 170, 252), 12))
            image = m.render(zoom=10)
        else:
            m.add_marker(CircleMarker((lon, lat), (r, g, b), 14))
            m.add_marker(CircleMarker((UNIPAZ_LON, UNIPAZ_LAT), (77, 170, 252), 10))
            m.add_line(Line([(lon, lat), (UNIPAZ_LON, UNIPAZ_LAT)],
                            (255, 255, 255, 160), 2))

            dist_lat = abs(lat - UNIPAZ_LAT)
            dist_lon = abs(lon - UNIPAZ_LON)
            max_dist = max(dist_lat, dist_lon)
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
        qimg = QImage(buf, image.width, image.height, QImage.Format_RGB888)
        pixmap = QPixmap.fromImage(qimg)
        return pixmap

    except Exception as e:
        logger.error(f"Error generando mapa: {e}")
        pixmap = QPixmap(480, 260)
        pixmap.fill()
        return pixmap
