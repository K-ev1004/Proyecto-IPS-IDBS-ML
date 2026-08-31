# =============================================================================
# geolocalizacion.py — Geolocalizacion de IPs atacantes + Mapa real OSM
# Usa ip-api.com (gratis, sin API key) y staticmap (tiles OpenStreetMap)
# =============================================================================

import time
import logging

logger = logging.getLogger(__name__)

# Cache simple: {ip: (timestamp, datos)}
_cache = {}
_CACHE_TTL = 3600  # 1 hora


def _hex_a_rgb(hex_color):
    """Convierte '#RRGGBB' a tupla (r, g, b)."""
    h = hex_color.lstrip('#')
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


def obtener_ubicacion_ip(ip):
    """
    Consulta ip-api.com para obtener geolocalizacion de una IP.
    Retorna dict con: country, regionName, city, lat, lon, isp, org, as
    """
    if not ip or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return {
            "status": "private",
            "country": "Red Privada",
            "regionName": "LAN Local",
            "city": "-",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "-",
            "org": "-",
            "as": "-"
        }

    ahora = time.time()
    if ip in _cache:
        ts, datos = _cache[ip]
        if ahora - ts < _CACHE_TTL:
            return datos

    try:
        import requests
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,org,as"
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") == "success":
            datos = {
                "status": "success",
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
            datos = {
                "status": "fail",
                "country": "Desconocido",
                "regionName": "Desconocido",
                "city": "Desconocido",
                "lat": 0.0,
                "lon": 0.0,
                "isp": "Desconocido",
                "org": "Desconocido",
                "as": "Desconocido"
            }

        _cache[ip] = (ahora, datos)
        return datos

    except Exception as e:
        logger.warning(f"Error geolocalizando IP {ip}: {e}")
        return {
            "status": "error",
            "country": "Error",
            "regionName": "Error",
            "city": "Error",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "Error",
            "org": "Error",
            "as": "Error"
        }


def generar_mapa_pixmap(lat, lon, ip, ciudad="", pais="", color="#E81123"):
    """
    Genera un mapa real de OpenStreetMap con staticmap y retorna un QPixmap.
    Muestra el punto del atacante y UNIPAZ Bogota como referencia.
    """
    from staticmap import StaticMap, CircleMarker, Line
    from PyQt5.QtGui import QPixmap, QImage

    try:
        UNIPAZ_LAT, UNIPAZ_LON = 4.7110, -74.0721

        if lat == 0.0 and lon == 0.0:
            m = StaticMap(480, 260, url_template='https://tile.openstreetmap.org/{z}/{x}/{y}.png')
            pixmap = QPixmap(480, 260)
            pixmap.fill()
            return pixmap

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

        m = StaticMap(480, 260, url_template='https://tile.openstreetmap.org/{z}/{x}/{y}.png')

        r, g, b = _hex_a_rgb(color)
        m.add_marker(CircleMarker((lon, lat), (r, g, b), 14))

        m.add_marker(CircleMarker((UNIPAZ_LON, UNIPAZ_LAT), (77, 170, 252), 10))

        m.add_line(Line([(lon, lat), (UNIPAZ_LON, UNIPAZ_LAT)], (255, 255, 255, 160), 2))

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
