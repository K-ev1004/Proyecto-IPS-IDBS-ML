# Informe de Línea Base de Tráfico de Red
## Captura de 5 minutos — Interfaz Ethernet (Realtek Gaming 2.5GbE)

**Fecha de captura:** 2026-08-31 16:44:28 → 16:49:28
**Duración total:** 299.97 s (~5 min)
**Herramienta:** Dumpcap (Wireshark) 4.6.8 + Npcap 1.88

---

## 1. Resumen global del tráfico (capinfos)

| Métrica | Valor |
|---------|-------|
| Paquetes capturados | 94,946 |
| Tamaño del archivo | 21 MB (18 MB de datos) |
| Tasa de datos | 61 kBps |
| Tasa de bits | 489 kbps |
| Paquetes promedio por segundo | 316 pkts/s |
| Tamaño promedio de paquete | 193.38 bytes |

---

## 2. Carga base (volumen del adaptador, muestreo cada 2 s)

> ⚠️ Nota: El muestreo con `Get-NetAdapterStatistics` del contador TX de este adaptador Realtek reportó 0 (el contador no se incrementaba de forma fiable). El tráfico real TX sí existe (visible en la captura). **Los valores de RX son fiables; los de TX deben tomarse del análisis de la captura.**

| Métrica | Media | P50 | P95 | P99 | Máx |
|---------|-------|-----|-----|-----|-----|
| RX bytes/s | 54 | 30 | 230 | 487 | 546 |
| RX paquetes/s | 272 | — | 907 | 994 | — |

**Interpretación:** El volumen base de recepción es MUY bajo en bytes pero alto en paquetes. Esto indica un tráfico predominante de **paquetes pequeños (broadcast/multicast/descubrimiento)**, no de transferencia de datos grandes.

---

## 3. Distribución de protocolos (jerarquía)

| Protocolo | Paquetes | Bytes | Observación |
|-----------|----------|-------|-------------|
| **IPv4** (0.0.0.0) | — | — | — |
| VLAN | 47,946 | 4.19 MB | Tráfico VLAN-etiquetado en el segmento |
| **ARP** | 36,442 | 2.19 MB | Tercer flujo mayor — ARP masivo (típico de LAN grande) |
| **mDNS** (IPv4+IPv6) | 4,627 | 1.08 MB | Descubrimiento de servicios (.local) |
| **Multicast mDNS** (224.0.0.251) | 5,564 | 1.23 MB | Mayor endpoint multicast |
| **SSDP** (239.255.255.250) | 1,535 | 655 kB | Descubrimiento UPnP |
| **IGMP** | 878 | 54 kB | Gestión de grupos multicast |
| **DHCP** | 330 | 115 kB | Asignación de IP |
| **LLMNR/NBNS/NetBIOS** | ~152 | ~15 kB | Resolución de nombres legado |
| **DNS** | 43 | 7 kB | Resolución de nombres |
| **mndp** (MikroTik) | 50 | 10.9 kB | Descubrimiento de routers MikroTik |
| **TCP/TLS** | 335 / 54 | 43 kB / 10 kB | Tráfico http/https |
| **QUIC** | 79 | 74 kB | HTTP/3 |
| **SMB (NetBIOS)** | 4 | 988 bytes | Compartición de archivos |

---

## 4. Tráfico predominante: Broadcast y Multicast (lo "recurrente")

La mayor parte del tráfico normal NO es navegación, sino **ruido de red de descubrimiento**. Los endpoints multicast/broadcast dominan:

| Endpoint | Paquetes | Bytes | Tipo |
|----------|----------|-------|------|
| 224.0.0.251 | 5,564 | 1,225 kB | mDNS multicast |
| 239.255.255.250 | 1,535 | 655 kB | SSDP (UPnP) |
| 255.255.255.255 | 1,370 | 473 kB | Broadcast global |
| 224.0.0.22 | 1,339 | 82 kB | IGMP multicast |
| 17.57.144.x (Apple) | — | — | Servicios Apple (APNs) |

---

## 5. Top conversaciones IPv4 (por volumen)

La máquina local es **172.10.8.29**. Las conversaciones con más tráfico (unicast, hacia Internet/LAN):

| Host remoto | Total bytes | Frames | Posible servicio |
|-------------|-------------|--------|------------------|
| 185.199.109.215 (GitHub Pages) | 5,472 kB | 5,541 | La conversación dominante — descarga de contenido web/CDN |
| 34.117.41.85 | 590 kB | 900 | Google Cloud |
| 172.217.162.99 | 502 kB | 544 | Google |
| 140.82.114.4 / 140.82.113.22 | 453 / 443 kB | ~1,100 | GitHub |
| 8.8.4.4 / 8.8.8.8 | 203 kB | 475 | Google DNS |
| 57.144.x.x | ~800 kB | ~1,500 | Amazon / CDN |
| 172.20.10.20, 172.30.14.63, 172.20.4.x | ~250 kB | ~1,600 | Tráfico interno LAN |

**Nota:** Aunque la conversación con GitHub Pages (185.199.109.215) domina por bytes (5.4 MB), representa solo ~30% del total de 18 MB. La mayor parte del resto es broadcast/multicast distribuido entre cientos de hosts de la LAN (miles de pares con pocos bytes cada uno).

---

## 6. Caracterización del tráfico normal / recurrente

1. **Altísimo volumen de paquetes pequeños** (~316 pkts/s) con poco ancho de banda (~489 kbps).
2. **ARP masivo** (36k paquetes) y **mDNS/SSDP constante** → red de área local grande y activa (múltiples subredes: 172.10.x, 172.20.x, 172.30.x) con muchos dispositivos.
3. **Tráfico multicast muy significativo**: mDNS, SSDP, IGMP.
4. **Dispositivos MikroTik** presentes (protocolo mndp).
5. **Tercero/quinto octeto de IPs** cambian constantemente → DHCP en redes /8 privadas con muchos hosts efímeros.
6. Navegación web unidireccional dominada por GitHub/Google/Amazon (CDNs).

---

## 7. Implicaciones para el modelo ML (evitar falsos positivos)

Para que tu detector (basado en ML) no marque falsos positivos por carga normal, considera:

- **¿Qué es "normal" (carga base aproximada)?**
  - ~300-1000 paquetes/s (P95 907 pkts/s)
  - ~50-230 bytes/s RX (P95) en ausencia de descargas
  - Trafico mayoritariamente broadcast/multicast/ARP

- **Alertas que probablemente sean FALSOS POSITIVOS en esta red:**
  - Picos de ARP (36k paquetes) → **NO es un ataque ARP** si es tráfico difundido de la LAN.
  - mDNS/SSDP constante → descubrimiento normal, NO exfiltración.
  - Multicast (224.0.0.251, 239.255.255.250) → **lo más recurrente**, debe estar en "lista blanca".
  - Alto contador de paquetes con bajo volumen de bytes → tráfico de control, normal aquí.

- **Umbrales sugeridos para el modelo:**
  - NO alarmar por multicast/broadcast per se.
  - Vigilar cambiando del patrón "pocos bytes + muchos paquetes pequeños" a "muchos bytes de un solo host" (ese sería un descarga/transferencia real, como la de GitHub Pages).
  - El tráfico unicast real consumidor de ancho de banda (GitHub/Google) es intermitente; la **línea base media de bytes RX ~50 B/s** (sin descargas).

---

## Archivos generados

| Archivo | Descripción |
|---------|-------------|
| `captura_5min.pcapng` | Captura completa de paquetes (21 MB) — analizable en Wireshark |
| `captura_volumen.csv` | Serie temporal de volumen del adaptador (muestreo 2 s, 149 muestras) |
| `capturar_linea_base.ps1` | Script reutilizable para repetir la captura |
| `resumen_linea_base.md` | Este informe |

## Recomendación

Ejecuta esta captura de línea base **en varias franjas horarias y días distintos** (mañana, tarde, noche, fin de semana) para que el ML tenga un espectro completo de la "carga normal" antes de fijar umbrales de detección de anomalías.
