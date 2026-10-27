#!/usr/bin/env python3
"""
Vigilante de Red Casero
=======================
Escanea tu red wifi, lista los aparatos conectados y te avisa
cuando aparece uno desconocido.

Es una herramienta de VIGILANCIA, no un antivirus:
- No bloquea, no desconecta ni limpia ningun aparato.
- Solo observa (ping + tabla ARP) y compara con tu lista de conocidos.
- La accion (desconectar algo raro, cambiar la clave) la haces vos
  en el router.

Uso:
    python vigilante.py                  Escanea y compara con conocidos
    python vigilante.py --aprender       Primer uso: guarda lo encontrado
    python vigilante.py --aprobar AA:BB:CC:DD:EE:FF
                                         Marca un aparato como conocido
    python vigilante.py --vigilar 30     Escanea cada 30 minutos sin parar
    python vigilante.py --red 192.168.1.0/24
                                         Escanea una red concreta
    python vigilante.py --sin-nombres    No intenta averiguar nombres

Requisitos: Python 3.8 o superior. Sin programas extra.
Funciona en Windows y Linux. No necesita permisos de administrador.
"""

import argparse
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

ARCHIVO_CONOCIDOS = "dispositivos_conocidos.json"
ARCHIVO_REPORTE = "ultimo_reporte.json"

# Tabla de fabricantes por prefijo MAC (OUI). Es referencial y ampliable:
# si tu aparato sale como "Desconocido", podes agregar su prefijo aca.
# El prefijo son los primeros 3 pares de la MAC, en mayusculas con ":".
OUI = {
    "FC:A1:83": "Samsung",
    "D8:63:75": "Samsung",
    "F0:18:98": "Apple",
    "A4:83:E7": "Apple",
    "28:ED:6A": "Apple",
    "64:CC:2E": "Xiaomi",
    "7C:2F:80": "Xiaomi",
    "38:8B:59": "LG",
    "E8:5A:8B": "Huawei",
    "48:46:4B": "Huawei",
    "50:C7:BF": "TP-Link",
    "B0:4E:26": "TP-Link",
    "14:CC:20": "TP-Link",
    "C0:25:A5": "TP-Link",
    "30:23:03": "Amazon (Echo/Fire)",
    "FC:A1:83": "Samsung",
    "00:1A:11": "Google",
    "F4:F5:D8": "Google",
    "D8:A0:1D": "LG",
    "84:10:0D": "Sony",
    "00:04:20": "Sony",
    "18:31:BF": "Hikvision (camaras)",
    "C0:56:E3": "Dahua (camaras)",
}


def es_windows():
    return platform.system() == "Windows"


def normalizar_mac(mac):
    """Deja la MAC como AA:BB:CC:DD:EE:FF. Devuelve None si no es valida."""
    if not mac:
        return None
    mac = mac.strip().upper().replace("-", ":")
    if re.fullmatch(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
        return mac
    return None


def fabricante(mac):
    """Fabricante segun el prefijo MAC, o 'Desconocido'."""
    if not mac or len(mac) < 8:
        return "Desconocido"
    return OUI.get(mac[:8], "Desconocido")


def parsear_salida_arp(texto):
    """Extrae {ip: mac} de la salida de `arp -a` (Windows o Linux).

    Se busca por linea: en Windows la MAC viene justo despues de la IP,
    en Linux viene la palabra "ether" en el medio. Por eso se buscan
    la IP y la MAC por separado dentro de cada linea.
    """
    encontrados = {}
    patron_ip = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
    patron_mac = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
    for linea in texto.splitlines():
        m_ip = patron_ip.search(linea)
        m_mac = patron_mac.search(linea)
        if not m_ip or not m_mac:
            continue
        ip = m_ip.group(0)
        mac = normalizar_mac(m_mac.group(0))
        if not mac:
            continue
        # Ignorar broadcast y multicast: no son aparatos.
        if ip == "255.255.255.255" or ip.startswith("224."):
            continue
        if ip.endswith(".255"):
            continue
        encontrados[ip] = mac
    return encontrados


def leer_arp():
    """Lee la tabla ARP del sistema. Devuelve {ip: mac}."""
    try:
        salida = subprocess.run(
            ["arp", "-a"], capture_output=True, timeout=15
        ).stdout.decode("utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return {}
    return parsear_salida_arp(salida)


def obtener_ip_local():
    """IP de la PC en la red local. No envia trafico: solo consulta la ruta."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return None


def obtener_red(ip):
    """Red local (ej: 192.168.1.0/24). Si no puede leer la mascara, usa /24."""
    if not ip:
        return None
    mascara = None
    try:
        if es_windows():
            salida = subprocess.run(
                ["ipconfig"], capture_output=True, timeout=10
            ).stdout.decode("utf-8", errors="replace")
            # Buscar el bloque del adaptador que tiene nuestra IP.
            for bloque in re.split(r"\n\s*\n", salida):
                if ip in bloque:
                    m = re.search(
                        r"(?:scara de subred|Subnet Mask)[^\d]*(\d{1,3}(?:\.\d{1,3}){3})",
                        bloque,
                    )
                    if m:
                        mascara = m.group(1)
                        break
        else:
            salida = subprocess.run(
                ["ip", "addr"], capture_output=True, timeout=10
            ).stdout.decode("utf-8", errors="replace")
            m = re.search(r"inet " + re.escape(ip) + r"/(\d+)", salida)
            if m:
                return ipaddress.ip_network(f"{ip}/{m.group(1)}", strict=False)
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    if mascara:
        try:
            return ipaddress.ip_network(f"{ip}/{mascara}", strict=False)
        except ValueError:
            pass
    return ipaddress.ip_network(f"{ip}/24", strict=False)


def hacer_ping(ip):
    """Un ping rapido. Devuelve True si el aparato responde."""
    if es_windows():
        cmd = ["ping", "-n", "1", "-w", "400", str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
    try:
        r = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
        )
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def resolver_nombre(ip):
    """Nombre del aparato si la red lo informa (puede fallar: devuelve None)."""
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except (OSError, socket.herror):
        return None


def escanear_red(red, ip_pc, sin_nombres=False):
    """Barrido de la red. Devuelve una lista de aparatos encontrados."""
    # Redes enormes: nos quedamos con el /24 de la PC (uso hogareño).
    if red.prefixlen < 24 or red.num_addresses > 1024:
        red = ipaddress.ip_network(f"{ip_pc}/24", strict=False)
        print(f"  (Red grande: escaneo solo {red})")

    hosts = list(red.hosts())
    print(f"  Escaneando {len(hosts)} direcciones en {red} ...")
    with ThreadPoolExecutor(max_workers=64) as pool:
        respuestas = list(pool.map(hacer_ping, hosts))
    activos = [ip for ip, ok in zip(hosts, respuestas) if ok]

    tabla_arp = leer_arp()
    aparatos = []
    nombres = {}
    if not sin_nombres and activos:
        with ThreadPoolExecutor(max_workers=32) as pool:
            for ip, nombre in zip(activos, pool.map(resolver_nombre, activos)):
                if nombre:
                    nombres[str(ip)] = nombre

    for ip in activos:
        ip_txt = str(ip)
        mac = tabla_arp.get(ip_txt, "desconocida")
        aparatos.append(
            {
                "ip": ip_txt,
                "mac": mac,
                "nombre": nombres.get(ip_txt, ""),
                "fabricante": fabricante(mac) if mac != "desconocida" else "Desconocido",
            }
        )
    return sorted(aparatos, key=lambda d: ipaddress.ip_address(d["ip"]))


def cargar_conocidos():
    if not os.path.exists(ARCHIVO_CONOCIDOS):
        return None
    try:
        with open(ARCHIVO_CONOCIDOS, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def guardar_conocidos(conocidos):
    with open(ARCHIVO_CONOCIDOS, "w", encoding="utf-8") as f:
        json.dump(conocidos, f, indent=2, ensure_ascii=False)


def guardar_reporte(aparatos, nuevos):
    reporte = {
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "total": len(aparatos),
        "nuevos": len(nuevos),
        "aparatos": aparatos,
    }
    with open(ARCHIVO_REPORTE, "w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)


def imprimir_reporte(aparatos, conocidos):
    ahora = datetime.now().strftime("%d/%m/%Y %H:%M")
    print()
    print(f"=== Vigilante de Red Casero — {ahora} ===")
    print(f"Aparatos encontrados: {len(aparatos)}")
    print()
    nuevos = []
    print(f"{'IP':<16}{'MAC':<20}{'FABRICANTE':<22}{'NOMBRE':<24}ESTADO")
    print("-" * 100)
    for d in aparatos:
        mac = d["mac"]
        if conocidos is None or mac in conocidos or mac == "desconocida":
            estado = "conocido" if conocidos and mac in conocidos else ""
        else:
            estado = "⚠ NUEVO"
            nuevos.append(d)
        print(
            f"{d['ip']:<16}{mac:<20}{d['fabricante']:<22}{d['nombre'][:23]:<24}{estado}"
        )
    print()
    if nuevos:
        print(f"⚠ ATENCION: {len(nuevos)} aparato(s) desconocido(s):")
        for d in nuevos:
            print(f"   - {d['ip']}  MAC {d['mac']}  ({d['fabricante']})")
        print()
        print("  Si no reconoces alguno: revisa en tu casa que aparato es,")
        print("  y si no es tuyo, cambia la clave del wifi y desconectalo")
        print("  desde el router. Para marcarlo como tuyo corre:")
        print("      python vigilante.py --aprobar <MAC>")
    else:
        print("Sin novedades: todos los aparatos son conocidos. 👍")
    print()
    return nuevos


def hacer_escaneo(red_txt, sin_nombres):
    """Un escaneo completo. Devuelve (aparatos, red_usada)."""
    ip_pc = obtener_ip_local()
    if red_txt:
        try:
            red = ipaddress.ip_network(red_txt, strict=False)
        except ValueError:
            print(f"Red invalida: {red_txt}")
            sys.exit(2)
    else:
        if not ip_pc:
            print("No pude detectar la IP de esta PC. Indica la red a mano:")
            print("    python vigilante.py --red 192.168.1.0/24")
            sys.exit(2)
        red = obtener_red(ip_pc)
    print(f"Tu IP: {ip_pc} | Red a escanear: {red}")
    aparatos = escanear_red(red, ip_pc, sin_nombres)
    return aparatos


def main():
    parser = argparse.ArgumentParser(
        description="Vigilante de Red Casero: detecta aparatos desconocidos en tu wifi."
    )
    parser.add_argument("--aprender", action="store_true",
                        help="Primer uso: guarda lo encontrado como aparatos conocidos.")
    parser.add_argument("--aprobar", metavar="MAC",
                        help="Marca un aparato como conocido (ej: AA:BB:CC:DD:EE:FF).")
    parser.add_argument("--vigilar", metavar="MINUTOS", type=int, default=0,
                        help="Escanea cada N minutos sin parar (Ctrl+C para parar).")
    parser.add_argument("--red", metavar="RED",
                        help="Red a escanear, ej: 192.168.1.0/24.")
    parser.add_argument("--sin-nombres", action="store_true",
                        help="No intenta averiguar nombres de aparatos (mas rapido).")
    args = parser.parse_args()

    if args.aprobar:
        mac = normalizar_mac(args.aprobar)
        if not mac:
            print(f"MAC invalida: {args.aprobar} (formato: AA:BB:CC:DD:EE:FF)")
            return 2
        conocidos = cargar_conocidos() or {}
        if mac in conocidos:
            print(f"La MAC {mac} ya estaba en conocidos.")
            return 0
        # Si hay un reporte previo, copiar los datos de ahi.
        datos = {"ip": "?", "nombre": "", "fabricante": fabricante(mac)}
        if os.path.exists(ARCHIVO_REPORTE):
            try:
                with open(ARCHIVO_REPORTE, encoding="utf-8") as f:
                    for d in json.load(f).get("aparatos", []):
                        if d.get("mac") == mac:
                            datos = d
                            break
            except (OSError, ValueError):
                pass
        datos["primera_vez"] = datetime.now().isoformat(timespec="seconds")
        datos["ultima_vez"] = datos["primera_vez"]
        conocidos[mac] = datos
        guardar_conocidos(conocidos)
        print(f"Aparato {mac} marcado como conocido. 👍")
        return 0

    if args.aprender:
        aparatos = hacer_escaneo(args.red, args.sin_nombres)
        conocidos = {}
        for d in aparatos:
            if d["mac"] == "desconocida":
                continue
            conocidos[d["mac"]] = {
                "ip": d["ip"],
                "nombre": d["nombre"],
                "fabricante": d["fabricante"],
                "primera_vez": datetime.now().isoformat(timespec="seconds"),
                "ultima_vez": datetime.now().isoformat(timespec="seconds"),
            }
        guardar_conocidos(conocidos)
        guardar_reporte(aparatos, [])
        print()
        print(f"Aprendidos {len(conocidos)} aparatos en {ARCHIVO_CONOCIDOS}.")
        print("Revisa la lista: si hay alguno que no es tuyo, borralo del archivo")
        print("antes de confiar en los proximos escaneos.")
        return 0

    conocidos = cargar_conocidos()
    if conocidos is None:
        print("Primera vez: todavia no hay lista de aparatos conocidos.")
        print("Corre primero:")
        print("    python vigilante.py --aprender")
        print("Revisa lo que encuentra y de ahi en mas te avisa de lo nuevo.")
        return 2

    def un_escaneo():
        aparatos = hacer_escaneo(args.red, args.sin_nombres)
        nuevos = imprimir_reporte(aparatos, conocidos)
        guardar_reporte(aparatos, nuevos)
        # Actualizar ultima vez visto de los conocidos.
        for d in aparatos:
            if d["mac"] in conocidos:
                conocidos[d["mac"]]["ultima_vez"] = datetime.now().isoformat(timespec="seconds")
                conocidos[d["mac"]]["ip"] = d["ip"]
        guardar_conocidos(conocidos)
        return nuevos

    if args.vigilar and args.vigilar > 0:
        print(f"Vigilancia continua cada {args.vigilar} minutos. Ctrl+C para parar.")
        try:
            while True:
                un_escaneo()
                print(f"Proximo escaneo en {args.vigilar} minutos...")
                time.sleep(args.vigilar * 60)
        except KeyboardInterrupt:
            print("\nVigilancia detenida. 👍")
            return 0

    un_escaneo()
    return 0


if __name__ == "__main__":
    sys.exit(main())
