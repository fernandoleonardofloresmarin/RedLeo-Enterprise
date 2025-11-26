
# -*- coding: utf-8 -*-
"""
Leo Enterprise – Network & Security Suite (Single File Demo)
----------------------------------------------------------------
Autor:  Fernando Leonardo Flores Marín
Email:  fernandoleonardofloresmarin@gmail.com
Versión: 2.2-enterprise-demo

Todos los derechos reservados.

Leo Enterprise ha sido desarrollado como una plataforma integral de
MONITOREO, ANÁLISIS y DEFENSA de redes, servidores y entornos de
telecomunicaciones, uniendo prácticas de ingeniería en redes con
ciberseguridad defensiva.

Esta edición está orientada exclusivamente a:
    • Observabilidad de la red y de los equipos.
    • Análisis de rendimiento y estabilidad.
    • Detección de exposición de puertos y servicios.
    • Apoyo al endurecimiento (hardening) mediante reglas de firewall.
    • Auditoría pasiva y generación de información para toma de decisiones.

No incluye funciones de ataque, explotación ni actividades ofensivas y
debe utilizarse únicamente en infraestructuras, equipos o servidores
donde el usuario tenga autorización expresa para administrar,
monitorear y auditar.

Para organizaciones que requieran despliegues a mayor escala, integración
con infraestructuras corporativas o módulos avanzados de análisis y
reportería ejecutiva, existen ediciones empresariales ampliadas. Estas
pueden incluir capacidades extendidas de:
    • Análisis profesional más profundo sobre redes y servidores.
    • Auditoría avanzada orientada a entornos corporativos.
    • Visualización y estadísticas consolidadas para equipos técnicos
      y gerenciales.
    • Generación de reportes ejecutivos y técnicos (por ejemplo, en PDF)
      para documentación y cumplimiento interno.

Para consultas, personalización o licenciamiento empresarial,
comuníquese directamente con Leonardo.
"""

import os
import sys
import time
import json
import socket
import platform
import subprocess
import http.client
from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Tuple

try:
    import psutil
    from ping3 import ping
    from tabulate import tabulate
except ImportError:
    print("[!] Faltan dependencias. Instale con:")
    print("    pip install psutil ping3 tabulate")
    sys.exit(1)

APP_NAME = "Leo Enterprise"
VERSION = "2.2-enterprise-demo"
AUTHOR = "Fernando Leonardo Flores Marín"
SUPPORT_EMAIL = "fernandoleonardofloresmarin@gmail.com"
ACTIVATION_CODE_DEMO = "Programleo21"

HOME = os.path.expanduser("~")
DATA_DIR = os.path.join(HOME, ".redleo_enterprise")
LOG_FILE = os.path.join(DATA_DIR, "redleo_enterprise.log")
PROFILE_FILE = os.path.join(DATA_DIR, "network_profile.json")
ROLE_FILE = os.path.join(DATA_DIR, "profile_role.json")
ACTIVATION_FILE = os.path.join(DATA_DIR, "activation.token")

os.makedirs(DATA_DIR, exist_ok=True)


# ------------------------------------------------------------------
# Utilidades básicas
# ------------------------------------------------------------------

def log(event: str, data: Optional[Dict[str, Any]] = None) -> None:
    try:
        entry = {
            "event": event,
            "data": data or {},
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "version": VERSION,
            "app": APP_NAME,
        }
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def wait():
    input("\nPresione ENTER para continuar...")


def bytes_to_mbps(bps: float) -> float:
    return (bps * 8.0) / 1_000_000.0


def shutil_which(cmd: str) -> Optional[str]:
    try:
        import shutil
    except ImportError:
        return None
    return shutil.which(cmd)


# ------------------------------------------------------------------
# Activación
# ------------------------------------------------------------------

def is_activated() -> bool:
    try:
        if not os.path.exists(ACTIVATION_FILE):
            return False
        token = open(ACTIVATION_FILE, "r", encoding="utf-8").read().strip()
        return bool(token)
    except Exception:
        return False


def save_activation(token: str) -> None:
    with open(ACTIVATION_FILE, "w", encoding="utf-8") as f:
        f.write(token.strip())
    log("ACTIVATED", {"hint": token[:3] + "***"})


def prompt_activation() -> bool:
    if is_activated():
        return True

    print("\n[🔐] " + APP_NAME + " requiere activación.")
    print("     Para una licencia empresarial o código único, contacte al creador:")
    print("     👉", SUPPORT_EMAIL, "\n")

    try:
        import getpass
        code = getpass.getpass("Ingrese su código de activación: ").strip()
    except Exception:
        code = input("Ingrese su código de activación: ").strip()

    if not code:
        print("\n[!] Código vacío. Modo limitado.")
        log("ACTIVATION_FAILED", {"reason": "empty"})
        return False

    if code == ACTIVATION_CODE_DEMO:
        print("\n[✅] Activación aceptada (modo DEMO).")
    else:
        print("\n[✅] Código aceptado. Activación local registrada.")

    save_activation(code)
    return True


# ------------------------------------------------------------------
# Perfil de red
# ------------------------------------------------------------------

@dataclass
class InterfaceInfo:
    name: str
    ip: Optional[str]
    is_up: bool
    speed: Optional[float]
    mtu: Optional[int]
    mac: Optional[str]


def get_interfaces() -> List[InterfaceInfo]:
    interfaces: List[InterfaceInfo] = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for name, st in stats.items():
        ip = None
        mac = None
        for addr in addrs.get(name, []):
            if addr.family == socket.AF_INET:
                ip = addr.address
            elif getattr(socket, "AF_LINK", None) and addr.family == socket.AF_LINK:
                mac = addr.address
            elif getattr(socket, "AF_PACKET", None) and addr.family == socket.AF_PACKET:
                mac = addr.address
        interfaces.append(
            InterfaceInfo(
                name=name,
                ip=ip,
                is_up=st.isup,
                speed=getattr(st, "speed", None),
                mtu=getattr(st, "mtu", None),
                mac=mac,
            )
        )
    return interfaces


def guess_primary_interface() -> Optional[InterfaceInfo]:
    for iface in get_interfaces():
        if iface.is_up and iface.ip:
            return iface
    return None


def save_profile(profile: Dict[str, Any]) -> None:
    with open(PROFILE_FILE, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2)
    log("NETWORK_PROFILE_SAVED", profile)


def load_profile() -> Optional[Dict[str, Any]]:
    if not os.path.exists(PROFILE_FILE):
        return None
    try:
        return json.load(open(PROFILE_FILE, "r", encoding="utf-8"))
    except Exception:
        return None


def has_profile() -> bool:
    return os.path.exists(PROFILE_FILE)


# ------------------------------------------------------------------
# Roles (Hogar / PyME / Empresa)
# ------------------------------------------------------------------

def save_role(role: str) -> None:
    data = {"role": role}
    with open(ROLE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    log("ROLE_SET", data)


def load_role() -> str:
    if not os.path.exists(ROLE_FILE):
        return "PERSONAL"
    try:
        data = json.load(open(ROLE_FILE, "r", encoding="utf-8"))
        return str(data.get("role", "PERSONAL"))
    except Exception:
        return "PERSONAL"


# ------------------------------------------------------------------
# 1) Detección avanzada de red
# ------------------------------------------------------------------

def detect_network() -> None:
    clear()
    print("=== 1) Detección avanzada de red ===\n")
    iface = guess_primary_interface()
    if iface is None or not iface.ip:
        print("[!] No se encontró una interfaz activa con IP.")
        log("DETECT_FAILED", {"reason": "no_iface"})
        wait()
        return

    print(f"[+] Interfaz principal: {iface.name}")
    print(f"    IP: {iface.ip}")
    print(f"    MAC: {iface.mac}")
    print(f"    MTU: {iface.mtu}")
    print(f"    Velocidad teórica (si disponible): {iface.speed} Mbps\n")

    target = "8.8.8.8"
    samples = 10
    latencies: List[float] = []
    lost = 0

    print(f"[+] Midiendo latencia, jitter y pérdida hacia {target}...\n")

    for i in range(samples):
        try:
            r = ping(target, timeout=1.0)
        except PermissionError:
            r = None
        if r is None:
            lost += 1
            print(f"  Muestra {i+1}: timeout")
        else:
            ms = r * 1000.0
            latencies.append(ms)
            print(f"  Muestra {i+1}: {ms:.2f} ms")
        time.sleep(0.2)

    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    jitter = 0.0
    if len(latencies) >= 2:
        diffs = [abs(latencies[i] - latencies[i-1]) for i in range(1, len(latencies))]
        jitter = sum(diffs) / len(diffs)
    loss_pct = (lost / samples) * 100.0

    counters_before = psutil.net_io_counters(pernic=True).get(iface.name)
    time.sleep(1.0)
    counters_after = psutil.net_io_counters(pernic=True).get(iface.name)
    down_bps = up_bps = 0.0
    if counters_before and counters_after:
        down_bps = counters_after.bytes_recv - counters_before.bytes_recv
        up_bps = counters_after.bytes_sent - counters_before.bytes_sent

    profile = {
        "interface": iface.name,
        "ip": iface.ip,
        "mac": iface.mac,
        "mtu": iface.mtu,
        "speed_mbps": iface.speed,
        "avg_latency_ms": round(avg_latency, 2),
        "jitter_ms": round(jitter, 2),
        "packet_loss_pct": round(loss_pct, 1),
        "approx_down_bps": down_bps,
        "approx_up_bps": up_bps,
        "platform": platform.platform(),
    }

    save_profile(profile)

    print("\n[✅] Perfil de red guardado:")
    for k, v in profile.items():
        print(f"   {k}: {v}")
    wait()


# ------------------------------------------------------------------
# 2) Monitor en tiempo real
# ------------------------------------------------------------------

def monitor_realtime(duration: int = 20) -> None:
    clear()
    print("=== 2) Monitor de red en tiempo real ===\n")
    profile = load_profile()
    if not profile:
        print("[!] No hay perfil. Use primero la opción 1 (detección).")
        wait()
        return

    iface_name = profile["interface"]
    print(f"[+] Monitoreando interfaz: {iface_name} durante {duration} segundos.\n")

    prev = psutil.net_io_counters(pernic=True).get(iface_name)
    if not prev:
        print("[!] No se pudieron leer contadores de la interfaz.")
        wait()
        return

    print(" Seg  | Bajada (Mbps)         | Subida (Mbps)")
    print("------+------------------------+------------------------")

    for sec in range(1, duration + 1):
        time.sleep(1.0)
        cur = psutil.net_io_counters(pernic=True).get(iface_name)
        if not cur:
            break
        down_bps = cur.bytes_recv - prev.bytes_recv
        up_bps = cur.bytes_sent - prev.bytes_sent
        prev = cur
        print(f"{sec:4} | {bytes_to_mbps(down_bps):8.3f}              | {bytes_to_mbps(up_bps):8.3f}")

    log("MONITOR_REALTIME", {"duration": duration, "iface": iface_name})
    wait()


# ------------------------------------------------------------------
# 3) Optimización automática de red (sin preguntar)
# ------------------------------------------------------------------

def auto_optimize_network() -> None:
    clear()
    print("=== 3) Optimización automática de red ===\n")
    print("[⚙] RedLeo Enterprise aplicará acciones básicas de optimización en este equipo.")
    print("    Esto puede incluir limpieza de DNS y renovación de direcciones.\n")

    if os.name == "nt":
        cmds = [
            ["ipconfig", "/flushdns"],
            ["ipconfig", "/release"],
            ["ipconfig", "/renew"],
        ]
    else:
        cmds = []
        if shutil_which("systemctl"):
            cmds.append(["sudo", "systemctl", "restart", "NetworkManager"])

    for cmd in cmds:
        try:
            print("Ejecutando:", " ".join(cmd))
            subprocess.run(cmd, check=False)
        except Exception as e:
            print("[!] Error al ejecutar", cmd, "->", e)

    print("\n[✅] Proceso de optimización automática completado (nivel básico).")
    print("    Revise la conectividad; en entornos críticos use ventanas de mantenimiento.")
    log("AUTO_OPTIMIZE", {"platform": platform.system()})
    wait()


# ------------------------------------------------------------------
# 4) Escaneo de puertos y análisis de riesgo
# ------------------------------------------------------------------

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080]

RISKY_PORTS = {
    21: "FTP sin cifrado.",
    23: "Telnet sin cifrado.",
    25: "SMTP expuesto sin medidas anti-spam.",
    445: "SMB expuesto; objetivo frecuente de ransomware.",
    3389: "RDP expuesto; debe restringirse y protegerse con MFA/VPN.",
}


def scan_ports_tcp(ip: str, ports: List[int], timeout: float = 0.5) -> Dict[int, str]:
    result: Dict[int, str] = {}
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, p))
            result[p] = "open"
        except (socket.timeout, ConnectionRefusedError, OSError):
            result[p] = "closed"
        finally:
            s.close()
    log("PORT_SCAN", {"target": ip, "open_ports": [p for p, st in result.items() if st == "open"]})
    return result


def analyze_risk(ports: Dict[int, str]) -> Dict[str, Any]:
    open_ports = [p for p, s in ports.items() if s == "open"]
    score = 0
    reasons: List[str] = []

    if not open_ports:
        reasons.append("No se detectaron puertos abiertos en el rango analizado.")
        return {"level": "bajo", "score": score, "reasons": reasons, "open_ports": open_ports}

    if len(open_ports) > 7:
        score += 2
        reasons.append("Muchos puertos abiertos; revise la superficie de exposición.")

    for p in open_ports:
        if p in RISKY_PORTS:
            score += 4
            reasons.append(f"Puerto crítico {p} abierto: {RISKY_PORTS[p]}")

    if score <= 3:
        level = "bajo"
    elif score <= 7:
        level = "medio"
    else:
        level = "alto"

    analysis = {"level": level, "score": score, "reasons": reasons, "open_ports": open_ports}
    log("RISK_ANALYSIS", analysis)
    return analysis


def option_vuln_scan() -> None:
    clear()
    print("=== 4) Escaneo de puertos y análisis de riesgo (host/servidor) ===\n")
    ip = input("Ingrese la IP a analizar (servidor / equipo actual): ").strip()
    if not ip:
        print("[!] IP inválida.")
        wait()
        return

    print(f"\n[+] Escaneando puertos comunes en {ip}...\n")
    result = scan_ports_tcp(ip, COMMON_PORTS)

    rows = [[p, st] for p, st in sorted(result.items())]
    print(tabulate(rows, headers=["Puerto", "Estado"], tablefmt="grid"))

    analysis = analyze_risk(result)
    print("\n[+] Nivel de riesgo:", analysis["level"].upper())
    print("    Puntaje:", analysis["score"])
    if analysis["reasons"]:
        print("\n[Motivos]:")
        for r in analysis["reasons"]:
            print(" -", r)

    if analysis["open_ports"]:
        print("\n[Recomendaciones]:")
        print(" - Limite el acceso a estos puertos solo desde redes o IPs de confianza.")
        print(" - Aplique firewall a nivel host y perimetral.")
    else:
        print("\nNo se detectaron puertos abiertos en el conjunto analizado.")

    print("\n* Esta función es defensiva: analiza exposición de puertos y recomienda endurecimiento.")
    wait()


# ------------------------------------------------------------------
# 5) Escudo de firewall RedLeo (pared de fuego)
# ------------------------------------------------------------------

def firewall_shield() -> None:
    clear()
    print("=== 5) Escudo de firewall RedLeo ===\n")
    print("[🛡] RedLeo intentará aplicar una configuración de firewall defensiva.")
    print("     Esto ayuda a reducir superficie de ataque en equipos y servidores.\n")

    if os.name == "nt":
        cmds = [
            ["netsh", "advfirewall", "set", "currentprofile", "state", "on"],
        ]
        for cmd in cmds:
            try:
                print("Ejecutando:", " ".join(cmd))
                subprocess.run(cmd, check=False)
            except Exception as e:
                print("[!] Error al ejecutar", cmd, "->", e)

        print("\nOpcional: reglas sugeridas para puertos críticos (solo si no los usa).")
        ans = input("¿Aplicar reglas de bloqueo para puertos críticos (21,23,445,3389)? (s/n): ").strip().lower()
        if ans == "s":
            extra_cmds = [
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 "name=RedLeo_Bloquear_21", "dir=in", "action=block", "protocol=TCP", "localport=21"],
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 "name=RedLeo_Bloquear_23", "dir=in", "action=block", "protocol=TCP", "localport=23"],
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 "name=RedLeo_Bloquear_445", "dir=in", "action=block", "protocol=TCP", "localport=445"],
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 "name=RedLeo_Bloquear_3389", "dir=in", "action=block", "protocol=TCP", "localport=3389"],
            ]
            for cmd in extra_cmds:
                try:
                    print("Ejecutando:", " ".join(cmd))
                    subprocess.run(cmd, check=False)
                except Exception as e:
                    print("[!] Error al ejecutar", cmd, "->", e)
            log("FIREWALL_HARDEN_EXTRA", {"platform": "windows"})
        log("FIREWALL_SHIELD", {"platform": "windows"})
        print("\n[✅] Firewall verificado/habilitado. Revise compatibilidad con sus servicios.")
    else:
        if shutil_which("ufw"):
            cmds = [
                ["sudo", "ufw", "default", "deny", "incoming"],
                ["sudo", "ufw", "default", "allow", "outgoing"],
                ["sudo", "ufw", "allow", "ssh"],
                ["sudo", "ufw", "enable"],
            ]
            for cmd in cmds:
                try:
                    print("Ejecutando:", " ".join(cmd))
                    subprocess.run(cmd, check=False)
                except Exception as e:
                    print("[!] Error al ejecutar", cmd, "->", e)

            ans = input("\n¿Desea añadir reglas UFW para bloquear puertos críticos (21,23,445,3389)? (s/n): ").strip().lower()
            if ans == "s":
                extra_cmds = [
                    ["sudo", "ufw", "deny", "21/tcp"],
                    ["sudo", "ufw", "deny", "23/tcp"],
                    ["sudo", "ufw", "deny", "445/tcp"],
                    ["sudo", "ufw", "deny", "3389/tcp"],
                ]
                for cmd in extra_cmds:
                    try:
                        print("Ejecutando:", " ".join(cmd))
                        subprocess.run(cmd, check=False)
                    except Exception as e:
                        print("[!] Error al ejecutar", cmd, "->", e)
                log("FIREWALL_HARDEN_EXTRA", {"platform": "linux_ufw"})
            log("FIREWALL_SHIELD", {"platform": "linux_ufw"})
            print("\n[✅] Reglas básicas aplicadas en UFW (revise su configuración detallada).")
        else:
            print("[!] No se encontró UFW. Configure iptables/nftables manualmente según políticas.")
            log("FIREWALL_SHIELD", {"platform": "linux_no_ufw"})
    print("\nNota: Ningún firewall garantiza 0 puntos ciegos. Use defensa en capas.")
    wait()


# ------------------------------------------------------------------
# 6) Auditoría pasiva de seguridad del host
# ------------------------------------------------------------------

def passive_security_audit() -> None:
    clear()
    print("=== 6) Auditoría pasiva de seguridad del host ===\n")
    issues: List[str] = []

    try:
        conns = psutil.net_connections()
        listening = [c for c in conns if c.status == psutil.CONN_LISTEN]
        if len(listening) > 25:
            issues.append("Se detectan muchos servicios en escucha; revise qué realmente es necesario.")
    except Exception:
        pass

    if platform.system().lower().startswith("win"):
        issues.append("Verifique que el firewall de Windows esté activo en todos los perfiles.")
    else:
        issues.append("Compruebe que iptables/nftables/ufw esté configurado según su política de seguridad.")

    if not issues:
        issues.append("No se detectaron hallazgos significativos en esta revisión rápida.")

    for i, issue in enumerate(issues, 1):
        print(f"{i}. {issue}")

    log("PASSIVE_AUDIT", {"issues": issues})
    wait()


# ------------------------------------------------------------------
# 7) Dispositivos conectados (ARP) + diagnóstico básico
# ------------------------------------------------------------------

OUI_VENDORS = {
    "00:1A:2B": "Cisco",
    "F4:EC:38": "TP-Link",
    "C8:D7:19": "Huawei",
    "10:13:31": "MikroTik",
    "D4:6E:0E": "Ubiquiti",
    "3C:37:86": "ZTE",
    "BC:14:01": "Netgear",
    "F8:1A:67": "Arris",
}


def guess_vendor(mac: str) -> str:
    mac = mac.upper().replace("-", ":")
    parts = mac.split(":")
    if len(parts) >= 3:
        prefix = ":".join(parts[:3])
        return OUI_VENDORS.get(prefix, "Desconocido")
    return "Desconocido"


def ping_host(ip: str, samples: int = 2, timeout: float = 0.8) -> Tuple[float, float]:
    latencies: List[float] = []
    lost = 0
    for _ in range(samples):
        try:
            r = ping(ip, timeout=timeout)
        except PermissionError:
            r = None
        if r is None:
            lost += 1
        else:
            latencies.append(r * 1000.0)
        time.sleep(0.1)
    avg = sum(latencies) / len(latencies) if latencies else 0.0
    loss = (lost / samples) * 100.0
    return avg, loss


def discover_devices() -> None:
    clear()
    print("=== 7) Dispositivos conectados (tabla ARP + diagnóstico) ===\n")

    devices: List[Tuple[str, str]] = []

    cmd = ["arp", "-a"]
    try:
        out = subprocess.check_output(cmd, text=True, errors="ignore")
        for line in out.splitlines():
            if "-" in line or ":" in line:
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    mac = parts[1]
                    devices.append((ip, mac))
    except Exception as e:
        print("[!] No se pudo leer la tabla ARP:", e)
        wait()
        return

    if not devices:
        print("No se detectaron dispositivos en la tabla ARP.")
        wait()
        return

    rows = []
    for ip, mac in devices:
        vendor = guess_vendor(mac)
        avg, loss = ping_host(ip)
        if loss >= 70 or avg > 200:
            calidad = "Muy lenta / inestable"
        elif loss > 30 or avg > 120:
            calidad = "Lenta"
        else:
            calidad = "Aceptable"
        rows.append([ip, mac, vendor, f"{avg:.1f} ms", f"{loss:.0f} %", calidad])

    print(tabulate(rows, headers=["IP", "MAC", "Vendor aprox", "Latencia", "Pérdida", "Calidad"], tablefmt="grid"))
    print("\n* Esta vista puede ayudar a un administrador a ver clientes/routers lentos o inestables.")
    log("ARP_DISCOVERY_DIAG", {"count": len(devices)})
    wait()


# ------------------------------------------------------------------
# 8) Información del router / gateway
# ------------------------------------------------------------------

def guess_gateway_ip() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        return None
    parts = local_ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3] + ["1"])
    return None


def router_info() -> None:
    clear()
    print("=== 8) Información del router / gateway ===\n")
    gw = guess_gateway_ip()
    if not gw:
        print("[!] No se pudo estimar el gateway.")
        wait()
        return

    print(f"[+] Posible gateway: {gw}")
    hostname = None
    try:
        hostname, _, _ = socket.gethostbyaddr(gw)
    except Exception:
        hostname = None
    if hostname:
        print(f"   Nombre/host del router (DNS inverso): {hostname}")
    info = {"ip": gw, "server": None, "hostname": hostname}

    try:
        conn = http.client.HTTPConnection(gw, 80, timeout=2.0)
        conn.request("GET", "/")
        resp = conn.getresponse()
        server = resp.getheader("Server")
        if server:
            info["server"] = server
        conn.close()
    except Exception:
        pass

    if info["server"]:
        print("   Cabecera HTTP del servidor:", info["server"])
    else:
        print("   No se obtuvo información HTTP. Muchos routers la ocultan.")

    print("\nRecomendaciones generales:")
    print(" - Cambie credenciales por defecto del router.")
    print(" - Desactive administración remota si no es necesaria.")
    print(" - Mantenga firmware actualizado.")
    log("ROUTER_INFO", info)
    wait()


# ------------------------------------------------------------------
# 9) Configuración de red + Rol + Asistente router
# ------------------------------------------------------------------

def router_access_assistant() -> None:
    print("\n[Asistente de acceso al router]")
    gw = guess_gateway_ip()
    if gw:
        print(f"Posible IP del router: {gw}")
        print("Abra en el navegador:")
        print(f"  http://{gw}  o  https://{gw}")
    else:
        print("No se pudo adivinar la IP del router. Use su IP de gateway manual.")
    print("\nSolo acceda a routers que administre o donde tenga autorización.")

    print("\nEjemplos de usuarios habituales (debe cambiar estas credenciales por algo fuerte):")
    print(" - admin / admin")
    print(" - admin / password")
    print(" - usuario / clave")
    print("\nRecomendación:")
    print(" - Una vez dentro, cambie usuario y contraseña por valores robustos.")
    log("ROUTER_ASSISTANT_VIEWED", {})


def network_config_tools() -> None:
    clear()
    print("=== 9) Herramientas de configuración de red ===\n")
    profile = load_profile()
    if profile:
        print("[Perfil RedLeo Enterprise]:")
        for k, v in profile.items():
            print(f"   {k}: {v}")
    else:
        print("[!] No hay perfil cargado.\n")

    role = load_role()
    print("\nRol actual de este equipo/servidor:", role)
    print("Opciones de rol:")
    print(" 1) PERSONAL / HOGAR")
    print(" 2) PyME")
    print(" 3) EMPRESA / DATA CENTER")
    print(" 4) Dejar como está")
    sub = input("\nSeleccione una opción de rol: ").strip()

    if sub == "1":
        save_role("PERSONAL")
    elif sub == "2":
        save_role("PYME")
    elif sub == "3":
        save_role("ENTERPRISE")

    print("\n[Configuración de red del sistema]\n")
    if os.name == "nt":
        subprocess.run(["ipconfig"], check=False)
    else:
        if shutil_which("ip"):
            subprocess.run(["ip", "addr"], check=False)
        else:
            subprocess.run(["ifconfig"], check=False)

    print("\nOpciones adicionales:")
    print(" 1) Asistente de acceso al router")
    print(" 2) Información sobre uso de VPN")
    print(" 3) Volver")
    extra = input("\nSeleccione una opción adicional: ").strip()
    if extra == "1":
        router_access_assistant()
    elif extra == "2":
        print("\n[VPN]:")
        print(" RedLeo Enterprise no crea túneles VPN, pero convive con soluciones VPN empresariales.")
        print(" Use clientes oficiales de su proveedor VPN o de su empresa.")
        log("VPN_INFO_VIEWED", {})
    log("NETCONFIG_ROLE", {"role": load_role(), "extra": extra})
    wait()


# ------------------------------------------------------------------
# 10) Analizador de tráfico (30s)
# ------------------------------------------------------------------

def traffic_analyzer() -> None:
    clear()
    print("=== 10) Analizador de tráfico (30s) ===\n")
    profile = load_profile()
    if not profile:
        print("[!] No hay perfil. Use primero la opción 1.")
        wait()
        return

    iface_name = profile["interface"]
    print(f"[+] Midiendo tráfico de {iface_name} durante 30 segundos...\n")
    prev = psutil.net_io_counters(pernic=True).get(iface_name)
    if not prev:
        print("[!] No se pudieron leer contadores.")
        wait()
        return

    samples: List[Tuple[float, float]] = []
    for _ in range(30):
        time.sleep(1.0)
        cur = psutil.net_io_counters(pernic=True).get(iface_name)
        if not cur:
            break
        down = cur.bytes_recv - prev.bytes_recv
        up = cur.bytes_sent - prev.bytes_sent
        prev = cur
        samples.append((down, up))

    if not samples:
        print("[!] No se obtuvieron muestras.")
        wait()
        return

    avg_down = sum(d for d, _ in samples) / len(samples)
    avg_up = sum(u for _, u in samples) / len(samples)
    peak_down = max(d for d, _ in samples)
    peak_up = max(u for _, u in samples)

    print("Promedio bajada:", f"{bytes_to_mbps(avg_down):.3f}", "Mbps")
    print("Promedio subida:", f"{bytes_to_mbps(avg_up):.3f}", "Mbps")
    print("Pico bajada:", f"{bytes_to_mbps(peak_down):.3f}", "Mbps")
    print("Pico subida:", f"{bytes_to_mbps(peak_up):.3f}", "Mbps")
    log("TRAFFIC_ANALYZER", {"samples": len(samples)})
    wait()


# ------------------------------------------------------------------
# 11) Reporte ejecutivo
# ------------------------------------------------------------------


# Función de exportación de reporte a PDF (opcional, defensiva/ejecutiva)
def export_report_pdf(profile: Optional[Dict[str, Any]], role: str) -> None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError:
        print("\n[!] No se encontró la librería 'reportlab'. Si desea exportar a PDF, instale primero:")
        print("    pip install reportlab")
        return

    pdf_path = os.path.join(DATA_DIR, "leo_enterprise_report.pdf")
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4

    y = height - 50
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "Leo Enterprise – Network & Security Report")
    y -= 24
    c.setFont("Helvetica", 10)
    c.drawString(40, y, f"Autor: {AUTHOR}")
    y -= 14
    c.drawString(40, y, f"Versión: {VERSION}")
    y -= 14
    c.drawString(40, y, f"Rol de entorno: {role}")
    y -= 24

    if profile:
        c.setFont("Helvetica-Bold", 11)
        c.drawString(40, y, "Perfil de red detectado:")
        y -= 18
        c.setFont("Helvetica", 10)
        for k, v in profile.items():
            line = f"- {k}: {v}"
            c.drawString(50, y, line[:110])
            y -= 14
            if y < 80:
                c.showPage()
                y = height - 50
    else:
        c.drawString(40, y, "No hay perfil de red guardado.")
        y -= 18

    y -= 10
    c.setFont("Helvetica-Bold", 11)
    c.drawString(40, y, "Notas:")
    y -= 16
    c.setFont("Helvetica", 10)
    notes = [
        "Este reporte ha sido generado por Leo Enterprise como resumen",
        "técnico de red y entorno. No reemplaza una auditoría formal de",
        "ciberseguridad ni garantiza seguridad absoluta.",
    ]
    for n in notes:
        c.drawString(50, y, n)
        y -= 14
        if y < 80:
            c.showPage()
            y = height - 50

    c.showPage()
    c.save()
    print(f"\n[✅] Reporte PDF generado en: {pdf_path}")
    log("REPORT_PDF_GENERATED", {"path": pdf_path})


def quick_report() -> None:
    clear()
    print("=== 11) Reporte ejecutivo de RedLeo Enterprise ===\n")

    profile = load_profile()
    role = load_role()

    print("RedLeo Enterprise – Network & Security Report")
    print("Autor:", AUTHOR)
    print("Versión:", VERSION)
    print("Rol:", role)
    print("-" * 60)

    if profile:
        print("\n[Perfil de red detectado]")
        for k, v in profile.items():
            print(f" - {k}: {v}")
    else:
        print("\nNo hay perfil de red guardado. Ejecute la detección primero.")

    print("\n[Ubicación del archivo de log]")
    print(" -", LOG_FILE)

    print("\nUse este reporte como base para documentación técnica o auditorías internas.")

    choice = input("\n¿Desea exportar este reporte en PDF? (s/n): ").strip().lower()
    if choice == "s":
        export_report_pdf(profile, role)

    log("REPORT_VIEWED", {})
    wait()


# ------------------------------------------------------------------
# 12) Checklist de seguridad / hardening
# ------------------------------------------------------------------

SECURITY_TIPS = [
    "Mantener SO, firmware y aplicaciones siempre actualizados.",
    "Deshabilitar servicios y puertos que no sean estrictamente necesarios.",
    "Aplicar principio de mínimo privilegio en cuentas, grupos y servicios.",
    "Proteger accesos administrativos con MFA y/o VPN.",
    "Segmentar la red (VLANs) para separar usuarios, servidores y entornos críticos.",
    "Implementar copias de seguridad regulares, probando su restauración.",
    "Centralizar logs y monitorizar eventos de seguridad.",
    "Limitar acceso físico a equipos y salas de comunicaciones.",
    "Documentar cambios en la infraestructura y revisarlos periódicamente.",
]


def security_checklist() -> None:
    clear()
    print("=== 12) Checklist de seguridad / hardening ===\n")
    for i, tip in enumerate(SECURITY_TIPS, 1):
        print(f"{i}. {tip}")
    print("\nUse este checklist como punto de partida; complemente con estándares (ISO 27001, CIS, etc.).")
    log("SECURITY_CHECKLIST", {"count": len(SECURITY_TIPS)})
    wait()


# ------------------------------------------------------------------
# 13) Estado y logs
# ------------------------------------------------------------------

def status_and_logs() -> None:
    clear()
    print("=== 13) Estado y logs de RedLeo Enterprise ===\n")
    print("Directorio de datos:", DATA_DIR)
    print("Archivo de log:", LOG_FILE)
    print("Perfil de red:", PROFILE_FILE)
    print("Rol:", load_role())
    print("Activation token:", ACTIVATION_FILE)
    print("\nPuede revisar el log (JSON por línea) para ver histórico de eventos.")
    log("STATUS_VIEWED", {})
    wait()


# ------------------------------------------------------------------
# 14) Modo ofensivo (BLOQUEADO)
# ------------------------------------------------------------------

def offensive_mode_blocked() -> None:
    clear()
    print("=== 14) Modo ofensivo (BLOQUEADO) ===\n")
    print("Esta versión de RedLeo Enterprise se centra en DEFENSA y MONITOREO.")
    print("No incluye ni incluirá funciones de ataque o explotación.")
    print("\nEl creador,", AUTHOR + ", NO ha habilitado esta opción en esta edición.")
    print("Para alianzas empresariales y desarrollo de soluciones avanzadas:")
    print("   ", SUPPORT_EMAIL)
    log("OFFENSIVE_MODE_ACCESSED", {})
    wait()


# ------------------------------------------------------------------
# Interfaz principal
# ------------------------------------------------------------------

LOGO = r"""
██╗     ███████╗ ██████╗ 
██║     ██╔════╝██╔═══██╗
██║     █████╗  ██║   ██║
██║     ██╔══╝  ██║   ██║
███████╗███████╗╚██████╔╝
╚══════╝╚══════╝ ╚═════╝ 

        Leo Enterprise – Network & Security Suite
"""


def main_menu(initial: bool) -> str:
    clear()
    print(LOGO)
    print(f"\nVersión: {VERSION}   Autor: {AUTHOR}")
    print("Email:", SUPPORT_EMAIL)
    print("Datos y logs en:", DATA_DIR)
    print("-" * 70)
    if initial and not has_profile():
        print("[1] Detectar red y crear perfil (OBLIGATORIO)")
        print("[0] Salir")
        return input("\nSeleccione una opción: ").strip()

    print("[ 1] Detectar/actualizar perfil de red")
    print("[ 2] Monitor de red en tiempo real")
    print("[ 3] Optimización automática de red")
    print("[ 4] Escaneo de puertos / análisis de riesgo")
    print("[ 5] Escudo de firewall RedLeo (pared de fuego)")
    print("[ 6] Auditoría pasiva de seguridad del host")
    print("[ 7] Dispositivos conectados + diagnóstico (ARP)")
    print("[ 8] Información del router / gateway")
    print("[ 9] Configuración de red, rol y acceso a router")
    print("[10] Analizador de tráfico (30s)")
    print("[11] Reporte ejecutivo")
    print("[12] Checklist de seguridad / hardening")
    print("[13] Estado y ubicación de logs")
    print("[14] (Bloqueado) Modo ofensivo")
    print("[ 0] Salir")
    return input("\nSeleccione una opción: ").strip()


def main():
    activated = prompt_activation()
    if not activated:
        print("\n[!] RedLeo Enterprise seguirá funcionando, pero algunas funciones pueden ser limitadas.\n")
        time.sleep(1.5)

    while not has_profile():
        choice = main_menu(initial=True)
        if choice == "1":
            detect_network()
        elif choice == "0":
            print("\nSaliendo de RedLeo Enterprise.\n")
            return
        else:
            print("\nOpción inválida.")
            time.sleep(1.0)

    while True:
        choice = main_menu(initial=False)
        if choice == "1":
            detect_network()
        elif choice == "2":
            monitor_realtime()
        elif choice == "3":
            auto_optimize_network()
        elif choice == "4":
            option_vuln_scan()
        elif choice == "5":
            firewall_shield()
        elif choice == "6":
            passive_security_audit()
        elif choice == "7":
            discover_devices()
        elif choice == "8":
            router_info()
        elif choice == "9":
            network_config_tools()
        elif choice == "10":
            traffic_analyzer()
        elif choice == "11":
            quick_report()
        elif choice == "12":
            security_checklist()
        elif choice == "13":
            status_and_logs()
        elif choice == "14":
            offensive_mode_blocked()
        elif choice == "0":
            print("\nSaliendo de RedLeo Enterprise.\n")
            break
        else:
            print("\nOpción inválida.")
            time.sleep(1.0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupción por el usuario. Cerrando RedLeo Enterprise.\n")
