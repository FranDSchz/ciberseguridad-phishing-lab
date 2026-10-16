"""
Módulo de evaluación y clasificación de indicadores reservados y funciones de sanitización (defanging).
Detecta dominios de ejemplo (RFC 2606 y RFC 6761) y rangos IPv4 de documentación (RFC 5737 TEST-NET-1/2/3)
y redes especiales (RFC 1918, Loopback, etc.).
"""

import ipaddress
import re
from typing import Optional, Tuple
from .models import TipoIOC

# TLDs reservados según RFC 2606 y RFC 6761
TLDS_RESERVADOS = {
    "example",
    "invalid",
    "localhost",
    "test",
}

# Dominios de segundo nivel reservados para documentación y ejemplos
DOMINIOS_BASE_RESERVADOS = {
    "example.com",
    "example.net",
    "example.org",
}

# Redes IPv4 especiales y de documentación
REDES_IPV4_RESERVADAS = [
    (ipaddress.IPv4Network("255.255.255.255/32"), "Broadcast limitado (RFC 919)"),
    (ipaddress.IPv4Network("192.0.2.0/24"), "TEST-NET-1 (RFC 5737 - Documentación y ejemplos)"),
    (ipaddress.IPv4Network("198.51.100.0/24"), "TEST-NET-2 (RFC 5737 - Documentación y ejemplos)"),
    (ipaddress.IPv4Network("203.0.113.0/24"), "TEST-NET-3 (RFC 5737 - Documentación y ejemplos)"),
    (ipaddress.IPv4Network("127.0.0.0/8"), "Loopback / Dirección local (RFC 1122)"),
    (ipaddress.IPv4Network("10.0.0.0/8"), "IPv4 Privada Clase A (RFC 1918)"),
    (ipaddress.IPv4Network("172.16.0.0/12"), "IPv4 Privada Clase B (RFC 1918)"),
    (ipaddress.IPv4Network("192.168.0.0/16"), "IPv4 Privada Clase C (RFC 1918)"),
    (ipaddress.IPv4Network("169.254.0.0/16"), "Enlace Local / Link-Local (RFC 3927)"),
    (ipaddress.IPv4Network("100.64.0.0/10"), "NAT de Nivel Operador / CGNAT (RFC 6598)"),
    (ipaddress.IPv4Network("198.18.0.0/15"), "Pruebas de Rendimiento / Benchmarking (RFC 2544)"),
    (ipaddress.IPv4Network("224.0.0.0/4"), "Multicast (RFC 5771)"),
    (ipaddress.IPv4Network("240.0.0.0/4"), "Reservado para uso futuro / Clase E (RFC 1112)"),
    (ipaddress.IPv4Network("0.0.0.0/8"), "Red actual / 'Este host' (RFC 1122)"),
]


def evaluar_dominio_reservado(dominio: str) -> Tuple[bool, Optional[str]]:
    """
    Determina si un dominio corresponde a nombres reservados para pruebas o documentación
    conforme a RFC 2606 y RFC 6761 (.example, .invalid, .localhost, .test, example.com, etc.).
    """
    if not dominio:
        return False, None

    # Limpieza básica
    dom = dominio.strip().lower().rstrip(".")
    if not dom:
        return False, None

    # Extraer el TLD
    partes = dom.split(".")
    tld = partes[-1]
    if tld in TLDS_RESERVADOS:
        return True, f"TLD reservado para pruebas/documentación: .{tld} (RFC 2606 / RFC 6761)"

    # Comprobar dominios base reservados (example.com, etc.)
    for base in DOMINIOS_BASE_RESERVADOS:
        if dom == base or dom.endswith("." + base):
            return True, f"Dominio reservado de ejemplo: {base} (RFC 2606 / RFC 6761)"

    return False, None


def evaluar_ip_reservada(ip_str: str) -> Tuple[bool, Optional[str]]:
    """
    Determina si una dirección IPv4 pertenece a rangos de documentación TEST-NET (RFC 5737)
    o rangos especiales reservados (RFC 1918, RFC 1122, etc.).
    """
    if not ip_str:
        return False, None

    try:
        direccion = ipaddress.IPv4Address(ip_str.strip())
    except (ipaddress.AddressValueError, ValueError):
        return False, None

    for red, descripcion in REDES_IPV4_RESERVADAS:
        if direccion in red:
            return True, descripcion

    return False, None


def es_indicador_reservado(valor: str, tipo: TipoIOC) -> Tuple[bool, Optional[str]]:
    """
    Función de conveniencia para evaluar el carácter reservado de cualquier IOC.
    """
    if tipo == TipoIOC.DOMINIO:
        return evaluar_dominio_reservado(valor)
    elif tipo == TipoIOC.IPV4:
        return evaluar_ip_reservada(valor)
    elif tipo == TipoIOC.URL:
        # Extraer el host para evaluar
        from urllib.parse import urlparse
        try:
            parsed = urlparse(valor)
            host = parsed.hostname or ""
            # Si el host es IP
            es_ip, desc_ip = evaluar_ip_reservada(host)
            if es_ip:
                return True, f"Host de URL en rango reservado: {desc_ip}"
            es_dom, desc_dom = evaluar_dominio_reservado(host)
            if es_dom:
                return True, f"Host de URL en dominio reservado: {desc_dom}"
        except Exception:
            pass
    elif tipo == TipoIOC.EMAIL:
        if "@" in valor:
            _, _, dom = valor.partition("@")
            return evaluar_dominio_reservado(dom)

    return False, None


def defang_ioc(valor: str, tipo: TipoIOC) -> str:
    """
    Convierte un IOC en su representación segura (defanged) para evitar clics accidentales
    o ejecución en herramientas que no diferencien texto de hipervínculos activos.
    """
    if not valor:
        return ""

    if tipo == TipoIOC.URL:
        # Reemplazar esquema http/https por hxxp/hxxps
        res = re.sub(r"^https://", "hxxps://", valor, flags=re.IGNORECASE)
        res = re.sub(r"^http://", "hxxp://", res, flags=re.IGNORECASE)
        res = re.sub(r"^ftp://", "fxp://", res, flags=re.IGNORECASE)
        # Sustituir puntos en el dominio
        partes = res.split("/", 3)
        if len(partes) >= 3:
            partes[2] = partes[2].replace(".", "[.]")
            return "/".join(partes)
        return res.replace(".", "[.]")

    elif tipo in (TipoIOC.DOMINIO, TipoIOC.IPV4):
        return valor.replace(".", "[.]")

    elif tipo == TipoIOC.EMAIL:
        if "@" in valor:
            user, _, domain = valor.partition("@")
            return f"{user}[@]{domain.replace('.', '[.]')}"
        return valor.replace(".", "[.]")

    return valor


def analizar_punycode(texto: str) -> Optional[str]:
    """
    Inspecciona si una cadena contiene representaciones Punycode (xn--) o caracteres IDN,
    y devuelve una descripción con su contraparte decodificada/codificada.
    """
    if not texto:
        return None

    from urllib.parse import urlsplit

    try:
        parsed = urlsplit(texto if "://" in texto else f"//{texto}")
        host = (parsed.hostname or "").rstrip(".")
    except ValueError:
        return None
    if not host:
        return None

    if host.isascii():
        labels = host.split(".")
        partes = []
        for label in labels:
            if not label.lower().startswith("xn--"):
                continue
            try:
                decodificado = label.encode("ascii").decode("idna")
                roundtrip = decodificado.encode("idna").decode("ascii").lower()
                if roundtrip != label.lower():
                    partes.append(f"Punycode detectado sin decodificación validada: '{label}'")
                else:
                    partes.append(f"Punycode '{label}' decodifica a Unicode: '{decodificado}'")
            except (UnicodeError, ValueError):
                partes.append(f"Punycode detectado sin decodificación validada: '{label}'")
        return "; ".join(partes) if partes else None

    try:
        ascii_host = host.encode("idna").decode("ascii")
        return f"Host Unicode (IDN). Representación Punycode del host: '{ascii_host}'"
    except (UnicodeError, ValueError):
        return "Host con caracteres internacionales (IDN); conversión no concluyente."
