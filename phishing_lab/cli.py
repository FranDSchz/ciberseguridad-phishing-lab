"""
Módulo de interfaz de línea de comandos (CLI) en español para Phishing Lab.
Permite analizar entradas manuales (URLs, dominios, IPs) y/o archivos .eml,
generando un informe forense estandarizado en formato Markdown.
"""

import argparse
import ipaddress
import os
import re
import sys
from typing import List, Optional
from urllib.parse import urlsplit

from . import __version__
from .extractor import ExtractorIOC
from .models import Procedencia, ResultadoLaboratorio, TipoIOC
from .parser_eml import ParserEML
from .references import ConstructorReferencias
from .reporter import GeneradorInforme
from .timezone_utils import TIMEZONE_NAME, formatear_fecha, obtener_fecha_referencia


def _dominio_valido(valor: str) -> bool:
    """Comprueba sintaxis básica de dominio/IDN sin resolverlo por red."""
    texto = valor.strip().rstrip(".")
    if not texto or len(texto) > 253 or any(ch.isspace() for ch in texto):
        return False
    try:
        ascii_domain = texto.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    labels = ascii_domain.split(".")
    return all(
        0 < len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label) is not None
        for label in labels
    )


def _validar_entradas_manuales(urls, dominios, ips) -> Optional[str]:
    """Valida forma de URL, dominio e IPv4 sin hacer consultas externas."""
    for url in urls or []:
        try:
            partes = urlsplit(url)
            host = partes.hostname
            if partes.scheme.lower() not in {"http", "https", "ftp"} or not host:
                return f"URL inválida (se requiere http, https o ftp con host): {url!r}"
            if partes.username is not None or partes.password is not None:
                return "No se aceptan credenciales incrustadas en una URL."
            try:
                ipaddress.IPv4Address(host)
            except ipaddress.AddressValueError:
                if not _dominio_valido(host):
                    return f"Host de URL inválido: {host!r}"
        except ValueError:
            return f"URL inválida: {url!r}"

    for dominio in dominios or []:
        if not _dominio_valido(dominio):
            return f"Dominio inválido: {dominio!r}"

    for ip in ips or []:
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            return f"Dirección IPv4 inválida: {ip!r}"
    return None


def crear_argument_parser() -> argparse.ArgumentParser:
    """Crea y configura el parser de argumentos de la CLI en español."""
    parser = argparse.ArgumentParser(
        prog="phishing-lab",
        description=(
            "Phishing Lab: Utilidad local forense y pasiva para preparación y análisis de phishing.\n"
            "Extrae URLs, dominios e IPs con procedencia, calcula SHA-256 local, inspecciona cabeceras MIME,\n"
            "detecta indicadores reservados (RFC 2606 / RFC 5737) y construye referencias seguras de consulta\n"
            "hacia VirusTotal, urlscan.io, WHOIS/DNSChecker y crt.sh (sin consultas de red ni veredictos automáticos)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-u",
        "--url",
        action="append",
        dest="urls",
        help="URL manual a analizar (puede repetirse)",
    )

    parser.add_argument(
        "-d",
        "--dominio",
        action="append",
        dest="dominios",
        help="Nombre de dominio manual a analizar (puede repetirse)",
    )

    parser.add_argument(
        "-i",
        "--ip",
        action="append",
        dest="ips",
        help="Dirección IPv4 manual a analizar (puede repetirse)",
    )

    parser.add_argument(
        "-e",
        "--eml",
        type=str,
        dest="eml_path",
        help="Ruta a un archivo de correo .eml para análisis forense pasivo",
    )

    parser.add_argument(
        "-o",
        "--salida",
        type=str,
        dest="salida_path",
        help="Ruta del archivo Markdown donde guardar el informe generado",
    )

    parser.add_argument(
        "--fecha",
        type=str,
        dest="fecha_referencia",
        help=(
            "Fecha/hora de referencia inyectable en formato ISO (ej. '2026-10-16T15:30:00' o '2026-10-16'). "
            f"Por defecto se utiliza la fecha/hora actual en zona horaria {TIMEZONE_NAME}."
        ),
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"Phishing Lab v{__version__}",
    )

    return parser


def ejecutar_analisis(
    urls: Optional[List[str]] = None,
    dominios: Optional[List[str]] = None,
    ips: Optional[List[str]] = None,
    eml_path: Optional[str] = None,
    fecha_referencia: Optional[str] = None,
) -> ResultadoLaboratorio:
    """
    Función orquestadora central del laboratorio.
    Ejecuta el procesamiento pasivo de los datos y devuelve el objeto ResultadoLaboratorio.
    """
    error_entrada = _validar_entradas_manuales(urls, dominios, ips)
    if error_entrada:
        raise ValueError(error_entrada)

    fecha_dt = obtener_fecha_referencia(fecha_referencia)
    fecha_str = formatear_fecha(fecha_dt)

    extractor = ExtractorIOC()
    entradas_manuales = {}
    metadatos_eml = None
    sha256_eml = None

    # 1. Procesar archivo .eml si fue provisto
    if eml_path:
        parser = ParserEML(eml_path)
        metadatos_eml, extractor = parser.procesar(extractor)
        sha256_eml = metadatos_eml.sha256_eml

    # 2. Procesar entradas manuales
    if urls:
        entradas_manuales["URLs"] = urls
        for u in urls:
            extractor.registrar_ioc(u, TipoIOC.URL, Procedencia.MANUAL)
            # Procesar posible host
            extractor.procesar_texto_plano(u, f"{Procedencia.MANUAL} (contenido de URL)")

    if dominios:
        entradas_manuales["Dominios"] = dominios
        for d in dominios:
            extractor.registrar_ioc(d, TipoIOC.DOMINIO, Procedencia.MANUAL)

    if ips:
        entradas_manuales["Direcciones IPv4"] = ips
        for ip in ips:
            extractor.registrar_ioc(ip, TipoIOC.IPV4, Procedencia.MANUAL)

    # 3. Consolidar indicadores
    indicadores = extractor.obtener_indicadores()

    # 4. Generar referencias para los 4 servicios
    constructor_refs = ConstructorReferencias(fecha_str)
    refs_dict = constructor_refs.generar_todas(indicadores)
    lista_referencias = []
    for srv in ["VirusTotal", "urlscan.io", "WHOIS / DNSChecker", "crt.sh"]:
        lista_referencias.extend(refs_dict.get(srv, []))

    # 5. Construir objeto de resultado
    resultado = ResultadoLaboratorio(
        fuentes_analizadas=[
            f"EML: {eml_path}" if eml_path else "",
            f"Manuales: {len(urls or []) + len(dominios or []) + len(ips or [])} elementos",
        ],
        ruta_eml=eml_path,
        sha256_eml=sha256_eml,
        entradas_manuales=entradas_manuales,
        metadatos_eml=metadatos_eml,
        indicadores=indicadores,
        referencias_consulta=lista_referencias,
        fecha_analisis=fecha_str,
        zona_horaria=TIMEZONE_NAME,
        version_herramienta=__version__,
    )

    return resultado


def main(argv: Optional[List[str]] = None) -> int:
    """Punto de entrada de la CLI."""
    parser = crear_argument_parser()
    args = parser.parse_args(argv)

    tiene_entradas = bool(args.urls or args.dominios or args.ips or args.eml_path)
    if not tiene_entradas:
        sys.stderr.write("Error: Debe especificar al menos una entrada (--url, --dominio, --ip o --eml).\n")
        parser.print_help(sys.stderr)
        return 1

    # Validar existencia de archivo .eml si fue especificado
    if args.eml_path and not os.path.exists(args.eml_path):
        sys.stderr.write(f"Error: El archivo .eml especificado no existe: '{args.eml_path}'\n")
        return 1

    error_entrada = _validar_entradas_manuales(args.urls, args.dominios, args.ips)
    if error_entrada:
        sys.stderr.write(f"Error: {error_entrada}\n")
        return 1

    try:
        resultado = ejecutar_analisis(
            urls=args.urls,
            dominios=args.dominios,
            ips=args.ips,
            eml_path=args.eml_path,
            fecha_referencia=args.fecha_referencia,
        )
    except Exception as e:
        sys.stderr.write(f"Error durante el análisis forense: {str(e)}\n")
        return 1

    informe_md = GeneradorInforme(resultado).generar()

    if args.salida_path:
        try:
            directorio_padre = os.path.dirname(os.path.abspath(args.salida_path))
            if directorio_padre and not os.path.exists(directorio_padre):
                os.makedirs(directorio_padre, exist_ok=True)
            with open(args.salida_path, "w", encoding="utf-8") as f:
                f.write(informe_md)
            print(f"[+] Informe forense generado exitosamente en: {args.salida_path}")
        except Exception as e:
            sys.stderr.write(f"Error al escribir el archivo de salida '{args.salida_path}': {str(e)}\n")
            return 1
    else:
        # Imprimir informe en salida estándar
        sys.stdout.write(informe_md + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
