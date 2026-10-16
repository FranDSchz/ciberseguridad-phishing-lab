"""
Módulo de interfaz de línea de comandos (CLI) en español para Phishing Lab.
Permite analizar entradas manuales (URLs, dominios, IPs) y/o archivos .eml,
generando un informe forense estandarizado en formato Markdown.
"""

import argparse
import ipaddress
import json
import mimetypes
import os
import re
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlsplit

from . import __version__
from .artifacts import describir_archivo
from .extractor import ExtractorIOC
from .models import ArchivoAnalizado, Procedencia, ResultadoLaboratorio, TipoIOC
from .online_lookups import OnlineLookupClient
from .parser_eml import ParserEML
from .references import ConstructorReferencias
from .reporter import GeneradorInforme
from .timezone_utils import TIMEZONE_NAME, formatear_fecha, obtener_fecha_referencia
from .verdict import evaluar_recursos


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
            "Phishing Lab: análisis estático local de correos, indicadores y archivos, con consultas API opcionales.\n"
            "Por defecto no realiza conexiones de red. --consultar-apis envía indicadores seleccionados a servicios\n"
            "externos para consultar reportes existentes; no sube muestras ni visita URLs."
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
        "-a",
        "--archivo",
        action="append",
        dest="archivos_path",
        help="Ruta a un archivo para cálculo local de SHA-256 y detección básica por firma (puede repetirse)",
    )

    parser.add_argument(
        "--consultar-apis",
        action="store_true",
        dest="consultar_apis",
        help=(
            "Consulta reportes existentes en VirusTotal, urlscan.io, RDAP, DNS-over-HTTPS y crt.sh. "
            "Revela los indicadores consultados a esos servicios; nunca sube los archivos ni visita sus URLs."
        ),
    )

    parser.add_argument(
        "-o",
        "--salida",
        type=str,
        dest="salida_path",
        help="Ruta del archivo Markdown donde guardar el informe generado",
    )

    parser.add_argument(
        "--salida-json",
        type=str,
        dest="salida_json_path",
        help="Ruta opcional para guardar el JSON completo, incluidas las respuestas API recibidas",
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
    archivos_path: Optional[List[str]] = None,
    consultar_apis: bool = False,
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
    archivos_analizados: List[ArchivoAnalizado] = []

    # 1. Procesar archivo .eml si fue provisto
    if eml_path:
        parser = ParserEML(eml_path)
        metadatos_eml, extractor = parser.procesar(extractor)
        sha256_eml = metadatos_eml.sha256_eml
        archivos_analizados.extend(metadatos_eml.adjuntos_analizados)

    # 1b. Archivos suministrados por separado: lectura/hash/firma local; nunca se ejecutan.
    if archivos_path:
        entradas_manuales["Archivos"] = archivos_path
        for ruta in archivos_path:
            with open(ruta, "rb") as archivo_local:
                contenido = archivo_local.read()
            nombre = os.path.basename(ruta) or ruta
            mime_declarado, _ = mimetypes.guess_type(nombre)
            descripcion = describir_archivo(contenido, nombre, mime_declarado)
            archivo_analizado = ArchivoAnalizado(
                nombre=descripcion.identificador,
                mime_declarado=descripcion.mime_declarado,
                tamano_bytes=descripcion.tamano_bytes,
                sha256=descripcion.sha256,
                tipo_detectado=descripcion.tipo_detectado,
                procedencia=f"Archivo local: {ruta}",
                mime_detectado=descripcion.mime_detectado,
                firma_detectada=descripcion.firma_detectada,
                nota=descripcion.nota,
            )
            archivos_analizados.append(archivo_analizado)
            extractor.registrar_ioc(
                descripcion.sha256,
                TipoIOC.SHA256,
                f"Archivo local ({nombre})",
            )

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

    # 3b. Consultas GET únicamente: solo cuando el usuario activa explícitamente la opción.
    consultas_objetos = []
    if consultar_apis:
        cliente = OnlineLookupClient()
        vistas = set()

        def agregar_consulta(servicio: str, tipo: str, valor: str, llamada) -> None:
            clave = (servicio, tipo, valor)
            if clave in vistas:
                return
            vistas.add(clave)
            try:
                consultas_objetos.append(llamada())
            except Exception as exc:
                consultas_objetos.append({
                    "service": servicio,
                    "indicator_type": tipo,
                    "indicator": valor,
                    "status": "client_error",
                    "queried_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "endpoint": "",
                    "http_status": None,
                    "data": None,
                    "message": f"La consulta no pudo prepararse ({type(exc).__name__}).",
                })

        for indicador in indicadores:
            if indicador.tipo == TipoIOC.URL:
                agregar_consulta("VirusTotal", "URL", indicador.valor,
                                 lambda ind=indicador: cliente.virustotal_report(ind.tipo, ind.valor))
                agregar_consulta("urlscan.io", "URL", indicador.valor,
                                 lambda ind=indicador: cliente.urlscan_search(ind.tipo, ind.valor))
            elif indicador.tipo == TipoIOC.DOMINIO:
                agregar_consulta("VirusTotal", "Dominio", indicador.valor,
                                 lambda ind=indicador: cliente.virustotal_report(ind.tipo, ind.valor))
                agregar_consulta("urlscan.io", "Dominio", indicador.valor,
                                 lambda ind=indicador: cliente.urlscan_search(ind.tipo, ind.valor))
                agregar_consulta("RDAP", "Dominio", indicador.valor,
                                 lambda ind=indicador: cliente.rdap_lookup(ind.tipo, ind.valor))
                agregar_consulta("DNS-over-HTTPS", "Dominio", indicador.valor,
                                 lambda ind=indicador: cliente.dns_lookup(ind.valor))
                agregar_consulta("crt.sh", "Dominio", indicador.valor,
                                 lambda ind=indicador: cliente.crtsh_search(ind.valor))
            elif indicador.tipo == TipoIOC.IPV4:
                agregar_consulta("VirusTotal", "IP", indicador.valor,
                                 lambda ind=indicador: cliente.virustotal_report(ind.tipo, ind.valor))
                agregar_consulta("urlscan.io", "IP", indicador.valor,
                                 lambda ind=indicador: cliente.urlscan_search(ind.tipo, ind.valor))
                agregar_consulta("RDAP", "IP", indicador.valor,
                                 lambda ind=indicador: cliente.rdap_lookup(ind.tipo, ind.valor))

        # Consultar hash de adjuntos/archivos, nunca el hash del correo completo ni los binarios.
        for archivo in archivos_analizados:
            agregar_consulta("VirusTotal", "SHA-256", archivo.sha256,
                             lambda item=archivo: cliente.virustotal_report(TipoIOC.SHA256, item.sha256))

    consultas_api = [asdict(item) if is_dataclass(item) else item for item in consultas_objetos]
    evaluaciones = evaluar_recursos(
        indicadores=indicadores,
        archivos=archivos_analizados,
        consultas=consultas_objetos,
        metadatos=metadatos_eml,
        ruta_eml=eml_path,
        consultas_solicitadas=consultar_apis,
    )

    # 4. Generar referencias para los 4 servicios
    constructor_refs = ConstructorReferencias(fecha_str)
    refs_dict = constructor_refs.generar_todas(indicadores)
    lista_referencias = []
    for srv in ["VirusTotal", "urlscan.io", "WHOIS / DNSChecker", "crt.sh"]:
        lista_referencias.extend(refs_dict.get(srv, []))

    # 5. Construir objeto de resultado
    resultado = ResultadoLaboratorio(
        fuentes_analizadas=[
            *([f"EML: {eml_path}"] if eml_path else []),
            *([f"Archivos: {len(archivos_path or [])} elemento(s)"] if archivos_path else []),
            f"Manuales: {len(urls or []) + len(dominios or []) + len(ips or [])} elemento(s)",
        ],
        ruta_eml=eml_path,
        sha256_eml=sha256_eml,
        entradas_manuales=entradas_manuales,
        metadatos_eml=metadatos_eml,
        indicadores=indicadores,
        referencias_consulta=lista_referencias,
        archivos_analizados=archivos_analizados,
        consultas_api=consultas_api,
        evaluaciones=evaluaciones,
        fecha_analisis=fecha_str,
        zona_horaria=TIMEZONE_NAME,
        version_herramienta=__version__,
    )

    return resultado


def main(argv: Optional[List[str]] = None) -> int:
    """Punto de entrada de la CLI."""
    parser = crear_argument_parser()
    args = parser.parse_args(argv)

    tiene_entradas = bool(args.urls or args.dominios or args.ips or args.eml_path or args.archivos_path)
    if not tiene_entradas:
        sys.stderr.write("Error: Debe especificar al menos una entrada (--url, --dominio, --ip, --eml o --archivo).\n")
        parser.print_help(sys.stderr)
        return 1

    # Validar existencia de archivo .eml si fue especificado
    if args.eml_path and not os.path.exists(args.eml_path):
        sys.stderr.write(f"Error: El archivo .eml especificado no existe: '{args.eml_path}'\n")
        return 1

    for ruta_archivo in args.archivos_path or []:
        if not os.path.isfile(ruta_archivo):
            sys.stderr.write(f"Error: El archivo especificado no existe o no es un archivo: '{ruta_archivo}'\n")
            return 1

    error_entrada = _validar_entradas_manuales(args.urls, args.dominios, args.ips)
    if error_entrada:
        sys.stderr.write(f"Error: {error_entrada}\n")
        return 1

    try:
        if args.consultar_apis:
            sys.stderr.write(
                "[!] Consultas externas activadas: se enviarán URLs, dominios, IPs y hashes de adjuntos/archivos "
                "a los proveedores correspondientes. No se subirán binarios ni se visitarán URLs. "
                "VirusTotal puede incorporar IOCs consultados a su dataset comunitario.\n"
            )
        resultado = ejecutar_analisis(
            urls=args.urls,
            dominios=args.dominios,
            ips=args.ips,
            eml_path=args.eml_path,
            fecha_referencia=args.fecha_referencia,
            archivos_path=args.archivos_path,
            consultar_apis=args.consultar_apis,
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

    if args.salida_json_path:
        try:
            directorio_json = os.path.dirname(os.path.abspath(args.salida_json_path))
            if directorio_json and not os.path.exists(directorio_json):
                os.makedirs(directorio_json, exist_ok=True)
            with open(args.salida_json_path, "w", encoding="utf-8") as salida_json:
                json.dump(asdict(resultado), salida_json, ensure_ascii=False, indent=2)
                salida_json.write("\n")
            print(f"[+] Evidencia JSON guardada en: {args.salida_json_path}")
        except Exception as e:
            sys.stderr.write(f"Error al escribir el JSON '{args.salida_json_path}': {str(e)}\n")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
