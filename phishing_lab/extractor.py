"""
Módulo extractor de indicadores (URLs, dominios, IPs) con trazabilidad de procedencia.
Procesa texto plano y cuerpos HTML mediante análisis sintáctico pasivo estricto
utilizando html.parser de la biblioteca estándar (sin renderizado, ejecución JS ni consultas).
"""

from html.parser import HTMLParser
import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .indicators import (
    analizar_punycode,
    defang_ioc,
    es_indicador_reservado,
    evaluar_dominio_reservado,
    evaluar_ip_reservada,
)
from .models import Indicador, Procedencia, TipoIOC

# Expresiones regulares para extracción
REGEX_URL = re.compile(
    r"""(?:https?|hxxps?|ftp|fxp)://[^\s<>"'{}|\\^`\[\]()]+""",
    re.IGNORECASE,
)
REGEX_IPV4 = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
REGEX_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
)
# Coincidencia para dominios sintácticos (incluyendo punycode xn-- y tlds de prueba)
REGEX_DOMINIO = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9-]{4,}|example|invalid|localhost|test)\b",
    re.IGNORECASE,
)
EXTENSIONES_ARCHIVO_COMUNES = {
    "7z", "avi", "bat", "bin", "bmp", "bz2", "c", "cfg", "class", "conf", "csv",
    "dat", "dll", "doc", "docx", "eml", "exe", "gif", "gz", "html", "ini", "iso",
    "jar", "jpeg", "jpg", "js", "json", "log", "m4a", "md", "mov", "mp3", "mp4",
    "pdf", "png", "ppt", "pptx", "ps1", "py", "rar", "rtf", "sh", "sql", "svg",
    "tar", "tmp", "ts", "tsv", "txt", "wav", "webp", "xls", "xlsx", "xml", "yaml",
    "yml", "zip",
}


def _limpiar_puntuacion_final(cadena: str) -> str:
    """Remueve signos de puntuación de cierre comunes que queden adheridos a una URL extraída."""
    while cadena and cadena[-1] in ".,;:!?)'\">]}":
        cadena = cadena[:-1]
    return cadena


class _HTMLParserSeguro(HTMLParser):
    """
    Parser HTML pasivo que no ejecuta JavaScript ni resuelve entidades externas.
    Extrae atributos 'href' y textos visibles / anclas asociando su procedencia correspondiente.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.enlaces_href: List[str] = []
        self.textos_ancla: List[str] = []
        self.texto_cuerpo: List[str] = []
        self._dentro_de_a = False
        self._texto_actual_ancla: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag_normalizado = tag.lower()
        if tag_normalizado == "a":
            self._dentro_de_a = True
            self._texto_actual_ancla = []
            for attr_nom, attr_val in attrs:
                if attr_nom.lower() == "href" and attr_val:
                    self.enlaces_href.append(attr_val.strip())

    def handle_endtag(self, tag: str) -> None:
        tag_normalizado = tag.lower()
        if tag_normalizado == "a":
            self._dentro_de_a = False
            texto_completo = " ".join(self._texto_actual_ancla).strip()
            if texto_completo:
                self.textos_ancla.append(texto_completo)
            self._texto_actual_ancla = []

    def handle_data(self, data: str) -> None:
        if self._dentro_de_a:
            self._texto_actual_ancla.append(data)
        else:
            self.texto_cuerpo.append(data)

    def error(self, message: str) -> None:
        # Silenciar errores no críticos de parsing para mantener robustez ante HTML malformado
        pass

    def finalizar(self) -> None:
        """Recupera el texto de un ancla sin cerrar al final del documento."""
        if self._dentro_de_a:
            texto_completo = " ".join(self._texto_actual_ancla).strip()
            if texto_completo:
                self.textos_ancla.append(texto_completo)
            self._texto_actual_ancla = []
            self._dentro_de_a = False


class ExtractorIOC:
    """
    Motor de extracción y consolidación de indicadores de compromiso (IOCs)
    con preservación rigurosa de procedencia.
    """

    def __init__(self):
        # Clave: (tipo, valor_normalizado) -> Indicador
        self._indicadores: Dict[Tuple[TipoIOC, str], Indicador] = {}

    def registrar_ioc(self, valor: str, tipo: TipoIOC, procedencia: str) -> None:
        """Registra o actualiza un indicador con su procedencia."""
        if not valor:
            return

        valor_limpio = valor.strip()
        if not valor_limpio:
            return

        # Normalización de clave
        if tipo in (TipoIOC.DOMINIO, TipoIOC.EMAIL):
            clave_val = valor_limpio.lower()
        elif tipo == TipoIOC.URL:
            # Eliminar slash final redundante para evitar duplicación superficial
            clave_val = valor_limpio.rstrip("/")
        else:
            clave_val = valor_limpio

        clave = (tipo, clave_val)

        if clave not in self._indicadores:
            # Evaluar reserva y punycode
            es_res, detalle_res = es_indicador_reservado(valor_limpio, tipo)
            puny_info = analizar_punycode(valor_limpio)
            defang_val = defang_ioc(valor_limpio, tipo)

            ind = Indicador(
                valor=valor_limpio,
                tipo=tipo,
                procedencias=[procedencia],
                es_reservado=es_res,
                detalle_reservado=detalle_res,
                punycode_info=puny_info,
                defanged=defang_val,
            )
            self._indicadores[clave] = ind
        else:
            self._indicadores[clave].agregar_procedencia(procedencia)

    def procesar_texto_plano(self, texto: str, procedencia: str = Procedencia.CUERPO_TEXTO) -> None:
        """Extrae URLs, IPs y dominios de un bloque de texto plano."""
        if not texto:
            return

        # 1. Extraer URLs
        for match in REGEX_URL.finditer(texto):
            url_candidata = _limpiar_puntuacion_final(match.group(0))
            if url_candidata:
                self.registrar_ioc(url_candidata, TipoIOC.URL, procedencia)
                # Extraer host asociado a la URL
                try:
                    parsed = urlparse(url_candidata)
                    host = parsed.hostname
                    if host:
                        # Si el host es una IP
                        try:
                            ipaddress.IPv4Address(host)
                            self.registrar_ioc(host, TipoIOC.IPV4, f"{procedencia} (host de URL)")
                        except ValueError:
                            self.registrar_ioc(host, TipoIOC.DOMINIO, f"{procedencia} (host de URL)")
                except Exception:
                    pass

        # 2. Extraer IPs
        for match in REGEX_IPV4.finditer(texto):
            ip_candidata = match.group(0)
            prefijo = texto[max(0, match.start() - 14):match.start()]
            if re.search(r"\b(?:v|ver|version|versión|release)\s*$", prefijo, re.IGNORECASE):
                continue
            try:
                ipaddress.IPv4Address(ip_candidata)
                self.registrar_ioc(ip_candidata, TipoIOC.IPV4, procedencia)
            except ValueError:
                pass

        # 3. Extraer emails y sus dominios
        for match in REGEX_EMAIL.finditer(texto):
            email_candidato = match.group(0)
            dominio_email = match.group(1)
            self.registrar_ioc(email_candidato, TipoIOC.EMAIL, procedencia)
            if dominio_email:
                self.registrar_ioc(dominio_email, TipoIOC.DOMINIO, f"{procedencia} (dominio emisor/receptor)")

        # 4. Extraer dominios candidatos fuera de direcciones y nombres de archivo.
        # No se dispone de una Public Suffix List en la biblioteca estándar, por lo
        # que esta detección es sintáctica y no afirma que el dominio exista.
        texto_sin_correos = REGEX_EMAIL.sub(" ", texto)
        for match in REGEX_DOMINIO.finditer(texto_sin_correos):
            dom_candidato = _limpiar_puntuacion_final(match.group(0))
            sufijo = dom_candidato.rsplit(".", 1)[-1].lower()
            if sufijo in EXTENSIONES_ARCHIVO_COMUNES:
                continue
            # Descartar si es parte de una IP o un archivo común sin contexto
            try:
                ipaddress.IPv4Address(dom_candidato)
                continue
            except ValueError:
                pass
            self.registrar_ioc(dom_candidato, TipoIOC.DOMINIO, procedencia)

    def procesar_html(self, html_contenido: str) -> None:
        """
        Analiza contenido HTML mediante el parser pasivo seguro,
        diferenciando href de anclas y texto general.
        """
        if not html_contenido:
            return

        parser = _HTMLParserSeguro()
        try:
            parser.feed(html_contenido)
            parser.close()
            parser.finalizar()
        except Exception:
            # Si el HTML está gravemente corrupto, recurrir a escaneo de texto seguro
            self.procesar_texto_plano(html_contenido, Procedencia.HTML_CUERPO)
            return

        # Procesar atributos href
        for href in parser.enlaces_href:
            if href.lower().startswith(("http://", "https://", "hxxp://", "hxxps://", "ftp://")):
                self.registrar_ioc(href, TipoIOC.URL, Procedencia.HTML_HREF)
                try:
                    parsed = urlparse(href)
                    if parsed.hostname:
                        try:
                            ipaddress.IPv4Address(parsed.hostname)
                            self.registrar_ioc(parsed.hostname, TipoIOC.IPV4, f"{Procedencia.HTML_HREF} (host de enlace)")
                        except ValueError:
                            self.registrar_ioc(parsed.hostname, TipoIOC.DOMINIO, f"{Procedencia.HTML_HREF} (host de enlace)")
                except Exception:
                    pass
            elif href.lower().startswith("mailto:"):
                correo = href[7:].split("?")[0].strip()
                if correo:
                    self.registrar_ioc(correo, TipoIOC.EMAIL, Procedencia.HTML_HREF)
                    if "@" in correo:
                        _, _, dom = correo.partition("@")
                        self.registrar_ioc(dom, TipoIOC.DOMINIO, f"{Procedencia.HTML_HREF} (dominio mailto)")
            else:
                # Podría ser un dominio directo o ruta relativa
                self.procesar_texto_plano(href, Procedencia.HTML_HREF)

        # Procesar texto visible de anclas (posibles incongruencias URL mostrada vs destino)
        for texto_ancla in parser.textos_ancla:
            self.procesar_texto_plano(texto_ancla, Procedencia.HTML_TEXTO)

        # Procesar resto del cuerpo HTML
        for trozo in parser.texto_cuerpo:
            self.procesar_texto_plano(trozo, Procedencia.HTML_CUERPO)

    def obtener_indicadores(self) -> List[Indicador]:
        """Retorna la lista ordenada y consolidada de todos los indicadores descubiertos."""
        orden_tipo = {
            TipoIOC.URL: 1,
            TipoIOC.DOMINIO: 2,
            TipoIOC.IPV4: 3,
            TipoIOC.EMAIL: 4,
            TipoIOC.SHA256: 5,
        }
        return sorted(
            self._indicadores.values(),
            key=lambda ind: (orden_tipo.get(ind.tipo, 99), ind.valor.lower()),
        )


def extraer_iocs_de_texto(texto: str, procedencia: str = Procedencia.CUERPO_TEXTO) -> List[Indicador]:
    """Función utilitaria directa para extraer indicadores de texto plano."""
    extractor = ExtractorIOC()
    extractor.procesar_texto_plano(texto, procedencia)
    return extractor.obtener_indicadores()


def extraer_iocs_de_html(html_contenido: str) -> List[Indicador]:
    """Función utilitaria directa para extraer indicadores de HTML."""
    extractor = ExtractorIOC()
    extractor.procesar_html(html_contenido)
    return extractor.obtener_indicadores()
