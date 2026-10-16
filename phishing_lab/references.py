"""
Módulo de construcción de referencias seguras de consulta forense.
Genera hipervínculos estructurados y escapados para los cuatro servicios requeridos:
VirusTotal, urlscan.io, WHOIS/DNSChecker y crt.sh.
Cumple estrictamente con las directivas de cero consultas de red, cero apertura automática,
cero subida de originales y registro de estado 'No consultado' / 'No aplicable'.
"""

from typing import Dict, List, Optional
from urllib.parse import quote, urlsplit

from .models import Indicador, ReferenciaConsulta, TipoIOC
from .timezone_utils import formatear_fecha


class ConstructorReferencias:
    """
    Generador pasivo de referencias de consulta forense hacia servicios de inteligencia de amenazas.
    """

    def __init__(self, fecha_referencia: Optional[str] = None):
        self.fecha_str = fecha_referencia or formatear_fecha()

    def construir_virustotal(self, indicador: Indicador) -> ReferenciaConsulta:
        """Construye referencia segura para VirusTotal."""
        val = indicador.valor
        tipo_fuente = "Dominio candidato" if indicador.tipo == TipoIOC.DOMINIO else indicador.tipo.value
        fuente_desc = f"{tipo_fuente}: {val} ({', '.join(indicador.procedencias)})"

        if indicador.tipo == TipoIOC.EMAIL:
            return ReferenciaConsulta(
                servicio="VirusTotal",
                pertinente="No aplicable (no se consulta una dirección de correo)",
                referencia_url="https://www.virustotal.com/",
                observacion="No se genera una consulta con la dirección completa. Si corresponde, evaluar manualmente el dominio extraído.",
                fuente=fuente_desc,
                fecha=self.fecha_str,
                estado="No aplicable",
            )

        # No mostrar un enlace público para el hash del EML completo: aunque el
        # hash se calculó localmente, abrir el enlace revelaría ese IOC al proveedor.
        es_hash_eml = (
            indicador.tipo == TipoIOC.SHA256
            and any("Archivo .eml local" in proc for proc in indicador.procedencias)
            and not any("Adjunto" in proc or "Archivo local (" in proc for proc in indicador.procedencias)
        )
        if es_hash_eml:
            return ReferenciaConsulta(
                servicio="VirusTotal",
                pertinente="No aplicable (hash del correo completo)",
                referencia_url="N/A",
                observacion="Se conserva localmente para integridad; no se envía ni se ofrece un enlace de consulta pública.",
                fuente=fuente_desc,
                fecha=self.fecha_str,
                estado="No aplicable",
            )

        if indicador.es_reservado:
            pertinente = "No aplicable (Indicador reservado)"
            estado = "No aplicable"
            observacion = (
                f"Indicador reservado ({indicador.detalle_reservado}). "
                "No corresponde consulta a telemetría pública."
            )
        else:
            pertinente = f"Sí ({tipo_fuente})"
            estado = "No consultado"
            observacion = (
                "Permite inspeccionar reputación histórica, detecciones de motores y telemetría de red. "
                "Aviso: Ningún dato ni URL ha sido enviado externamente."
            )

        if indicador.tipo == TipoIOC.DOMINIO:
            url = f"https://www.virustotal.com/gui/domain/{quote(val)}"
        elif indicador.tipo == TipoIOC.IPV4:
            url = f"https://www.virustotal.com/gui/ip-address/{quote(val)}"
        elif indicador.tipo == TipoIOC.SHA256:
            url = f"https://www.virustotal.com/gui/file/{quote(val)}"
            pertinente = "Sí (Búsqueda pasiva de hash SHA-256 local)"
            observacion = (
                "Búsqueda por hash local del archivo sin haber subido el binario original a la plataforma. "
                "Preserva confidencialidad de la muestra."
            )
        else:  # URL
            url = f"https://www.virustotal.com/gui/search/{quote(val)}"

        return ReferenciaConsulta(
            servicio="VirusTotal",
            pertinente=pertinente,
            referencia_url=url,
            observacion=observacion,
            fuente=fuente_desc,
            fecha=self.fecha_str,
            estado=estado,
        )

    def construir_urlscan(self, indicador: Indicador) -> ReferenciaConsulta:
        """Construye referencia segura para urlscan.io."""
        val = indicador.valor
        tipo_fuente = "Dominio candidato" if indicador.tipo == TipoIOC.DOMINIO else indicador.tipo.value
        fuente_desc = f"{tipo_fuente}: {val} ({', '.join(indicador.procedencias)})"

        if indicador.tipo == TipoIOC.SHA256 or indicador.tipo == TipoIOC.EMAIL:
            return ReferenciaConsulta(
                servicio="urlscan.io",
                pertinente="No aplicable",
                referencia_url="https://urlscan.io/search/",
                observacion="urlscan.io indexa navegaciones web (URLs, dominios, IPs); no procesa hashes ni buzones.",
                fuente=fuente_desc,
                fecha=self.fecha_str,
                estado="No aplicable",
            )

        if indicador.es_reservado:
            pertinente = "No aplicable (Indicador reservado)"
            estado = "No aplicable"
            observacion = (
                f"Indicador reservado ({indicador.detalle_reservado}). "
                "No existen escaneos de navegación de internet pública."
            )
        else:
            pertinente = f"Sí ({tipo_fuente})"
            estado = "No consultado"
            observacion = (
                "Permite consultar escaneos pasivos previos, árboles DOM y capturas de pantalla registradas sin iniciar un escaneo nuevo."
            )

        if indicador.tipo == TipoIOC.DOMINIO:
            url = f"https://urlscan.io/search/#domain:{quote(val)}"
        elif indicador.tipo == TipoIOC.IPV4:
            url = f"https://urlscan.io/search/#ip:{quote(val)}"
        else:  # URL
            url = f"https://urlscan.io/search/#page.url:{quote(val)}"

        return ReferenciaConsulta(
            servicio="urlscan.io",
            pertinente=pertinente,
            referencia_url=url,
            observacion=observacion,
            fuente=fuente_desc,
            fecha=self.fecha_str,
            estado=estado,
        )

    def construir_whois_dnschecker(self, indicador: Indicador) -> ReferenciaConsulta:
        """Construye referencia segura para WHOIS / DNSChecker."""
        val = indicador.valor
        tipo_fuente = "Dominio candidato" if indicador.tipo == TipoIOC.DOMINIO else indicador.tipo.value
        fuente_desc = f"{tipo_fuente}: {val} ({', '.join(indicador.procedencias)})"

        if indicador.tipo not in (TipoIOC.DOMINIO, TipoIOC.IPV4, TipoIOC.URL):
            return ReferenciaConsulta(
                servicio="WHOIS / DNSChecker",
                pertinente="No aplicable",
                referencia_url="https://whois.domaintools.com/",
                observacion="WHOIS y resolución DNS aplican exclusivamente sobre nombres de dominio e infraestructura IP.",
                fuente=fuente_desc,
                fecha=self.fecha_str,
                estado="No aplicable",
            )

        valor_consulta = val
        if indicador.tipo == TipoIOC.URL:
            try:
                valor_consulta = urlsplit(val).hostname or ""
            except ValueError:
                valor_consulta = ""
            if not valor_consulta:
                return ReferenciaConsulta(
                    servicio="WHOIS / DNSChecker",
                    pertinente="No aplicable (URL sin host válido)",
                    referencia_url="N/A",
                    observacion="No se pudo extraer un host para una consulta manual WHOIS/DNS.",
                    fuente=fuente_desc,
                    fecha=self.fecha_str,
                    estado="No aplicable",
                )

        if indicador.es_reservado:
            pertinente = "No aplicable (Indicador reservado)"
            estado = "No aplicable"
            observacion = (
                f"Indicador de rango/nombre reservado ({indicador.detalle_reservado}). "
                "No posee delegación de autoridad en registros de internet públicos."
            )
            url = f"https://whois.domaintools.com/{quote(valor_consulta)}"
        else:
            pertinente = f"Sí ({tipo_fuente})"
            estado = "No consultado"
            if indicador.tipo == TipoIOC.DOMINIO:
                url = (
                    f"WHOIS: https://whois.domaintools.com/{quote(val)} | "
                    f"DNS: https://dnschecker.org/all-dns-records-of-domain.php?query={quote(val)}"
                )
                observacion = (
                    "Permite examinar antigüedad de registro, titular/registrador y validar registros DNS públicos (MX, TXT, SPF, DMARC)."
                )
            elif indicador.tipo == TipoIOC.IPV4:
                url = f"https://whois.domaintools.com/{quote(valor_consulta)}"
                observacion = "Permite identificar Sistema Autónomo (ASN), prefijo BGP y RIR responsable (ARIN/LACNIC/RIPE)."
            else:
                url = f"WHOIS: https://whois.domaintools.com/{quote(valor_consulta)} | " \
                    f"DNS: https://dnschecker.org/all-dns-records-of-domain.php?query={quote(valor_consulta)}"
                observacion = "Consulta orientada al host de la URL indicada; la ruta y los parámetros se omiten."

        return ReferenciaConsulta(
            servicio="WHOIS / DNSChecker",
            pertinente=pertinente,
            referencia_url=url,
            observacion=observacion,
            fuente=fuente_desc,
            fecha=self.fecha_str,
            estado=estado,
        )

    def construir_crt_sh(self, indicador: Indicador) -> ReferenciaConsulta:
        """Construye referencia segura para crt.sh (Certificate Transparency)."""
        val = indicador.valor
        fuente_desc = f"{indicador.tipo.value}: {val} ({', '.join(indicador.procedencias)})"

        # crt.sh aplica esencialmente a dominios
        if indicador.tipo != TipoIOC.DOMINIO:
            return ReferenciaConsulta(
                servicio="crt.sh",
                pertinente="No aplicable",
                referencia_url="https://crt.sh/",
                observacion="crt.sh monitorea registros Certificate Transparency (CT logs); solo aplica a nombres de dominio FQDN.",
                fuente=fuente_desc,
                fecha=self.fecha_str,
                estado="No aplicable",
            )

        if indicador.es_reservado:
            return ReferenciaConsulta(
                servicio="crt.sh",
                pertinente="No aplicable (Dominio reservado)",
                referencia_url=f"https://crt.sh/?q={quote(val)}",
                observacion=(
                    f"Dominio reservado ({indicador.detalle_reservado}). "
                    "Las Autoridades Certificadoras públicas no emiten certificados válidos para dominios de prueba."
                ),
                fuente=fuente_desc,
                fecha=self.fecha_str,
                estado="No aplicable",
            )

        return ReferenciaConsulta(
            servicio="crt.sh",
            pertinente="Sí (Nombre de dominio FQDN)",
            referencia_url=f"https://crt.sh/?q={quote(val)}",
            observacion=(
                "Permite descubrir subdominios históricos, fechas de emisión de certificados SSL/TLS y autoridades certificadoras."
            ),
            fuente=fuente_desc,
            fecha=self.fecha_str,
            estado="No consultado",
        )

    def generar_todas(self, indicadores: List[Indicador]) -> Dict[str, List[ReferenciaConsulta]]:
        """
        Genera la matriz de referencias agrupadas por cada uno de los 4 servicios requeridos:
        VirusTotal, urlscan.io, WHOIS / DNSChecker, crt.sh.
        """
        resultado: Dict[str, List[ReferenciaConsulta]] = {
            "VirusTotal": [],
            "urlscan.io": [],
            "WHOIS / DNSChecker": [],
            "crt.sh": [],
        }

        # Si no hay indicadores procesados, registrar una entrada 'No aplicable' para cada servicio
        if not indicadores:
            for srv in resultado:
                resultado[srv].append(
                    ReferenciaConsulta(
                        servicio=srv,
                        pertinente="No aplicable (Sin indicadores)",
                        referencia_url="N/A",
                        observacion="No se suministraron ni extrajeron indicadores de compromiso para formular consultas.",
                        fuente="Ninguna",
                        fecha=self.fecha_str,
                        estado="No aplicable",
                    )
                )
            return resultado

        for ind in indicadores:
            resultado["VirusTotal"].append(self.construir_virustotal(ind))
            resultado["urlscan.io"].append(self.construir_urlscan(ind))
            resultado["WHOIS / DNSChecker"].append(self.construir_whois_dnschecker(ind))
            resultado["crt.sh"].append(self.construir_crt_sh(ind))

        return resultado


def generar_referencias_servicio(
    indicadores: List[Indicador], fecha_referencia: Optional[str] = None
) -> Dict[str, List[ReferenciaConsulta]]:
    """Función de conveniencia para construir las referencias de los 4 servicios."""
    constructor = ConstructorReferencias(fecha_referencia)
    return constructor.generar_todas(indicadores)
