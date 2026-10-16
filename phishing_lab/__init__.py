"""
Phishing Lab - Utilidad local forense y pasiva de preparación para análisis de phishing.

Herramienta diseñada con la biblioteca estándar de Python para análisis seguro
de correos electrónicos (.eml) e indicadores manuales (URLs, dominios, IPs),
garantizando cero consultas de red, cero visitas activas y sin emisión de
veredictos automáticos.
"""

__version__ = "1.0.0"
__author__ = "Laboratorio de Ciberseguridad"

from .models import (
    TipoIOC,
    Procedencia,
    Indicador,
    MetadatosCorreo,
    ReferenciaConsulta,
    ResultadoLaboratorio,
)
from .timezone_utils import (
    TIMEZONE_NAME,
    obtener_zona_horaria_ba,
    formatear_fecha,
    obtener_fecha_referencia,
)
from .indicators import (
    evaluar_dominio_reservado,
    evaluar_ip_reservada,
    defang_ioc,
    es_indicador_reservado,
)
from .extractor import (
    ExtractorIOC,
    extraer_iocs_de_texto,
    extraer_iocs_de_html,
)
from .parser_eml import (
    ParserEML,
    parsear_archivo_eml,
    calcular_sha256_bytes,
)
from .references import (
    ConstructorReferencias,
    generar_referencias_servicio,
)
from .reporter import (
    GeneradorInforme,
    generar_informe_markdown,
)

__all__ = [
    "TipoIOC",
    "Procedencia",
    "Indicador",
    "MetadatosCorreo",
    "ReferenciaConsulta",
    "ResultadoLaboratorio",
    "TIMEZONE_NAME",
    "obtener_zona_horaria_ba",
    "formatear_fecha",
    "obtener_fecha_referencia",
    "evaluar_dominio_reservado",
    "evaluar_ip_reservada",
    "defang_ioc",
    "es_indicador_reservado",
    "ExtractorIOC",
    "extraer_iocs_de_texto",
    "extraer_iocs_de_html",
    "ParserEML",
    "parsear_archivo_eml",
    "calcular_sha256_bytes",
    "ConstructorReferencias",
    "generar_referencias_servicio",
    "GeneradorInforme",
    "generar_informe_markdown",
]
