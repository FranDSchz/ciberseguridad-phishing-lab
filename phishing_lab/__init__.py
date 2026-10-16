"""
Phishing Lab - Triage estático de correos, archivos e indicadores de phishing.

El modo local no usa la red. Las consultas a APIs son optativas y se invocan
explícitamente; las muestras nunca se ejecutan ni se suben.
"""

__version__ = "1.1.0"
__author__ = "Laboratorio de Ciberseguridad"

from .models import (
    TipoIOC,
    Procedencia,
    Indicador,
    MetadatosCorreo,
    ReferenciaConsulta,
    ArchivoAnalizado,
    EvaluacionRecurso,
    ResultadoLaboratorio,
)
from .artifacts import DescripcionArtefacto, describir_archivo
from .online_lookups import LookupResult, LookupStatus, OnlineLookupClient
from .verdict import evaluar_recursos
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
    "ArchivoAnalizado",
    "EvaluacionRecurso",
    "ResultadoLaboratorio",
    "DescripcionArtefacto",
    "describir_archivo",
    "LookupResult",
    "LookupStatus",
    "OnlineLookupClient",
    "evaluar_recursos",
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
