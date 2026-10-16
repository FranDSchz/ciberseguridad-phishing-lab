"""
Modelos de datos para Phishing Lab.
Define las estructuras para indicadores, metadatos MIME, referencias de consulta
y resultados del laboratorio forense.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class TipoIOC(str, Enum):
    """Tipos de Indicadores de Compromiso (IOCs) gestionados."""
    URL = "URL"
    DOMINIO = "Dominio"
    IPV4 = "IPv4"
    SHA256 = "SHA-256"
    EMAIL = "Dirección de correo"


class Procedencia:
    """Orígenes posibles de los indicadores dentro del análisis."""
    MANUAL = "Entrada manual"
    ENCABEZADO = "Encabezado MIME"
    CUERPO_TEXTO = "Cuerpo de texto plano"
    HTML_HREF = "Cuerpo HTML (atributo href)"
    HTML_TEXTO = "Cuerpo HTML (texto de ancla)"
    HTML_CUERPO = "Cuerpo HTML (texto visible)"


@dataclass
class Indicador:
    """
    Representa un indicador de compromiso individual con su procedencia
    y estado de reserva de documentación/ejemplo.
    """
    valor: str
    tipo: TipoIOC
    procedencias: List[str] = field(default_factory=list)
    es_reservado: bool = False
    detalle_reservado: Optional[str] = None
    punycode_info: Optional[str] = None
    defanged: str = ""

    def agregar_procedencia(self, proc: str) -> None:
        """Agrega una procedencia evitando duplicados."""
        if proc not in self.procedencias:
            self.procedencias.append(proc)


@dataclass
class MetadatosCorreo:
    """
    Metadatos extraídos de un archivo de correo electrónico .eml.
    Preserva el resumen de la estructura sin volcar el cuerpo completo.
    """
    asunto: Optional[str] = None
    de: Optional[str] = None
    para: Optional[str] = None
    fecha_cabecera: Optional[str] = None
    message_id: Optional[str] = None
    return_path: Optional[str] = None
    reply_to: Optional[str] = None
    sha256_eml: Optional[str] = None
    tiene_cuerpo_texto: bool = False
    tiene_cuerpo_html: bool = False
    longitud_cuerpo_texto: int = 0
    longitud_cuerpo_html: int = 0
    resumen_cuerpo: Optional[str] = None
    cabeceras_autenticacion: Dict[str, List[str]] = field(default_factory=dict)
    tiene_dkim_signature: bool = False
    aviso_dkim: Optional[str] = None
    saltos_received: List[str] = field(default_factory=list)
    archivos_adjuntos: List[str] = field(default_factory=list)
    adjuntos_analizados: List["ArchivoAnalizado"] = field(default_factory=list)
    es_malformado: bool = False
    errores_parseo: List[str] = field(default_factory=list)


@dataclass
class ReferenciaConsulta:
    """
    Referencia de consulta pasiva generada para servicios de análisis externos.
    Cumple con el esquema: Pertinente, Referencia, Observación, Fuente, Fecha y Estado.
    """
    servicio: str
    pertinente: str
    referencia_url: str
    observacion: str
    fuente: str
    fecha: str
    estado: str = "No consultado"


@dataclass
class ArchivoAnalizado:
    """Metadatos estáticos de un archivo; nunca contiene ni ejecuta el binario."""
    nombre: str
    mime_declarado: Optional[str]
    tamano_bytes: int
    sha256: str
    tipo_detectado: str
    procedencia: str = "Archivo local"
    mime_detectado: Optional[str] = None
    firma_detectada: Optional[str] = None
    nota: Optional[str] = None


@dataclass
class EvaluacionRecurso:
    """Veredicto explicable ligado a un artefacto específico del caso."""
    recurso_id: str
    tipo: str
    identificador: str
    veredicto: str
    confianza: str
    fundamentos: List[str] = field(default_factory=list)
    amenaza: str = "No determinada"
    impacto_cia: Dict[str, str] = field(default_factory=dict)
    medida_usuario: str = ""
    control_organizacion: str = ""
    cobertura: str = ""


@dataclass
class ResultadoLaboratorio:
    """
    Contenedor global de resultados del laboratorio de phishing.
    Reúne los datos procesados para emisión reproducible en Markdown.
    """
    fuentes_analizadas: List[str] = field(default_factory=list)
    ruta_eml: Optional[str] = None
    sha256_eml: Optional[str] = None
    entradas_manuales: Dict[str, List[str]] = field(default_factory=dict)
    metadatos_eml: Optional[MetadatosCorreo] = None
    indicadores: List[Indicador] = field(default_factory=list)
    referencias_consulta: List[ReferenciaConsulta] = field(default_factory=list)
    archivos_analizados: List[ArchivoAnalizado] = field(default_factory=list)
    consultas_api: List[Dict[str, Any]] = field(default_factory=list)
    evaluaciones: List[EvaluacionRecurso] = field(default_factory=list)
    fecha_analisis: str = ""
    zona_horaria: str = "America/Argentina/Buenos_Aires"
    version_herramienta: str = "1.1.0"
