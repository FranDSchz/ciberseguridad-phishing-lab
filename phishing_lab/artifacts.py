"""Identificación estática y cálculo de hash de bytes de artefactos.

Este módulo no lee rutas, extrae contenedores, ejecuta archivos ni realiza
consultas externas. Solo compara firmas conocidas en los bytes recibidos.
"""

from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Optional, Tuple


TIPO_DESCONOCIDO = "desconocido"


@dataclass(frozen=True)
class DescripcionArtefacto:
    """Descripción básica de un artefacto, sin inferir si es benigno o malicioso.

    ``mime_declarado`` proviene de quien llama a la función (por ejemplo, el
    Content-Type MIME del adjunto). ``tipo_detectado`` y ``mime_detectado`` se
    derivan únicamente de firmas binarias reconocidas.
    """

    identificador: str
    sha256: str
    tamano_bytes: int
    mime_declarado: Optional[str]
    tipo_detectado: str
    mime_detectado: Optional[str]
    firma_detectada: Optional[str]
    nota: Optional[str] = None

    def to_dict(self) -> dict:
        """Devuelve una representación compuesta solo por valores JSON básicos."""
        return asdict(self)


# Firmas cortas, binarias y legibles. El orden coloca formatos más específicos
# antes de firmas de contenedor genéricas.
_FIRMAS: Tuple[Tuple[bytes, str, str, str], ...] = (
    (b"%PDF-", "PDF", "application/pdf", "25 50 44 46 2D (%PDF-), offset 0"),
    (b"\x7fELF", "Ejecutable o objeto ELF", "application/x-elf", "7F 45 4C 46, offset 0"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Contenedor OLE Compound File", "application/x-ole-storage", "D0 CF 11 E0 A1 B1 1A E1, offset 0"),
    (b"Rar!\x1a\x07\x00", "Archivo RAR", "application/vnd.rar", "52 61 72 21 1A 07 00, offset 0"),
    (b"Rar!\x1a\x07\x01\x00", "Archivo RAR 5", "application/vnd.rar", "52 61 72 21 1A 07 01 00, offset 0"),
    (b"7z\xbc\xaf\x27\x1c", "Archivo 7-Zip", "application/x-7z-compressed", "37 7A BC AF 27 1C, offset 0"),
    (b"\x1f\x8b\x08", "Flujo GZIP", "application/gzip", "1F 8B 08, offset 0"),
    (b"BZh", "Flujo BZIP2", "application/x-bzip2", "42 5A 68 (BZh), offset 0"),
    (b"\xfd7zXZ\x00", "Flujo XZ", "application/x-xz", "FD 37 7A 58 5A 00, offset 0"),
    (b"\x89PNG\r\n\x1a\n", "Imagen PNG", "image/png", "89 50 4E 47 0D 0A 1A 0A, offset 0"),
    (b"\xff\xd8\xff", "Imagen JPEG", "image/jpeg", "FF D8 FF, offset 0"),
    (b"GIF87a", "Imagen GIF", "image/gif", "47 49 46 38 37 61, offset 0"),
    (b"GIF89a", "Imagen GIF", "image/gif", "47 49 46 38 39 61, offset 0"),
    (b"{\\rtf", "Documento RTF", "application/rtf", "7B 5C 72 74 66 ({\\rtf), offset 0"),
)

_FIRMAS_ZIP = (
    (b"PK\x03\x04", "50 4B 03 04 (ZIP local file header), offset 0"),
    (b"PK\x05\x06", "50 4B 05 06 (ZIP end of central directory), offset 0"),
    (b"PK\x07\x08", "50 4B 07 08 (ZIP spanning marker), offset 0"),
)

_FIRMAS_MACH_O = (
    (b"\xfe\xed\xfa\xce", "Ejecutable u objeto Mach-O de 32 bits", "FE ED FA CE, offset 0"),
    (b"\xfe\xed\xfa\xcf", "Ejecutable u objeto Mach-O de 64 bits", "FE ED FA CF, offset 0"),
    (b"\xce\xfa\xed\xfe", "Ejecutable u objeto Mach-O de 32 bits", "CE FA ED FE, offset 0"),
    (b"\xcf\xfa\xed\xfe", "Ejecutable u objeto Mach-O de 64 bits", "CF FA ED FE, offset 0"),
)


def _detectar_tipo(contenido: bytes) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
    """Devuelve tipo, MIME, firma y nota; no interpreta el contenido interno."""
    for firma, tipo, mime, descripcion_firma in _FIRMAS:
        if contenido.startswith(firma):
            return tipo, mime, descripcion_firma, None

    # ZIP también es la base de DOCX/XLSX/PPTX/JAR/APK. Sin inspeccionar el
    # directorio interno, solo se informa el contenedor ZIP.
    for firma, descripcion_firma in _FIRMAS_ZIP:
        if contenido.startswith(firma):
            return "Contenedor ZIP", "application/zip", descripcion_firma, (
                "La firma no permite identificar de forma segura el formato interno; "
                "no se extrajo ni inspeccionó el contenedor."
            )

    for firma, tipo, descripcion_firma in _FIRMAS_MACH_O:
        if contenido.startswith(firma):
            return tipo, "application/x-mach-binary", descripcion_firma, None

    # Requerir un encabezado BMP de tamaño mínimo y un offset de píxeles dentro
    # del archivo; dos bytes "BM" aislados no alcanzan para identificarlo.
    if contenido.startswith(b"BM") and len(contenido) >= 14:
        tamano_declarado = int.from_bytes(contenido[2:6], byteorder="little")
        offset_pixeles = int.from_bytes(contenido[10:14], byteorder="little")
        if 14 <= offset_pixeles <= len(contenido) and (tamano_declarado == 0 or 14 <= tamano_declarado <= len(contenido)):
            return "Imagen BMP", "image/bmp", "42 4D (BM) con cabecera BMP mínima válida, offset 0", None

    # Reconocer MZ como indicio, pero confirmar PE solo si el puntero e_lfanew
    # apunta dentro de los bytes disponibles y allí aparece la firma PE\0\0.
    if contenido.startswith(b"MZ"):
        if len(contenido) >= 0x40:
            offset_pe = int.from_bytes(contenido[0x3C:0x40], byteorder="little")
            fin_firma = offset_pe + 4
            if 0 <= offset_pe <= len(contenido) - 4 and contenido[offset_pe:fin_firma] == b"PE\x00\x00":
                return (
                    "Ejecutable o biblioteca Windows PE",
                    "application/vnd.microsoft.portable-executable",
                    "4D 5A (MZ), offset 0; 50 45 00 00 (PE), offset {}".format(offset_pe),
                    "La firma identifica PE, pero no distingue EXE de DLL ni determina si es malicioso."
                )
        return (
            TIPO_DESCONOCIDO,
            None,
            "4D 5A (MZ), offset 0",
            "Se observó la cabecera MZ, pero no se confirmó una firma PE válida dentro de los bytes disponibles.",
        )

    # Reconocer TAR solamente con su identificador ustar en el offset definido.
    if len(contenido) >= 262 and contenido[257:262] == b"ustar":
        return "Archivo TAR", "application/x-tar", "75 73 74 61 72 (ustar), offset 257", None

    # RIFF es un contenedor: distinguir solo subtipos cuya firma está presente.
    if len(contenido) >= 12 and contenido[:4] == b"RIFF":
        subtipo = contenido[8:12]
        if subtipo == b"WEBP":
            return "Imagen WebP", "image/webp", "52 49 46 46 (RIFF) + 57 45 42 50 (WEBP), offset 0/8", None
        if subtipo == b"WAVE":
            return "Audio WAV", "audio/wav", "52 49 46 46 (RIFF) + 57 41 56 45 (WAVE), offset 0/8", None
        if subtipo == b"AVI ":
            return "Video AVI", "video/x-msvideo", "52 49 46 46 (RIFF) + 41 56 49 20 (AVI ), offset 0/8", None

    return TIPO_DESCONOCIDO, None, None, "No se reconoció una firma compatible con los formatos contemplados."


def describir_archivo(
    contenido: bytes,
    identificador: str,
    mime_declarado: Optional[str] = None,
) -> DescripcionArtefacto:
    """Calcula SHA-256, tamaño e identificación probable de ``contenido``.

    Args:
        contenido: Bytes ya disponibles en memoria. No se lee ninguna ruta.
        identificador: ID estable asignado por quien llama para este recurso.
        mime_declarado: Content-Type proporcionado por el origen, si existe.

    Returns:
        Una ``DescripcionArtefacto`` con MIME declarado y detección binaria en
        campos separados. Un tipo no reconocido se etiqueta como
        ``"desconocido"``.

    Raises:
        TypeError: Si ``contenido`` no es ``bytes`` o el MIME no es texto.
        ValueError: Si el identificador está vacío.
    """
    if not isinstance(contenido, bytes):
        raise TypeError("contenido debe ser bytes")
    if not isinstance(identificador, str):
        raise TypeError("identificador debe ser str")
    identificador_limpio = identificador.strip()
    if not identificador_limpio:
        raise ValueError("identificador no puede estar vacío")
    if mime_declarado is not None and not isinstance(mime_declarado, str):
        raise TypeError("mime_declarado debe ser str o None")

    mime_limpio = mime_declarado.strip() if mime_declarado and mime_declarado.strip() else None
    tipo, mime_detectado, firma, nota = _detectar_tipo(contenido)

    return DescripcionArtefacto(
        identificador=identificador_limpio,
        sha256=sha256(contenido).hexdigest(),
        tamano_bytes=len(contenido),
        mime_declarado=mime_limpio,
        tipo_detectado=tipo,
        mime_detectado=mime_detectado,
        firma_detectada=firma,
        nota=nota,
    )
