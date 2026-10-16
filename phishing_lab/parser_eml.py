"""
Módulo de parseo forense de archivos .eml con biblioteca estándar email.parser.
Calcula el hash SHA-256 local sin transmisión externa, extrae encabezados MIME,
recopila declaraciones de autenticación (SPF/DKIM/DMARC) sin verificarlas,
advierte sobre la ausencia de DKIM-Signature y resume el contenido del cuerpo
sin volcarlo completo al informe.
"""

from email import policy
from email.parser import BytesParser
import hashlib
import os
import re
from typing import List, Optional, Tuple

from .extractor import ExtractorIOC
from .models import MetadatosCorreo, Procedencia, TipoIOC

# Expresiones regulares para detección de patrones BEC / transferencias urgentes en el resumen
PATRON_TRANSFERENCIA_BEC = re.compile(
    r"""(?:\$4\.8M|\$4[,\.]800[,\.]000|transferencia\s+urgente|urgente\s+transferencia|wire\s+transfer|confidential\s+acquisition|adquisici[oó]n\s+confidencial)""",
    re.IGNORECASE,
)


def calcular_sha256_bytes(contenido: bytes) -> str:
    """Calcula el hash criptográfico SHA-256 de los bytes de forma 100% local."""
    hasher = hashlib.sha256()
    hasher.update(contenido)
    return hasher.hexdigest()


class ParserEML:
    """
    Parser pasivo de archivos de correo en formato RFC 5322 / MIME (.eml).
    """

    def __init__(self, ruta_archivo: str):
        self.ruta_archivo = ruta_archivo
        if not os.path.exists(ruta_archivo):
            raise FileNotFoundError(f"No se encontró el archivo de correo: {ruta_archivo}")

    def procesar(self, extractor: Optional[ExtractorIOC] = None) -> Tuple[MetadatosCorreo, ExtractorIOC]:
        """
        Lee y procesa el archivo .eml, registrando los indicadores en el extractor provisto
        o creando uno nuevo. Retorna la tupla (metadatos, extractor).
        """
        if extractor is None:
            extractor = ExtractorIOC()

        # Lectura de bytes y cálculo de SHA-256 local
        with open(self.ruta_archivo, "rb") as f:
            raw_bytes = f.read()

        sha256_local = calcular_sha256_bytes(raw_bytes)
        # Registrar el hash SHA-256 del archivo como indicador con procedencia local
        extractor.registrar_ioc(
            sha256_local,
            TipoIOC.SHA256,
            f"Archivo .eml local ({os.path.basename(self.ruta_archivo)})",
        )

        metadatos = MetadatosCorreo(sha256_eml=sha256_local)

        # Parseo con BytesParser y política estándar
        try:
            parser = BytesParser(policy=policy.default)
            mensaje = parser.parsebytes(raw_bytes)
            if mensaje.defects:
                metadatos.es_malformado = True
                metadatos.errores_parseo.extend(
                    f"Defecto MIME: {type(defecto).__name__}" for defecto in mensaje.defects
                )
            for nombre, valor in mensaje.items():
                for defecto in getattr(valor, "defects", ()):
                    metadatos.es_malformado = True
                    metadatos.errores_parseo.append(
                        f"Defecto en encabezado {nombre}: {type(defecto).__name__}"
                    )
        except Exception as e:
            metadatos.es_malformado = True
            metadatos.errores_parseo.append(f"Falla crítica en parseo MIME: {str(e)}")
            return metadatos, extractor

        # 1. Extracción de encabezados estándar
        try:
            metadatos.asunto = str(mensaje.get("Subject", "")).strip() or None
            metadatos.de = str(mensaje.get("From", "")).strip() or None
            metadatos.para = str(mensaje.get("To", "")).strip() or None
            metadatos.fecha_cabecera = str(mensaje.get("Date", "")).strip() or None
            metadatos.message_id = str(mensaje.get("Message-ID", "")).strip() or None
            metadatos.return_path = str(mensaje.get("Return-Path", "")).strip() or None
            metadatos.reply_to = str(mensaje.get("Reply-To", "")).strip() or None
        except Exception as e:
            metadatos.errores_parseo.append(f"Error procesando encabezados básicos: {str(e)}")

        # Extracción de IOCs desde encabezados clave
        if metadatos.de:
            extractor.procesar_texto_plano(metadatos.de, f"{Procedencia.ENCABEZADO} (From)")
        if metadatos.para:
            extractor.procesar_texto_plano(metadatos.para, f"{Procedencia.ENCABEZADO} (To)")
        if metadatos.return_path:
            extractor.procesar_texto_plano(metadatos.return_path, f"{Procedencia.ENCABEZADO} (Return-Path)")
        if metadatos.reply_to:
            extractor.procesar_texto_plano(metadatos.reply_to, f"{Procedencia.ENCABEZADO} (Reply-To)")

        # 2. Encabezados Received (saltos de transporte)
        try:
            received_headers = mensaje.get_all("Received", [])
            for rcv in received_headers:
                rcv_str = str(rcv).strip()
                metadatos.saltos_received.append(rcv_str)
                extractor.procesar_texto_plano(rcv_str, f"{Procedencia.ENCABEZADO} (Received)")
        except Exception as e:
            metadatos.errores_parseo.append(f"Error procesando encabezados Received: {str(e)}")

        # 3. Declaraciones de autenticación de correo (SPF / DKIM / DMARC)
        # NUNCA se verifican; se capturan estrictamente como declaraciones incluidas
        auth_keys = [
            "Authentication-Results",
            "Received-SPF",
            "DKIM-Signature",
            "ARC-Authentication-Results",
            "ARC-Seal",
            "ARC-Message-Signature",
        ]
        for key in auth_keys:
            try:
                valores = mensaje.get_all(key, [])
                if valores:
                    metadatos.cabeceras_autenticacion[key] = [str(v).strip() for v in valores]
                    for v in valores:
                        # Evitar tratar nombres de campos de Authentication-Results
                        # (p. ej. "header.from" y "smtp.mailfrom") como dominios.
                        valor_para_ioc = re.sub(
                            r"\b(?:header\.(?:from|d|i|s)|smtp\.(?:mailfrom|helo)|dmarc\.(?:domain|policy))\b(?=\s*=)",
                            " ",
                            str(v),
                            flags=re.IGNORECASE,
                        )
                        extractor.procesar_texto_plano(valor_para_ioc, f"{Procedencia.ENCABEZADO} ({key})")
            except Exception as e:
                metadatos.errores_parseo.append(f"Error leyendo encabezado {key}: {str(e)}")

        # Verificación explícita de presencia/ausencia de DKIM-Signature
        firmas_dkim = metadatos.cabeceras_autenticacion.get("DKIM-Signature", [])
        if firmas_dkim:
            metadatos.tiene_dkim_signature = True
            metadatos.aviso_dkim = "Se detectó encabezado 'DKIM-Signature' como declaración textual. (Nota: No verificado criptográficamente)."
        else:
            metadatos.tiene_dkim_signature = False
            metadatos.aviso_dkim = (
                "Aviso crítico: No se detectó encabezado 'DKIM-Signature' en el mensaje analizado. "
                "Esta observación no valida ni refuta por sí sola la identidad del remitente. "
                "Las declaraciones de Authentication-Results son texto incluido en el archivo y no fueron verificadas."
            )

        # 4. Procesamiento de partes del cuerpo y adjuntos
        textos_planos: List[str] = []
        textos_html: List[str] = []

        try:
            if mensaje.is_multipart():
                for parte in mensaje.walk():
                    content_type = parte.get_content_type()
                    content_disposition = str(parte.get("Content-Disposition", ""))

                    if "attachment" in content_disposition.lower():
                        nombre_adj = parte.get_filename() or "archivo_sin_nombre"
                        metadatos.archivos_adjuntos.append(f"{nombre_adj} ({content_type})")
                        continue

                    if content_type == "text/plain":
                        payload = parte.get_content()
                        if isinstance(payload, str):
                            textos_planos.append(payload)
                        elif isinstance(payload, bytes):
                            textos_planos.append(payload.decode("utf-8", errors="replace"))

                    elif content_type == "text/html":
                        payload = parte.get_content()
                        if isinstance(payload, str):
                            textos_html.append(payload)
                        elif isinstance(payload, bytes):
                            textos_html.append(payload.decode("utf-8", errors="replace"))
            else:
                c_type = mensaje.get_content_type()
                payload = mensaje.get_content()
                texto_str = payload if isinstance(payload, str) else payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else str(payload)
                if c_type == "text/html":
                    textos_html.append(texto_str)
                else:
                    textos_planos.append(texto_str)

        except Exception as e:
            metadatos.es_malformado = True
            metadatos.errores_parseo.append(f"Error extrayendo partes del cuerpo: {str(e)}")

        # Resumen del cuerpo (NO volcar cuerpo completo al informe)
        long_plano = sum(len(t) for t in textos_planos)
        long_html = sum(len(t) for t in textos_html)

        metadatos.tiene_cuerpo_texto = any(texto != "" for texto in textos_planos)
        metadatos.tiene_cuerpo_html = any(texto != "" for texto in textos_html)
        metadatos.longitud_cuerpo_texto = long_plano
        metadatos.longitud_cuerpo_html = long_html

        # Construir resumen cualitativo y forense del contenido
        cuerpo_unificado = "\n".join(textos_planos + textos_html)
        coincidencias_bec = PATRON_TRANSFERENCIA_BEC.findall(cuerpo_unificado)

        resumen_lineas = [
            f"- Presencia de texto plano: {'Sí' if metadatos.tiene_cuerpo_texto else 'No'} ({long_plano} caracteres).",
            f"- Presencia de formato HTML: {'Sí' if metadatos.tiene_cuerpo_html else 'No'} ({long_html} caracteres).",
            f"- Archivos adjuntos detectados: {len(metadatos.archivos_adjuntos)}.",
        ]

        if coincidencias_bec:
            patrones_unicos = sorted(list(set(m.strip() for m in coincidencias_bec)))
            resumen_lineas.append(
                f"- **Alerta temática BEC detectada:** Se identificaron patrones de alta urgencia financiera / transferencia: {patrones_unicos}."
            )
        else:
            resumen_lineas.append("- No se detectaron patrones predefinidos de urgencia financiera o transferencia.")

        resumen_lineas.append(
            "- **Política de higiene forense:** El cuerpo completo del correo ha sido omitido deliberadamente de este informe para prevenir la exposición de datos personales o cargas no deseadas."
        )

        metadatos.resumen_cuerpo = "\n".join(resumen_lineas)

        # 5. Extracción de IOCs de los cuerpos
        for t_plano in textos_planos:
            extractor.procesar_texto_plano(t_plano, Procedencia.CUERPO_TEXTO)

        for t_html in textos_html:
            extractor.procesar_html(t_html)

        return metadatos, extractor


def parsear_archivo_eml(
    ruta_archivo: str, extractor: Optional[ExtractorIOC] = None
) -> Tuple[MetadatosCorreo, ExtractorIOC]:
    """Función de conveniencia para parsear un archivo .eml."""
    parser = ParserEML(ruta_archivo)
    return parser.procesar(extractor)
