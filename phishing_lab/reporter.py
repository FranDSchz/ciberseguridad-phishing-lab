"""
Módulo de generación de informes forenses reproducibles en formato Markdown.
Presenta los metadatos, IOCs con procedencia, declaraciones de autenticación
(con advertencia explícita sobre DKIM) y las cuatro tablas de servicios externos
(VirusTotal, urlscan.io, WHOIS/DNSChecker, crt.sh) en estado 'No consultado' / 'No aplicable'.
Garantiza que el cuerpo completo no sea volcado y que no se emitan veredictos automáticos.
"""

import html
import re
from typing import Dict, List, Optional
from .models import MetadatosCorreo, Indicador, ReferenciaConsulta, ResultadoLaboratorio, TipoIOC
from .references import ConstructorReferencias


def _escapar_markdown(texto: Optional[str]) -> str:
    """Escapa HTML y sintaxis Markdown en texto no confiable."""
    if not texto:
        return ""
    limpio = html.escape(str(texto).replace("\r", " ").replace("\n", " "), quote=False)
    return re.sub(r"([\\`*_{}\[\]#!])", r"\\\1", limpio).replace("|", "\\|")


def _codigo_inline(texto: Optional[str]) -> str:
    """Envuelve datos no confiables en un code span que no puede cerrarse desde el dato."""
    valor = str(texto or "").replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    longest = max((len(run) for run in re.findall(r"`+", valor)), default=0)
    fence = "`" * (longest + 1)
    padding = " " if valor.startswith((" ", "`")) or valor.endswith((" ", "`")) else ""
    return f"{fence}{padding}{valor}{padding}{fence}"


def _bloque_codigo(texto: Optional[str], lenguaje: str = "text") -> str:
    """Crea un bloque seguro aun si el valor incluye cercas Markdown."""
    valor = str(texto or "")
    longest = max((len(run) for run in re.findall(r"`+", valor)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lenguaje}\n{valor}\n{fence}"


class GeneradorInforme:
    """
    Construye informes forenses en formato Markdown estándar a partir
    de los resultados consolidados de Phishing Lab.
    """

    def __init__(self, resultado: ResultadoLaboratorio):
        self.res = resultado

    def generar(self) -> str:
        lineas: List[str] = []

        # Encabezado principal
        lineas.append("# Laboratorio de Análisis Forense de Phishing (Phishing Lab)")
        lineas.append("")
        lineas.append(f"**Fecha y hora del análisis:** `{self.res.fecha_analisis}`  ")
        lineas.append(f"**Zona horaria predeterminada:** `{self.res.zona_horaria}`  ")
        lineas.append(f"**Versión de la herramienta:** `{self.res.version_herramienta}`  ")
        lineas.append("")

        # Bloque de aviso legal y metodológico
        lineas.append("> [!IMPORTANT]")
        lineas.append("> **Declaración de Entorno Pasivo y Ausencia de Veredicto Automático:**")
        lineas.append("> - Esta herramienta opera de manera estrictamente local y pasiva.")
        lineas.append("> - **CERO consultas de red realizadas:** No se enviaron peticiones HTTP/DNS ni se conectó con APIs o motores externos.")
        lineas.append("> - **Sin apertura automática:** Los hipervínculos de consulta generados NO fueron ejecutados ni abiertos.")
        lineas.append("> - **No veredicto automático:** La determinación de maliciosidad o fraude es de exclusiva competencia del analista forense.")
        lineas.append("> - **Privacidad de artefactos:** Los binarios originales no se suben a ningún servicio público o privado.")
        lineas.append("")

        # Sección 1: Fuentes y Datos de Entrada
        lineas.append("## 1. Datos de Entrada y Fuentes Analizadas")
        lineas.append("")
        if self.res.entradas_manuales:
            lineas.append("### Entradas Manuales Suministradas")
            for categoria, valores in self.res.entradas_manuales.items():
                lineas.append(f"- **{categoria}:**")
                for v in valores:
                    lineas.append(f"  - {_codigo_inline(v)}")
            lineas.append("")

        if self.res.ruta_eml:
            lineas.append("### Archivo de Correo Electrónico (.eml)")
            lineas.append(f"- **Ruta local:** `{self.res.ruta_eml}`")
            lineas.append(f"- **Hash SHA-256 local:** `{self.res.sha256_eml}`")
            lineas.append(
                "- **Nota de integridad:** Hash calculado de forma 100% local; el archivo no fue transmitido a la red."
            )
            lineas.append("")
        elif not self.res.entradas_manuales:
            lineas.append("*No se proporcionaron entradas para el análisis.*")
            lineas.append("")

        # Sección 2: Metadatos y Encabezados del Correo
        if self.res.metadatos_eml:
            meta = self.res.metadatos_eml
            lineas.append("## 2. Metadatos y Estructura MIME del Correo (.eml)")
            lineas.append("")

            # Tabla de encabezados estándar
            lineas.append("### Encabezados Estándar del Mensaje")
            lineas.append("| Encabezado | Valor Declarado |")
            lineas.append("| :--- | :--- |")
            lineas.append(f"| **Subject** | {_escapar_markdown(meta.asunto or 'N/A')} |")
            lineas.append(f"| **From** | {_escapar_markdown(meta.de or 'N/A')} |")
            lineas.append(f"| **To** | {_escapar_markdown(meta.para or 'N/A')} |")
            lineas.append(f"| **Date** | {_escapar_markdown(meta.fecha_cabecera or 'N/A')} |")
            lineas.append(f"| **Message-ID** | {_escapar_markdown(meta.message_id or 'N/A')} |")
            lineas.append(f"| **Return-Path** | {_escapar_markdown(meta.return_path or 'N/A')} |")
            lineas.append(f"| **Reply-To** | {_escapar_markdown(meta.reply_to or 'N/A')} |")
            lineas.append("")

            # Declaraciones de autenticación de correo
            lineas.append("### Declaraciones de Autenticación de Correo (SPF / DKIM / DMARC)")
            lineas.append("")
            lineas.append("> [!NOTE]")
            lineas.append("> **Aviso Forense sobre Autenticación:**")
            lineas.append("> Los siguientes encabezados se presentan estrictamente como **declaraciones textuales** recibidas en el archivo.")
            lineas.append("> **NUNCA son verificadas criptográficamente** ni contrastadas contra registros DNS en tiempo real por esta herramienta.")
            lineas.append("> En ausencia de verificación de confianza o si provienen de saltos comprometidos, estos valores pueden estar forjados.")
            lineas.append("")

            if meta.cabeceras_autenticacion:
                for cabecera, valores in meta.cabeceras_autenticacion.items():
                    lineas.append(f"#### Encabezado `{cabecera}`")
                    for val in valores:
                        lineas.append(_bloque_codigo(val))
            else:
                lineas.append("*No se detectaron encabezados explícitos de autenticación (SPF/DKIM/DMARC).*")
                lineas.append("")

            # Alerta crítica sobre DKIM-Signature
            if not meta.tiene_dkim_signature:
                lineas.append("")
                lineas.append("> [!WARNING]")
                lineas.append(f"> **{_escapar_markdown(meta.aviso_dkim)}**")
                lineas.append("")
            else:
                lineas.append("")
                lineas.append(f"- **Estado DKIM declarado:** {_escapar_markdown(meta.aviso_dkim)}")
                lineas.append("")

            # Resumen del cuerpo (Sin volcado completo)
            lineas.append("### Resumen Estructural y Temático del Cuerpo")
            lineas.append(meta.resumen_cuerpo or "*Sin resumen disponible.*")
            lineas.append("")

            # Errores o advertencias de parseo si los hubiera
            if meta.es_malformado or meta.errores_parseo:
                lineas.append("### Advertencias de Parseo de Entrada")
                for err in meta.errores_parseo:
                    lineas.append(f"- :warning: {_codigo_inline(err)}")
                lineas.append("")

        # Sección 3: Indicadores de Compromiso (IOCs) y Procedencia
        lineas.append("## 3. Indicadores de Compromiso (IOCs) y Procedencia")
        lineas.append("")
        if not self.res.indicadores:
            lineas.append("*No se encontraron indicadores de compromiso (URLs, dominios ni IPs).*")
            lineas.append("")
        else:
            lineas.append("| Tipo | Indicador (Sanitizado / Defanged) | Indicador Original | Procedencia / Origen | ¿Reservado / Doc? | Detalle / Punycode |")
            lineas.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for ind in self.res.indicadores:
                tipo_visible = "Dominio candidato" if ind.tipo == TipoIOC.DOMINIO else ind.tipo.value
                tipo_str = _escapar_markdown(tipo_visible)
                defanged_str = _codigo_inline(ind.defanged)
                original_str = _codigo_inline(ind.valor)
                procedencias_str = _escapar_markdown("; ".join(ind.procedencias))
                reservado_str = "**Sí (reservado/documentación)**" if ind.es_reservado else "No detectado como reservado"

                detalles = []
                if ind.detalle_reservado:
                    detalles.append(ind.detalle_reservado)
                if ind.punycode_info:
                    detalles.append(ind.punycode_info)
                detalle_final = _escapar_markdown("; ".join(detalles)) if detalles else "-"

                lineas.append(f"| {tipo_str} | {defanged_str} | {original_str} | {procedencias_str} | {reservado_str} | {detalle_final} |")
            lineas.append("")

        # Sección 4: Cuatro Secciones de Consulta Externa
        lineas.append("## 4. Secciones de Consulta Externa (Referencias Pasivas Seguras)")
        lineas.append("")
        lineas.append(
            "Se construyen referencias dirigidas hacia cuatro servicios clave para la labor manual del analista. "
            "**Estado unificado: 'No consultado' / 'No aplicable'** (ninguna petición fue enviada)."
        )
        lineas.append("")

        # Agrupar referencias por servicio
        servicios_orden = [
            "VirusTotal",
            "urlscan.io",
            "WHOIS / DNSChecker",
            "crt.sh",
        ]
        refs_por_srv: Dict[str, List[ReferenciaConsulta]] = {s: [] for s in servicios_orden}
        for ref in self.res.referencias_consulta:
            if ref.servicio in refs_por_srv:
                refs_por_srv[ref.servicio].append(ref)
            else:
                refs_por_srv.setdefault(ref.servicio, []).append(ref)

        for idx, srv_nombre in enumerate(servicios_orden, start=1):
            lineas.append(f"### 4.{idx}. {srv_nombre}")
            lineas.append("")
            refs_srv = refs_por_srv.get(srv_nombre, [])
            if not refs_srv:
                lineas.append(f"*No hay referencias generadas para {srv_nombre}.*")
                lineas.append("")
                continue

            lineas.append("| Pertinente | Referencia de Consulta | Observación | Fuente / Indicador | Fecha | Estado |")
            lineas.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for r in refs_srv:
                pert_str = _escapar_markdown(r.pertinente)
                # Formatear la URL de consulta de forma clicable pero segura
                if r.referencia_url and r.referencia_url != "N/A":
                    if " | " in r.referencia_url:
                        # Múltiples enlaces (caso WHOIS + DNSChecker)
                        partes_enlace = []
                        for sub_enlace in r.referencia_url.split(" | "):
                            if ":" in sub_enlace:
                                tag, _, u = sub_enlace.partition(": ")
                                partes_enlace.append(f"[{tag.strip()}]({u.strip()})")
                            else:
                                partes_enlace.append(f"[Enlace]({sub_enlace.strip()})")
                        ref_url_str = " \\| ".join(partes_enlace)
                    else:
                        ref_url_str = f"[Consulta {srv_nombre}]({r.referencia_url})"
                else:
                    ref_url_str = "`N/A`"

                obs_str = _escapar_markdown(r.observacion)
                fuente_str = _escapar_markdown(r.fuente)
                fecha_str = _escapar_markdown(r.fecha)
                estado_str = f"**{_escapar_markdown(r.estado)}**"

                lineas.append(
                    f"| {pert_str} | {ref_url_str} | {obs_str} | {fuente_str} | {fecha_str} | {estado_str} |"
                )
            lineas.append("")

        # Veredicto y Conclusiones del Laboratorio
        lineas.append("## 5. Veredicto y Dictamen del Laboratorio")
        lineas.append("")
        lineas.append("> [!NOTE]")
        lineas.append("> **Veredicto Automático:** `NO EMITIDO (Requiere Análisis Humano)`  ")
        lineas.append("> **Veredicto Humano Recomendado:**  ")
        lineas.append("> [ ] Legítimo  ")
        lineas.append("> [ ] Sospechoso  ")
        lineas.append("> [ ] Malicioso (Phishing / BEC / Suplantación)  ")
        lineas.append("> [ ] No Concluyente  ")
        lineas.append("")
        lineas.append("---")
        lineas.append("*Informe forense generado por Phishing Lab.*")

        return "\n".join(lineas)


def generar_informe_markdown(resultado: ResultadoLaboratorio) -> str:
    """Función directa para generar el informe Markdown a partir del resultado."""
    generador = GeneradorInforme(resultado)
    return generador.generar()
