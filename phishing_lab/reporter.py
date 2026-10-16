"""Genera informes Markdown con evidencia local, consultas API y triage por recurso.

No incluye el cuerpo completo del correo y separa los resultados API de las
referencias para consulta manual.
"""

import html
import re
from datetime import datetime, timezone
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


def _obj(valor) -> Dict:
    return valor if isinstance(valor, dict) else {}


def _resumen_api(consulta: Dict) -> str:
    """Reduce una respuesta API a hechos concretos, evitando imprimir endpoints activos."""
    servicio = str(consulta.get("service", "Servicio externo"))
    status = str(consulta.get("status", "unknown"))
    datos = consulta.get("data")
    hechos: List[str] = []

    if servicio == "VirusTotal" and isinstance(datos, dict):
        registro = _obj(datos.get("data"))
        atributos = _obj(registro.get("attributes"))
        stats = _obj(atributos.get("last_analysis_stats"))
        if stats:
            hechos.append(
                "motores: "
                + ", ".join(f"{key}={value}" for key, value in sorted(stats.items()))
            )
            results = _obj(atributos.get("last_analysis_results"))
            detecciones = []
            for engine, result in results.items():
                result_row = _obj(result)
                if result_row.get("category") in {"malicious", "suspicious"}:
                    etiqueta = result_row.get("result") or result_row.get("category")
                    detecciones.append(f"{engine}={etiqueta}")
            if detecciones:
                hechos.append("motores con alerta: " + ", ".join(detecciones[:5]))
        analysis_date = atributos.get("last_analysis_date")
        if isinstance(analysis_date, (int, float)):
            try:
                fecha = datetime.fromtimestamp(analysis_date, tz=timezone.utc).isoformat(timespec="seconds")
            except (OverflowError, OSError, ValueError):
                fecha = None
            if fecha:
                hechos.append(f"fecha del análisis informado: {fecha} UTC")

    elif servicio == "urlscan.io" and isinstance(datos, dict):
        resultados = datos.get("results", [])
        if isinstance(resultados, list):
            for resultado in resultados[:5]:
                fila = _obj(resultado)
                task = _obj(fila.get("task"))
                page = _obj(fila.get("page"))
                overall = _obj(_obj(fila.get("verdicts")).get("overall"))
                hechos.append(
                    "escaneo "
                    + str(task.get("uuid") or fila.get("_id") or "sin ID")
                    + f": fecha={task.get('time', 'N/D')}, malicioso={overall.get('malicious', 'sin veredicto')}, "
                    + f"título={page.get('title', 'N/D')}"
                )
            total = datos.get("total")
            if total is not None:
                hechos.append(f"total informado por el servicio: {total}")

    elif servicio == "DNS-over-HTTPS" and isinstance(datos, dict):
        queries = _obj(datos.get("queries"))
        for record_type, record in queries.items():
            answers = _obj(record).get("Answer", [])
            values = [str(_obj(answer).get("data", "")) for answer in answers if _obj(answer).get("data") is not None]
            if values:
                hechos.append(f"{record_type}: " + ", ".join(values[:6]))
            else:
                facts_code = _obj(record).get("Status")
                hechos.append(f"{record_type}: sin respuesta (DNS status {facts_code})")

    elif servicio == "RDAP" and isinstance(datos, dict):
        event_rows = datos.get("events", [])
        if not isinstance(event_rows, list):
            event_rows = []
        for event in event_rows:
            fila = _obj(event)
            if fila.get("eventAction") in {"registration", "last changed", "expiration"}:
                hechos.append(f"{fila.get('eventAction')}={fila.get('eventDate', 'N/D')}")
        nameservers = datos.get("nameservers", [])
        if isinstance(nameservers, list):
            names = [str(_obj(item).get("ldhName", "")) for item in nameservers if _obj(item).get("ldhName")]
            if names:
                hechos.append("servidores DNS: " + ", ".join(names[:6]))
        network = _obj(datos.get("network"))
        if network:
            facts = [f"{key}={network[key]}" for key in ("name", "handle", "startAddress", "endAddress", "country") if network.get(key)]
            hechos.extend(facts[:5])

    elif servicio == "crt.sh" and isinstance(datos, list):
        hechos.append(f"{len(datos)} entrada(s) CT devuelta(s)")
        for fila in datos[:5]:
            row = _obj(fila)
            hechos.append(
                f"certificado {row.get('id', 'N/D')}: nombre={row.get('name_value', 'N/D')}, "
                f"emisor={row.get('issuer_name', 'N/D')}, vigencia={row.get('not_before', 'N/D')} a {row.get('not_after', 'N/D')}"
            )

    message = consulta.get("message")
    if message:
        hechos.append(str(message))
    if not hechos:
        hechos.append("sin datos resumibles")
    return f"{servicio} [{status}]: " + "; ".join(hechos)


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
        lineas.append("> **Alcance y privacidad:**")
        lineas.append("> - Los correos y archivos se inspeccionan localmente; las muestras no se ejecutan ni se suben.")
        lineas.append("> - Las consultas a APIs solo ocurren con `--consultar-apis`; en ese modo se envían indicadores (no binarios) a los proveedores.")
        lineas.append("> - Las URLs extraídas no se visitan. Las referencias manuales de la sección 4 tampoco se abrieron desde el programa.")
        lineas.append("> - El tipo de archivo y la ausencia de detecciones no prueban por sí solos que una muestra sea maliciosa o inocua.")
        lineas.append("> - VirusTotal advierte que un IOC consultado puede quedar incorporado a su dataset comunitario; no consultar datos confidenciales o personales.")
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
            lineas.append("- **Nota de integridad:** Hash calculado de forma local. El hash del correo completo no se consulta en VirusTotal.")
            lineas.append("")

        if self.res.archivos_analizados:
            lineas.append("### Archivos y adjuntos analizados localmente")
            lineas.append("| Nombre | Origen | Tamaño | SHA-256 | MIME declarado | Firma/tipo detectado |")
            lineas.append("| :--- | :--- | ---: | :--- | :--- | :--- |")
            for archivo in self.res.archivos_analizados:
                firma = archivo.firma_detectada or archivo.tipo_detectado
                lineas.append(
                    f"| {_escapar_markdown(archivo.nombre)} | {_escapar_markdown(archivo.procedencia)} | "
                    f"{archivo.tamano_bytes} bytes | {_codigo_inline(archivo.sha256)} | "
                    f"{_escapar_markdown(archivo.mime_declarado or 'N/D')} | {_escapar_markdown(firma)} |"
                )
            lineas.append("")
            lineas.append("La identificación por firma es una observación estática; no determina si el archivo contiene malware.")
            lineas.append("")
        elif not self.res.entradas_manuales and not self.res.ruta_eml:
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

            if meta.archivos_adjuntos:
                lineas.append("### Adjuntos detectados")
                lineas.append("Los hashes SHA-256 se calcularon sobre los bytes decodificados en memoria; no se guardaron ni ejecutaron los adjuntos.")
                for adjunto in meta.archivos_adjuntos:
                    lineas.append(f"- {_codigo_inline(adjunto)}")
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
            lineas.append("*No se encontraron IOCs en el correo o las entradas suministradas.*")
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
        lineas.append("## 4. Referencias para consulta manual")
        lineas.append("")
        lineas.append(
            "Estos enlaces sirven para una revisión manual y el programa no los abre. Esta tabla conserva las referencias generadas; "
            "los resultados de las APIs ejecutadas se muestran por separado en la sección 5."
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

        # Resultados obtenidos por consultas API
        lineas.append("## 5. Resultados de consultas API")
        lineas.append("")
        if not self.res.consultas_api:
            lineas.append("No se ejecutaron consultas externas. El informe conserva el análisis local y clasifica el resultado como SOSPECHOSO cuando no hay cobertura suficiente para llamarlo limpio.")
            lineas.append("")
        else:
            lineas.append("Cada respuesta se conserva en el JSON de salida si se solicitó `--salida-json`. `sin resultados`, error, límite de cuota y falta de clave son estados distintos; no equivalen a limpio.")
            lineas.append("")
            lineas.append("| Servicio | Tipo | Indicador | Estado | HTTP | Hora UTC | Resultado / evidencia |")
            lineas.append("| :--- | :--- | :--- | :--- | ---: | :--- | :--- |")
            for consulta in self.res.consultas_api:
                service = _escapar_markdown(consulta.get("service", "N/D"))
                kind = _escapar_markdown(consulta.get("indicator_type", "N/D"))
                indicator = str(consulta.get("indicator", ""))
                # Mostrar los IOCs de red defanged y sin convertirlos en enlaces activos.
                for item in self.res.indicadores:
                    if item.valor == indicator:
                        indicator = item.defanged or indicator
                        break
                if indicator.startswith(("http://", "https://")):
                    indicator = indicator.replace("https://", "hxxps://", 1).replace("http://", "hxxp://", 1)
                status = _escapar_markdown(consulta.get("status", "unknown"))
                http_status = _escapar_markdown(consulta.get("http_status") or "N/D")
                queried_at = _escapar_markdown(consulta.get("queried_at", "N/D"))
                summary = _escapar_markdown(_resumen_api(consulta))
                lineas.append(
                    f"| {service} | {kind} | {_codigo_inline(indicator)} | **{status}** | {http_status} | {queried_at} | {summary} |"
                )
            lineas.append("")
            lineas.append("RDAP informa datos registrales; DNS y Certificate Transparency describen infraestructura. Esos datos aportan contexto, pero por sí solos no constituyen detección de malware.")
            lineas.append("")

        # Veredictos separados por recurso
        lineas.append("## 6. Veredicto y recomendaciones por recurso")
        lineas.append("")
        if not self.res.evaluaciones:
            lineas.append("No se generaron fichas de evaluación para esta entrada.")
            lineas.append("")
        else:
            lineas.append("### Resumen")
            lineas.append("| ID | Recurso | Identificador | Veredicto | Confianza | Cobertura |")
            lineas.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for evaluacion in self.res.evaluaciones:
                lineas.append(
                    f"| {_escapar_markdown(evaluacion.recurso_id)} | {_escapar_markdown(evaluacion.tipo)} | "
                    f"{_codigo_inline(evaluacion.identificador)} | **{_escapar_markdown(evaluacion.veredicto)}** | "
                    f"{_escapar_markdown(evaluacion.confianza)} | {_escapar_markdown(evaluacion.cobertura)} |"
                )
            lineas.append("")

            for evaluacion in self.res.evaluaciones:
                lineas.append(f"### {evaluacion.recurso_id} — {evaluacion.tipo}: {_codigo_inline(evaluacion.identificador)}")
                lineas.append(f"- **Veredicto:** {evaluacion.veredicto} ({evaluacion.confianza})")
                lineas.append(f"- **Amenaza:** {_escapar_markdown(evaluacion.amenaza)}")
                lineas.append(f"- **Cobertura:** {_escapar_markdown(evaluacion.cobertura)}")
                lineas.append("- **Evidencia y observaciones:**")
                for fundamento in evaluacion.fundamentos:
                    lineas.append(f"  - {_escapar_markdown(fundamento)}")
                lineas.append("- **Impacto potencial C-I-A:**")
                for dimension, impacto in evaluacion.impacto_cia.items():
                    lineas.append(f"  - **{_escapar_markdown(dimension)}:** {_escapar_markdown(impacto)}")
                lineas.append(f"- **Medida para el usuario:** {_escapar_markdown(evaluacion.medida_usuario)}")
                lineas.append(f"- **Control para la organización:** {_escapar_markdown(evaluacion.control_organizacion)}")
                lineas.append("")

        lineas.append("### Alcance de la clasificación")
        lineas.append("`LIMPIO` significa que las consultas de reputación que se pudieron evaluar no informaron detecciones; no garantiza ausencia de malware. `SOSPECHOSO` puede indicar señales concretas que requieren corroboración o, con confianza baja, falta de evidencia para despejar el riesgo. `MALICIOSO/INFECTADO` se emite ante una detección externa explícita; no se infiere una familia de malware sin evidencia específica.")
        lineas.append("")
        lineas.append("---")
        lineas.append("*Informe forense generado por Phishing Lab.*")

        return "\n".join(lineas)


def generar_informe_markdown(resultado: ResultadoLaboratorio) -> str:
    """Función directa para generar el informe Markdown a partir del resultado."""
    generador = GeneradorInforme(resultado)
    return generador.generar()
