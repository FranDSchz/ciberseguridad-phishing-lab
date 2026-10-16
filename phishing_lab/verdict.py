"""Reglas explicables de triage para correos, indicadores y archivos.

Las reglas separan hallazgos observados de contexto y limitaciones de cobertura.
No ejecutan muestras ni llaman servicios externos.
"""

from email.utils import parseaddr
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .models import ArchivoAnalizado, EvaluacionRecurso, Indicador, MetadatosCorreo, TipoIOC


def _dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "__dict__"):
        return dict(value.__dict__)
    return {}


def _field(value: Any, name: str, default: Any = None) -> Any:
    return _dict(value).get(name, default)


def _status(query: Any) -> str:
    return str(_field(query, "status", "unknown")).lower()


def _data(query: Any) -> Any:
    return _field(query, "data")


def _queries_for(queries: Iterable[Any], indicator: str) -> List[Any]:
    return [query for query in queries if str(_field(query, "indicator", "")) == indicator]


def _vt_stats(query: Any) -> Optional[Dict[str, int]]:
    outer = _dict(_data(query))
    record = _dict(outer.get("data", outer))
    attributes = _dict(record.get("attributes"))
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        return None
    return {str(key): int(value or 0) for key, value in stats.items() if isinstance(value, (int, float))}


def _urlscan_results(query: Any) -> List[Dict[str, Any]]:
    results = _dict(_data(query)).get("results", [])
    return [_dict(item) for item in results] if isinstance(results, list) else []


def _urlscan_flags(query: Any) -> Tuple[bool, bool]:
    """Return (malicious, has_explicit_overall_verdict)."""
    malicious = False
    has_verdict = False
    for result in _urlscan_results(query):
        overall = _dict(_dict(result.get("verdicts")).get("overall"))
        value = overall.get("malicious")
        if isinstance(value, bool):
            has_verdict = True
            malicious = malicious or value
    return malicious, has_verdict


def _positive_detection(query: Any) -> Tuple[bool, Optional[str], bool]:
    """Return (malicious verdict, evidence, weak detection)."""
    service = str(_field(query, "service", "")).lower()
    if service.startswith("virustotal"):
        stats = _vt_stats(query)
        if stats is None:
            return False, None, False
        count = stats.get("malicious", 0)
        if count >= 3:
            return True, f"VirusTotal informa {count} detecciones maliciosas en su análisis del indicador.", False
        if count > 0:
            return False, f"VirusTotal informa {count} detección(es) maliciosa(s); requiere corroboración.", True
        suspicious = stats.get("suspicious", 0)
        if suspicious > 0:
            return False, f"VirusTotal informa {suspicious} detección(es) sospechosa(s), sin confirmación maliciosa.", True
    elif service.startswith("urlscan"):
        malicious, _ = _urlscan_flags(query)
        if malicious:
            return True, "urlscan.io marca como malicioso al menos un escaneo histórico del indicador.", False
    return False, None, False


def _reputation_complete(query: Any) -> bool:
    """Only usable, concrete reputation reports count as completed coverage."""
    if _status(query) != "found":
        return False
    service = str(_field(query, "service", "")).lower()
    if service.startswith("virustotal"):
        stats = _vt_stats(query)
        return stats is not None and (stats.get("harmless", 0) + stats.get("undetected", 0) > 0)
    if service.startswith("urlscan"):
        results = _urlscan_results(query)
        return bool(results) and all(
            isinstance(
                _dict(_dict(_dict(result).get("verdicts")).get("overall")).get("malicious"),
                bool,
            )
            for result in results
        )
    return False


def _email_signals(meta: Optional[MetadatosCorreo]) -> List[str]:
    if not meta:
        return []
    signals: List[str] = []
    if meta.resumen_cuerpo and "Alerta temática BEC detectada" in meta.resumen_cuerpo:
        signals.append(
            "El cuerpo contiene un patrón predefinido de urgencia financiera/transferencia; es un indicio de posible BEC, no una confirmación."
        )
    sender = parseaddr(meta.de or "")[1].rsplit("@", 1)
    reply_to = parseaddr(meta.reply_to or "")[1].rsplit("@", 1)
    if len(sender) == 2 and len(reply_to) == 2 and sender[1].lower() != reply_to[1].lower():
        signals.append("El dominio de Reply-To difiere del dominio de From; requiere verificar la identidad del remitente.")
    return signals


def _context_summary(query: Any) -> str:
    """Summarize infrastructure context without treating it as malware evidence."""
    service = str(_field(query, "service", "Fuente externa"))
    status = _status(query)
    data = _data(query)
    message = _field(query, "message")

    if service == "DNS-over-HTTPS" and isinstance(data, dict):
        query_map = data.get("queries", {})
        answers: List[str] = []
        if isinstance(query_map, dict):
            for record_type, record_data in query_map.items():
                for answer in _dict(record_data).get("Answer", []) or []:
                    answer_value = _dict(answer).get("data")
                    if answer_value is not None:
                        answers.append(f"{record_type}={answer_value}")
        detail = "; ".join(answers[:12]) if answers else "sin respuestas en los tipos consultados"
        return f"DNS público: {detail} (estado: {status})."

    if service == "RDAP" and isinstance(data, dict):
        events = data.get("events", [])
        dates = []
        if isinstance(events, list):
            for event in events:
                row = _dict(event)
                if row.get("eventAction") in {"registration", "last changed", "expiration"} and row.get("eventDate"):
                    dates.append(f"{row.get('eventAction')}={row.get('eventDate')}")
        if not dates:
            network = _dict(data.get("network"))
            dates = [f"red={network['name']}" for _ in [0] if network.get("name")]
        detail = "; ".join(dates[:4]) if dates else "registro RDAP disponible"
        return f"RDAP: {detail} (dato registral, no veredicto de malware)."

    if service == "crt.sh" and isinstance(data, list):
        names = sorted({
            str(_dict(row).get("name_value", "")).strip()
            for row in data
            if _dict(row).get("name_value")
        })
        detail = ", ".join(names[:8]) if names else "sin nombres visibles"
        return f"crt.sh: {len(data)} entrada(s) CT; nombres observados: {detail}. La presencia de certificados no determina maliciosidad."

    return f"{service}: {message or 'sin observación resumida'} (estado: {status}; contexto, no veredicto de malware)."


def _reputation_summary(query: Any) -> str:
    service = str(_field(query, "service", "Fuente externa"))
    status = _status(query)
    message = _field(query, "message")
    if service == "VirusTotal" and _vt_stats(query) is not None:
        stats = _vt_stats(query) or {}
        return (
            "VirusTotal: "
            f"{stats.get('malicious', 0)} maliciosa(s), {stats.get('suspicious', 0)} sospechosa(s), "
            f"{stats.get('undetected', 0)} no detectada(s) (según los motores que respondieron)."
        )
    if service == "urlscan.io" and status == "found":
        results = _urlscan_results(query)
        flags = [_urlscan_flags(query) for _ in results]
        marked = sum(1 for malicious, _ in flags if malicious)
        verdicts = sum(1 for _, explicit in flags if explicit)
        return f"urlscan.io: {len(results)} escaneo(s) histórico(s); {marked} marcado(s) malicioso(s), {verdicts} con veredicto explícito."
    return f"{service}: {message or 'sin informe existente'} (estado: {status})."


def _recommendations(kind: str, verdict: str) -> Tuple[str, str, Dict[str, str]]:
    if kind == "Correo electrónico":
        user = "No responder ni abrir enlaces/adjuntos; reportar el correo y conservar el original."
        organization = "Poner en cuarentena los mensajes coincidentes, buscar otros destinatarios y verificar pedidos de pago por un canal alternativo."
        cia = {
            "Confidencialidad": "Riesgo potencial de exposición de credenciales o datos si hubo interacción.",
            "Integridad": "Riesgo potencial de uso no autorizado de la cuenta o modificación de pagos.",
            "Disponibilidad": "No demostrado con la evidencia actual.",
        }
    elif kind == "Archivo":
        user = "No ejecutar ni abrir la muestra; conservarla aislada y registrar su SHA-256."
        organization = "Bloquear el hash si la evidencia lo confirma; buscar equipos afectados y activar respuesta a incidentes según corresponda."
        cia = {
            "Confidencialidad": "Impacto potencial sujeto al comportamiento confirmado; no inferido por tipo o extensión.",
            "Integridad": "Impacto potencial sujeto al comportamiento confirmado; no inferido por tipo o extensión.",
            "Disponibilidad": "Impacto potencial sujeto al comportamiento confirmado; no inferido por tipo o extensión.",
        }
    else:
        user = "No visitar el enlace; reportar el indicador y evitar ingresar credenciales."
        organization = "Bloquear el IOC confirmado en los controles disponibles y revisar registros de navegación y correo."
        cia = {
            "Confidencialidad": "Riesgo potencial de robo de credenciales/datos si hubo interacción.",
            "Integridad": "No demostrado; podría afectarse si se usaron credenciales comprometidas.",
            "Disponibilidad": "No demostrado con la evidencia actual.",
        }

    if verdict == "LIMPIO":
        user = "No se observaron indicadores en las consultas registradas; mantener las prácticas habituales."
        organization = "Conservar el resultado y monitorear según la política interna; la ausencia de detecciones no garantiza inocuidad."
    return user, organization, cia


def evaluar_recursos(
    indicadores: List[Indicador],
    archivos: List[ArchivoAnalizado],
    consultas: List[Any],
    metadatos: Optional[MetadatosCorreo],
    ruta_eml: Optional[str],
    consultas_solicitadas: bool,
) -> List[EvaluacionRecurso]:
    """Genera un dictamen separado por correo, artefacto e IOC, con cobertura visible."""
    evaluations: List[EvaluacionRecurso] = []
    seen = set()

    def create(
        kind: str,
        identifier: str,
        resource_id: str,
        lookup_key: Optional[str] = None,
        local_signals: Optional[List[str]] = None,
        local_observations: Optional[List[str]] = None,
    ) -> None:
        key = (kind, resource_id)
        if key in seen:
            return
        seen.add(key)

        relevant = _queries_for(consultas, lookup_key or identifier)
        evidence = list(local_observations or [])
        signals = list(local_signals or [])
        positive_providers = set()
        weak_detections: List[str] = []
        reputation_queries = 0
        successful_reputation_queries = 0

        for query in relevant:
            service = str(_field(query, "service", ""))
            if service in {"VirusTotal", "urlscan.io"}:
                reputation_queries += 1
                if _reputation_complete(query):
                    successful_reputation_queries += 1
                    evidence.append(_reputation_summary(query))
                else:
                    evidence.append(_reputation_summary(query))
                malicious, detail, weak = _positive_detection(query)
                if detail:
                    evidence.append(detail)
                    if malicious:
                        positive_providers.add(service)
                    elif weak:
                        weak_detections.append(detail)
            else:
                # DNS, RDAP y CT aportan contexto; por sí solos no prueban que el IOC sea malicioso.
                evidence.append(_context_summary(query))

        if positive_providers:
            verdict = "MALICIOSO/INFECTADO"
            confidence = "Alta" if len(positive_providers) >= 2 else "Media"
            threat = "La fuente externa marca el indicador; familia y comportamiento requieren evidencia específica."
        elif signals or weak_detections:
            verdict = "SOSPECHOSO"
            confidence = "Media" if len(signals) + len(weak_detections) >= 2 else "Baja"
            threat = "Posible phishing/BEC o archivo de riesgo; no confirmado como malware."
        elif reputation_queries and successful_reputation_queries == reputation_queries:
            verdict = "LIMPIO"
            confidence = "Baja"
            evidence.append("Las consultas de reputación aplicables devolvieron informes sin detección maliciosa; esto no garantiza inocuidad.")
            threat = "No se observaron detecciones en las consultas registradas."
        else:
            verdict = "SOSPECHOSO"
            confidence = "Baja"
            if reputation_queries:
                evidence.append(
                    f"Cobertura incompleta: {successful_reputation_queries}/{reputation_queries} consultas de reputación devolvieron un informe evaluable; no alcanza para concluir limpio."
                )
            else:
                reason = "Las consultas externas no se realizaron." if not consultas_solicitadas else "No hubo resultados de reputación evaluables."
                evidence.append(f"{reason} La clasificación es preventiva y no afirma que el recurso sea malware.")
            threat = "No determinada con la evidencia disponible."

        user_action, organization_control, cia = _recommendations(kind, verdict)
        evaluations.append(EvaluacionRecurso(
            recurso_id=resource_id,
            tipo=kind,
            identificador=identifier,
            veredicto=verdict,
            confianza=confidence,
            fundamentos=list(dict.fromkeys(evidence)),
            amenaza=threat,
            impacto_cia=cia,
            medida_usuario=user_action,
            control_organizacion=organization_control,
            cobertura=(
                f"{successful_reputation_queries}/{reputation_queries} consultas de reputación con informe evaluable"
                if reputation_queries
                else ("Consultas externas solicitadas, sin fuente de reputación aplicable" if consultas_solicitadas else "Modo local; sin consultas de reputación")
            ),
        ))

    if ruta_eml:
        create("Correo electrónico", ruta_eml, "EML-01", local_signals=_email_signals(metadatos))

    for index, file_info in enumerate(archivos, start=1):
        observations = [f"Tipo detectado por firma: {file_info.tipo_detectado}."]
        if file_info.firma_detectada:
            observations.append(f"Firma observada: {file_info.firma_detectada}.")
        if file_info.nota:
            observations.append(file_info.nota)
        create(
            "Archivo",
            file_info.nombre,
            f"ARCHIVO-{index:02d}",
            lookup_key=file_info.sha256,
            local_observations=observations,
        )

    for index, indicator in enumerate(indicadores, start=1):
        if indicator.tipo in {TipoIOC.SHA256, TipoIOC.EMAIL}:
            continue
        kind = {
            TipoIOC.URL: "URL",
            TipoIOC.DOMINIO: "Dominio",
            TipoIOC.IPV4: "IP",
        }.get(indicator.tipo, "Indicador")
        create(kind, indicator.valor, f"{kind.upper()}-{index:02d}")

    # Un adjunto marcado por una fuente de reputación también es evidencia ligada al correo que lo transportó.
    email_evaluations = [item for item in evaluations if item.tipo == "Correo electrónico"]
    if email_evaluations:
        email_eval = email_evaluations[0]
        local_email_signals = _email_signals(metadatos)
        for index, file_info in enumerate(archivos, start=1):
            if file_info.procedencia != "Adjunto del archivo .eml":
                continue
            resource_id = f"ARCHIVO-{index:02d}"
            file_eval = next((item for item in evaluations if item.recurso_id == resource_id), None)
            if file_eval and file_eval.veredicto == "MALICIOSO/INFECTADO":
                email_eval.veredicto = "MALICIOSO/INFECTADO"
                email_eval.confianza = "Media"
                email_eval.amenaza = "El correo transporta un adjunto cuyo hash fue marcado como malicioso por una fuente externa."
                email_eval.fundamentos.append(
                    f"Adjunto {file_info.nombre}: SHA-256 {file_info.sha256} clasificado MALICIOSO/INFECTADO."
                )
            elif file_eval and file_eval.veredicto == "SOSPECHOSO" and any(
                "detección" in item.lower() or "marcado como malicioso" in item.lower()
                for item in file_eval.fundamentos
            ):
                email_eval.fundamentos.append(
                    f"Adjunto {file_info.nombre}: una fuente reportó una detección que requiere corroboración; ver su ficha independiente."
                )
                if email_eval.veredicto == "LIMPIO":
                    email_eval.veredicto = "SOSPECHOSO"
                    email_eval.confianza = "Baja"

        related_resources: List[EvaluacionRecurso] = []
        for index, file_info in enumerate(archivos, start=1):
            if file_info.procedencia == "Adjunto del archivo .eml":
                related = next((item for item in evaluations if item.recurso_id == f"ARCHIVO-{index:02d}"), None)
                if related:
                    related_resources.append(related)
        for indicator in indicadores:
            if indicator.tipo in {TipoIOC.SHA256, TipoIOC.EMAIL}:
                continue
            if not any("Entrada manual" not in provenance for provenance in indicator.procedencias):
                continue
            related = next(
                (item for item in evaluations if item.identificador == indicator.valor and item.tipo in {"URL", "Dominio", "IP"}),
                None,
            )
            if related:
                related_resources.append(related)

        for related in related_resources:
            if related.veredicto == "MALICIOSO/INFECTADO":
                email_eval.veredicto = "MALICIOSO/INFECTADO"
                email_eval.confianza = "Media"
                email_eval.amenaza = "El correo contiene un archivo o indicador relacionado marcado como malicioso por una fuente externa."
                email_eval.fundamentos.append(
                    f"Recurso relacionado {related.tipo} {related.identificador}: marcado MALICIOSO/INFECTADO; ver ficha {related.recurso_id}."
                )
            elif related.veredicto == "SOSPECHOSO" and any(
                "detección" in item.lower() or "marcado como malicioso" in item.lower()
                for item in related.fundamentos
            ):
                email_eval.fundamentos.append(
                    f"Recurso relacionado {related.tipo} {related.identificador}: una fuente informó una detección que requiere corroboración; ver ficha {related.recurso_id}."
                )
                if email_eval.veredicto != "MALICIOSO/INFECTADO":
                    email_eval.veredicto = "SOSPECHOSO"
                    email_eval.confianza = "Baja"

        # Solo se extiende un resultado LIMPIO al correo si todos sus recursos
        # relacionados tuvieron reportes de reputación evaluables y sin alertas.
        if related_resources and not local_email_signals and all(item.veredicto == "LIMPIO" for item in related_resources):
            email_eval.veredicto = "LIMPIO"
            email_eval.confianza = "Baja"
            email_eval.amenaza = "No se observaron detecciones en los recursos relacionados consultados; el correo completo no tiene un reporte independiente."
            email_eval.fundamentos.append("Todos los enlaces, dominios, IPs y adjuntos relacionados evaluados quedaron LIMPIOS con confianza baja.")
            email_eval.medida_usuario, email_eval.control_organizacion, email_eval.impacto_cia = _recommendations("Correo electrónico", "LIMPIO")

    return evaluations


__all__ = ["evaluar_recursos"]
