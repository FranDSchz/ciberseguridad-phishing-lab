"""Explicit, read-only lookups against public threat-intelligence services.

This module performs network requests only when one of the public methods is
called; importing it never contacts a service. Every request is an HTTPS GET.
It does not submit URLs to urlscan, upload files, request rescans, open an IOC
in a browser, or navigate to a URL supplied as an indicator.

Privacy and disclosure note
---------------------------
Calling a lookup discloses the indicator to the named provider. VirusTotal
receives the SHA-256, URL, domain, or IP in its API path and the API key in an
HTTPS header. VirusTotal documents that queried IOCs may be scanned and added
to its community dataset; do not query confidential, personal, or otherwise
sensitive indicators. urlscan.io receives a search expression containing the
IOC (and, if configured, its API key in a header); this module calls only the
existing-scan search endpoint, never the scan-submission endpoint. RDAP sends
the domain/IP to rdap.org, which redirects the request to the authoritative
RDAP server; both services can observe it. Cloudflare DNS-over-HTTPS receives
the queried domain and record type. crt.sh receives the queried domain.

These are external lookups, not offline analysis. Responses may be incomplete,
stale, rate-limited, or absent. In particular, a missing report or DNS answer
does not establish that a resource is clean. Keep API keys in environment
variables and follow the organization's disclosure policy before making calls.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from http.client import HTTPException
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .indicators import es_indicador_reservado
from .models import TipoIOC


DEFAULT_TIMEOUT_SECONDS = 8.0
DEFAULT_MAX_RESPONSE_BYTES = 1_000_000
DEFAULT_URLSCAN_RESULT_LIMIT = 10
DEFAULT_DNS_RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME")
VIRUSTOTAL_API_KEY_ENV = "VIRUSTOTAL_API_KEY"
URLSCAN_API_KEY_ENV = "URLSCAN_API_KEY"


class LookupStatus(str, Enum):
    """Normalized outcomes shared by all lookup providers."""

    FOUND = "found"
    NO_RESULTS = "no_results"
    NOT_FOUND = "not_found"
    NOT_APPLICABLE = "not_applicable"
    NOT_CONFIGURED = "not_configured"
    INVALID_INDICATOR = "invalid_indicator"
    INVALID_RESPONSE = "invalid_response"
    RESPONSE_TOO_LARGE = "response_too_large"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"
    PROVIDER_ERROR = "provider_error"
    HTTP_ERROR = "http_error"
    PARTIAL = "partial"


@dataclass(frozen=True)
class LookupResult:
    """A bounded provider response or an explicit normalized failure state.

    ``data`` contains parsed JSON on success, or ``None`` on failure. It is
    deliberately left in provider format so later report code can retain
    concrete evidence such as detection counts, scan identifiers, and dates.
    ``endpoint`` is included for auditability and can contain the IOC; never
    include this result in public output without checking its sensitivity.
    """

    service: str
    indicator_type: str
    indicator: str
    status: str
    queried_at: str
    endpoint: str
    http_status: Optional[int] = None
    data: Any = None
    message: Optional[str] = None


class _HTTPSOnlyRedirectHandler(HTTPRedirectHandler):
    """Follow service/RDAP redirects, but reject HTTPS-to-HTTP downgrade."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme.lower() != "https":
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _normalizar_tipo(tipo: Any) -> Optional[str]:
    """Map model enum values and common labels to the module's IOC types."""
    raw = getattr(tipo, "value", tipo)
    value = re.sub(r"[^a-z0-9]", "", str(raw).strip().lower())
    aliases = {
        "url": "url",
        "uri": "url",
        "domain": "domain",
        "dominio": "domain",
        "fqdn": "domain",
        "ip": "ip",
        "ipv4": "ip",
        "ipv6": "ip",
        "ipaddress": "ip",
        "direccionip": "ip",
        "sha256": "sha256",
        "hash": "sha256",
        "file": "sha256",
        "archivo": "sha256",
    }
    return aliases.get(value)


def _tipo_visible(tipo: Any) -> str:
    return _normalizar_tipo(tipo) or str(getattr(tipo, "value", tipo))


def _normalizar_dominio(valor: str) -> Optional[str]:
    value = str(valor).strip().rstrip(".")
    if not value or any(ch.isspace() for ch in value) or "/" in value or "@" in value:
        return None
    try:
        ascii_value = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(ascii_value) > 253:
        return None
    labels = ascii_value.split(".")
    if any(
        not label
        or len(label) > 63
        or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
        for label in labels
    ):
        return None
    return ascii_value


def _validar_url(valor: str) -> Optional[str]:
    value = str(valor).strip()
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        # Accessing .port validates malformed port values without any network I/O.
        _ = parsed.port
    except ValueError:
        return None
    return value


def _normalizar_indicador(tipo: Any, valor: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (canonical type, canonical value), or a validation error."""
    kind = _normalizar_tipo(tipo)
    if kind is None:
        return None, "Tipo no admitido; use SHA-256, URL, dominio o dirección IP."
    value = str(valor).strip()
    if not value:
        return None, "El indicador está vacío."

    if kind == "sha256":
        if not re.fullmatch(r"[A-Fa-f0-9]{64}", value):
            return None, "Se requiere un hash SHA-256 de 64 caracteres hexadecimales."
        return kind, value.lower()
    if kind == "url":
        normalized = _validar_url(value)
        if normalized is None:
            return None, "Se requiere una URL HTTP/HTTPS válida, sin credenciales incrustadas."
        return kind, normalized
    if kind == "domain":
        normalized = _normalizar_dominio(value)
        if normalized is None:
            return None, "El dominio no tiene una sintaxis válida."
        return kind, normalized
    try:
        return kind, str(ipaddress.ip_address(value))
    except ValueError:
        return None, "Se requiere una dirección IPv4 o IPv6 válida."


def _es_reservado(kind: str, value: str) -> bool:
    """Avoid leaking known documentation/private indicators to public services."""
    if kind == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        if address.version == 6:
            return not address.is_global
    tipo_modelo = {
        "url": TipoIOC.URL,
        "domain": TipoIOC.DOMINIO,
        "ip": TipoIOC.IPV4,
    }.get(kind)
    if tipo_modelo is None:
        return False
    return es_indicador_reservado(value, tipo_modelo)[0]


class OnlineLookupClient:
    """On-demand GET-only client for existing public reports and metadata.

    No request is made until a method is invoked. Timeouts and response limits
    are enforced per HTTP response; DNS lookup issues up to ten bounded GETs.
    The client does not retry rate limits and does not perform scan/submission
    operations.

    Args:
        timeout: Per-request timeout in seconds, clamped to 1–30.
        max_response_bytes: Maximum bytes read from each response, clamped to
            1 KiB–2 MiB.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self.timeout = min(30.0, max(1.0, float(timeout)))
        self.max_response_bytes = min(2_000_000, max(1_024, int(max_response_bytes)))
        self._opener = build_opener(_HTTPSOnlyRedirectHandler())

    def _result(
        self,
        service: str,
        indicator_type: Any,
        indicator: str,
        status: LookupStatus,
        endpoint: str,
        http_status: Optional[int] = None,
        data: Any = None,
        message: Optional[str] = None,
    ) -> LookupResult:
        return LookupResult(
            service=service,
            indicator_type=_tipo_visible(indicator_type),
            indicator=indicator,
            status=status.value,
            queried_at=_now_utc(),
            endpoint=endpoint,
            http_status=http_status,
            data=data,
            message=message,
        )

    def _get_json(
        self,
        service: str,
        indicator_type: Any,
        indicator: str,
        endpoint: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> LookupResult:
        request_headers = {
            "Accept": "application/json",
            "User-Agent": "PhishingLab/1.0 (read-only IOC lookup)",
        }
        if headers:
            request_headers.update(headers)
        request = Request(endpoint, headers=request_headers, method="GET")

        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read(self.max_response_bytes + 1)
                code = getattr(response, "status", response.getcode())
        except HTTPError as error:
            status = {
                400: LookupStatus.INVALID_INDICATOR,
                401: LookupStatus.UNAUTHORIZED,
                403: LookupStatus.FORBIDDEN,
                404: LookupStatus.NOT_FOUND,
                408: LookupStatus.TIMEOUT,
                429: LookupStatus.RATE_LIMITED,
            }.get(error.code, LookupStatus.PROVIDER_ERROR if error.code >= 500 else LookupStatus.HTTP_ERROR)
            message = (
                "No existe un reporte/registro disponible (HTTP 404). No se solicitó escaneo."
                if error.code == 404
                else f"El servicio respondió HTTP {error.code}."
            )
            return self._result(service, indicator_type, indicator, status, endpoint, error.code, message=message)
        except (socket.timeout, TimeoutError):
            return self._result(
                service, indicator_type, indicator, LookupStatus.TIMEOUT, endpoint, message="Se agotó el tiempo de espera."
            )
        except URLError as error:
            if isinstance(error.reason, (socket.timeout, TimeoutError)):
                status = LookupStatus.TIMEOUT
                message = "Se agotó el tiempo de espera."
            else:
                status = LookupStatus.NETWORK_ERROR
                message = "No se pudo conectar con el servicio externo."
            return self._result(service, indicator_type, indicator, status, endpoint, message=message)
        except HTTPException:
            return self._result(
                service, indicator_type, indicator, LookupStatus.NETWORK_ERROR, endpoint,
                message="La conexión HTTP terminó de forma inesperada.",
            )
        except OSError:
            return self._result(
                service, indicator_type, indicator, LookupStatus.NETWORK_ERROR, endpoint,
                message="No se pudo completar la conexión externa.",
            )

        if len(body) > self.max_response_bytes:
            return self._result(
                service, indicator_type, indicator, LookupStatus.RESPONSE_TOO_LARGE, endpoint, code,
                message=f"La respuesta supera el límite de {self.max_response_bytes} bytes.",
            )
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._result(
                service, indicator_type, indicator, LookupStatus.INVALID_RESPONSE, endpoint, code,
                message="El servicio no devolvió JSON UTF-8 válido.",
            )
        return self._result(service, indicator_type, indicator, LookupStatus.FOUND, endpoint, code, data=data)

    def virustotal_report(self, indicator_type: Any, value: str) -> LookupResult:
        """Retrieve an existing VirusTotal report using ``VIRUSTOTAL_API_KEY``.

        This method uses GET report endpoints only (files, URLs, domains, IPs).
        It never submits a file or requests a rescan. VirusTotal documents that
        queried IOCs may be added to its community dataset; see the module-level
        disclosure warning before calling it.
        """
        original = str(value)
        kind, normalized_or_error = _normalizar_indicador(indicator_type, original)
        if kind is None:
            return self._result(
                "VirusTotal", indicator_type, original, LookupStatus.INVALID_INDICATOR,
                "https://www.virustotal.com/api/v3/", message=normalized_or_error,
            )
        normalized = normalized_or_error
        if _es_reservado(kind, normalized):
            return self._result(
                "VirusTotal", kind, normalized, LookupStatus.NOT_APPLICABLE,
                "https://www.virustotal.com/api/v3/",
                message="Indicador reservado o de red privada; no se consultó el servicio público.",
            )

        api_key = os.environ.get(VIRUSTOTAL_API_KEY_ENV, "").strip()
        if not api_key:
            return self._result(
                "VirusTotal", kind, normalized, LookupStatus.NOT_CONFIGURED,
                "https://www.virustotal.com/api/v3/",
                message=f"Configure la variable de entorno {VIRUSTOTAL_API_KEY_ENV}.",
            )

        if kind == "sha256":
            path = f"files/{quote(normalized, safe='')}"
        elif kind == "url":
            url_id = base64.urlsafe_b64encode(normalized.encode("utf-8")).decode("ascii").rstrip("=")
            path = f"urls/{url_id}"
        elif kind == "domain":
            path = f"domains/{quote(normalized, safe='')}"
        else:
            path = f"ip_addresses/{quote(normalized, safe='')}"
        endpoint = f"https://www.virustotal.com/api/v3/{path}"
        result = self._get_json(
            "VirusTotal", kind, normalized, endpoint, headers={"x-apikey": api_key}
        )
        if result.status == LookupStatus.NOT_FOUND.value:
            return self._replace_result(
                result, LookupStatus.NO_RESULTS,
                "VirusTotal no devolvió un reporte existente (HTTP 404); no se solicitó escaneo.",
            )
        return result

    def urlscan_search(self, indicator_type: Any, value: str, size: int = DEFAULT_URLSCAN_RESULT_LIMIT) -> LookupResult:
        """Search archived urlscan.io results; never submits or opens an IOC."""
        original = str(value)
        kind, normalized_or_error = _normalizar_indicador(indicator_type, original)
        if kind is None or kind not in {"url", "domain", "ip"}:
            return self._result(
                "urlscan.io", indicator_type, original, LookupStatus.INVALID_INDICATOR,
                "https://urlscan.io/api/v1/search/", message=normalized_or_error or "Tipo de IOC no admitido.",
            )
        normalized = normalized_or_error
        try:
            limit = int(size)
        except (TypeError, ValueError):
            limit = 0
        if not 1 <= limit <= 10:
            return self._result(
                "urlscan.io", kind, normalized, LookupStatus.INVALID_INDICATOR,
                "https://urlscan.io/api/v1/search/", message="El límite de resultados debe estar entre 1 y 10.",
            )
        if _es_reservado(kind, normalized):
            return self._result(
                "urlscan.io", kind, normalized, LookupStatus.NOT_APPLICABLE,
                "https://urlscan.io/api/v1/search/",
                message="Indicador reservado o de red privada; no se consultó el servicio público.",
            )

        field = {"url": "canonical.page.url", "domain": "page.domain", "ip": "page.ip"}[kind]
        escaped_value = re.sub(r"([+\-=&&||><!(){}\[\]^\"~*?:\\/])", r"\\\1", normalized)
        query = f'{field}:"{escaped_value}"' if kind == "url" else f"{field}:{escaped_value}"
        params = urlencode({"q": query, "size": limit})
        endpoint = f"https://urlscan.io/api/v1/search/?{params}"
        headers: Dict[str, str] = {}
        api_key = os.environ.get(URLSCAN_API_KEY_ENV, "").strip()
        if api_key:
            headers["api-key"] = api_key
        result = self._get_json("urlscan.io", kind, normalized, endpoint, headers=headers)
        if result.status != LookupStatus.FOUND.value:
            return result
        data = result.data
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            return self._replace_result(
                result, LookupStatus.INVALID_RESPONSE, "La respuesta de búsqueda no tiene el formato esperado."
            )
        results = data.get("results", [])
        total = data.get("total", len(results))
        if not results:
            return self._replace_result(
                result, LookupStatus.NO_RESULTS, "No se encontraron escaneos archivados para el indicador."
            )
        return self._replace_result(
            result, LookupStatus.FOUND,
            message=f"Se encontraron {len(results)} resultados devueltos (total informado: {total}).",
        )

    def rdap_lookup(self, indicator_type: Any, value: str) -> LookupResult:
        """Query registration data for a domain or IP via rdap.org (HTTPS GET)."""
        original = str(value)
        kind, normalized_or_error = _normalizar_indicador(indicator_type, original)
        if kind not in {"domain", "ip"}:
            return self._result(
                "RDAP", indicator_type, original, LookupStatus.INVALID_INDICATOR,
                "https://rdap.org/", message=normalized_or_error or "RDAP requiere un dominio o una IP.",
            )
        normalized = normalized_or_error
        if _es_reservado(kind, normalized):
            return self._result(
                "RDAP", kind, normalized, LookupStatus.NOT_APPLICABLE, "https://rdap.org/",
                message="Indicador reservado o de red privada; no se consultó el servicio público.",
            )
        object_type = "domain" if kind == "domain" else "ip"
        endpoint = f"https://rdap.org/{object_type}/{quote(normalized, safe='')}"
        result = self._get_json(
            "RDAP", kind, normalized, endpoint,
            headers={"Accept": "application/rdap+json, application/json"},
        )
        if result.status == LookupStatus.NOT_FOUND.value:
            return self._replace_result(
                result, LookupStatus.NO_RESULTS, "No se encontró un servicio/registro RDAP para el indicador."
            )
        if result.status == LookupStatus.FOUND.value and not isinstance(result.data, dict):
            return self._replace_result(result, LookupStatus.INVALID_RESPONSE, "La respuesta RDAP no es un objeto JSON.")
        return result

    def dns_lookup(
        self,
        domain: str,
        record_types: Optional[Iterable[str]] = None,
    ) -> LookupResult:
        """Query DNS records through Cloudflare's JSON DoH endpoint using GET."""
        original = str(domain)
        normalized = _normalizar_dominio(original)
        endpoint_base = "https://cloudflare-dns.com/dns-query"
        if normalized is None:
            return self._result(
                "DNS-over-HTTPS", "domain", original, LookupStatus.INVALID_INDICATOR,
                endpoint_base, message="El dominio no tiene una sintaxis válida.",
            )
        if _es_reservado("domain", normalized):
            return self._result(
                "DNS-over-HTTPS", "domain", normalized, LookupStatus.NOT_APPLICABLE,
                endpoint_base, message="Dominio reservado; no se consultó el servicio público.",
            )

        try:
            requested_types = tuple(dict.fromkeys(str(item).strip().upper() for item in (record_types or DEFAULT_DNS_RECORD_TYPES)))
        except TypeError:
            requested_types = ()
        allowed_types = {"A", "AAAA", "CAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"}
        if not requested_types or len(requested_types) > 10 or any(t not in allowed_types for t in requested_types):
            return self._result(
                "DNS-over-HTTPS", "domain", normalized, LookupStatus.INVALID_INDICATOR,
                endpoint_base, message="Tipos DNS inválidos; use hasta 10 tipos entre A, AAAA, CAA, CNAME, MX, NS, PTR, SOA, SRV y TXT.",
            )

        queries: Dict[str, Any] = {}
        endpoints: List[str] = []
        errors: List[str] = []
        any_answer = False
        last_http_status: Optional[int] = None
        for record_type in requested_types:
            endpoint = f"{endpoint_base}?{urlencode({'name': normalized, 'type': record_type})}"
            endpoints.append(endpoint)
            result = self._get_json(
                "DNS-over-HTTPS", "domain", normalized, endpoint,
                headers={"Accept": "application/dns-json"},
            )
            last_http_status = result.http_status
            if result.status != LookupStatus.FOUND.value:
                errors.append(f"{record_type}: {result.status}")
                continue
            data = result.data
            if not isinstance(data, dict) or not isinstance(data.get("Status"), int):
                errors.append(f"{record_type}: invalid_response")
                continue
            answers = data.get("Answer", [])
            if answers:
                any_answer = True
            elif data.get("Status") in {0, 3}:
                # NOERROR without answers or NXDOMAIN are concrete no-record results.
                pass
            else:
                errors.append(f"{record_type}: DNS RCODE {data.get('Status')}")
            queries[record_type] = data

        if any_answer and errors:
            status = LookupStatus.PARTIAL
            message = "Se recibieron algunas respuestas DNS y hubo consultas parciales fallidas: " + ", ".join(errors)
        elif any_answer:
            status = LookupStatus.FOUND
            message = None
        elif errors:
            status = LookupStatus.PROVIDER_ERROR
            message = "No se pudieron completar todas las consultas DNS: " + ", ".join(errors)
        else:
            status = LookupStatus.NO_RESULTS
            message = "El resolver no devolvió registros en los tipos consultados."
        return self._result(
            "DNS-over-HTTPS", "domain", normalized, status,
            " | ".join(endpoints), last_http_status,
            data={"queries": queries, "record_types": list(requested_types)}, message=message,
        )

    def crtsh_search(self, domain: str) -> LookupResult:
        """Retrieve existing Certificate Transparency entries from crt.sh."""
        original = str(domain)
        normalized = _normalizar_dominio(original)
        base = "https://crt.sh/"
        if normalized is None:
            return self._result(
                "crt.sh", "domain", original, LookupStatus.INVALID_INDICATOR,
                base, message="El dominio no tiene una sintaxis válida.",
            )
        if _es_reservado("domain", normalized):
            return self._result(
                "crt.sh", "domain", normalized, LookupStatus.NOT_APPLICABLE, base,
                message="Dominio reservado; no se consultó el servicio público.",
            )
        endpoint = f"{base}?{urlencode({'q': normalized, 'output': 'json'})}"
        result = self._get_json("crt.sh", "domain", normalized, endpoint)
        if result.status != LookupStatus.FOUND.value:
            return result
        if not isinstance(result.data, list):
            return self._replace_result(result, LookupStatus.INVALID_RESPONSE, "crt.sh no devolvió una lista JSON.")
        if not result.data:
            return self._replace_result(result, LookupStatus.NO_RESULTS, "No se encontraron entradas CT para el dominio.")
        return result

    @staticmethod
    def _replace_result(
        result: LookupResult,
        status: LookupStatus,
        message: Optional[str],
    ) -> LookupResult:
        return LookupResult(
            service=result.service,
            indicator_type=result.indicator_type,
            indicator=result.indicator,
            status=status.value,
            queried_at=result.queried_at,
            endpoint=result.endpoint,
            http_status=result.http_status,
            data=result.data,
            message=message,
        )


__all__ = [
    "DEFAULT_DNS_RECORD_TYPES",
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_URLSCAN_RESULT_LIMIT",
    "LookupResult",
    "LookupStatus",
    "OnlineLookupClient",
    "URLSCAN_API_KEY_ENV",
    "VIRUSTOTAL_API_KEY_ENV",
]
