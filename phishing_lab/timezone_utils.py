"""
Módulo de utilidades de fecha y zona horaria para Phishing Lab.
Garantiza el uso estricto de la zona horaria America/Argentina/Buenos_Aires
con soporte para inyección determinista de fechas en pruebas automatizadas.
"""

import datetime
from typing import Optional, Union

try:
    import zoneinfo
except ImportError:
    zoneinfo = None  # type: ignore

TIMEZONE_NAME = "America/Argentina/Buenos_Aires"
OFFSET_HORAS_BA = -3


def obtener_zona_horaria_ba() -> datetime.tzinfo:
    """
    Obtiene el objeto tzinfo para America/Argentina/Buenos_Aires.
    Si zoneinfo no dispone de la base tzdata en el sistema operativo local,
    utiliza un timezone fijo UTC-3 con el nombre canónico correspondiente.
    """
    if zoneinfo is not None:
        try:
            return zoneinfo.ZoneInfo(TIMEZONE_NAME)
        except Exception:
            pass
    # Respaldo seguro para entornos Windows sin paquete tzdata del sistema
    return datetime.timezone(
        datetime.timedelta(hours=OFFSET_HORAS_BA),
        name=TIMEZONE_NAME,
    )


def obtener_fecha_referencia(
    fecha_inyectada: Optional[Union[str, datetime.datetime]] = None
) -> datetime.datetime:
    """
    Retorna la fecha/hora de referencia para el análisis localizada en
    America/Argentina/Buenos_Aires. Permite inyectar una fecha fija para pruebas.
    """
    tz_ba = obtener_zona_horaria_ba()

    if fecha_inyectada is None:
        return datetime.datetime.now(tz=tz_ba)

    if isinstance(fecha_inyectada, datetime.datetime):
        if fecha_inyectada.tzinfo is None:
            # Datetime ingenuo, asociar directamente la zona horaria de Buenos Aires
            return fecha_inyectada.replace(tzinfo=tz_ba)
        # Convertir a la zona horaria de Buenos Aires
        return fecha_inyectada.astimezone(tz_ba)

    if isinstance(fecha_inyectada, str):
        # Admite formatos ISO como YYYY-MM-DD, YYYY-MM-DDTHH:MM:SS o con offset
        texto = fecha_inyectada.strip()
        # Si sólo viene fecha YYYY-MM-DD, añadir hora neutra T00:00:00
        if len(texto) == 10 and texto.count("-") == 2:
            texto = f"{texto}T00:00:00"
        dt = datetime.datetime.fromisoformat(texto)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=tz_ba)
        return dt.astimezone(tz_ba)

    raise ValueError(f"Formato de fecha de referencia no soportado: {type(fecha_inyectada)}")


def formatear_fecha(dt: Optional[Union[str, datetime.datetime]] = None) -> str:
    """
    Formatea la fecha como cadena reproducible: YYYY-MM-DD HH:MM:SS -03:00.
    """
    fecha_dt = obtener_fecha_referencia(dt)
    return fecha_dt.strftime("%Y-%m-%d %H:%M:%S %z")
