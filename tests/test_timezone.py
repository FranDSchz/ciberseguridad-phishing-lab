"""
Pruebas unitarias para utilidades de zona horaria y fechas (timezone_utils.py).
Valida el uso de America/Argentina/Buenos_Aires y la inyección determinista de fechas.
"""

import datetime
import unittest

from phishing_lab.timezone_utils import (
    TIMEZONE_NAME,
    formatear_fecha,
    obtener_fecha_referencia,
    obtener_zona_horaria_ba,
)


class TestTimezone(unittest.TestCase):

    def test_zona_horaria_buenos_aires_offset(self):
        """Valida que la zona horaria corresponda a UTC-3 (America/Argentina/Buenos_Aires)."""
        tz = obtener_zona_horaria_ba()
        self.assertIsNotNone(tz)

        # Crear un datetime de prueba localizado
        dt = datetime.datetime(2026, 10, 16, 15, 30, 0, tzinfo=tz)
        offset = dt.utcoffset()
        self.assertIsNotNone(offset)
        self.assertEqual(offset.total_seconds(), -3 * 3600, "El offset de Buenos Aires debe ser UTC-3 (-10800s).")

    def test_fecha_inyectable_cadena_iso(self):
        """Verifica la inyección determinista de fecha desde formato ISO."""
        fecha_inyectada = "2026-10-16T14:25:30"
        dt_res = obtener_fecha_referencia(fecha_inyectada)

        self.assertEqual(dt_res.year, 2026)
        self.assertEqual(dt_res.month, 10)
        self.assertEqual(dt_res.day, 16)
        self.assertEqual(dt_res.hour, 14)
        self.assertEqual(dt_res.minute, 25)
        self.assertEqual(dt_res.second, 30)

        cadena_formateada = formatear_fecha(fecha_inyectada)
        self.assertIn("2026-10-16 14:25:30", cadena_formateada)
        self.assertIn("-0300", cadena_formateada)

    def test_fecha_inyectable_solo_fecha(self):
        """Verifica la inyección de fecha en formato simple YYYY-MM-DD."""
        fecha_inyectada = "2026-10-16"
        cadena_formateada = formatear_fecha(fecha_inyectada)
        self.assertIn("2026-10-16 00:00:00", cadena_formateada)

    def test_fecha_inyectable_objeto_datetime(self):
        """Verifica la inyección directa de un objeto datetime de Python."""
        dt_obj = datetime.datetime(2026, 12, 1, 9, 0, 0)
        dt_res = obtener_fecha_referencia(dt_obj)
        self.assertEqual(dt_res.year, 2026)
        self.assertEqual(dt_res.month, 12)
        self.assertEqual(dt_res.day, 1)
        self.assertEqual(dt_res.hour, 9)


if __name__ == "__main__":
    unittest.main()
