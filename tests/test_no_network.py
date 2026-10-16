"""
Pruebas unitarias de aislamiento de red (test_no_network.py).
Garantiza que Phishing Lab no realice NINGUNA conexión de red, consulta DNS,
llamada a socket ni peticiones HTTP/API durante todo su ciclo de análisis y reporte.
"""

import os
import socket
import unittest
from unittest.mock import patch

from phishing_lab.cli import ejecutar_analisis
from phishing_lab.reporter import GeneradorInforme


class TestNoRed(unittest.TestCase):

    def setUp(self):
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        self.ruta_bec = os.path.join(self.fixtures_dir, "caso5_bec_sintetico.eml")
        self.ruta_html = os.path.join(self.fixtures_dir, "correo_html_punycode.eml")

    def _fallar_por_red(self, *args, **kwargs):
        raise RuntimeError("VIOLACIÓN DE AISLAMIENTO: Se detectó un intento de conexión de red en Phishing Lab.")

    def test_aislamiento_total_de_red_durante_analisis(self):
        """
        Interdicta los sockets del sistema y ejecuta el pipeline completo
        asegurando cero llamadas de red externas.
        """
        with patch("socket.socket", side_effect=self._fallar_por_red), \
             patch("socket.create_connection", side_effect=self._fallar_por_red), \
             patch("socket.getaddrinfo", side_effect=self._fallar_por_red), \
             patch("socket.gethostbyname", side_effect=self._fallar_por_red):

            # 1. Pipeline sobre archivo BEC caso 5
            res_bec = ejecutar_analisis(
                eml_path=self.ruta_bec,
                fecha_referencia="2026-10-16T12:00:00",
            )
            informe_bec = GeneradorInforme(res_bec).generar()
            self.assertIn("Laboratorio de Análisis Forense", informe_bec)

            # 2. Pipeline sobre archivo HTML con punycode
            res_html = ejecutar_analisis(
                eml_path=self.ruta_html,
                fecha_referencia="2026-10-16T12:00:00",
            )
            informe_html = GeneradorInforme(res_html).generar()
            self.assertIn("xn--bcher-kva", informe_html)

            # 3. Pipeline sobre entradas manuales mixtas
            res_manual = ejecutar_analisis(
                urls=["https://phishing.example/login", "http://198.51.100.99/auth"],
                dominios=["phishing.example", "sub.banco.example"],
                ips=["198.51.100.99", "192.0.2.1"],
                fecha_referencia="2026-10-16T12:00:00",
            )
            informe_manual = GeneradorInforme(res_manual).generar()
            self.assertIn("Entrada manual", informe_manual)


if __name__ == "__main__":
    unittest.main()
