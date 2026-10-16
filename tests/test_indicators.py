"""
Pruebas unitarias para el módulo de indicadores reservados y defanging (indicators.py).
Valida la detección de dominios de prueba (RFC 2606 / RFC 6761),
rangos de documentación IPv4 TEST-NET (RFC 5737) y redes privadas.
"""

import unittest

from phishing_lab.indicators import (
    analizar_punycode,
    defang_ioc,
    es_indicador_reservado,
    evaluar_dominio_reservado,
    evaluar_ip_reservada,
)
from phishing_lab.models import TipoIOC


class TestIndicadores(unittest.TestCase):

    def test_dominios_reservados_rfc2606_rfc6761(self):
        """Valida que los dominios y TLDs de ejemplo sean identificados como reservados."""
        casos_reservados = [
            "empresa.example",
            "servidor.test",
            "sitio.invalid",
            "localhost",
            "maquina.localhost",
            "example.com",
            "sub.example.com",
            "correo.example.net",
            "portal.example.org",
        ]
        for dom in casos_reservados:
            es_res, detalle = evaluar_dominio_reservado(dom)
            self.assertTrue(es_res, f"El dominio '{dom}' debería ser detectado como reservado.")
            self.assertIsNotNone(detalle)

    def test_dominios_publicos_no_reservados(self):
        """Valida que dominios públicos de producción NO sean marcados como reservados."""
        casos_publicos = [
            "banco.com.ar",
            "google.com",
            "entidad-financiera.com",
            "seguridad-login.net",
        ]
        for dom in casos_publicos:
            es_res, detalle = evaluar_dominio_reservado(dom)
            self.assertFalse(es_res, f"El dominio '{dom}' NO debería ser marcado como reservado.")
            self.assertIsNone(detalle)
        self.assertFalse(evaluar_dominio_reservado("instituto.example.edu")[0])

    def test_ips_documentacion_testnet_rfc5737(self):
        """Valida los rangos IPv4 TEST-NET-1, TEST-NET-2 y TEST-NET-3."""
        # TEST-NET-1: 192.0.2.0/24
        es_res1, det1 = evaluar_ip_reservada("192.0.2.1")
        self.assertTrue(es_res1)
        self.assertIn("TEST-NET-1", det1)

        # TEST-NET-2: 198.51.100.0/24 (Caso 5)
        es_res2, det2 = evaluar_ip_reservada("198.51.100.25")
        self.assertTrue(es_res2)
        self.assertIn("TEST-NET-2", det2)

        # TEST-NET-3: 203.0.113.0/24
        es_res3, det3 = evaluar_ip_reservada("203.0.113.50")
        self.assertTrue(es_res3)
        self.assertIn("TEST-NET-3", det3)

    def test_ips_privadas_y_loopback(self):
        """Valida rangos especiales RFC 1918 y Loopback."""
        es_res_loop, det_loop = evaluar_ip_reservada("127.0.0.1")
        self.assertTrue(es_res_loop)
        self.assertIn("Loopback", det_loop)

        es_res_priv, det_priv = evaluar_ip_reservada("192.168.1.1")
        self.assertTrue(es_res_priv)
        self.assertIn("RFC 1918", det_priv)

    def test_ips_publicas_no_reservadas(self):
        """Valida que direcciones IP públicas globales no se clasifiquen como reservadas."""
        casos_publicos = ["8.8.8.8", "1.1.1.1", "93.184.216.34"]
        for ip in casos_publicos:
            es_res, det = evaluar_ip_reservada(ip)
            self.assertFalse(es_res, f"La IP '{ip}' es pública y no debería ser reservada.")
            self.assertIsNone(det)

    def test_broadcast_limitado_reservado(self):
        es_res, detalle = evaluar_ip_reservada("255.255.255.255")
        self.assertTrue(es_res)
        self.assertIn("Broadcast", detalle)

    def test_punycode_se_limita_al_host_y_valida_el_roundtrip(self):
        self.assertIsNone(analizar_punycode("https://ejemplo.example/path/xn--no-es-un-idn"))
        self.assertIsNotNone(analizar_punycode("https://xn--bcher-kva.example/inicio"))

    def test_defanging_seguro(self):
        """Valida la sanitización sintáctica para prevenir clics accidentales."""
        self.assertEqual(
            defang_ioc("https://login.example/auth", TipoIOC.URL),
            "hxxps://login[.]example/auth",
        )
        self.assertEqual(
            defang_ioc("198.51.100.25", TipoIOC.IPV4),
            "198[.]51[.]100[.]25",
        )
        self.assertEqual(
            defang_ioc("corporacion.example", TipoIOC.DOMINIO),
            "corporacion[.]example",
        )
        self.assertEqual(
            defang_ioc("ceo@corporacion.example", TipoIOC.EMAIL),
            "ceo[@]corporacion[.]example",
        )


if __name__ == "__main__":
    unittest.main()
