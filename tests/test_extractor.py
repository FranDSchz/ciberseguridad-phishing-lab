"""
Pruebas unitarias para el extractor de indicadores (extractor.py).
Verifica extracción segura sin renderizado ni ejecución HTML,
manejo de punycode (IDN), y preservación de procedencias.
"""

import os
import unittest

from phishing_lab.extractor import ExtractorIOC, extraer_iocs_de_html, extraer_iocs_de_texto
from phishing_lab.models import Procedencia, TipoIOC
from phishing_lab.parser_eml import ParserEML


class TestExtractorIOC(unittest.TestCase):

    def setUp(self):
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        self.ruta_html_punycode = os.path.join(self.fixtures_dir, "correo_html_punycode.eml")

    def test_extraccion_html_href_y_texto_punycode(self):
        """Verifica la extracción fiel de URLs con punycode diferenciando href de texto de ancla."""
        self.assertTrue(os.path.exists(self.ruta_html_punycode))
        parser = ParserEML(self.ruta_html_punycode)
        metadatos, extractor = parser.procesar()

        indicadores = extractor.obtener_indicadores()

        # Buscar el indicador con punycode
        ind_puny = next(
            (ind for ind in indicadores if "xn--bcher-kva" in ind.valor),
            None,
        )
        self.assertIsNotNone(ind_puny, "Debe extraer la URL con punycode 'xn--bcher-kva.example'.")
        self.assertIsNotNone(ind_puny.punycode_info, "Debe contener metadatos sobre la decodificación de punycode.")
        self.assertIn("bücher", ind_puny.punycode_info)

        # Comprobar procedencia del enlace href
        self.assertTrue(
            any(Procedencia.HTML_HREF in p for p in ind_puny.procedencias),
            "La URL punycode debe tener procedencia HTML_HREF.",
        )

        # Buscar el texto del ancla que contenía la versión Unicode
        ind_ancla = next(
            (ind for ind in indicadores if "bücher.example" in ind.valor),
            None,
        )
        self.assertIsNotNone(ind_ancla)
        self.assertIn(Procedencia.HTML_TEXTO, ind_ancla.procedencias)
        self.assertIn("xn--bcher-kva", ind_puny.punycode_info)
        self.assertIn("Host Unicode", ind_ancla.punycode_info)

    def test_html_malformado_recupera_url_de_ancla_abierta(self):
        indicadores = extraer_iocs_de_html(
            '<a href="https://uno.example/x">Ir al portal https://dos.example/y'
        )
        por_valor = {ind.valor: ind for ind in indicadores}
        self.assertIn("https://uno.example/x", por_valor)
        self.assertIn("https://dos.example/y", por_valor)
        self.assertIn(Procedencia.HTML_TEXTO, por_valor["https://dos.example/y"].procedencias)

    def test_procedencia_html_visible_y_candidatos_de_dominio(self):
        indicadores = extraer_iocs_de_html(
            "<p>portal-validacion.example</p><p>factura.pdf version 4.8.2.1</p>"
        )
        valores = {ind.valor: ind for ind in indicadores}
        self.assertIn("portal-validacion.example", valores)
        self.assertIn(Procedencia.HTML_CUERPO, valores["portal-validacion.example"].procedencias)
        self.assertNotIn("factura.pdf", valores)
        self.assertNotIn("4.8.2.1", valores)

    def test_no_clasifica_partes_locales_de_correo_como_dominios(self):
        indicadores = extraer_iocs_de_texto(
            "Contacto: director.ejecutivo@empresa.example y datos.xlsx"
        )
        dominios = {ind.valor for ind in indicadores if ind.tipo == TipoIOC.DOMINIO}
        self.assertIn("empresa.example", dominios)
        self.assertNotIn("director.ejecutivo", dominios)
        self.assertNotIn("datos.xlsx", dominios)

    def test_extraccion_sin_ejecucion_html(self):
        """
        Garantiza que cadenas HTML con etiquetas script o eventos inline no se ejecuten
        y sus contenidos sean tratados como texto pasivo o descartados de forma segura.
        """
        html_peligroso = """
        <html>
            <body>
                <script>alert("XSS ejecutado");</script>
                <a href="https://sitio-malicioso.example/login" onclick="malware()">Acceso</a>
                <p>Visite 192.0.2.77 para soporte.</p>
            </body>
        </html>
        """
        indicadores = extraer_iocs_de_html(html_peligroso)

        urls = [ind.valor for ind in indicadores if ind.tipo == TipoIOC.URL]
        ips = [ind.valor for ind in indicadores if ind.tipo == TipoIOC.IPV4]

        self.assertIn("https://sitio-malicioso.example/login", urls)
        self.assertIn("192.0.2.77", ips)
        # La instrucción script no debe figurar como URL ni dominio
        self.assertNotIn("alert", [ind.valor for ind in indicadores])

    def test_acumulacion_de_procedencias_multiples(self):
        """Verifica que un mismo IOC presente en distintos orígenes acumule todas sus procedencias."""
        extractor = ExtractorIOC()
        # Mismo dominio en entrada manual y en cuerpo de texto
        extractor.registrar_ioc("portal.example", TipoIOC.DOMINIO, Procedencia.MANUAL)
        extractor.registrar_ioc("portal.example", TipoIOC.DOMINIO, Procedencia.CUERPO_TEXTO)

        indicadores = extractor.obtener_indicadores()
        ind = next((i for i in indicadores if i.valor == "portal.example"), None)

        self.assertIsNotNone(ind)
        self.assertEqual(len(ind.procedencias), 2)
        self.assertIn(Procedencia.MANUAL, ind.procedencias)
        self.assertIn(Procedencia.CUERPO_TEXTO, ind.procedencias)

    def test_extraccion_texto_plano_simple(self):
        """Verifica la extracción de dominios, URLs e IPs desde un texto plano con defanging."""
        texto = "Revise el sitio https://banco-prueba.example/auth o la IP 198.51.100.10 y contacte soporte@empresa.example."
        indicadores = extraer_iocs_de_texto(texto, Procedencia.CUERPO_TEXTO)

        valores = {ind.valor for ind in indicadores}
        self.assertIn("https://banco-prueba.example/auth", valores)
        self.assertIn("198.51.100.10", valores)
        self.assertIn("soporte@empresa.example", valores)
        self.assertIn("empresa.example", valores)


if __name__ == "__main__":
    unittest.main()
