"""
Pruebas unitarias para el generador de informes (reporter.py).
Valida la generación de informes Markdown fieles al Caso 5 / Grupo 5:
omisión de volcado completo de cuerpo, ausencia de DKIM-Signature,
secciones de consulta con estado 'No consultado' / 'No aplicable',
sin resultados inventados ni veredictos automáticos.
"""

import os
import unittest

from phishing_lab.cli import ejecutar_analisis
from phishing_lab.models import MetadatosCorreo, ResultadoLaboratorio
from phishing_lab.reporter import GeneradorInforme


class TestReporter(unittest.TestCase):

    def setUp(self):
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        self.ruta_bec = os.path.join(self.fixtures_dir, "caso5_bec_sintetico.eml")

    def test_informe_fiel_caso5_grupo5(self):
        """
        Verifica que el informe Markdown generado para el Caso 5 cumpla todas las directivas:
        todas las secciones en 'No consultado'/'No aplicable', sin inventar resultados,
        con aviso de ausencia de DKIM y sin volcar el cuerpo.
        """
        resultado = ejecutar_analisis(
            eml_path=self.ruta_bec,
            fecha_referencia="2026-10-16T12:00:00",
        )

        generador = GeneradorInforme(resultado)
        informe = generador.generar()

        # 1. Cabecera y metadatos de entorno
        self.assertIn("# Laboratorio de Análisis Forense de Phishing", informe)
        self.assertIn("America/Argentina/Buenos_Aires", informe)
        self.assertIn("2026-10-16 12:00:00", informe)

        # 2. Ausencia de veredicto automático
        self.assertIn("NO EMITIDO (Requiere Análisis Humano)", informe)
        self.assertIn("CERO consultas de red realizadas", informe)

        # 3. Hash SHA-256 local
        self.assertIn(resultado.sha256_eml, informe)
        self.assertIn("Hash calculado de forma 100% local", informe)

        # 4. Declaraciones de autenticación y ausencia de DKIM-Signature
        self.assertIn("NUNCA son verificadas criptográficamente", informe)
        self.assertIn("No se detectó encabezado 'DKIM-Signature'", informe)

        # 5. Cuerpo completo NO volcado
        # No debe contener el saludo completo o párrafos textuales directos del correo
        self.assertNotIn("Me encuentro actualmente en una reunión confidencial del directorio", informe)
        self.assertIn("Resumen Estructural y Temático del Cuerpo", informe)
        self.assertIn("Política de higiene forense", informe)

        # 6. Cuatro secciones presentes y con estado 'No consultado' o 'No aplicable'
        for titulo in [
            "### 4.1. VirusTotal",
            "### 4.2. urlscan.io",
            "### 4.3. WHOIS / DNSChecker",
            "### 4.4. crt.sh",
        ]:
            self.assertIn(titulo, informe)

        # Comprobar que en las tablas figuren explícitamente los estados
        self.assertIn("**No consultado**", informe)
        # No debe existir ninguna afirmación de detección activa ni veredicto inventado
        self.assertNotIn("Malicioso detectado por", informe)
        self.assertNotIn("Detección positiva:", informe)

    def test_datos_no_confiables_no_inyectan_markdown_ni_html(self):
        metadatos = MetadatosCorreo(
            asunto="Factura <img src=x onerror=alert(1)> `cerrar`",
            cabeceras_autenticacion={"Authentication-Results": ["dato ```\n<script>alert(1)</script>"]},
        )
        resultado = ResultadoLaboratorio(
            metadatos_eml=metadatos,
            fecha_analisis="2026-10-16 12:00:00 -0300",
            referencias_consulta=[],
        )
        informe = GeneradorInforme(resultado).generar()
        self.assertNotIn("<img src=x", informe)
        self.assertIn("````text\ndato ```\n<script>alert(1)</script>\n````", informe)
        self.assertIn("&lt;img", informe)


if __name__ == "__main__":
    unittest.main()
