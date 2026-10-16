"""
Pruebas unitarias para la interfaz de línea de comandos (cli.py).
Valida parámetros de entrada, control de errores en español,
generación de archivos de salida y manejo de códigos de retorno.
"""

import io
import os
import tempfile
import unittest
from unittest.mock import patch

from phishing_lab.cli import main


class TestCLI(unittest.TestCase):

    def setUp(self):
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        self.ruta_bec = os.path.join(self.fixtures_dir, "caso5_bec_sintetico.eml")

    def test_cli_sin_argumentos_retorna_error(self):
        """Verifica que ejecutar la CLI sin opciones retorne código 1 y mensaje en stderr."""
        stderr_capturado = io.StringIO()
        with patch("sys.stderr", stderr_capturado):
            codigo = main([])
        self.assertEqual(codigo, 1)
        self.assertIn("Error: Debe especificar al menos una entrada", stderr_capturado.getvalue())

    def test_cli_archivo_eml_inexistente(self):
        """Verifica que indicar un archivo inexistente retorne código 1 y mensaje en español."""
        stderr_capturado = io.StringIO()
        with patch("sys.stderr", stderr_capturado):
            codigo = main(["--eml", "no_existe_este_correo.eml"])
        self.assertEqual(codigo, 1)
        self.assertIn("Error: El archivo .eml especificado no existe", stderr_capturado.getvalue())

    def test_cli_entradas_manuales_exitosas(self):
        """Verifica la ejecución exitosa de análisis manual con salida a stdout."""
        stdout_capturado = io.StringIO()
        with patch("sys.stdout", stdout_capturado):
            codigo = main([
                "--url", "https://seguridad.example/login",
                "--dominio", "banco.example",
                "--ip", "198.51.100.10",
                "--fecha", "2026-10-16T15:00:00",
            ])
        self.assertEqual(codigo, 0)
        salida = stdout_capturado.getvalue()
        self.assertIn("# Laboratorio de Análisis Forense de Phishing", salida)
        self.assertIn("seguridad.example", salida)
        self.assertIn("198.51.100.10", salida)

    def test_cli_rechaza_dominio_ip_y_url_invalidos(self):
        """Rechaza entrada con sintaxis inválida antes de construir referencias."""
        for argumentos, esperado in [
            (["--ip", "999.999.100.1"], "IPv4 inválida"),
            (["--dominio", "dominio con espacios.example"], "Dominio inválido"),
            (["--url", "javascript:alert(1)"], "URL inválida"),
        ]:
            with self.subTest(argumentos=argumentos):
                stderr_capturado = io.StringIO()
                with patch("sys.stderr", stderr_capturado):
                    codigo = main(argumentos)
                self.assertEqual(codigo, 1)
                self.assertIn(esperado, stderr_capturado.getvalue())

    def test_cli_archivo_eml_con_salida_en_fichero(self):
        """Verifica la generación del archivo Markdown mediante la opción -o / --salida."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ruta_salida = os.path.join(tmpdir, "reporte_test.md")
            codigo = main([
                "-e", self.ruta_bec,
                "-o", ruta_salida,
                "--fecha", "2026-10-16T12:00:00",
            ])
            self.assertEqual(codigo, 0)
            self.assertTrue(os.path.exists(ruta_salida), "El archivo de salida debe haberse creado.")

            with open(ruta_salida, "r", encoding="utf-8") as f:
                contenido = f.read()

            self.assertIn("caso5_bec_sintetico.eml", contenido)
            self.assertIn("No se detectó encabezado 'DKIM-Signature'", contenido)
            self.assertIn("**No consultado**", contenido)


if __name__ == "__main__":
    unittest.main()
