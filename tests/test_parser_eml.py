"""
Pruebas unitarias para el módulo de parseo de archivos .eml (parser_eml.py).
Verifica el comportamiento pasivo sobre el fixture BEC Caso 5, ausencia de DKIM-Signature,
resumen del cuerpo sin volcado completo, cálculo de SHA-256 local y manejo de errores.
"""

import os
import unittest

from phishing_lab.models import Procedencia, TipoIOC
from phishing_lab.parser_eml import ParserEML, calcular_sha256_bytes


class TestParserEML(unittest.TestCase):

    def setUp(self):
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        self.ruta_bec = os.path.join(self.fixtures_dir, "caso5_bec_sintetico.eml")
        self.ruta_malformado = os.path.join(self.fixtures_dir, "entrada_malformada.eml")

    def test_caso5_bec_sintetico_fiel(self):
        """Verifica las propiedades forenses requeridas para el Caso 5 BEC."""
        self.assertTrue(os.path.exists(self.ruta_bec), "El fixture sintético Caso 5 debe existir.")

        parser = ParserEML(self.ruta_bec)
        metadatos, extractor = parser.procesar()

        # 1. Cuerpo plain text y ausencia de HTML
        self.assertTrue(metadatos.tiene_cuerpo_texto, "El correo BEC debe tener cuerpo en texto plano.")
        self.assertFalse(metadatos.tiene_cuerpo_html, "El correo BEC Caso 5 no debe tener cuerpo HTML.")

        # 2. Ausencia total de URLs en el cuerpo del correo
        indicadores = extractor.obtener_indicadores()
        urls_cuerpo = [
            ind for ind in indicadores
            if ind.tipo == TipoIOC.URL and any(Procedencia.CUERPO_TEXTO in p for p in ind.procedencias)
        ]
        self.assertEqual(len(urls_cuerpo), 0, "El cuerpo del Caso 5 BEC no debe contener URLs.")

        # 3. Detección temática del monto y la solicitud urgente del fixture fiel
        self.assertIsNotNone(metadatos.resumen_cuerpo)
        self.assertIn("$4.800.000", self._leer_fixture(self.ruta_bec))
        self.assertIn("$4.800.000", metadatos.resumen_cuerpo)
        self.assertIn("ALERTA TEMÁTICA BEC", metadatos.resumen_cuerpo.upper())

        # 4. No volcar cuerpo completo al informe
        # El resumen debe ser un bloque estructurado con viñetas, no la carta completa
        self.assertNotIn("Me encuentro actualmente en una reunión confidencial", metadatos.resumen_cuerpo)
        self.assertIn("Política de higiene forense", metadatos.resumen_cuerpo)

        # 5. Declaraciones de autenticación: Authentication-Results incluye 'pass' pero falta DKIM-Signature
        self.assertIn("Authentication-Results", metadatos.cabeceras_autenticacion)
        auth_results = " ".join(metadatos.cabeceras_autenticacion["Authentication-Results"])
        self.assertIn("spf=pass", auth_results)

        # 6. Verificación explícita de ausencia de DKIM-Signature
        self.assertFalse(metadatos.tiene_dkim_signature, "El correo Caso 5 debe carecer de cabecera DKIM-Signature.")
        self.assertIsNotNone(metadatos.aviso_dkim)
        self.assertIn("No se detectó encabezado 'DKIM-Signature'", metadatos.aviso_dkim)

        # 7. Presencia de dominios e IP de ejemplo/documentación reservados
        dominios_extraidos = [ind.valor for ind in indicadores if ind.tipo == TipoIOC.DOMINIO]
        self.assertTrue(
            any("example" in d for d in dominios_extraidos),
            "Deben extraerse dominios reservados bajo .example.",
        )
        self.assertNotIn("header.from", dominios_extraidos)
        self.assertNotIn("smtp.mailfrom", dominios_extraidos)

        ips_extraidas = [ind for ind in indicadores if ind.tipo == TipoIOC.IPV4]
        ip_testnet = next((ind for ind in ips_extraidas if ind.valor == "198.51.100.240"), None)
        self.assertIsNotNone(ip_testnet, "Debe extraerse la IP 198.51.100.240 del encabezado Received.")
        self.assertTrue(ip_testnet.es_reservado, "198.51.100.240 debe ser clasificada como reservada.")
        self.assertIn("TEST-NET-2", ip_testnet.detalle_reservado)

        # 8. Hash SHA-256 local
        self.assertIsNotNone(metadatos.sha256_eml)
        self.assertEqual(len(metadatos.sha256_eml), 64)

    def test_calculo_sha256_bytes_local(self):
        """Verifica el cálculo determinista y local del hash SHA-256."""
        datos = b"Contenido de prueba para calculo SHA-256 local"
        esperado = "cfae60f779776d5e1efd63d8dca5f91f16590b0ee409f6eb722c81a1a72d3f25"
        # Comprobar contra hashlib directamente
        import hashlib
        self.assertEqual(calcular_sha256_bytes(datos), hashlib.sha256(datos).hexdigest())

    def test_hash_del_archivo_coincide_con_sha256_de_bytes(self):
        import hashlib
        with open(self.ruta_bec, "rb") as archivo:
            esperado = hashlib.sha256(archivo.read()).hexdigest()
        metadatos, _ = ParserEML(self.ruta_bec).procesar()
        self.assertEqual(metadatos.sha256_eml, esperado)

    def test_correo_vacio_no_informa_cuerpo_presente(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directorio:
            ruta = os.path.join(directorio, "vacio.eml")
            with open(ruta, "wb"):
                pass
            metadatos, _ = ParserEML(ruta).procesar()
        self.assertFalse(metadatos.tiene_cuerpo_texto)
        self.assertFalse(metadatos.tiene_cuerpo_html)

    @staticmethod
    def _leer_fixture(ruta):
        with open(ruta, encoding="utf-8") as archivo:
            return archivo.read()

    def test_archivo_desconocido_o_inexistente(self):
        """Verifica que un archivo inexistente levante FileNotFoundError con mensaje claro."""
        ruta_falsa = os.path.join(self.fixtures_dir, "archivo_que_no_existe_12345.eml")
        with self.assertRaises(FileNotFoundError):
            ParserEML(ruta_falsa)

    def test_archivo_malformado(self):
        """Verifica que un archivo con formato MIME dañado no interrumpa la ejecución."""
        self.assertTrue(os.path.exists(self.ruta_malformado))
        parser = ParserEML(self.ruta_malformado)
        metadatos, extractor = parser.procesar()

        # Debe procesarse sin levantar excepciones no controladas
        self.assertIsNotNone(metadatos)
        self.assertIsNotNone(metadatos.sha256_eml)
        self.assertTrue(metadatos.es_malformado)
        # Debe haber extraído los IOCs reconocibles a pesar de la malformación
        indicadores = extractor.obtener_indicadores()
        ips = [ind.valor for ind in indicadores if ind.tipo == TipoIOC.IPV4]
        self.assertIn("203.0.113.19", ips)


if __name__ == "__main__":
    unittest.main()
