"""
Pruebas unitarias para el constructor de referencias de consulta (references.py).
Verifica la creación estructurada de enlaces pasivos para VirusTotal, urlscan.io,
WHOIS/DNSChecker y crt.sh con estado 'No consultado' / 'No aplicable' y sin veredictos automáticos.
"""

import unittest

from phishing_lab.models import Indicador, TipoIOC
from phishing_lab.references import ConstructorReferencias, generar_referencias_servicio


class TestReferencias(unittest.TestCase):

    def setUp(self):
        self.constructor = ConstructorReferencias(fecha_referencia="2026-10-16 12:00:00 -03:00")

    def test_cuatro_servicios_presentes(self):
        """Verifica que se generen listas para los cuatro servicios requeridos."""
        ind_dom = Indicador(
            valor="empresa-ejemplo.example",
            tipo=TipoIOC.DOMINIO,
            procedencias=["Entrada manual"],
            es_reservado=True,
            detalle_reservado="Dominio .example",
        )
        refs = self.constructor.generar_todas([ind_dom])

        servicios_esperados = {"VirusTotal", "urlscan.io", "WHOIS / DNSChecker", "crt.sh"}
        self.assertEqual(set(refs.keys()), servicios_esperados)

    def test_esquema_completo_y_estado_no_consultado(self):
        """
        Verifica que cada entrada registre:
        pertinente, referencia_url, observacion, fuente, fecha y estado ('No consultado'/'No aplicable').
        """
        ind_ip = Indicador(
            valor="198.51.100.25",
            tipo=TipoIOC.IPV4,
            procedencias=["Encabezado MIME (Received)"],
            es_reservado=True,
            detalle_reservado="TEST-NET-2",
        )
        refs = self.constructor.generar_todas([ind_ip])

        for srv, lista_refs in refs.items():
            self.assertGreater(len(lista_refs), 0, f"Debe haber al menos una referencia para {srv}.")
            for ref in lista_refs:
                self.assertIsNotNone(ref.pertinente)
                self.assertTrue(len(ref.pertinente) > 0)
                self.assertIsNotNone(ref.referencia_url)
                self.assertTrue(len(ref.referencia_url) > 0)
                self.assertIsNotNone(ref.observacion)
                self.assertTrue(len(ref.observacion) > 0)
                self.assertIsNotNone(ref.fuente)
                self.assertTrue(len(ref.fuente) > 0)
                self.assertEqual(ref.fecha, "2026-10-16 12:00:00 -03:00")
                # Estado DEBE ser estrictamente 'No consultado' o 'No aplicable'
                self.assertIn(ref.estado, ["No consultado", "No aplicable"])

    def test_referencia_sha256_virustotal_segura(self):
        """Verifica que el hash local genere una búsqueda segura sin subir el binario."""
        hash_local = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ind_hash = Indicador(
            valor=hash_local,
            tipo=TipoIOC.SHA256,
            procedencias=["Archivo .eml local"],
        )
        ref_vt = self.constructor.construir_virustotal(ind_hash)

        self.assertEqual(ref_vt.servicio, "VirusTotal")
        self.assertIn(hash_local, ref_vt.referencia_url)
        self.assertIn("https://www.virustotal.com/gui/file/", ref_vt.referencia_url)
        self.assertIn("No consultado", ref_vt.estado)
        self.assertIn("sin haber subido el binario original", ref_vt.observacion)

    def test_crt_sh_no_aplicable_a_ips(self):
        """Verifica que crt.sh registre 'No aplicable' cuando el indicador es una IP o hash."""
        ind_ip = Indicador(
            valor="8.8.8.8",
            tipo=TipoIOC.IPV4,
            procedencias=["Manual"],
        )
        ref_crt = self.constructor.construir_crt_sh(ind_ip)
        self.assertEqual(ref_crt.estado, "No aplicable")
        self.assertIn("solo aplica a nombres de dominio", ref_crt.observacion)

    def test_whois_para_url_usa_solo_host(self):
        ind_url = Indicador(
            valor="https://login.example/auth?token=abc",
            tipo=TipoIOC.URL,
            procedencias=["Entrada manual"],
        )
        referencia = self.constructor.construir_whois_dnschecker(ind_url)
        self.assertIn("whois.domaintools.com/login.example", referencia.referencia_url)
        self.assertIn("query=login.example", referencia.referencia_url)
        self.assertNotIn("token", referencia.referencia_url)

    def test_no_se_genera_consulta_vt_con_direccion_de_correo(self):
        ind_email = Indicador(
            valor="persona@empresa.example",
            tipo=TipoIOC.EMAIL,
            procedencias=["Encabezado MIME"],
        )
        referencia = self.constructor.construir_virustotal(ind_email)
        self.assertEqual(referencia.estado, "No aplicable")
        self.assertNotIn("persona@empresa.example", referencia.referencia_url)


if __name__ == "__main__":
    unittest.main()
