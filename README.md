# Phishing Lab

Phishing Lab es una herramienta de triage para correos `.eml`, archivos adjuntos, archivos individuales y sus IOCs. Extrae URLs, dominios e IPs, calcula SHA-256 local, identifica algunas firmas de archivo, consulta reportes existentes mediante APIs optativas y emite una ficha explicable por recurso.

## Alcance y seguridad

- El modo predeterminado es local: no hace conexiones de red.
- El parser de correo no abre enlaces ni muestra el cuerpo completo en el informe.
- Los adjuntos se decodifican en memoria para calcular SHA-256 y reconocer algunas firmas. No se guardan, extraen ni ejecutan.
- La consulta externa es optativa (`--consultar-apis`). Se envían los IOCs al proveedor correspondiente; nunca se envían los binarios ni el correo completo.
- **Privacidad:** una consulta de VirusTotal por API puede incorporar el indicador a su conjunto comunitario. No consultes direcciones personales, URLs internas ni información confidencial sin autorización. Las consultas de urlscan, RDAP, DNS y crt.sh también revelan el indicador al servicio.
- Para respetar un entorno de VM sin red, primero analiza los archivos sin `--consultar-apis`. Solo realiza consultas externas desde un entorno controlado y autorizado, enviando indicadores aprobados.
- No es un sandbox ni un motor antivirus local. No ejecuta código, analiza comportamiento, descomprime archivos ni determina familias de malware. Un tipo de archivo detectado o un resultado ausente no demuestra infección ni legitimidad.

## APIs y fuentes

| Fuente | Qué consulta Phishing Lab | Operación |
| :--- | :--- | :--- |
| VirusTotal | Reporte existente de URL, dominio, IP y SHA-256 de archivos/adjuntos | GET de reportes; requiere `VIRUSTOTAL_API_KEY`; no sube muestras ni solicita rescan. Consultar un IOC puede agregarlo al dataset de VirusTotal. |
| urlscan.io | Escaneos históricos para URL, dominio e IP | GET de búsqueda; nunca envía una URL para escanear. `URLSCAN_API_KEY` es opcional, sujeto a los límites de acceso del servicio. |
| RDAP | Datos registrales de dominio o IP | GET a `rdap.org`; sirve como contexto de registro, no como veredicto de malware. |
| DNS-over-HTTPS | Respuestas DNS A, AAAA, MX, TXT, NS y CNAME | GET al servicio JSON de Cloudflare. Es una API DNS pública, no una llamada a la API de DNSChecker.org. |
| crt.sh | Entradas públicas de Certificate Transparency para dominios | GET a `crt.sh` con salida JSON. La presencia de un certificado no indica por sí sola que el sitio sea malicioso. |

La herramienta también genera referencias web para revisión manual. La consulta API de RDAP y DNS-over-HTTPS reemplaza las consultas manuales de WHOIS/DNS; no automatiza la web de DNSChecker.org.

## Veredictos

Las fichas usan `LIMPIO`, `SOSPECHOSO` o `MALICIOSO/INFECTADO`, y muestran confianza, cobertura, fundamentos, posible impacto C-I-A y recomendaciones.

- `MALICIOSO/INFECTADO`: una fuente de reputación devuelve una detección explícita. No se infiere una familia (troyano, gusano, descargador) si la respuesta no la identifica.
- `SOSPECHOSO`: hay señales que requieren corroboración —por ejemplo, un pedido de transferencia urgente, discrepancia de dominios From/Reply-To o una detección aislada— o la cobertura es insuficiente para concluir limpio. El informe dice cuál de los dos motivos aplica.
- `LIMPIO`: las consultas de reputación aplicables devolvieron reportes evaluables sin detecciones. La confianza es baja y el resultado no garantiza inocuidad.

RDAP, DNS y Certificate Transparency se informan como contexto; no hacen que un recurso pase a malicioso por sí solos. La salida es triage automático y debe contrastarse con el caso y la evidencia visible.

## Requisitos

- Python 3.9 o superior.
- No requiere paquetes externos.
- Para VirusTotal, define `VIRUSTOTAL_API_KEY` en el entorno. urlscan.io puede consultar sin clave, con límites del proveedor; define `URLSCAN_API_KEY` si corresponde.

## Uso

La herramienta se puede ejecutar con `python phishing_lab.py` o `python -m phishing_lab`.

### Analizar un correo y sus adjuntos localmente

```bash
python phishing_lab.py --eml correo_sospechoso.eml --salida informe.md --salida-json evidencia.json
```

### Analizar archivos suministrados por separado

```bash
python phishing_lab.py --archivo muestra.exe --archivo documento.pdf --salida informe.md --salida-json evidencia.json
```

### Consultar las APIs de forma explícita

```bash
python phishing_lab.py --eml correo_sospechoso.eml --consultar-apis --salida informe.md --salida-json evidencia.json
```

Al activar `--consultar-apis`, el programa muestra una advertencia y consulta los IOCs extraídos y las huellas de adjuntos/archivos. El hash del `.eml` completo no se consulta. Si falta una clave, no hay reporte o el servicio limita la consulta, el estado queda explícito y no se interpreta como limpio.

### Entradas manuales

```bash
python phishing_lab.py --url "https://sitio-sospechoso.invalid/login" --dominio "sitio-sospechoso.invalid" --ip "203.0.113.10"
```

Los nombres `.example`, `.invalid`, `.localhost`, `.test` y rangos IP reservados se reconocen localmente y no se envían a servicios públicos.

### Variables de entorno en PowerShell

```powershell
$env:VIRUSTOTAL_API_KEY = "<tu-clave>"
$env:URLSCAN_API_KEY = "<tu-clave-opcional>"
python phishing_lab.py --url "https://dominio-a-investigar.tld/ruta" --consultar-apis --salida informe.md --salida-json evidencia.json
```

`evidencia.json` conserva las respuestas recibidas con sus estados, marcas de tiempo y datos de API. Puede contener IOCs, endpoints y datos registrales públicos; mantenlo junto con la evidencia del caso y no lo publiques sin revisar.

## Archivos principales

- `phishing_lab/cli.py`: argumentos y coordinación del análisis.
- `phishing_lab/parser_eml.py`: extracción MIME y hash de adjuntos.
- `phishing_lab/artifacts.py`: SHA-256 y detección estática básica por firma.
- `phishing_lab/online_lookups.py`: clientes de consulta GET, errores y límites de respuesta.
- `phishing_lab/verdict.py`: reglas transparentes de triage por recurso.
- `phishing_lab/reporter.py`: informe Markdown con resultados, evidencias y recomendaciones.
- `phishing_lab/references.py`: enlaces para revisión manual.
