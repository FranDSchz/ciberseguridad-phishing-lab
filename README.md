# Phishing Lab

**Phishing Lab** es una utilidad local y pasiva para la preparación, triage y análisis forense preliminar de incidentes de phishing y compromiso de correo corporativo (BEC - *Business Email Compromise*).

Construida íntegramente con la **biblioteca estándar de Python** (sin dependencias externas ni llamadas de red), permite analizar tanto entradas manuales (URLs, dominios, direcciones IPv4) como archivos de correo electrónico en formato `.eml`.

---

## Principios de Diseño y Seguridad Forense

1. **Aislamiento Estricto y Cero Consultas de Red:**
   La herramienta no realiza ninguna petición HTTP, DNS ni conexión de socket activa. No consume APIs, no requiere credenciales ni visita enlaces.
2. **Sin Apertura Automática de Navegador:**
   Las referencias hacia plataformas de inteligencia de amenazas se construyen de forma sanitizada y clicable para el analista, pero jamás se ejecutan o abren de forma desatendida.
3. **Privacidad de Artefactos (No Subir Originales):**
   El hash SHA-256 del archivo `.eml` se calcula localmente en memoria. El binario o contenido del correo nunca es transmitido hacia servicios externos.
4. **Higiene Forense del Cuerpo:**
   Para proteger datos personales, secretos comerciales y prevenir la propagación de cargas maliciosas, **el cuerpo completo del correo nunca se vuelca en el informe**. Se genera un resumen forense estructurado con métricas y alertas temáticas.
5. **Declaraciones de Autenticación sin Validación Engañosa:**
   Los encabezados SPF, DKIM y DMARC (como `Authentication-Results` o `Received-SPF`) se reportan exclusivamente como declaraciones textuales contenidas en el mensaje. **Nunca se asume su validez ni se verifican criptográficamente**, y se advierte de forma explícita ante la ausencia del encabezado crítico `DKIM-Signature`.
6. **Sin Veredictos Automáticos:**
   La herramienta no genera clasificaciones binarias automáticas ("Malicioso / Limpio") ni inventa resultados de detección. Todos los servicios externos quedan registrados con estado **`No consultado`** o **`No aplicable`**. La decisión final corresponde siempre al criterio humano del analista forense.
7. **Zona Horaria y Determinismo:**
   La zona horaria predeterminada de trabajo es `America/Argentina/Buenos_Aires` (UTC-3), admitiendo la inyección de marcas temporales fijas para garantizar reproducibilidad en auditorías y pruebas.

Los dominios extraídos son candidatos por su forma textual; la herramienta no confirma que existan ni consulta DNS. Los nombres reservados se marcan aparte.

---

## Arquitectura del Proyecto

```
ciberseguridad-phishing-lab/
├── phishing_lab/
│   ├── __init__.py           # Exportaciones del paquete
│   ├── __main__.py           # Punto de ejecución python -m phishing_lab
│   ├── cli.py                # Interfaz CLI en español y orquestador
│   ├── models.py             # Modelos de datos (Indicador, Metadatos, Referencias)
│   ├── parser_eml.py         # Parseo MIME pasivo, SHA-256 local y resumen
│   ├── extractor.py          # Extracción con procedencia, HTML pasivo y punycode
│   ├── indicators.py         # Detección de dominios/IPs reservados (RFCs) y defanging
│   ├── references.py         # Constructor seguro para VT, urlscan, WHOIS y crt.sh
│   ├── reporter.py           # Generador de informes reproducibles en Markdown
│   └── timezone_utils.py     # Manejo de zona horaria America/Argentina/Buenos_Aires
├── tests/
│   ├── __init__.py
│   ├── fixtures/
│   │   ├── caso5_bec_sintetico.eml      # Fixture sintético fiel: $4.800.000, .example y TEST-NET-2
│   │   ├── correo_html_punycode.eml     # Fixture HTML (href vs texto, IDN punycode)
│   │   └── entrada_malformada.eml       # Fixture MIME dañado para pruebas de robustez
│   ├── test_cli.py           # Pruebas de la CLI y códigos de retorno
│   ├── test_extractor.py     # Pruebas de extracción segura y punycode
│   ├── test_indicators.py    # Pruebas de dominios e IPs reservados (TEST-NET)
│   ├── test_no_network.py    # Validación de interdicción y aislamiento de red
│   ├── test_parser_eml.py    # Pruebas de parseo MIME y Caso 5 BEC
│   ├── test_references.py    # Pruebas del constructor de los 4 servicios
│   ├── test_reporter.py      # Pruebas del informe Markdown generado
│   └── test_timezone.py      # Pruebas de zona horaria y fecha inyectable
├── phishing_lab.py           # Script ejecutable directo en la raíz
├── .gitignore                # Reglas de exclusión para Git
└── README.md                 # Documentación técnica en español
```

---

## Requisitos de Ejecución

- **Python:** 3.9 o superior (probado en Python 3.11).
- **Dependencias:** Ninguna (utiliza exclusivamente módulos estándar como `email`, `html.parser`, `urllib.parse`, `hashlib`, `ipaddress`, `argparse`, `dataclasses`, `datetime` y `zoneinfo`).

---

## Flujo de Trabajo del Laboratorio

```
  [ Entrada Manual ]             [ Archivo de Correo .eml ]
  (URLs, Dominios, IPs)                       │
           │                     ┌────────────┴────────────┐
           │                     ▼                         ▼
           │             SHA-256 Local               BytesParser (MIME)
           │          (Sin subir a la red)                 │
           │                                      ┌────────┴────────┐
           │                                      ▼                 ▼
           │                                 Encabezados      Cuerpos (Plano/HTML)
           │                                (From, Rcv, Auth) (Resumen sin volcado)
           │                                      │                 │
           └──────────────────────┬───────────────┴─────────────────┘
                                  ▼
                        Extractor con Procedencia
                 (HTML pasivo seguro, punycode, defanging)
                                  │
                                  ▼
                    Clasificación de Reservados
               (RFC 2606 / RFC 6761 / RFC 5737 TEST-NET)
                                  │
                                  ▼
                 Constructor de Referencias Seguras
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
    VirusTotal               urlscan.io           WHOIS / DNSChecker      crt.sh
 (Sin envío auto)         (Sin escaneo auto)        (Sin consulta auto)  (Sin consulta auto)
         └────────────────────────┬────────────────────────┘
                                  ▼
                 Informe Forense Markdown Reproducible
                 (Estado: No consultado / No aplicable)
                 (Veredicto Automático: NO EMITIDO)
```

---

## Comandos Ejecutables

La herramienta puede invocarse mediante `python phishing_lab.py` o mediante el módulo `python -m phishing_lab`.

### 1. Ayuda de la CLI en español

```bash
python phishing_lab.py --help
```

### 2. Análisis de entrada manual (URL, dominio e IP)

Permite analizar indicadores individuales sin necesidad de un archivo de correo:

```bash
python phishing_lab.py --url "https://login-portal.example/auth" --dominio "portal.example" --ip "198.51.100.25"
```

### 3. Análisis de archivo `.eml` (Caso 5: Ataque BEC sintético)

Procesa el archivo de correo de prueba, calcula su SHA-256 local, detecta la ausencia de firma DKIM, alerta sobre la transferencia urgente de $4.8M y genera el reporte:

```bash
python phishing_lab.py --eml tests/fixtures/caso5_bec_sintetico.eml
```

### 4. Guardar el informe Markdown en un archivo de salida

Utilice la opción `-o` o `--salida` para persistir el informe forense:

```bash
python phishing_lab.py --eml tests/fixtures/caso5_bec_sintetico.eml --salida informe_caso5.md
```

### 5. Análisis combinado (Archivo `.eml` + Indicadores manuales adicionales)

```bash
python phishing_lab.py -e tests/fixtures/caso5_bec_sintetico.eml -u "https://enlace-externo.example/pago" -i "192.0.2.1" -o informe_combinado.md
```

### 6. Análisis reproducible con fecha inyectada (`--fecha`)

Para auditorías o pruebas deterministas, es posible fijar la fecha/hora de referencia del análisis (formato ISO):

```bash
python phishing_lab.py -e tests/fixtures/caso5_bec_sintetico.eml --fecha "2026-10-16T12:00:00" -o reporte_auditoria.md
```

---

## Descripción de las Cuatro Secciones de Consulta

Para cada indicador extraído, Phishing Lab prepara la referencia de consulta pasiva en las cuatro plataformas de análisis requeridas:

| Servicio | Tipo de IOC Pertinente | Enlace Construido de Ejemplo | Acción Realizada por la Herramienta |
| :--- | :--- | :--- | :--- |
| **VirusTotal** | Hash SHA-256 del archivo, Dominios, IPs y URLs | `https://www.virustotal.com/gui/file/<hash>` | **No consultado** (no se envían archivos ni datos) |
| **urlscan.io** | URLs, Dominios y Direcciones IP | `https://urlscan.io/search/#domain:<dominio>` | **No consultado** (no se inician escaneos activos) |
| **WHOIS / DNSChecker** | Dominios e Infraestructura IPv4 | `https://whois.domaintools.com/<dominio>` | **No consultado** (no se consultan servidores WHOIS ni DNS) |
| **crt.sh** | Nombres de Dominio FQDN | `https://crt.sh/?q=<dominio>` | **No consultado** (no se consulta base de Certificate Transparency) |

### Esquema Registrado para Cada Entrada
Cada fila de las tablas de consulta externa documenta obligatoriamente:
- **Pertinente:** Si el indicador aplica técnica y legalmente al servicio (o si es `No aplicable` por ser de documentación/reservado).
- **Referencia de consulta:** URL de búsqueda codificada de forma segura y presentada como enlace Markdown.
- **Observación:** Nota técnica para el analista que describe el objetivo de la inspección manual.
- **Fuente:** Origen y procedencia exacta del indicador dentro del artefacto analizado.
- **Fecha:** Marca temporal en zona horaria `America/Argentina/Buenos_Aires`.
- **Estado:** Estrictamente **`No consultado`** o **`No aplicable`**.

---

## Caso 5 del grupo 5

El reporte [`examples/informe-caso5-grupo5.md`](examples/informe-caso5-grupo5.md) se generó localmente a partir del `.eml` docente preservado en Facultad; el correo original no se copia a este repositorio. El reporte registra metadatos, indicadores con procedencia, hash local y las cuatro secciones como no consultadas o no aplicables. Omite el cuerpo completo.

Los hechos observados en el original son cuerpo `text/plain` sin URLs ni adjuntos; pedido urgente y confidencial de $4.800.000 a un proveedor nuevo antes de las 15:00; dominios `.example`; IP `198.51.100.240` (TEST-NET-2); declaraciones SPF/DKIM/DMARC `pass` dentro del archivo y ausencia de `DKIM-Signature`. Esas declaraciones no se verificaron. La ausencia de una firma no establece por sí sola la identidad ni la legitimidad del mensaje. No se consultó reputación, DNS ni certificados y el informe no emite veredicto.

---

## Ejecución de Comprobaciones Automatizadas

Las pruebas unitarias están organizadas mediante el módulo estándar `unittest`:

```bash
python -m unittest discover -s tests -v
```

Las suites cubren:
- Extracción segura y fidelidad del caso BEC 5 (`test_parser_eml.py`).
- Extracción HTML pasiva y resolución de punycode (`test_extractor.py`).
- Clasificación de indicadores reservados RFC 2606/6761 y RFC 5737 (`test_indicators.py`).
- Construcción de referencias de los 4 servicios y estado 'No consultado' (`test_references.py`).
- Generación de informe Markdown y omisión de volcado completo (`test_reporter.py`).
- Aislamiento total de red e interdicción de sockets (`test_no_network.py`).
- Comportamiento de la CLI y códigos de salida (`test_cli.py`).
- Zona horaria de Buenos Aires y determinismo de fecha (`test_timezone.py`).
