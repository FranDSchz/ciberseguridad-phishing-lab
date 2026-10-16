# Laboratorio de Análisis Forense de Phishing (Phishing Lab)

**Fecha y hora del análisis:** `2026-10-16 (hora no especificada)`
**Zona horaria predeterminada:** `America/Argentina/Buenos_Aires`
**Versión de la herramienta:** `1.0.0`

> [!IMPORTANT]
> **Declaración de Entorno Pasivo y Ausencia de Veredicto Automático:**
> - Esta herramienta opera de manera estrictamente local y pasiva.
> - **CERO consultas de red realizadas:** No se enviaron peticiones HTTP/DNS ni se conectó con APIs o motores externos.
> - **Sin apertura automática:** Los hipervínculos de consulta generados NO fueron ejecutados ni abiertos.
> - **No veredicto automático:** La determinación de maliciosidad o fraude es de exclusiva competencia del analista forense.
> - **Privacidad de artefactos:** Los binarios originales no se suben a ningún servicio público o privado.

## 1. Datos de Entrada y Fuentes Analizadas

### Archivo de Correo Electrónico (.eml)
- **Ruta local:** `Fuente docente local preservada en Facultad; el original no se incluye en este repositorio.`
- **Hash SHA-256 local:** `afc3dcbb120e479ca4797125a5873ad4f4f0de7fbddcaf19f1bb7c5baf54f8f1`
- **Nota de integridad:** Hash calculado de forma 100% local; el archivo no fue transmitido a la red.

## 2. Metadatos y Estructura MIME del Correo (.eml)

### Encabezados Estándar del Mensaje
| Encabezado | Valor Declarado |
| :--- | :--- |
| **Subject** | Transferencia urgente - confidencial |
| **From** | "Ricardo Gomez (Gerencia)" &lt;gerencia.general2026@gm-x.example&gt; |
| **To** | tesoreria5@empresa-cliente.example |
| **Date** | Fri, 02 Oct 2026 13:22:45 -0300 |
| **Message-ID** | &lt;bec2026@gm-x.example&gt; |
| **Return-Path** | &lt;gerencia.general2026@gm-x.example&gt; |
| **Reply-To** | gerencia.general2026@gm-x.example |

### Declaraciones de Autenticación de Correo (SPF / DKIM / DMARC)

> [!NOTE]
> **Aviso Forense sobre Autenticación:**
> Los siguientes encabezados se presentan estrictamente como **declaraciones textuales** recibidas en el archivo.
> **NUNCA son verificadas criptográficamente** ni contrastadas contra registros DNS en tiempo real por esta herramienta.
> En ausencia de verificación de confianza o si provienen de saltos comprometidos, estos valores pueden estar forjados.

#### Encabezado `Authentication-Results`
```text
mx.empresa-cliente.example;        spf=pass smtp.mailfrom=gerencia.general2026@gm-x.example;        dkim=pass header.d=gm-x.example;        dmarc=pass header.from=gm-x.example
```

> [!WARNING]
> **Aviso crítico: No se detectó encabezado 'DKIM-Signature' en el mensaje analizado. Esta observación no valida ni refuta por sí sola la identidad del remitente. Las declaraciones de Authentication-Results son texto incluido en el archivo y no fueron verificadas.**

### Resumen Estructural y Temático del Cuerpo
- Presencia de texto plano: Sí (261 caracteres).
- Presencia de formato HTML: No (0 caracteres).
- Archivos adjuntos detectados: 0.
- **Alerta temática BEC detectada:** Se identificaron patrones de alta urgencia financiera / transferencia: ['$4.800.000'].
- **Política de higiene forense:** El cuerpo completo del correo ha sido omitido deliberadamente de este informe para prevenir la exposición de datos personales o cargas no deseadas.

## 3. Indicadores de Compromiso (IOCs) y Procedencia

| Tipo | Indicador (Sanitizado / Defanged) | Indicador Original | Procedencia / Origen | ¿Reservado / Doc? | Detalle / Punycode |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Dominio candidato | `empresa-cliente[.]example` | `empresa-cliente.example` | Encabezado MIME (To) (dominio emisor/receptor); Encabezado MIME (Received) (dominio emisor/receptor) | **Sí (reservado/documentación)** | TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761) |
| Dominio candidato | `gm-x[.]example` | `gm-x.example` | Encabezado MIME (From) (dominio emisor/receptor); Encabezado MIME (Return-Path) (dominio emisor/receptor); Encabezado MIME (Reply-To) (dominio emisor/receptor); Encabezado MIME (Authentication-Results) (dominio emisor/receptor); Encabezado MIME (Authentication-Results) | **Sí (reservado/documentación)** | TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761) |
| Dominio candidato | `mail[.]gm-x[.]example` | `mail.gm-x.example` | Encabezado MIME (Received) | **Sí (reservado/documentación)** | TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761) |
| Dominio candidato | `mx[.]empresa-cliente[.]example` | `mx.empresa-cliente.example` | Encabezado MIME (Received); Encabezado MIME (Authentication-Results) | **Sí (reservado/documentación)** | TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761) |
| IPv4 | `198[.]51[.]100[.]240` | `198.51.100.240` | Encabezado MIME (Received) | **Sí (reservado/documentación)** | TEST-NET-2 (RFC 5737 - Documentación y ejemplos) |
| Dirección de correo | `gerencia.general2026[@]gm-x[.]example` | `gerencia.general2026@gm-x.example` | Encabezado MIME (From); Encabezado MIME (Return-Path); Encabezado MIME (Reply-To); Encabezado MIME (Authentication-Results) | **Sí (reservado/documentación)** | TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761) |
| Dirección de correo | `tesoreria5[@]empresa-cliente[.]example` | `tesoreria5@empresa-cliente.example` | Encabezado MIME (To); Encabezado MIME (Received) | **Sí (reservado/documentación)** | TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761) |
| SHA-256 | `afc3dcbb120e479ca4797125a5873ad4f4f0de7fbddcaf19f1bb7c5baf54f8f1` | `afc3dcbb120e479ca4797125a5873ad4f4f0de7fbddcaf19f1bb7c5baf54f8f1` | Archivo .eml local (caso\_grupo\_5\_bec.eml) | No detectado como reservado | - |

## 4. Secciones de Consulta Externa (Referencias Pasivas Seguras)

Se construyen referencias dirigidas hacia cuatro servicios clave para la labor manual del analista. **Estado unificado: 'No consultado' / 'No aplicable'** (ninguna petición fue enviada).

### 4.1. VirusTotal

| Pertinente | Referencia de Consulta | Observación | Fuente / Indicador | Fecha | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- |
| No aplicable (Indicador reservado) | [Consulta VirusTotal](https://www.virustotal.com/gui/domain/empresa-cliente.example) | Indicador reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). No corresponde consulta a telemetría pública. | Dominio candidato: empresa-cliente.example (Encabezado MIME (To) (dominio emisor/receptor), Encabezado MIME (Received) (dominio emisor/receptor)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (Indicador reservado) | [Consulta VirusTotal](https://www.virustotal.com/gui/domain/gm-x.example) | Indicador reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). No corresponde consulta a telemetría pública. | Dominio candidato: gm-x.example (Encabezado MIME (From) (dominio emisor/receptor), Encabezado MIME (Return-Path) (dominio emisor/receptor), Encabezado MIME (Reply-To) (dominio emisor/receptor), Encabezado MIME (Authentication-Results) (dominio emisor/receptor), Encabezado MIME (Authentication-Results)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (Indicador reservado) | [Consulta VirusTotal](https://www.virustotal.com/gui/domain/mail.gm-x.example) | Indicador reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). No corresponde consulta a telemetría pública. | Dominio candidato: mail.gm-x.example (Encabezado MIME (Received)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (Indicador reservado) | [Consulta VirusTotal](https://www.virustotal.com/gui/domain/mx.empresa-cliente.example) | Indicador reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). No corresponde consulta a telemetría pública. | Dominio candidato: mx.empresa-cliente.example (Encabezado MIME (Received), Encabezado MIME (Authentication-Results)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (Indicador reservado) | [Consulta VirusTotal](https://www.virustotal.com/gui/ip-address/198.51.100.240) | Indicador reservado (TEST-NET-2 (RFC 5737 - Documentación y ejemplos)). No corresponde consulta a telemetría pública. | IPv4: 198.51.100.240 (Encabezado MIME (Received)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (no se consulta una dirección de correo) | [Consulta VirusTotal](https://www.virustotal.com/) | No se genera una consulta con la dirección completa. Si corresponde, evaluar manualmente el dominio extraído. | Dirección de correo: gerencia.general2026@gm-x.example (Encabezado MIME (From), Encabezado MIME (Return-Path), Encabezado MIME (Reply-To), Encabezado MIME (Authentication-Results)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (no se consulta una dirección de correo) | [Consulta VirusTotal](https://www.virustotal.com/) | No se genera una consulta con la dirección completa. Si corresponde, evaluar manualmente el dominio extraído. | Dirección de correo: tesoreria5@empresa-cliente.example (Encabezado MIME (To), Encabezado MIME (Received)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| Sí (Búsqueda pasiva de hash SHA-256 local) | [Consulta VirusTotal](https://www.virustotal.com/gui/file/afc3dcbb120e479ca4797125a5873ad4f4f0de7fbddcaf19f1bb7c5baf54f8f1) | Búsqueda por hash local del archivo sin haber subido el binario original a la plataforma. Preserva confidencialidad de la muestra. | SHA-256: afc3dcbb120e479ca4797125a5873ad4f4f0de7fbddcaf19f1bb7c5baf54f8f1 (Archivo .eml local (caso\_grupo\_5\_bec.eml)) | 2026-10-16 (hora no especificada) | **No consultado** |

### 4.2. urlscan.io

| Pertinente | Referencia de Consulta | Observación | Fuente / Indicador | Fecha | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- |
| No aplicable (Indicador reservado) | [Consulta urlscan.io](https://urlscan.io/search/#domain:empresa-cliente.example) | Indicador reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). No existen escaneos de navegación de internet pública. | Dominio candidato: empresa-cliente.example (Encabezado MIME (To) (dominio emisor/receptor), Encabezado MIME (Received) (dominio emisor/receptor)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (Indicador reservado) | [Consulta urlscan.io](https://urlscan.io/search/#domain:gm-x.example) | Indicador reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). No existen escaneos de navegación de internet pública. | Dominio candidato: gm-x.example (Encabezado MIME (From) (dominio emisor/receptor), Encabezado MIME (Return-Path) (dominio emisor/receptor), Encabezado MIME (Reply-To) (dominio emisor/receptor), Encabezado MIME (Authentication-Results) (dominio emisor/receptor), Encabezado MIME (Authentication-Results)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (Indicador reservado) | [Consulta urlscan.io](https://urlscan.io/search/#domain:mail.gm-x.example) | Indicador reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). No existen escaneos de navegación de internet pública. | Dominio candidato: mail.gm-x.example (Encabezado MIME (Received)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (Indicador reservado) | [Consulta urlscan.io](https://urlscan.io/search/#domain:mx.empresa-cliente.example) | Indicador reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). No existen escaneos de navegación de internet pública. | Dominio candidato: mx.empresa-cliente.example (Encabezado MIME (Received), Encabezado MIME (Authentication-Results)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (Indicador reservado) | [Consulta urlscan.io](https://urlscan.io/search/#ip:198.51.100.240) | Indicador reservado (TEST-NET-2 (RFC 5737 - Documentación y ejemplos)). No existen escaneos de navegación de internet pública. | IPv4: 198.51.100.240 (Encabezado MIME (Received)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable | [Consulta urlscan.io](https://urlscan.io/search/) | urlscan.io indexa navegaciones web (URLs, dominios, IPs); no procesa hashes ni buzones. | Dirección de correo: gerencia.general2026@gm-x.example (Encabezado MIME (From), Encabezado MIME (Return-Path), Encabezado MIME (Reply-To), Encabezado MIME (Authentication-Results)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable | [Consulta urlscan.io](https://urlscan.io/search/) | urlscan.io indexa navegaciones web (URLs, dominios, IPs); no procesa hashes ni buzones. | Dirección de correo: tesoreria5@empresa-cliente.example (Encabezado MIME (To), Encabezado MIME (Received)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable | [Consulta urlscan.io](https://urlscan.io/search/) | urlscan.io indexa navegaciones web (URLs, dominios, IPs); no procesa hashes ni buzones. | SHA-256: afc3dcbb120e479ca4797125a5873ad4f4f0de7fbddcaf19f1bb7c5baf54f8f1 (Archivo .eml local (caso\_grupo\_5\_bec.eml)) | 2026-10-16 (hora no especificada) | **No aplicable** |

### 4.3. WHOIS / DNSChecker

| Pertinente | Referencia de Consulta | Observación | Fuente / Indicador | Fecha | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- |
| No aplicable (Indicador reservado) | [Consulta WHOIS / DNSChecker](https://whois.domaintools.com/empresa-cliente.example) | Indicador de rango/nombre reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). No posee delegación de autoridad en registros de internet públicos. | Dominio candidato: empresa-cliente.example (Encabezado MIME (To) (dominio emisor/receptor), Encabezado MIME (Received) (dominio emisor/receptor)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (Indicador reservado) | [Consulta WHOIS / DNSChecker](https://whois.domaintools.com/gm-x.example) | Indicador de rango/nombre reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). No posee delegación de autoridad en registros de internet públicos. | Dominio candidato: gm-x.example (Encabezado MIME (From) (dominio emisor/receptor), Encabezado MIME (Return-Path) (dominio emisor/receptor), Encabezado MIME (Reply-To) (dominio emisor/receptor), Encabezado MIME (Authentication-Results) (dominio emisor/receptor), Encabezado MIME (Authentication-Results)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (Indicador reservado) | [Consulta WHOIS / DNSChecker](https://whois.domaintools.com/mail.gm-x.example) | Indicador de rango/nombre reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). No posee delegación de autoridad en registros de internet públicos. | Dominio candidato: mail.gm-x.example (Encabezado MIME (Received)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (Indicador reservado) | [Consulta WHOIS / DNSChecker](https://whois.domaintools.com/mx.empresa-cliente.example) | Indicador de rango/nombre reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). No posee delegación de autoridad en registros de internet públicos. | Dominio candidato: mx.empresa-cliente.example (Encabezado MIME (Received), Encabezado MIME (Authentication-Results)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (Indicador reservado) | [Consulta WHOIS / DNSChecker](https://whois.domaintools.com/198.51.100.240) | Indicador de rango/nombre reservado (TEST-NET-2 (RFC 5737 - Documentación y ejemplos)). No posee delegación de autoridad en registros de internet públicos. | IPv4: 198.51.100.240 (Encabezado MIME (Received)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable | [Consulta WHOIS / DNSChecker](https://whois.domaintools.com/) | WHOIS y resolución DNS aplican exclusivamente sobre nombres de dominio e infraestructura IP. | Dirección de correo: gerencia.general2026@gm-x.example (Encabezado MIME (From), Encabezado MIME (Return-Path), Encabezado MIME (Reply-To), Encabezado MIME (Authentication-Results)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable | [Consulta WHOIS / DNSChecker](https://whois.domaintools.com/) | WHOIS y resolución DNS aplican exclusivamente sobre nombres de dominio e infraestructura IP. | Dirección de correo: tesoreria5@empresa-cliente.example (Encabezado MIME (To), Encabezado MIME (Received)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable | [Consulta WHOIS / DNSChecker](https://whois.domaintools.com/) | WHOIS y resolución DNS aplican exclusivamente sobre nombres de dominio e infraestructura IP. | SHA-256: afc3dcbb120e479ca4797125a5873ad4f4f0de7fbddcaf19f1bb7c5baf54f8f1 (Archivo .eml local (caso\_grupo\_5\_bec.eml)) | 2026-10-16 (hora no especificada) | **No aplicable** |

### 4.4. crt.sh

| Pertinente | Referencia de Consulta | Observación | Fuente / Indicador | Fecha | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- |
| No aplicable (Dominio reservado) | [Consulta crt.sh](https://crt.sh/?q=empresa-cliente.example) | Dominio reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). Las Autoridades Certificadoras públicas no emiten certificados válidos para dominios de prueba. | Dominio: empresa-cliente.example (Encabezado MIME (To) (dominio emisor/receptor), Encabezado MIME (Received) (dominio emisor/receptor)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (Dominio reservado) | [Consulta crt.sh](https://crt.sh/?q=gm-x.example) | Dominio reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). Las Autoridades Certificadoras públicas no emiten certificados válidos para dominios de prueba. | Dominio: gm-x.example (Encabezado MIME (From) (dominio emisor/receptor), Encabezado MIME (Return-Path) (dominio emisor/receptor), Encabezado MIME (Reply-To) (dominio emisor/receptor), Encabezado MIME (Authentication-Results) (dominio emisor/receptor), Encabezado MIME (Authentication-Results)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (Dominio reservado) | [Consulta crt.sh](https://crt.sh/?q=mail.gm-x.example) | Dominio reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). Las Autoridades Certificadoras públicas no emiten certificados válidos para dominios de prueba. | Dominio: mail.gm-x.example (Encabezado MIME (Received)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable (Dominio reservado) | [Consulta crt.sh](https://crt.sh/?q=mx.empresa-cliente.example) | Dominio reservado (TLD reservado para pruebas/documentación: .example (RFC 2606 / RFC 6761)). Las Autoridades Certificadoras públicas no emiten certificados válidos para dominios de prueba. | Dominio: mx.empresa-cliente.example (Encabezado MIME (Received), Encabezado MIME (Authentication-Results)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable | [Consulta crt.sh](https://crt.sh/) | crt.sh monitorea registros Certificate Transparency (CT logs); solo aplica a nombres de dominio FQDN. | IPv4: 198.51.100.240 (Encabezado MIME (Received)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable | [Consulta crt.sh](https://crt.sh/) | crt.sh monitorea registros Certificate Transparency (CT logs); solo aplica a nombres de dominio FQDN. | Dirección de correo: gerencia.general2026@gm-x.example (Encabezado MIME (From), Encabezado MIME (Return-Path), Encabezado MIME (Reply-To), Encabezado MIME (Authentication-Results)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable | [Consulta crt.sh](https://crt.sh/) | crt.sh monitorea registros Certificate Transparency (CT logs); solo aplica a nombres de dominio FQDN. | Dirección de correo: tesoreria5@empresa-cliente.example (Encabezado MIME (To), Encabezado MIME (Received)) | 2026-10-16 (hora no especificada) | **No aplicable** |
| No aplicable | [Consulta crt.sh](https://crt.sh/) | crt.sh monitorea registros Certificate Transparency (CT logs); solo aplica a nombres de dominio FQDN. | SHA-256: afc3dcbb120e479ca4797125a5873ad4f4f0de7fbddcaf19f1bb7c5baf54f8f1 (Archivo .eml local (caso\_grupo\_5\_bec.eml)) | 2026-10-16 (hora no especificada) | **No aplicable** |

## 5. Veredicto y Dictamen del Laboratorio

> [!NOTE]
> **Veredicto Automático:** `NO EMITIDO (Requiere Análisis Humano)`
> **Veredicto Humano Recomendado:**
> [ ] Legítimo
> [ ] Sospechoso
> [ ] Malicioso (Phishing / BEC / Suplantación)
> [ ] No Concluyente

---
*Informe forense generado por Phishing Lab.*
