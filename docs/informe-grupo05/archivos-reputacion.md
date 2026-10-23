# Laboratorio de Análisis Forense de Phishing (Phishing Lab)

**Fecha y hora del análisis:** `2026-10-23 14:30:48 -0300`  
**Zona horaria predeterminada:** `America/Argentina/Buenos_Aires`  
**Versión de la herramienta:** `1.2.0`  

> [!IMPORTANT]
> **Alcance y privacidad:**
> - Los correos y archivos se inspeccionan localmente; las muestras no se ejecutan ni se suben.
> - Las consultas a APIs solo ocurren con `--consultar-apis`; en ese modo se envían indicadores (no binarios) a los proveedores.
> - Las URLs extraídas no se visitan. Las referencias manuales de la sección 4 tampoco se abrieron desde el programa.
> - El tipo de archivo y la ausencia de detecciones no prueban por sí solos que una muestra sea maliciosa o inocua.
> - VirusTotal advierte que un IOC consultado puede quedar incorporado a su dataset comunitario; no consultar datos confidenciales o personales.

## 1. Datos de Entrada y Fuentes Analizadas

### Entradas Manuales Suministradas
- **SHA-256:**
  - `6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba`
  - `06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec`

## 3. Indicadores de Compromiso (IOCs) y Procedencia

| Tipo | Indicador (Sanitizado / Defanged) | Indicador Original | Procedencia / Origen | ¿Reservado / Doc? | Detalle / Punycode |
| :--- | :--- | :--- | :--- | :--- | :--- |
| SHA-256 | `06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec` | `06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec` | Entrada manual (SHA-256) | No detectado como reservado | - |
| SHA-256 | `6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba` | `6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba` | Entrada manual (SHA-256) | No detectado como reservado | - |

## 4. Referencias para consulta manual

Estos enlaces sirven para una revisión manual y el programa no los abre. Esta tabla conserva las referencias generadas; los resultados de las APIs ejecutadas se muestran por separado en la sección 5.

### 4.1. VirusTotal

| Pertinente | Referencia de Consulta | Observación | Fuente / Indicador | Fecha | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Sí (Búsqueda pasiva de hash SHA-256 local) | [Consulta VirusTotal](https://www.virustotal.com/gui/file/06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec) | Búsqueda por hash local del archivo sin haber subido el binario original a la plataforma. Preserva confidencialidad de la muestra. | SHA-256: 06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec (Entrada manual (SHA-256)) | 2026-10-23 14:30:48 -0300 | **No consultado** |
| Sí (Búsqueda pasiva de hash SHA-256 local) | [Consulta VirusTotal](https://www.virustotal.com/gui/file/6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba) | Búsqueda por hash local del archivo sin haber subido el binario original a la plataforma. Preserva confidencialidad de la muestra. | SHA-256: 6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba (Entrada manual (SHA-256)) | 2026-10-23 14:30:48 -0300 | **No consultado** |

### 4.2. urlscan.io

| Pertinente | Referencia de Consulta | Observación | Fuente / Indicador | Fecha | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- |
| No aplicable | [Consulta urlscan.io](https://urlscan.io/search/) | urlscan.io indexa navegaciones web (URLs, dominios, IPs); no procesa hashes ni buzones. | SHA-256: 06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec (Entrada manual (SHA-256)) | 2026-10-23 14:30:48 -0300 | **No aplicable** |
| No aplicable | [Consulta urlscan.io](https://urlscan.io/search/) | urlscan.io indexa navegaciones web (URLs, dominios, IPs); no procesa hashes ni buzones. | SHA-256: 6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba (Entrada manual (SHA-256)) | 2026-10-23 14:30:48 -0300 | **No aplicable** |

### 4.3. WHOIS / DNSChecker

| Pertinente | Referencia de Consulta | Observación | Fuente / Indicador | Fecha | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- |
| No aplicable | [Consulta WHOIS / DNSChecker](https://whois.domaintools.com/) | WHOIS y resolución DNS aplican exclusivamente sobre nombres de dominio e infraestructura IP. | SHA-256: 06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec (Entrada manual (SHA-256)) | 2026-10-23 14:30:48 -0300 | **No aplicable** |
| No aplicable | [Consulta WHOIS / DNSChecker](https://whois.domaintools.com/) | WHOIS y resolución DNS aplican exclusivamente sobre nombres de dominio e infraestructura IP. | SHA-256: 6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba (Entrada manual (SHA-256)) | 2026-10-23 14:30:48 -0300 | **No aplicable** |

### 4.4. crt.sh

| Pertinente | Referencia de Consulta | Observación | Fuente / Indicador | Fecha | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- |
| No aplicable | [Consulta crt.sh](https://crt.sh/) | crt.sh monitorea registros Certificate Transparency (CT logs); solo aplica a nombres de dominio FQDN. | SHA-256: 06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec (Entrada manual (SHA-256)) | 2026-10-23 14:30:48 -0300 | **No aplicable** |
| No aplicable | [Consulta crt.sh](https://crt.sh/) | crt.sh monitorea registros Certificate Transparency (CT logs); solo aplica a nombres de dominio FQDN. | SHA-256: 6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba (Entrada manual (SHA-256)) | 2026-10-23 14:30:48 -0300 | **No aplicable** |

## 5. Resultados de consultas API

Cada respuesta se conserva en el JSON de salida si se solicitó `--salida-json`. `sin resultados`, error, límite de cuota y falta de clave son estados distintos; no equivalen a limpio.

| Servicio | Tipo | Indicador | Estado | HTTP | Hora UTC | Resultado / evidencia |
| :--- | :--- | :--- | :--- | ---: | :--- | :--- |
| VirusTotal | sha256 | `06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec` | **found** | 200 | 2026-10-23T17:30:49+00:00 | VirusTotal \[found\]: motores: confirmed-timeout=0, failure=2, harmless=0, malicious=47, suspicious=0, timeout=0, type-unsupported=4, undetected=22; motores con alerta: Bkav=W32.Malware.D21A217D, Lionic=Trojan.Win32.Valley.m\!c, MicroWorld-eScan=Trojan.Generic.40652856, CTX=exe.trojan.generic, ALYac=Trojan.Generic.40652856; fecha del análisis informado: 2026-10-15T07:36:37+00:00 UTC; Primera observación en VirusTotal (UTC): 2026-10-12T01:38:16+00:00.; Última observación en VirusTotal (UTC): 2026-10-12T01:38:16+00:00.; Último análisis en VirusTotal (UTC): 2026-10-15T07:36:37+00:00.; Tipo informado por VirusTotal: Win32 EXE.; Tamaño informado por VirusTotal (bytes): 1559216.; Nombre destacado en VirusTotal: Setup64.exe.; Nombres observados en VirusTotal: 06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec.exe, Setup64.exe, 0jtzym5.exe, WinCombo.exe, wincombo.exe, rfc7f8u.exe.; Motor Bkav: malicious; etiqueta informada: W32.Malware.D21A217D.; Motor Lionic: malicious; etiqueta informada: Trojan.Win32.Valley.m\!c.; Motor MicroWorld-eScan: malicious; etiqueta informada: Trojan.Generic.40652856.; Motor CTX: malicious; etiqueta informada: exe.trojan.generic.; Motor ALYac: malicious; etiqueta informada: Trojan.Generic.40652856.; Motor Cylance: malicious; etiqueta informada: Unsafe.; Motor VIPRE: malicious; etiqueta informada: Trojan.Generic.40652856.; Motor Sangfor: malicious; etiqueta informada: Backdoor.Win32.Valley.V5wn.; Motor K7AntiVirus: malicious; etiqueta informada: Backdoor ( 006e8e661 ).; Motor BitDefender: malicious; etiqueta informada: Trojan.Generic.40652856.; Resumen histórico de sandbox informado por VirusTotal (C2AE): malicious; STEALER, MALWARE, KeyloggerGeneric, PEguise. No se solicitó una nueva ejecución ni incluye necesariamente procesos/conexiones.; Resumen histórico de sandbox informado por VirusTotal (Zenbox): malicious; MALWARE, TROJAN, EVADER, RAT, ValleyRAT. No se solicitó una nueva ejecución ni incluye necesariamente procesos/conexiones.; Resumen histórico de sandbox informado por VirusTotal (VMRay): malicious; MALWARE, ValleyRAT, App/Generic-PH, Mal/Generic-S. No se solicitó una nueva ejecución ni incluye necesariamente procesos/conexiones.; Resumen histórico de sandbox informado por VirusTotal (Yomi Hunter): malicious; MALWARE. No se solicitó una nueva ejecución ni incluye necesariamente procesos/conexiones. |
| VirusTotal | sha256 | `6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba` | **found** | 200 | 2026-10-23T17:30:49+00:00 | VirusTotal \[found\]: motores: confirmed-timeout=0, failure=2, harmless=0, malicious=47, suspicious=0, timeout=1, type-unsupported=4, undetected=21; motores con alerta: Lionic=Trojan.Win32.Xkcp.m\!c, Elastic=malicious (high confidence), MicroWorld-eScan=Application.Generic.37102404, CTX=dll.trojan.malwarex, CAT-QuickHeal=Hacktool.Agent; fecha del análisis informado: 2026-10-22T13:15:48+00:00 UTC; Primera observación en VirusTotal (UTC): 2026-10-14T07:02:51+00:00.; Última observación en VirusTotal (UTC): 2026-10-14T12:08:18+00:00.; Último análisis en VirusTotal (UTC): 2026-10-22T13:15:48+00:00.; Tipo informado por VirusTotal: Win32 DLL.; Tamaño informado por VirusTotal (bytes): 2264968.; Nombre destacado en VirusTotal: Setup64.exe.; Nombres observados en VirusTotal: Setup64.exe, 6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba.exe, libPdfCore.dll, gnps7ej.exe, hx8sh.exe.; Motor Lionic: malicious; etiqueta informada: Trojan.Win32.Xkcp.m\!c.; Motor Elastic: malicious; etiqueta informada: malicious (high confidence).; Motor MicroWorld-eScan: malicious; etiqueta informada: Application.Generic.37102404.; Motor CTX: malicious; etiqueta informada: dll.trojan.malwarex.; Motor CAT-QuickHeal: malicious; etiqueta informada: Hacktool.Agent.; Motor ALYac: malicious; etiqueta informada: Application.Generic.37102404.; Motor Malwarebytes: malicious; etiqueta informada: Trojan.ShellCode.; Motor VIPRE: malicious; etiqueta informada: Application.Generic.37102404.; Motor Sangfor: malicious; etiqueta informada: Trojan.Win32.Save.a.; Motor K7AntiVirus: malicious; etiqueta informada: Hacktool ( 005ce32e1 ).; Resumen histórico de sandbox informado por VirusTotal (Zenbox): malicious; MALWARE, EVADER. No se solicitó una nueva ejecución ni incluye necesariamente procesos/conexiones.; Resumen histórico de sandbox informado por VirusTotal (C2AE): undetected; UNKNOWN\_VERDICT. No se solicitó una nueva ejecución ni incluye necesariamente procesos/conexiones.; Resumen histórico de sandbox informado por VirusTotal (VMRay): malicious; MALWARE, ValleyRAT, App/Generic-IH, App/Generic-MB. No se solicitó una nueva ejecución ni incluye necesariamente procesos/conexiones. |

RDAP informa datos registrales; DNS y Certificate Transparency describen infraestructura. Esos datos aportan contexto, pero por sí solos no constituyen detección de malware.

## 6. Veredicto y recomendaciones por recurso

### Resumen
| ID | Recurso | Identificador | Veredicto | Confianza | Cobertura |
| :--- | :--- | :--- | :--- | :--- | :--- |
| HASH-01 | Hash de archivo | `06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec` | **MALICIOSO/INFECTADO** | Media | 1/1 consultas de reputación con informe evaluable |
| HASH-02 | Hash de archivo | `6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba` | **MALICIOSO/INFECTADO** | Media | 1/1 consultas de reputación con informe evaluable |

### HASH-01 — Hash de archivo: `06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec`
- **Veredicto:** MALICIOSO/INFECTADO (Media)
- **Amenaza:** La fuente externa marca el indicador; familia y comportamiento requieren evidencia específica.
- **Cobertura:** 1/1 consultas de reputación con informe evaluable
- **Evidencia y observaciones:**
  - SHA-256 suministrado manualmente. No se leyó ningún archivo ni se comprobó su contenido localmente.
  - VirusTotal: 47 maliciosa(s), 0 sospechosa(s), 0 inocua(s), 22 sin opinión/detección. Fecha del análisis (epoch UTC): 1792049797.
  - Primera observación en VirusTotal (UTC): 2026-10-12T01:38:16+00:00.
  - Última observación en VirusTotal (UTC): 2026-10-12T01:38:16+00:00.
  - Último análisis en VirusTotal (UTC): 2026-10-15T07:36:37+00:00.
  - Tipo informado por VirusTotal: Win32 EXE.
  - Tamaño informado por VirusTotal (bytes): 1559216.
  - Nombre destacado en VirusTotal: Setup64.exe.
  - Nombres observados en VirusTotal: 06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec.exe, Setup64.exe, 0jtzym5.exe, WinCombo.exe, wincombo.exe, rfc7f8u.exe.
  - Motor Bkav: malicious; etiqueta informada: W32.Malware.D21A217D.
  - Motor Lionic: malicious; etiqueta informada: Trojan.Win32.Valley.m\!c.
  - Motor MicroWorld-eScan: malicious; etiqueta informada: Trojan.Generic.40652856.
  - Motor CTX: malicious; etiqueta informada: exe.trojan.generic.
  - Motor ALYac: malicious; etiqueta informada: Trojan.Generic.40652856.
  - Motor Cylance: malicious; etiqueta informada: Unsafe.
  - Motor VIPRE: malicious; etiqueta informada: Trojan.Generic.40652856.
  - Motor Sangfor: malicious; etiqueta informada: Backdoor.Win32.Valley.V5wn.
  - Motor K7AntiVirus: malicious; etiqueta informada: Backdoor ( 006e8e661 ).
  - Motor BitDefender: malicious; etiqueta informada: Trojan.Generic.40652856.
  - Resumen histórico de sandbox informado por VirusTotal (C2AE): malicious; STEALER, MALWARE, KeyloggerGeneric, PEguise. No se solicitó una nueva ejecución ni incluye necesariamente procesos/conexiones.
  - Resumen histórico de sandbox informado por VirusTotal (Zenbox): malicious; MALWARE, TROJAN, EVADER, RAT, ValleyRAT. No se solicitó una nueva ejecución ni incluye necesariamente procesos/conexiones.
  - Resumen histórico de sandbox informado por VirusTotal (VMRay): malicious; MALWARE, ValleyRAT, App/Generic-PH, Mal/Generic-S. No se solicitó una nueva ejecución ni incluye necesariamente procesos/conexiones.
  - Resumen histórico de sandbox informado por VirusTotal (Yomi Hunter): malicious; MALWARE. No se solicitó una nueva ejecución ni incluye necesariamente procesos/conexiones.
  - VirusTotal informa 47 detecciones maliciosas; supera el umbral heurístico local de 3 motores. Requiere revisión humana y no prueba infección del equipo.
- **Impacto potencial C-I-A:**
  - **Confidencialidad:** Impacto potencial sujeto al comportamiento confirmado; no inferido por tipo o extensión.
  - **Integridad:** Impacto potencial sujeto al comportamiento confirmado; no inferido por tipo o extensión.
  - **Disponibilidad:** Impacto potencial sujeto al comportamiento confirmado; no inferido por tipo o extensión.
- **Medida para el usuario:** No ejecutar ni abrir la muestra; conservarla aislada y registrar su SHA-256.
- **Control para la organización:** Bloquear el hash si la evidencia lo confirma; buscar equipos afectados y activar respuesta a incidentes según corresponda.

### HASH-02 — Hash de archivo: `6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba`
- **Veredicto:** MALICIOSO/INFECTADO (Media)
- **Amenaza:** La fuente externa marca el indicador; familia y comportamiento requieren evidencia específica.
- **Cobertura:** 1/1 consultas de reputación con informe evaluable
- **Evidencia y observaciones:**
  - SHA-256 suministrado manualmente. No se leyó ningún archivo ni se comprobó su contenido localmente.
  - VirusTotal: 47 maliciosa(s), 0 sospechosa(s), 0 inocua(s), 21 sin opinión/detección. Fecha del análisis (epoch UTC): 1792674948.
  - Primera observación en VirusTotal (UTC): 2026-10-14T07:02:51+00:00.
  - Última observación en VirusTotal (UTC): 2026-10-14T12:08:18+00:00.
  - Último análisis en VirusTotal (UTC): 2026-10-22T13:15:48+00:00.
  - Tipo informado por VirusTotal: Win32 DLL.
  - Tamaño informado por VirusTotal (bytes): 2264968.
  - Nombre destacado en VirusTotal: Setup64.exe.
  - Nombres observados en VirusTotal: Setup64.exe, 6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba.exe, libPdfCore.dll, gnps7ej.exe, hx8sh.exe.
  - Motor Lionic: malicious; etiqueta informada: Trojan.Win32.Xkcp.m\!c.
  - Motor Elastic: malicious; etiqueta informada: malicious (high confidence).
  - Motor MicroWorld-eScan: malicious; etiqueta informada: Application.Generic.37102404.
  - Motor CTX: malicious; etiqueta informada: dll.trojan.malwarex.
  - Motor CAT-QuickHeal: malicious; etiqueta informada: Hacktool.Agent.
  - Motor ALYac: malicious; etiqueta informada: Application.Generic.37102404.
  - Motor Malwarebytes: malicious; etiqueta informada: Trojan.ShellCode.
  - Motor VIPRE: malicious; etiqueta informada: Application.Generic.37102404.
  - Motor Sangfor: malicious; etiqueta informada: Trojan.Win32.Save.a.
  - Motor K7AntiVirus: malicious; etiqueta informada: Hacktool ( 005ce32e1 ).
  - Resumen histórico de sandbox informado por VirusTotal (Zenbox): malicious; MALWARE, EVADER. No se solicitó una nueva ejecución ni incluye necesariamente procesos/conexiones.
  - Resumen histórico de sandbox informado por VirusTotal (C2AE): undetected; UNKNOWN\_VERDICT. No se solicitó una nueva ejecución ni incluye necesariamente procesos/conexiones.
  - Resumen histórico de sandbox informado por VirusTotal (VMRay): malicious; MALWARE, ValleyRAT, App/Generic-IH, App/Generic-MB. No se solicitó una nueva ejecución ni incluye necesariamente procesos/conexiones.
  - VirusTotal informa 47 detecciones maliciosas; supera el umbral heurístico local de 3 motores. Requiere revisión humana y no prueba infección del equipo.
- **Impacto potencial C-I-A:**
  - **Confidencialidad:** Impacto potencial sujeto al comportamiento confirmado; no inferido por tipo o extensión.
  - **Integridad:** Impacto potencial sujeto al comportamiento confirmado; no inferido por tipo o extensión.
  - **Disponibilidad:** Impacto potencial sujeto al comportamiento confirmado; no inferido por tipo o extensión.
- **Medida para el usuario:** No ejecutar ni abrir la muestra; conservarla aislada y registrar su SHA-256.
- **Control para la organización:** Bloquear el hash si la evidencia lo confirma; buscar equipos afectados y activar respuesta a incidentes según corresponda.

### Alcance de la clasificación
La herramienta no emite `LIMPIO` automáticamente: la ausencia de alertas necesita corroboración de autenticidad, contexto y comportamiento. `SOSPECHOSO` indica señales concretas que requieren corroboración. `EVIDENCIA INSUFICIENTE` es un estado pendiente de análisis y revisión humana antes de la entrega académica. `MALICIOSO/INFECTADO` es triage por reputación: umbral heurístico local de 3 motores VirusTotal o un veredicto explícito de urlscan sobre el recurso exacto. No demuestra ejecución, infección del equipo ni familia de malware. Los reportes son históricos; revisar sus fechas y pertinencia.

---
*Informe forense generado por Phishing Lab.*