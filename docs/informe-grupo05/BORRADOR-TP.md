# TP Grupo 05 — borrador de análisis con evidencias

Estado: revisados los siete recursos principales (dos binarios, dos correos y tres URLs). Los límites y verificaciones pendientes siguen señalados; no se presenta como cumplimiento completo de la consigna.

## Método y resultados propuestos

Análisis estático en VM aislada sin red. No se ejecutó ninguna muestra ni se solicitaron nuevos escaneos. Las consultas externas enviaron únicamente indicadores a informes existentes y fuentes públicas. Las capturas de sitios corresponden a imágenes históricas de urlscan, no a visitas actuales. Se distinguen evidencia local, reputación de terceros e hipótesis.

| Recurso | Clasificación propuesta | Evidencia principal |
| :--- | :--- | :--- |
| F001 | Malicioso | Identidad por tres hashes/tamaño, 47 motores y tipo DLL |
| F002 | Malicioso | Identidad por tres hashes/tamaño, 47 motores y tipo EXE |
| R004 | Sospechoso | Cabeceras, Reply-To distinto y enlaces con alertas |
| R005 | Sospechoso | Cabeceras y dominio de enlaces con alertas |
| U001 | Sospechoso | 2 alertas de phishing y página histórica de orientación CPF con enlace externo |
| U002 | Malicioso | URL con alertas, descarga ELF MIPS histórica, hash y tamaño coincidentes y 50 motores |
| U003 | Sospechoso | Alertas de URL/dominio, histórico de dominio aparcado; sin fraude confirmado |

[Índice de evidencias y pendientes](INDICE-EVIDENCIAS.md). [Registro de capturas](capturas/registro-capturas.json). [Inventario estático inicial](primarios/vm/grupo05-inventario-estatico.json).

Los binarios F001/F002 son independientes de los correos, que no tienen adjuntos. El ELF asociado a U002 es información de una descarga histórica de terceros: no fue descargado en nuestro entorno ni es uno de los PE del ZIP.

# Grupo 05 — fichas de los archivos Windows

## Procedimiento y alcance

Huellas y tipo estático calculados previamente dentro de la VM sin red. El 23/10/2026 se consultaron desde el host únicamente los dos SHA-256 mediante GET de informes existentes de VirusTotal. No se subieron binarios, no se ejecutaron muestras y no se solicitaron análisis nuevos. Los resúmenes históricos de terceros no son observaciones propias de comportamiento.

Fuentes conservadas: [respuesta y estados de API](archivos-reputacion.json), [informe automático](archivos-reputacion.md) e inventario local `/home/fran/VMs/ciberseguridad-minima/grupo05-archivos-estaticos.json`.

Los identificadores HASH-01/HASH-02 del informe automático se ordenan por hash: HASH-01 corresponde a F002; HASH-02, a F001. Estas fichas conservan los identificadores del inventario para evitar confusiones.

## F001 — file_1.zip

**Clasificación propuesta: MALICIOSO. Confianza: alta en la reputación maliciosa; atribución de familia y comportamiento pendiente de corroboración.** La confianza es una revisión de estas evidencias; la herramienta automática conserva su nivel genérico Media.

- SHA-256: `6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba`.
- MD5: `cd22bb73046551dfbafcc7f4c3ed505f`.
- SHA-1: `87b79ae55a56acde041fb7ee0677b89d967ec851`.
- Tamaño local y en VirusTotal: 2264968 bytes.
- Tipo estático local: PE32+ executable for MS Windows 6.00 (DLL), x86-64, 7 sections.
- Tipo informado por VirusTotal: Win32 DLL.
- Consulta (UTC): 2026-10-23T17:30:49+00:00.
- Primera observación en VirusTotal (UTC): 2026-10-14T07:02:51+00:00.
- Último análisis existente (UTC): 2026-10-22T13:15:48+00:00.
- Estadísticas conservadas: {"malicious": 47, "suspicious": 0, "undetected": 21, "harmless": 0, "timeout": 1, "confirmed-timeout": 0, "failure": 2, "type-unsupported": 4}.

Fundamento: las tres huellas y el tamaño del inventario coinciden con el objeto de VirusTotal; 47 motores lo señalan como malicioso. No se toma el total de motores como una votación independiente ni se interpreta undetected como limpio. Primera observación en VirusTotal no equivale a fecha de creación del archivo.

El formato DLL coincide entre la firma local y VirusTotal, pese al sufijo original `.exe`. Es un dato de formato; por sí solo no prueba intención maliciosa. Entre los nombres históricos figuran `Setup64.exe` y `libPdfCore.dll`. Las etiquetas incluyen Trojan.ShellCode y troyanos genéricos; VMRay informa ValleyRAT en su resumen histórico. Otros resúmenes discrepan: C2AE registra undetected/UNKNOWN_VERDICT. No se afirma una familia única confirmada.

**Impacto C-I-A potencial:** las etiquetas de troyano/acceso remoto respaldan como hipótesis un riesgo para confidencialidad (acceso a información) e integridad (alteraciones no autorizadas). No se observaron esas acciones. El impacto concreto sobre disponibilidad queda sin determinar; no hay evidencia aquí para afirmar cifrado, borrado o interrupción.

**Medida para el usuario:** mantener aislado, no abrir ni ejecutar, y reportar su procedencia. **Control organizacional propuesto:** bloquear estas huellas mediante EDR/antimalware cuando esté disponible y buscar coincidencias en telemetría. Una coincidencia o posible ejecución requeriría evaluación de respuesta a incidentes; poseer el ZIP no demuestra infección.

[Informe existente de VirusTotal](https://www.virustotal.com/gui/file/6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba)

## F002 — file_2.zip

**Clasificación propuesta: MALICIOSO. Confianza: alta en la reputación maliciosa; atribución de familia y comportamiento pendiente de corroboración.** La confianza es una revisión de estas evidencias; la herramienta automática conserva su nivel genérico Media.

- SHA-256: `06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec`.
- MD5: `104c9a1a490d8c05966f46bbbc62028d`.
- SHA-1: `b958aa7bd82263c37a9c520ef277db3f95fc1369`.
- Tamaño local y en VirusTotal: 1559216 bytes.
- Tipo estático local: PE32+ executable for MS Windows 6.00 (GUI), x86-64, 7 sections.
- Tipo informado por VirusTotal: Win32 EXE.
- Consulta (UTC): 2026-10-23T17:30:49+00:00.
- Primera observación en VirusTotal (UTC): 2026-10-12T01:38:16+00:00.
- Último análisis existente (UTC): 2026-10-15T07:36:37+00:00.
- Estadísticas conservadas: {"malicious": 47, "suspicious": 0, "undetected": 22, "harmless": 0, "timeout": 0, "confirmed-timeout": 0, "failure": 2, "type-unsupported": 4}.

Fundamento: las tres huellas y el tamaño del inventario coinciden con el objeto de VirusTotal; 47 motores lo señalan como malicioso. No se toma el total de motores como una votación independiente ni se interpreta undetected como limpio. Primera observación en VirusTotal no equivale a fecha de creación del archivo.

Entre los nombres históricos figuran `Setup64.exe` y `WinCombo.exe`. Motores y resúmenes históricos informan etiquetas de troyano, backdoor y ValleyRAT; algunos también informan stealer/keylogger. Estas son atribuciones de terceros, no capacidades verificadas localmente.

**Impacto C-I-A potencial:** las etiquetas de troyano/acceso remoto respaldan como hipótesis un riesgo para confidencialidad (acceso a información) e integridad (alteraciones no autorizadas). No se observaron esas acciones. El impacto concreto sobre disponibilidad queda sin determinar; no hay evidencia aquí para afirmar cifrado, borrado o interrupción.

**Medida para el usuario:** mantener aislado, no abrir ni ejecutar, y reportar su procedencia. **Control organizacional propuesto:** bloquear estas huellas mediante EDR/antimalware cuando esté disponible y buscar coincidencias en telemetría. Una coincidencia o posible ejecución requeriría evaluación de respuesta a incidentes; poseer el ZIP no demuestra infección.

[Informe existente de VirusTotal](https://www.virustotal.com/gui/file/06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec)

## Evidencia pendiente

No se ejecutarán las muestras. Quedan pendientes detalles estáticos adicionales pertinentes y, si el TP exige procesos/conexiones, evidencia documental existente de terceros: los resúmenes recuperados no incluyen ese detalle. Los correos y las tres URLs todavía requieren fichas separadas. Estas fichas no completan todo el TP.

## Evidencia visual incorporada

Las imágenes se capturaron después de las consultas API. La fecha del último análisis del proveedor no es la fecha de captura. Los JSON y registros originales se conservan como fuente de detalle. [Registro de capturas](capturas/registro-capturas.json).

### F001

**F001-virustotal-detecciones.jpg** — captura externa real. Captura UTC: 2026-10-23T17:43:03.381326+00:00.

![F001-virustotal-detecciones.jpg](capturas/F001-virustotal-detecciones.jpg)

**F001-virustotal-propiedades.jpg** — captura externa real. Captura UTC: 2026-10-23T17:43:22.805301+00:00.

![F001-virustotal-propiedades.jpg](capturas/F001-virustotal-propiedades.jpg)

### F002

**F002-virustotal-detecciones.jpg** — captura externa real. Captura UTC: 2026-10-23T17:43:52.974256+00:00.

![F002-virustotal-detecciones.jpg](capturas/F002-virustotal-detecciones.jpg)

**Fechas y nombres observados** — captura externa real. Captura UTC: 2026-10-23T17:51:34.953140+00:00.

![Fechas y nombres observados](capturas/F002-virustotal-historial.jpg)

**Huellas, tipo, tamaño y fechas** — captura externa real. Captura UTC: 2026-10-23T17:51:43.833273+00:00.

![Huellas, tipo, tamaño y fechas](capturas/F002-virustotal-propiedades.jpg)


# Grupo 05 — fichas de correos

## Procedimiento y límites

Análisis estático dentro de la VM aislada sin red. No se ejecutaron muestras ni se renderizó HTML, cargaron imágenes, abrieron enlaces o solicitaron nuevos escaneos. MIME/quoted-printable se decodificó como datos. Se exportaron texto, cabeceras, estructura y hashes; no los EML completos ni binarios. La integridad de la exportación por consola se comprobó con SHA-256.

El parser instalado en la VM informa versión 1.1.0; no se atribuye este análisis local a la versión 1.2.0 del host. Las tres huellas de cada EML se toman del inventario estático previo y el SHA-256 se volvió a contrastar. Los resúmenes HTML son extracción de etiquetas/texto, no capturas de cómo se verían los mensajes.

Las cabeceras Authentication-Results y Received son declaraciones del archivo cuya confianza de origen no se ha establecido. No se revalidaron firmas DKIM ni SPF contra DNS histórico. Los registros DNS actuales no reconstruyen necesariamente la autenticación de julio. Los campos pass/none se transcriben sin convertir none en fail.

Para DMARC se distingue autenticación de alineación: un DKIM pass de otro dominio no basta para validar el dominio From; SPF aprobado y alineado puede respaldar DMARC. El análisis de contenido está fuera del alcance de DMARC. Referencia técnica: [RFC 9989, secciones 2.2 y 4.4](https://www.rfc-editor.org/rfc/rfc9989.html).

Evidencias: [análisis estático](correos-estaticos.json), [estructura HTML](correos-html-resumen.json), [reputación de remitentes/IP](correos-reputacion.json), [reputación de enlaces](enlaces-correo-reputacion.json). Los indicadores de este documento se muestran neutralizados.

## R004 — sample-10070.eml

**Clasificación propuesta: SOSPECHOSO. Confianza: media.** No hay evidencia suficiente para atribuir robo de credenciales, entrega de malware o infección del destinatario.

- Asunto: `Say goodbye to sharp, stabbing pains today!`.
- SHA-256: `511e3e59b9ca1947df591e15da12aed9813b811ace03e7a28aa70e116de878e4`.
- MD5: `6f67d861f68328504fc8fe10859dde98`.
- SHA-1: `f3896d7ef15586eabc1d5f99e41104a6ff096e8f`.
- Tamaño: 12294 bytes.
- From: `Knee Relief Alert <renewzl429@ginnybedellphotography[.]com>`.
- Return-Path: `renewlljwzs@ginnybedellphotography[.]com`.
- Reply-To: `replyto@brendamurphyrealestate[.]com`.
- Fecha declarada: `Thu, 02 Jul 2026 17:08:05 +0000`.
- Adjuntos: 0. No corresponde análisis de macros de adjuntos en estos mensajes.

### Autenticación y transporte

Declaración literal: `spf=pass (sender IP is 20[.]169[.]217[.]199) smtp[.]mailfrom=ginnybedellphotography[.]com; dkim=pass (signature was verified) header[.]d=associationlienservices[.]com;dmarc=pass action=none header[.]from=ginnybedellphotography[.]com;compauth=pass reason=100`.

From y Return-Path comparten dominio: la alineación SPF declarada es compatible con el DMARC pass incluido. El dominio DKIM `associationlienservices[.]com` difiere del From: esa firma por sí sola no está alineada. Reply-To usa `brendamurphyrealestate[.]com`, un tercer dominio; el enlace mailto de baja apunta además a `vresan[.]com`. Son diferencias que requieren contexto, no prueba autónoma de suplantación.

El salto público de entrada a protección de correo declara `20[.]169[.]217[.]199` con HELO `associationlienservices[.]com`. Es la IP de entrega observada en la cadena, no una identificación del autor. Los saltos posteriores declaran infraestructura Outlook. El encabezado Date es del 2 de julio y Received del 6 de julio: se registra la diferencia sin inferir su causa.

### Contenido y señales

Promoción de alivio de dolor de rodilla que invoca a un investigador de Harvard; esa afirmación no fue verificada. Incluye dos destinos acortados de shorturl y un recurso de imagen de 1×1 píxeles en `pnreap[.]com`, compatible con seguimiento de apertura. No se cargó. Las dos URLs acortadas tienen dos alertas maliciosas cada una en la consulta guardada; no se confirmó su destino final. La combinación respalda sospecha de spam o contenido engañoso, no una familia de malware.

### Reputación consultada

- VirusTotal / `ginnybedellphotography[.]com`: **found**; 1 maliciosos, 0 sospechosos, 53 harmless, 38 undetected; alertas Chong Lua Dao: malicious; fecha del análisis guardado (epoch UTC): 1791795871. Consulta UTC: 2026-10-23T17:36:30+00:00.
- VirusTotal / `20[.]169[.]217[.]199`: **found**; 0 maliciosos, 0 sospechosos, 0 harmless, 92 undetected; fecha del análisis guardado (epoch UTC): 1792191711. Consulta UTC: 2026-10-23T17:36:47+00:00.
- VirusTotal / `hxxps://shorturl[.]at/zEbf9`: **found**; 2 maliciosos, 0 sospechosos, 60 harmless, 31 undetected; alertas Chong Lua Dao: malicious; SafeToOpen: phishing; fecha del análisis guardado (epoch UTC): 1792191681. Consulta UTC: 2026-10-23T17:37:50+00:00.
- urlscan.io / `hxxps://shorturl[.]at/zEbf9`: **no_results**; resultados históricos devueltos: 0. Consulta UTC: 2026-10-23T17:37:51+00:00.
- VirusTotal / `hxxps://shorturl[.]at/8IYrs`: **found**; 2 maliciosos, 0 sospechosos, 59 harmless, 32 undetected; alertas Chong Lua Dao: malicious; SafeToOpen: phishing; fecha del análisis guardado (epoch UTC): 1792191681. Consulta UTC: 2026-10-23T17:38:08+00:00.
- urlscan.io / `hxxps://shorturl[.]at/8IYrs`: **no_results**; resultados históricos devueltos: 0. Consulta UTC: 2026-10-23T17:38:09+00:00.

La reputación actual de una IP de infraestructura compartida no califica el mensaje como limpio. no_results no significa dominio inexistente ni inocuo; undetected no representa un resultado de seguridad afirmativo. Se conserva la cobertura de los motores de VirusTotal; la consulta dedicada posterior de MXToolbox se documenta en la actualización de cierre. Las respuestas históricas de urlscan no prueban cómo se comportan hoy todos los enlaces.

### Impacto y medidas

**Confidencialidad:** riesgo potencial de seguimiento y de revelar datos al responder/interactuar. No se observó exfiltración. **Integridad:** no se observaron cambios; un posible engaño que induzca acciones del usuario requiere más evidencia. **Disponibilidad:** sin impacto demostrado.

**Medida para el usuario:** no interactuar, no cargar imágenes remotas ni usar enlaces de baja del mensaje; reportarlo como sospechoso. **Control organizacional propuesto:** filtrar spam/enlaces, revisar autenticación y alineación con otras señales, desactivar carga automática de recursos remotos cuando corresponda y revisar mensajes similares. No bloquear rangos enteros de proveedores compartidos por este caso.

## R005 — sample-10071.eml

**Clasificación propuesta: SOSPECHOSO. Confianza: media.** No hay evidencia suficiente para atribuir robo de credenciales, entrega de malware o infección del destinatario.

- Asunto: `100 Balls[.] $5 No Deposit Required !`.
- SHA-256: `43cbe639b7ce04294b5f11ef5daf2a5acf8d7b5e2a057fe699e071251a4f0fb8`.
- MD5: `09831e7fb7b600104d0c3a6aae054379`.
- SHA-1: `114537dded5d8ada673a8efef5de874a846064a1`.
- Tamaño: 465737 bytes.
- From: `free spin <taylor[.]flores@ezagameroasin02[.]onmicrosoft[.]com>`.
- Return-Path: `taylor[.]flores@ezagameroasin02[.]onmicrosoft[.]com`.
- Reply-To: ausente.
- Fecha declarada: `Mon, 06 Jul 2026 15:53:28 -0700`.
- Adjuntos: 0. No corresponde análisis de macros de adjuntos en estos mensajes.

### Autenticación y transporte

Declaración literal: `spf=none (sender IP is 209[.]85[.]167[.]46) smtp[.]mailfrom=ezagameroasin02[.]onmicrosoft[.]com; dkim=pass (signature was verified) header[.]d=ezagameroasin02-onmicrosoft-com[.]20251104[.]gappssmtp[.]com;dmarc=none action=none header[.]from=ezagameroasin02[.]onmicrosoft[.]com;`.

From y Return-Path comparten `ezagameroasin02[.]onmicrosoft[.]com`. La cabecera declara SPF none y DMARC none; eso no equivale a fail. DKIM figura pass con `d=ezagameroasin02-onmicrosoft-com[.]20251104[.]gappssmtp[.]com`, distinto del dominio From; no hay alineación DKIM visible para ese From.

La IP pública de entrega a protección de correo es `209[.]85[.]167[.]46`, con nombre declarado `mail-lf1-f46[.]google[.]com`. También hay líneas que mencionan gmailapi/HTTPREST; no identifican una IP original del usuario. No se atribuye el envío a Google ni Microsoft como autores por usar su infraestructura.

### Contenido y señales

Promoción de Plinko con promesa de premios de hasta un millón de dólares y oferta de 100 bolas por 5 dólares. El HTML contiene gran cantidad de texto alfanumérico largo y al menos un elemento con display:none; se registra como relleno/ocultamiento, sin afirmar que sea un programa o una carga ejecutable. Los tres enlaces de acción/baja apuntan a `woondsplay[.]com`. Hay una imagen 1×1 en ese dominio compatible con seguimiento. Otro src contiene el destinatario antes de @: no se consultó ni cargó esa URL.

La falta de autenticación alineada declarada, la oferta y los enlaces externos justifican cautela. No se verificó un formulario de credenciales ni un pago real; no se afirma phishing confirmado.

### Reputación consultada

- VirusTotal / `ezagameroasin02[.]onmicrosoft[.]com`: **no_results**. Consulta UTC: 2026-10-23T17:37:04+00:00.
- VirusTotal / `209[.]85[.]167[.]46`: **found**; 0 maliciosos, 0 sospechosos, 56 harmless, 36 undetected; fecha del análisis guardado (epoch UTC): 1792767412. Consulta UTC: 2026-10-23T17:37:21+00:00.
- VirusTotal / `woondsplay[.]com`: **found**; 7 maliciosos, 2 sospechosos, 50 harmless, 33 undetected; alertas alphaMountain[.]ai: phishing; Bkav: malicious; CRDF: malicious; ESET: suspicious; Forcepoint ThreatSeeker: spam; Fortinet: phishing; Seclookup: malicious; SOCRadar: malicious; Webroot: malicious; fecha del análisis guardado (epoch UTC): 1792750493. Consulta UTC: 2026-10-23T17:38:25+00:00.
- urlscan.io / `woondsplay[.]com`: **no_results**; resultados históricos devueltos: 0. Consulta UTC: 2026-10-23T17:38:26+00:00.

La reputación actual de una IP de infraestructura compartida no califica el mensaje como limpio. no_results no significa dominio inexistente ni inocuo; undetected no representa un resultado de seguridad afirmativo. Se conserva la cobertura de los motores de VirusTotal; la consulta dedicada posterior de MXToolbox se documenta en la actualización de cierre. Las respuestas históricas de urlscan no prueban cómo se comportan hoy todos los enlaces.

### Impacto y medidas

**Confidencialidad:** riesgo potencial de seguimiento y de revelar datos al responder/interactuar. No se observó exfiltración. **Integridad:** no se observaron cambios; un posible engaño que induzca acciones del usuario requiere más evidencia. **Disponibilidad:** sin impacto demostrado.

**Medida para el usuario:** no interactuar, no cargar imágenes remotas ni usar enlaces de baja del mensaje; reportarlo como sospechoso. **Control organizacional propuesto:** filtrar spam/enlaces, revisar autenticación y alineación con otras señales, desactivar carga automática de recursos remotos cuando corresponda y revisar mensajes similares. No bloquear rangos enteros de proveedores compartidos por este caso.

## Pendientes para la entrega

Resolver destino final/redirecciones con evidencia histórica disponible, revisar capturas o reportes detallados existentes si los hay y documentar las listas antispam que se consulten. No se solicitarán nuevos escaneos ni se visitarán los enlaces. Siguen pendientes las fichas independientes de las tres URLs de url.txt. Los dos binarios independientes F001/F002 no se atribuyen a estos correos, ya que ninguno contiene adjuntos.

## Evidencia visual incorporada

Las imágenes se capturaron después de las consultas API. La fecha del último análisis del proveedor no es la fecha de captura. Los JSON y registros originales se conservan como fuente de detalle. [Registro de capturas](capturas/registro-capturas.json).

### R004

**R004-cabeceras-local.jpg** — captura de vista local derivada. Captura UTC: 2026-10-23T17:52:53.927069+00:00.

![R004-cabeceras-local.jpg](capturas/R004-cabeceras-local.jpg)

**R004-consultas-local-continuacion.jpg** — captura de vista local derivada. Captura UTC: 2026-10-23T17:53:40.365556+00:00.

![R004-consultas-local-continuacion.jpg](capturas/R004-consultas-local-continuacion.jpg)

**R004-consultas-local.jpg** — captura de vista local derivada. Captura UTC: 2026-10-23T17:53:16.610290+00:00.

![R004-consultas-local.jpg](capturas/R004-consultas-local.jpg)

**Primer enlace acortado: dos alertas** — captura externa real. Captura UTC: 2026-10-23T17:53:14.370364+00:00.

![Primer enlace acortado: dos alertas](capturas/R004-enlace-1-virustotal.jpg)

**Segundo enlace acortado: dos alertas** — captura externa real. Captura UTC: 2026-10-23T17:53:37.833630+00:00.

![Segundo enlace acortado: dos alertas](capturas/R004-enlace-2-virustotal.jpg)

**IP de entrega; sin detecciones, no demuestra legitimidad** — captura externa real. Captura UTC: 2026-10-23T17:54:44.635928+00:00.

![IP de entrega; sin detecciones, no demuestra legitimidad](capturas/R004-ip-entrega-virustotal.jpg)

**R004-mime-enlaces-local.jpg** — captura de vista local derivada. Captura UTC: 2026-10-23T17:52:54.555047+00:00.

![R004-mime-enlaces-local.jpg](capturas/R004-mime-enlaces-local.jpg)

**Reputación del dominio remitente: una detección** — captura externa real. Captura UTC: 2026-10-23T17:54:12.524680+00:00.

![Reputación del dominio remitente: una detección](capturas/R004-remitente-virustotal.jpg)

### R005

**R005-cabeceras-local.jpg** — captura de vista local derivada. Captura UTC: 2026-10-23T17:52:54.283056+00:00.

![R005-cabeceras-local.jpg](capturas/R005-cabeceras-local.jpg)

**R005-consultas-local.jpg** — captura de vista local derivada. Captura UTC: 2026-10-23T17:53:16.982278+00:00.

![R005-consultas-local.jpg](capturas/R005-consultas-local.jpg)

**Dominio de los enlaces: detecciones maliciosas y sospechosas** — captura externa real. Captura UTC: 2026-10-23T17:52:33.487842+00:00.

![Dominio de los enlaces: detecciones maliciosas y sospechosas](capturas/R005-dominio-enlaces-virustotal.jpg)

**IP de entrega; sin detecciones, no demuestra legitimidad** — captura externa real. Captura UTC: 2026-10-23T18:03:46.849621+00:00.

![IP de entrega; sin detecciones, no demuestra legitimidad](capturas/R005-ip-entrega-virustotal.jpg)

**R005-mime-enlaces-local.jpg** — captura de vista local derivada. Captura UTC: 2026-10-23T17:52:54.823037+00:00.

![R005-mime-enlaces-local.jpg](capturas/R005-mime-enlaces-local.jpg)

### Precisiones y límites de evidencia

Las vistas locales muestran campos de los JSON preservados; no son nuevas verificaciones de autenticación ni capturas de los EML abiertos. El texto From/Return-Path/Reply-To y Authentication-Results sigue disponible completo en correos-estaticos.json. Las vistas no contienen el cuerpo HTML original ni recursos remotos.

En los dos enlaces acortados, el informe guardado de VirusTotal registra redirection_chain desde shorturl[.]at a www[.]shorturl[.]at, con last_http_response_code 200. Eso respalda únicamente el salto histórico al subdominio www; no permite afirmar que se haya identificado el destino malicioso final de la campaña.

Las imágenes de las IP también muestran referencias a archivos que contienen esas IP: esa relación no demuestra autoría, infección ni maliciosidad de los mensajes. La ausencia de resultados de urlscan y del dominio remitente de R005 está respaldada por las respuestas originales y sus vistas locales; no se sustituye por una pantalla externa inventada.

Persisten como pendientes analíticos la verificación independiente de autenticación y comportamiento/destino final de los enlaces. No se presentan como tareas completadas.

## Actualización de cierre — listas antispam y búsqueda exacta

Se completó la consulta dedicada en MXToolbox para las dos IP públicas de entrega: R004 / 20[.]169[.]217[.]199, 0 listados y 1 timeout entre 60 listas; R005 / 209[.]85[.]167[.]46, 0 listados y 0 timeouts entre 60 listas. Es el resultado de la consulta actual, no una reconstrucción de julio ni prueba de legitimidad del mensaje. No se interpreta el timeout como resultado negativo.

[Registro de adquisición](cierre/mxtoolbox-adquisicion.json), [salida textual R004](cierre/R004-mxtoolbox-texto.txt), [salida textual R005](cierre/R005-mxtoolbox-texto.txt). Las salidas de texto son extracciones del árbol accesible del navegador, no respuestas de una API de MXToolbox. Se omitió en el texto el pie «Your IP» del equipo consultante.

![MXToolbox R004](capturas/R004-mxtoolbox-blacklist.jpg)

![MXToolbox R005](capturas/R005-mxtoolbox-blacklist.jpg)

Se repitieron las búsquedas de los cinco enlaces HTTP(S) de correo con `task.url.keyword`, conservando la URL exacta. Ninguna devolvió resultados en esta adquisición. [Respuestas completas de la revisión](cierre/urlscan-correo-revision-exacta.json). Se preservaron las búsquedas iniciales para documentar el cambio de campo; no se concluye que jamás haya existido un escaneo o que el enlace sea inocuo.

La revisión no modifica las clasificaciones propuestas de los correos: SOSPECHOSO con confianza media. El destino posterior de las URLs acortadas y la autenticidad histórica independiente siguen sin confirmarse.


# Grupo 05 — fichas de las tres URLs

## Alcance y procedencia

Las tres URLs provienen de R006 / url.txt, SHA-256 `972f6f2322a6bce4e1adfdfea8fde8d0d76f357a8855c064e8cc0c734cd91125`. Se consultaron informes y datos públicos existentes; no se visitaron destinos sospechosos, descargaron cargas ni solicitaron escaneos nuevos. Las IP, HTTP y contenidos históricos son observaciones de terceros del 16/10/2026, distintas del estado DNS/registral consultado el 23/10/2026.

Las búsquedas exactas con canonical.page.url no devolvieron resultados. Se amplió al host/IP y se seleccionaron localmente únicamente task.url idénticos a la URL del recurso. No se atribuyen al recurso los resultados de otras rutas de la misma IP. Se conserva la búsqueda vacía y la ampliada. La ausencia inicial no demuestra ausencia de históricos. El detalle U001 sin clave respondió 403; una consulta posterior autenticada tuvo éxito.

Los veredictos urlscan son discordantes: overall.malicious=false y urlscan.hasVerdicts=false en los tres reportes; el bloque engines informa malicious=true para U001/U003 y false para U002. Se preservan todas las señales y no se traduce false/sin clasificación a limpio. Las detecciones de VT no son votos estadísticamente independientes.

[Resumen normalizado con referencias](urls/20261023T180740Z/resumen-normalizado.json). [Registro de capturas](capturas/registro-capturas.json).

## U001 — `hxxps://g-comeceseuatendimenton[.]shop/`

**Clasificación propuesta: SOSPECHOSO. Confianza: Media.**

Fuentes: [consultas originales](urls/20261023T180740Z/U001.json), [informe detallado histórico](urls/20261023T180740Z/U001-urlscan-detalle-autenticado-01a1462b-bbda-773d-a9b2-fa0511ed4b52.json). Adquisición UTC: 2026-10-23T18:07:40.710075+00:00.

### Reputación y observación histórica

- VT de la URL exacta: {"malicious": 2, "suspicious": 0, "undetected": 36, "harmless": 55, "timeout": 0}. Último análisis UTC: 2026-10-16T20:33:02+00:00.
- Etiquetas de motores: `ESET: phishing`, `LevelBlue: phishing`.
- urlscan: 2026-10-16T19:24:00.159Z; título `Consulta de Informações Financeiras`; IP `88[.]80[.]17[.]232`; país informado SE; HTTP 200. La geolocalización no identifica al operador.
- Dominios contactados por el escaneo: `g-comeceseuatendimenton[.]shop`, `fonts[.]gstatic[.]com`, `ipapi[.]co`, `fonts[.]googleapis[.]com`. No implica que todos sean maliciosos.
- Redirecciones: lista vacía en el detalle urlscan; VT informa URL final `hxxps://g-comeceseuatendimenton[.]shop/`. Esto describe esos reportes, no garantiza ausencia de redirecciones en otro momento.

La captura archivada muestra una oferta de orientación sobre información de CPF con temporizador y botón “Acessar orientações”. Incluye avisos de contenido educativo y de no ser institución financiera; esas afirmaciones pertenecen al sitio y no se validaron. No se observa en esa captura un formulario para introducir credenciales. El detalle registra un enlace saliente hacia `hxxps://feiraoaberto[.]netlify[.]app/login/`: un enlace no es una redirección ni prueba de envío de datos. No se siguió.

Dos motores de VT etiquetan phishing; el título/temática y el enlace saliente sostienen sospecha de ingeniería social. No se confirma captación de credenciales, exfiltración ni una entidad suplantada.

### Registro, DNS y certificados

- Registro: 2026-07-29T13:23:01.0Z; antigüedad aproximada a la consulta: 86 días. Registrar: Dynadot Inc.
- Estados RDAP: `server hold`, `client transfer prohibited`.
- NS según RDAP: `ns1[.]dyna-ns[.]net`, `ns2[.]dyna-ns[.]net`.
- DNS actual: RCODE 3 (NXDOMAIN) en los tipos consultados. No se presenta como limpio ni contradice la existencia de históricos. No se atribuye una causa de suspensión; los estados hold/inactive se conservan como contexto.
- Nombres observados en CT: `g-comeceseuatendimenton[.]shop`.

  Certificado/entrada 28359107479: `g-comeceseuatendimenton[.]shop`; 2026-07-29T18:47:32 a 2026-10-27T18:47:31; emisor `C=US, O=Let's Encrypt, CN=YR2`.
  Certificado/entrada 28359104673: `g-comeceseuatendimenton[.]shop`; 2026-07-29T18:47:32 a 2026-10-27T18:47:31; emisor `C=US, O=Let's Encrypt, CN=YR2`.

Las entradas duplicadas de pre-certificado/certificado no cuentan como dominios distintos. El registro CT no prueba que el servidor actual use ese certificado ni que el sitio sea legítimo. La vigencia anotada es la declarada por la entrada; no se probó una conexión TLS al destino. Para U001 se conservó el timeout inicial y luego se obtuvo la consulta de subdominios.

Certificado principal según el histórico urlscan: g-comeceseuatendimenton.shop, emisor YR1; válido de 2026-09-25T22:34:26+00:00 a 2026-12-24T22:34:25+00:00. Es una observación de ese escaneo y puede diferir de las entradas CT enumeradas; no se verificó el certificado actual ni se infiere legitimidad.

### Impacto y medidas

**Confidencialidad potencial:** riesgo de revelar información al interactuar con un recurso sospechoso o su destino enlazado; no se observó envío de credenciales. **Integridad/disponibilidad:** sin efecto demostrado. **Usuario:** evitar interacción y verificar por un canal oficial independiente. **Organización:** aplicar filtrado y revisión contextual de indicadores; no bloquear dominios de infraestructura compartida por aparecer como recursos de terceros.

### Evidencia visual

captura de vista local derivada. Captura UTC: 2026-10-23T18:15:49.369277+00:00.

![U001-certificados-local](capturas/U001-certificados-local.jpg)

captura de vista local derivada. Captura UTC: 2026-10-23T18:15:48.813274+00:00.

![U001-registro-dns-local](capturas/U001-registro-dns-local.jpg)

captura de imagen histórica de tercero. Captura UTC: 2026-10-23T18:10:20.158327+00:00.

![U001-urlscan-imagen-archivada](capturas/U001-urlscan-imagen-archivada.jpg)

captura externa real. Captura UTC: 2026-10-23T18:09:43.386198+00:00.

![U001-urlscan-resumen](capturas/U001-urlscan-resumen.jpg)

captura externa real. Captura UTC: 2026-10-23T18:09:05.390073+00:00.

![U001-virustotal-url](capturas/U001-virustotal-url.jpg)

Los JPEG son capturas reales del navegador. Los que terminan en “local” muestran datos derivados de JSON y lo indican en pantalla; no son imágenes del proveedor ni del sitio. Las imágenes “archivada” corresponden a capturas ya existentes de urlscan, no a visitas actuales.

## U002 — `hxxp://221[.]15[.]173[.]51:41661/bin[.]sh`

**Clasificación propuesta: MALICIOSO. Confianza: Alta en reputación y asociación histórica al binario; sin ejecución propia.**

Fuentes: [consultas originales](urls/20261023T180740Z/U002.json), [informe detallado histórico](urls/20261023T180740Z/U002-urlscan-detalle-autenticado-01a1464c-f4e2-70ba-8c0c-131c9851a684.json). Adquisición UTC: 2026-10-23T18:08:05.447916+00:00.

### Reputación y observación histórica

- VT de la URL exacta: {"malicious": 4, "suspicious": 3, "undetected": 33, "harmless": 53, "timeout": 0}. Último análisis UTC: 2026-10-16T19:48:07+00:00.
- Etiquetas de motores: `alphaMountain[.]ai: suspicious`, `Emsisoft: malware`, `Fortinet: malware`, `GreyNoise: malicious`, `Gridinsoft: suspicious`, `SOCRadar: suspicious`, `Webroot: malicious`.
- urlscan: 2026-10-16T20:00:43.057Z; título no informado; IP `221[.]15[.]173[.]51`; país informado CN; HTTP 200. La geolocalización no identifica al operador.
- Dominios contactados por el escaneo: ninguno; acceso a IP literal. No implica que todos sean maliciosos.
- Redirecciones: lista vacía en el detalle urlscan; VT informa URL final `hxxp://221[.]15[.]173[.]51:41661/bin[.]sh`. Esto describe esos reportes, no garantiza ausencia de redirecciones en otro momento.

El histórico documenta una descarga completada llamada `bin.sh`: 137480 bytes, descrita como **ELF 32-bit MIPS**, no como script shell. El MIME HTTP reportado como application/zip no determina el formato real. El SHA-256 de descarga coincide con el hash de contenido HTTP de VT y con un informe de archivo separado:

`f6c97b1e2ed02578ca1066c8235ba4f991e645f89012406c639dbccc6582eec8`

Ese informe existente informa **50 motores maliciosos**, tipo ELF y tamaño idéntico. Etiqueta popular: `trojan.mirai/mozi`; son atribuciones del servicio, no una familia determinada mediante análisis propio. La combinación de descarga histórica, identidad por hash y reputación respalda clasificación maliciosa con alta confianza. No se descargó ni ejecutó ese binario; tampoco pertenece a los dos Windows PE del ZIP.

[Reputación del hash asociado](urls/20261023T180740Z/U002-archivo-reputacion.json). Último análisis del archivo UTC: 2026-10-13T21:17:41+00:00. No se deducen procesos, persistencia o DDoS ejecutados a partir de esas etiquetas.

### Registro, DNS y certificados

La URL usa una IP literal por HTTP y puerto 41661. Antigüedad/registrador/NS de dominio y certificados HTTPS de dominio no aplican a este recurso. El RDAP de red registra `UNICOM-HA`, país CN, bloque `221[.]13[.]128[.]0`–`221[.]15[.]255[.]255`. Su fecha de asignación 2008-09-04T06:52:49Z no equivale a antigüedad de una campaña.

### Impacto y medidas

**C-I-A potencial:** la distribución de un ejecutable con reputación maliciosa supone riesgo para integridad y confidencialidad si llega a ejecutarse en un sistema compatible. Las etiquetas de botnet/DDoS justifican evaluar disponibilidad como hipótesis, sin afirmar ataques observados. **Usuario:** no descargar ni ejecutar. **Organización:** bloquear URL/hash y revisar telemetría de accesos o descargas; investigar solo si hay indicios de afectación.

### Evidencia visual

captura de vista local derivada. Captura UTC: 2026-10-23T18:16:30.826627+00:00.

![U002-registro-ip-local](capturas/U002-registro-ip-local.jpg)

captura externa real. Captura UTC: 2026-10-23T18:12:57.786950+00:00.

![U002-urlscan-descarga-detalle](capturas/U002-urlscan-descarga-detalle.jpg)

captura externa real. Captura UTC: 2026-10-23T18:11:21.878559+00:00.

![U002-urlscan-descarga](capturas/U002-urlscan-descarga.jpg)

captura externa real. Captura UTC: 2026-10-23T18:12:55.714941+00:00.

![U002-virustotal-hash-descarga](capturas/U002-virustotal-hash-descarga.jpg)

captura externa real. Captura UTC: 2026-10-23T18:11:14.990532+00:00.

![U002-virustotal-url](capturas/U002-virustotal-url.jpg)

Los JPEG son capturas reales del navegador. Los que terminan en “local” muestran datos derivados de JSON y lo indican en pantalla; no son imágenes del proveedor ni del sitio. Las imágenes “archivada” corresponden a capturas ya existentes de urlscan, no a visitas actuales.

## U003 — `hxxps://www[.]pneustorebr[.]cfd/`

**Clasificación propuesta: SOSPECHOSO. Confianza: Media.**

Fuentes: [consultas originales](urls/20261023T180740Z/U003.json), [informe detallado histórico](urls/20261023T180740Z/U003-urlscan-detalle-autenticado-01a1460d-11c6-71b9-9818-3caec90d10c7.json). Adquisición UTC: 2026-10-23T18:08:38.818631+00:00.

### Reputación y observación histórica

- VT de la URL exacta: {"malicious": 1, "suspicious": 0, "undetected": 35, "harmless": 57, "timeout": 0}. Último análisis UTC: 2026-10-16T20:47:16+00:00.
- Etiquetas de motores: `ESET: phishing`.
- urlscan: 2026-10-16T18:50:34.640Z; título `Domain registered \| Dynadot`; IP `54[.]215[.]31[.]113`; país informado US; HTTP 404. La geolocalización no identifica al operador.
- Dominios contactados por el escaneo: `widget[.]trustpilot[.]com`, `fonts[.]cdnfonts[.]com`, `www[.]pneustorebr[.]cfd`, `oss[.]dynadot[.]com`. No implica que todos sean maliciosos.
- Redirecciones: lista vacía en el detalle urlscan; VT informa URL final `hxxps://www[.]pneustorebr[.]cfd/`. Esto describe esos reportes, no garantiza ausencia de redirecciones en otro momento.

urlscan muestra una página de dominio aparcado “Domain registered | Dynadot” y HTTP 404. VT, en otro horario, reporta HTTP 200 y una IP distinta: se conservan ambos resultados sin inventar una causa. La URL exacta tiene una detección de phishing; el dominio raíz tiene seis maliciosas y dos sospechosas en su consulta separada. El dominio raíz no se confunde con la URL www.

No se observó en ese histórico una tienda ni un formulario de credenciales. El parecido del nombre con una marca no prueba suplantación. Se propone sospechoso por las alertas y el contexto; no se afirma fraude de una tienda demostrado por la página aparcada.

### Registro, DNS y certificados

- Registro: 2026-09-04T03:47:46.0Z; antigüedad aproximada a la consulta: 49 días. Registrar: Dynadot Inc.
- Estados RDAP: `server transfer prohibited`, `client hold`, `client transfer prohibited`, `inactive`.
- NS según RDAP: no incluidos en la respuesta.
- DNS actual: RCODE 3 (NXDOMAIN) en los tipos consultados. No se presenta como limpio ni contradice la existencia de históricos. No se atribuye una causa de suspensión; los estados hold/inactive se conservan como contexto.
- Nombres observados en CT: `pneustorebr[.]cfd`, `www[.]pneustorebr[.]cfd`.

  Certificado/entrada 29336333368: `pneustorebr[.]cfd`; 2026-09-04T07:31:13 a 2026-12-03T07:31:12; emisor `C=US, O=Let's Encrypt, CN=YR2`.
  Certificado/entrada 29676156333: `pneustorebr[.]cfd`; 2026-09-04T07:31:13 a 2026-12-03T07:31:12; emisor `C=US, O=Let's Encrypt, CN=YR2`.
  Certificado/entrada 29336334494: `www[.]pneustorebr[.]cfd`; 2026-09-04T07:31:13 a 2026-12-03T07:31:12; emisor `C=US, O=Let's Encrypt, CN=YR1`.
  Certificado/entrada 29808327070: `www[.]pneustorebr[.]cfd`; 2026-09-04T07:31:13 a 2026-12-03T07:31:12; emisor `C=US, O=Let's Encrypt, CN=YR1`.

Las entradas duplicadas de pre-certificado/certificado no cuentan como dominios distintos. El registro CT no prueba que el servidor actual use ese certificado ni que el sitio sea legítimo. La vigencia anotada es la declarada por la entrada; no se probó una conexión TLS al destino. Para U001 se conservó el timeout inicial y luego se obtuvo la consulta de subdominios.

Certificado principal según el histórico urlscan: *.dynadot.com, emisor GlobalSign GCC R6 AlphaSSL CA 2025; válido de 2025-10-18T00:00:00+00:00 a 2026-11-18T23:59:59+00:00. Es una observación de ese escaneo y puede diferir de las entradas CT enumeradas; no se verificó el certificado actual ni se infiere legitimidad.

### Impacto y medidas

**Confidencialidad potencial:** riesgo de revelar información al interactuar con un recurso sospechoso o su destino enlazado; no se observó envío de credenciales. **Integridad/disponibilidad:** sin efecto demostrado. **Usuario:** evitar interacción y verificar por un canal oficial independiente. **Organización:** aplicar filtrado y revisión contextual de indicadores; no bloquear dominios de infraestructura compartida por aparecer como recursos de terceros.

### Evidencia visual

captura de vista local derivada. Captura UTC: 2026-10-23T18:15:50.221281+00:00.

![U003-certificados-local](capturas/U003-certificados-local.jpg)

captura de vista local derivada. Captura UTC: 2026-10-23T18:15:49.937280+00:00.

![U003-registro-dns-local](capturas/U003-registro-dns-local.jpg)

captura de imagen histórica de tercero. Captura UTC: 2026-10-23T18:12:18.842788+00:00.

![U003-urlscan-imagen-archivada](capturas/U003-urlscan-imagen-archivada.jpg)

captura externa real. Captura UTC: 2026-10-23T18:12:18.466786+00:00.

![U003-urlscan-resumen](capturas/U003-urlscan-resumen.jpg)

captura externa real. Captura UTC: 2026-10-23T18:17:10.546679+00:00.

![U003-virustotal-dominio](capturas/U003-virustotal-dominio.jpg)

captura externa real. Captura UTC: 2026-10-23T18:12:07.194740+00:00.

![U003-virustotal-url](capturas/U003-virustotal-url.jpg)

Los JPEG son capturas reales del navegador. Los que terminan en “local” muestran datos derivados de JSON y lo indican en pantalla; no son imágenes del proveedor ni del sitio. Las imágenes “archivada” corresponden a capturas ya existentes de urlscan, no a visitas actuales.

## Límites de este bloque

Los tres recursos fueron revisados con datos existentes. No se verificó el sitio actual ni se ejecutó contenido. No se siguió el enlace de login externo de U001. El archivo de U002 no se descargó. Los hallazgos no prueban infección del equipo ni autoría de operadores. Las diferencias de DNS, HTTP, IP, TLS y veredictos se conservan con su fecha y alcance.
