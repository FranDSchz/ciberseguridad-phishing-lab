[Descargar el informe técnico editable en Word (versión previa al suplemento ANY.RUN del 29/10)](entrega/Grupo_05_Informe_Tecnico.docx)

# Análisis y triage de recursos sospechosos

UTN FRRe · Fundamentos de Ciberseguridad · Trabajo práctico 2 · Grupo 05 · 30/10/2026

Integrantes: Benetucci Ignacio; Maurel Garcete Philippe; Rodas Sebastián; Sánchez Franco.

## Resumen ejecutivo

Analizamos siete recursos: dos archivos Windows, dos correos y tres URLs. Clasificamos cuatro como maliciosos y tres como sospechosos, ninguno limpio. F001 y F002 son de tipo MALICIOSO: a las huellas coincidentes y 47 detecciones de VirusTotal por binario se agregan dos reportes de ejecución de ANY.RUN, que clasifican ambas muestras como «Malicious activity». El ELF asociado a U002 tiene 50 detecciones. R004 incorpora una URL remota exacta con 12 detecciones. Los restantes casos presentan señales mixtas.

## Metodología y entorno

La fase inicial fue análisis estático y reputación. El ZIP se preservó con su SHA-256; los archivos y correos se extrajeron como datos en una VM mínima derivada de Kali, sin red, sin integración con el host y con montajes noexec. La recuperación usa una base limpia y disco diferencial; no acredita un snapshot formal del hipervisor. En esa fase no se ejecutaron muestras, cargaron HTML ni visitaron destinos sospechosos. Para archivos conocidos consultamos hashes en VirusTotal; para URLs revisamos informes históricos de urlscan. Completamos cabeceras, MXToolbox, RDAP, DNS y crt.sh. Los registros conservan consultas y estados de cada adquisición.

Se tiene reportes PDF de ejecuciones de los archivos .exe en ANY.RUN, en Windows 10 Professional de 64 bits con red. Cada objeto se identifica con su SHA-256 en el archivo inventariado y consultado en VirusTotal. Los PDF son un resumen automático, indicadores y detecciones de comportamiento; no incluyen un volcado de eventos o tráfico suficiente para validar de forma independiente todas las relaciones entre procesos, persistencia y comunicaciones que afirma el resumen automático. Las recomendaciones del reporte son contenido generado por IA.

Las cabeceras de correo declaran resultados de autenticación; no revalidamos DKIM criptográficamente ni reconstruimos SPF histórico. Las etiquetas de familia (ValleyRAT, SilverFox, Winos) las provee ANY.RUN. Las IP listadas por ANY.RUN no se tratan como C2 confirmados ni como indicadores para bloqueo sin revisar el tráfico y su relación con el proceso. Una URL sin informe, un dominio aparcado o una IP no listada no acreditan legitimidad.

## F001 Archivo 1

| Campo | Resultado |
| :--- | :--- |
| Identificador del recurso | F001 · Archivo 1 · file_1.zip |
| Tipo | DLL Windows PE32+ x64, 2.264.968 bytes. Recurso independiente del ZIP. |
| Herramientas usadas | file, 7-Zip y hashes en VM; VirusTotal por hash; reporte de ejecución ANY.RUN. |
| Evidencia clave | Los SHA-256, SHA-1 y MD5 y el tamaño coinciden con VT. 47 motores maliciosos. Nombres históricos: Setup64.exe y libPdfCore.dll; el tipo real es DLL. ANY.RUN analizó el mismo SHA-256 y calificó la actividad como maliciosa; su tabla de detecciones incluye ejecución mediante rundll32/cmd, búsqueda de software y cambio de autorun (T1547.001). El resumen automático atribuye comunicación a 204[.]194[.]49[.]108, sin prueba de C2 o exfiltración verificable en este PDF. |
| Tipo de amenaza si aplica | Troyano o herramienta de acceso remoto según reputación y análisis de ANY.RUN. ValleyRAT/SilverFox/Winos segun el mismo |
| Impacto C-I-A | C: posible acceso a información. I: posibles cambios no autorizados; ANY.RUN señala un cambio de autorun dentro del sandbox. A: efecto concreto sin determinar. No se demuestra impacto en un equipo externo. |
| VEREDICTO | MALICIOSO |
| Confianza | Alta en identidad y clasificación maliciosa; comportamiento específico sujeto a los límites del reporte PDF. |
| Medida usuario / organización | Usuario: mantener aislado y no ejecutar. Organización: bloquear el hash y buscar coincidencias en EDR; investigar si hay indicios de ejecución. |

SHA-256: `6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba`.

![Evidencia F001](capturas/F001-virustotal-detecciones.jpg)

Captura original: 2026-10-23T17:43:03.381326+00:00.

Fuentes: [VirusTotal](https://www.virustotal.com/gui/file/6f9f663f832a06474913ec6bb0f94e3cca6e0658396a68053ff36abedbb050ba) · [Huellas y tipo](primarios/vm/grupo05-archivos-estaticos.json) · [Respuesta de VT](archivos-reputacion.json) · [PDF ANY.RUN F001](primarios/anyrun/F001-ANYRUN-20261029.pdf) · [Tarea interactiva](https://app.any.run/tasks/53d8309d-8070-42b7-b134-2eee1f815e1b).

## F002 Archivo 2

| Campo | Resultado |
| :--- | :--- |
| Identificador del recurso | F002 · Archivo 2 · file_2.zip |
| Tipo | Ejecutable Windows PE32+ GUI x64, 1.559.216 bytes. Recurso independiente del ZIP. |
| Herramientas usadas | file, 7-Zip y hashes en VM; VirusTotal por hash; reporte de ejecución ANY.RUN. |
| Evidencia clave | Los SHA-256, SHA-1 y MD5 y el tamaño coinciden con VT. 47 motores maliciosos. Nombres históricos: Setup64.exe y WinCombo.exe. ANY.RUN analizó el mismo SHA-256 y calificó la actividad como maliciosa; su tabla de detecciones incluye ejecución de cmd.exe y búsqueda de software. El resumen automático atribuye una configuración hacia 202[.]61[.]157[.]33, pero el PDF no confirma una conexión C2 ni exfiltración; tampoco registra persistencia. |
| Tipo de amenaza si aplica | Troyano o herramienta de acceso remoto según reputación y análisis de ANY.RUN. ValleyRAT/SilverFox/Winos, backdoor y stealer son etiquetas de terceros; no se confirmó una familia por análisis independiente. |
| Impacto C-I-A | C: posible acceso a datos. I: posibles alteraciones del equipo. A: sin efecto determinado. No se observó infección de un equipo externo ni persistencia confirmada en este reporte. |
| VEREDICTO | MALICIOSO |
| Confianza | Alta en identidad y clasificación maliciosa; comportamiento específico sujeto a los límites del reporte PDF. |
| Medida usuario / organización | Usuario: no ejecutar y reportar su procedencia. Organización: bloquear el hash y revisar telemetría de endpoints antes de declarar un incidente. |

SHA-256: `06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec`.

![Evidencia F002](capturas/F002-virustotal-detecciones.jpg)

Captura original: 2026-10-23T17:43:52.974256+00:00.

Fuentes: [VirusTotal](https://www.virustotal.com/gui/file/06af7db1507c685154f7a291c862b0bfe5649c989de4e7acbeff23fd3252e4ec) · [Huellas y tipo](primarios/vm/grupo05-archivos-estaticos.json) · [Respuesta de VT](archivos-reputacion.json) · [PDF ANY.RUN F002](primarios/anyrun/F002-ANYRUN-20261029.pdf) · [Tarea interactiva](https://app.any.run/tasks/ce5eebef-5d93-4667-9ac7-747ea8c5d165).

## R004 Correo 1

| Campo | Resultado |
| :--- | :--- |
| Identificador del recurso | R004 · Correo 1 |
| Tipo | sample-10070.eml, 12.294 bytes; HTML y cero adjuntos. |
| Herramientas usadas | Parser MIME y cabeceras; VirusTotal; MXToolbox; consulta de históricos de urlscan. |
| Evidencia clave | From y Return-Path: ginnybedellphotography[.]com; Reply-To: brendamurphyrealestate[.]com. Cabeceras: SPF pass, DKIM pass no alineado y DMARC pass compatible con SPF. URL exacta del píxel pnreap[.]com: 12 motores maliciosos y 1 sospechoso; dos acortadores: 2 alertas cada uno. IP de entrega 20[.]169[.]217[.]199: 0/60 listas y 1 timeout en MXToolbox. |
| Tipo de amenaza si aplica | Spam con recurso remoto de reputación maliciosa y seguimiento. No se confirmó captación de credenciales. |
| Impacto C-I-A | C: posible seguimiento o revelación de datos al interactuar. I y A: sin impacto demostrado. Los pass declarados no prueban contenido legítimo. |
| VEREDICTO | MALICIOSO |
| Confianza | Media; sustentado en la URL remota exacta. No se revalidó DKIM ni SPF histórico. |
| Medida usuario / organización | Usuario: no responder, seguir enlaces ni cargar imágenes. Organización: filtrar enlaces y correo similar; revisar autenticación y desactivar carga remota automática. |

![Evidencia R004](capturas/R004-pnreap-verificado.jpg)

Captura original: 2026-10-23T19:12:50.373696+00:00.

Fuentes: [VirusTotal de la URL](https://www.virustotal.com/gui/url/b5964327810a7c813ae6a17ec150228e0f3c1bc77fa5dba775f7eaae5eda674d) · [Cabeceras y enlaces](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/correos-estaticos.json) · [Consulta del píxel](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/cierre/R004-pnreap-verificacion.json) · [Listas antispam](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/cierre/mxtoolbox-adquisicion.json).

## R005 Correo 2

| Campo | Resultado |
| :--- | :--- |
| Identificador del recurso | R005 · Correo 2 |
| Tipo | sample-10071.eml, 465.737 bytes; texto y HTML quoted-printable, cero adjuntos. |
| Herramientas usadas | Parser MIME y cabeceras; VirusTotal; MXToolbox; consulta de históricos de urlscan. |
| Evidencia clave | From y Return-Path: taylor.flores@ezagameroasin02[.]onmicrosoft[.]com. SPF none y DMARC none; DKIM pass con dominio no alineado. Promoción Plinko: 3 enlaces de acción y 1 píxel en woondsplay[.]com. Dominio: 7 motores maliciosos y 2 sospechosos; reputación de URLs exactas insuficiente. IP de entrega 209[.]85[.]167[.]46: 0/60 listas, sin timeout. |
| Tipo de amenaza si aplica | Posible spam o ingeniería social mediante apuestas y premios. No se identificó una carga maliciosa ni fraude confirmado. |
| Impacto C-I-A | C: riesgo potencial de seguimiento y entrega de datos. I y A: sin efecto demostrado. SPF/DMARC none no equivale a fail. |
| VEREDICTO | SOSPECHOSO |
| Confianza | Media; señales de dominio y contenido sin confirmación del comportamiento de cada URL. |
| Medida usuario / organización | Usuario: no interactuar y reportar. Organización: filtrar enlaces y revisar mensajes similares; no bloquear rangos completos de Google por esta IP compartida. |

![Evidencia R005](capturas/R005-dominio-enlaces-virustotal.jpg)

Captura original: 2026-10-23T17:52:33.487842+00:00.

Fuentes: [VirusTotal del dominio](https://www.virustotal.com/gui/domain/woondsplay.com) · [Cabeceras y enlaces](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/correos-estaticos.json) · [Contenido MIME](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/correos-html-resumen.json) · [Listas antispam](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/cierre/mxtoolbox-adquisicion.json).

## U001 Enlace 1

| Campo | Resultado |
| :--- | :--- |
| Identificador del recurso | U001 · Enlace 1 |
| Tipo | URL HTTPS: hxxps://g-comeceseuatendimenton[.]shop/ |
| Herramientas usadas | VirusTotal, urlscan histórico exacto, RDAP/WHOIS, DNS y crt.sh. |
| Evidencia clave | VT URL: 2 alertas de phishing. urlscan del 16/10: HTTP 200, IP 88[.]80[.]17[.]232, Suecia; orientación financiera sobre CPF y enlace externo a un login, sin formulario observado. Sin redirecciones registradas; contactos Google Fonts e ipapi[.]co. Creado 29/07/2026 (86 días al consultar), Dynadot; NS dyna-ns[.]net. CT: dominio, certificado 29/07–27/10. DNS actual: NXDOMAIN. |
| Tipo de amenaza si aplica | Posible ingeniería social. El enlace externo y el motor ML no prueban robo de credenciales; el veredicto global de urlscan no confirma malicia. |
| Impacto C-I-A | C: posible revelación de datos si el usuario interactúa. I y A: sin efectos demostrados. |
| VEREDICTO | SOSPECHOSO |
| Confianza | Media; alertas escasas y señales contradictorias entre motores. |
| Medida usuario / organización | Usuario: no interactuar y verificar por canal oficial. Organización: filtrar y revisar el indicador en contexto, sin atribuir malicia a sus proveedores externos. |

![Evidencia U001](capturas/U001-urlscan-resumen.jpg)

Captura original: 2026-10-23T18:09:43.386198+00:00.

Fuentes: [urlscan histórico](https://urlscan.io/result/01a1462b-bbda-773d-a9b2-fa0511ed4b52/) · [VT, RDAP, DNS y CT](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/urls/20261023T180740Z/U001.json) · [Certificados CT](https://crt.sh/?q=%25.g-comeceseuatendimenton.shop).

## U002 Enlace 2

| Campo | Resultado |
| :--- | :--- |
| Identificador del recurso | U002 · Enlace 2 |
| Tipo | URL HTTP por IP: hxxp://221[.]15[.]173[.]51:41661/bin[.]sh |
| Herramientas usadas | VirusTotal URL, IP y hash de archivo; urlscan histórico exacto y RDAP de red. |
| Evidencia clave | VT URL: 4 maliciosos y 3 sospechosos. urlscan del 16/10: HTTP 200, IP 221[.]15[.]173[.]51, China; descarga ELF de 32 bits MIPS, 137.480 bytes. Hash y tamaño coinciden con VT archivo: 50 motores maliciosos. Sin redirecciones ni dominios contactados. RDAP: UNICOM-HA (CN). Registro, NS y certificados de dominio no aplican a una IP literal por HTTP. |
| Tipo de amenaza si aplica | Distribución de ejecutable malicioso. Etiquetas Mirai/Mozi de terceros, asociadas a botnets. La extensión .sh no define el tipo real. |
| Impacto C-I-A | C e I: posible acceso o alteración si se ejecuta en un sistema compatible. A: riesgo potencial de botnet/DDoS; no se observaron ataques. |
| VEREDICTO | MALICIOSO |
| Confianza | Alta en asociación histórica por hash y reputación; sin ejecución propia. |
| Medida usuario / organización | Usuario: no descargar ni ejecutar. Organización: bloquear URL/hash y revisar accesos o descargas; investigar afectación si existe telemetría. |

SHA-256: `f6c97b1e2ed02578ca1066c8235ba4f991e645f89012406c639dbccc6582eec8`.

![Evidencia U002](capturas/U002-urlscan-descarga-detalle.jpg)

Captura original: 2026-10-23T18:12:57.786950+00:00.

Fuentes: [urlscan histórico](https://urlscan.io/result/01a1464c-f4e2-70ba-8c0c-131c9851a684/) · [VirusTotal del ELF](https://www.virustotal.com/gui/file/f6c97b1e2ed02578ca1066c8235ba4f991e645f89012406c639dbccc6582eec8) · [Respuesta de VT archivo](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/urls/20261023T180740Z/U002-archivo-reputacion.json) · [VT y RDAP](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/urls/20261023T180740Z/U002.json).

## U003 Enlace 3

| Campo | Resultado |
| :--- | :--- |
| Identificador del recurso | U003 · Enlace 3 |
| Tipo | URL HTTPS: hxxps://www[.]pneustorebr[.]cfd/ |
| Herramientas usadas | VirusTotal, urlscan histórico exacto, RDAP/WHOIS, DNS y crt.sh. |
| Evidencia clave | VT URL: 1 motor malicioso; dominio raíz: 6 maliciosos y 2 sospechosos. urlscan del 16/10: dominio aparcado Dynadot, HTTP 404, IP 54[.]215[.]31[.]113, EE. UU.; sin redirecciones ni formulario. Contactos: Trustpilot, cdnfonts y Dynadot. Creado 04/09/2026 (49 días), Dynadot; NS no informados. CT: raíz y www, vigencia 04/09–03/12. DNS actual: NXDOMAIN. |
| Tipo de amenaza si aplica | Posible engaño por dominio o uso previo. No se observó tienda fraudulenta ni se confirmó suplantación por semejanza del nombre. |
| Impacto C-I-A | C: posible engaño si el dominio se utiliza para captar datos. I y A: sin impacto demostrado. |
| VEREDICTO | SOSPECHOSO |
| Confianza | Media; alertas de reputación y página histórica aparcada, sin fraude demostrado. |
| Medida usuario / organización | Usuario: evitar interacción y verificar el comercio por canal independiente. Organización: revisar y filtrar el indicador según contexto; no bloquear proveedores compartidos. |

![Evidencia U003](capturas/U003-urlscan-resumen.jpg)

Captura original: 2026-10-23T18:12:18.466786+00:00.

Fuentes: [urlscan histórico](https://urlscan.io/result/01a1460d-11c6-71b9-9818-3caec90d10c7/) · [VirusTotal del dominio](https://www.virustotal.com/gui/domain/pneustorebr.cfd) · [VT, RDAP, DNS y CT](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/urls/20261023T180740Z/U003.json) · [Certificados CT](https://crt.sh/?q=%25.pneustorebr.cfd).

## Conclusiones

F001, F002, R004 y U002: maliciosos. R005, U001 y U003: sospechosos. Los reportes ANY.RUN agregan comportamiento en sandbox para F001 y F002 y refuerzan su veredicto, sin cambiar la clasificación de los siete recursos. No se acreditó infección de un equipo fuera del sandbox ni un recurso legítimo. Conservar aislado, reportar y aplicar controles sobre indicadores confirmados con revisión de telemetría.

## Anexo de evidencia verificable

- [Capturas completas](https://github.com/FranDSchz/ciberseguridad-phishing-lab/tree/main/docs/informe-grupo05/capturas)

- [Registro de capturas y huellas](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/capturas/registro-capturas-informe.json)

- [Salidas de archivos y hashes](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/primarios/vm/grupo05-archivos-estaticos.json)

- [VirusTotal de archivos](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/archivos-reputacion.json)

- [Reportes originales ANY.RUN F001 y F002](primarios/anyrun/) e [integridad de ambos PDF](primarios/anyrun/SHA256SUMS)

- [Cabeceras y enlaces de correos](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/correos-estaticos.json)

- [Resumen MIME de los correos](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/correos-html-resumen.json)

- [Reputación de enlaces de correo](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/enlaces-correo-reputacion.json)

- [Listas antispam MXToolbox](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/cierre/mxtoolbox-adquisicion.json)

- [Informes de URL, RDAP, DNS y certificados](https://github.com/FranDSchz/ciberseguridad-phishing-lab/tree/main/docs/informe-grupo05/urls/20261023T180740Z)

- [Integridad de las evidencias](https://github.com/FranDSchz/ciberseguridad-phishing-lab/blob/main/docs/informe-grupo05/SHA256SUMS)
