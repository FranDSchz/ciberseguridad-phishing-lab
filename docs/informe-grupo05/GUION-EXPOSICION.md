# Guion de exposición del Grupo 05

Duración prevista: **8 min 40 s**, siete diapositivas. Se agrega el análisis dinámico (diapositiva 2) y se corrige toda mención a «ninguna muestra ejecutada»: la fase estática no ejecutó nada, pero F001 y F002 se ejecutaron después en el sandbox de ANY.RUN. La demostración de dos herramientas sigue en U002: dejar abiertos los informes de urlscan y VirusTotal, y también las dos tareas de ANY.RUN, antes de exponer.

## Diapositiva 1 · Binarios: análisis estático

0:00–1:10 (70 s). Propuesta: Benetucci Ignacio. Introducción (10 s): siete recursos, en dos fases; primero análisis estático y de reputación sin ejecutar nada, después análisis dinámico de los dos binarios en un sandbox. F001 es una DLL aunque su nombre histórico termine en .exe; F002 es un ejecutable. SHA-256, SHA-1, MD5 y tamaño coinciden con VirusTotal: 47 detecciones cada uno. RAT significa troyano de acceso remoto. Veredicto estático: maliciosos, confianza alta. Pasamos a ver qué hacen realmente.

Texto en pantalla, cambiar la nota inferior por: «VirusTotal: informes existentes. Capturas: 23/10/2026. Fase estática: sin ejecución local.»

## Diapositiva 2 · Binarios: análisis dinámico (nueva)

1:10–2:40 (90 s). Propuesta: Maurel Garcete Philippe, que realizó las ejecuciones. Ejecutamos F001 y F002 en ANY.RUN, en Windows 10 con red, unos 60 segundos cada uno; los hashes coinciden con los del estático. Respondemos las cuatro preguntas. Procesos: F001 se carga con rundll32, un binario legítimo de Windows, y lanza cmd y Setup64.exe; F002 lanza cmd seis veces y pide elevación. Archivos: los dos crean WinCombo.exe y erasecode.dat en la misma carpeta, ProgramData\MicroPoint. Registro: F001 cambia un valor de autorun, o sea persistencia, técnica T1547.001; los dos leen datos del equipo y el software instalado. Red: F001 consulta su IP pública y contacta 204.194.49.108; F002 tiene configurada 202.61.157.33. Separamos el ruido: WaaSMedicAgent y el tráfico de certificados son de Windows, y ANY.RUN no marca ningún indicador de red como malicioso, así que no afirmamos C2. Hallazgo: F001 deja Setup64.exe y termina en WinCombo.exe, los dos nombres históricos de F002; es un indicio de que forman la misma cadena, no lo confirmamos por hash. Límite: con 60 segundos podemos perder comportamiento; por eso F002 no mostró persistencia. Conclusión: el dinámico confirma maliciosos, confianza alta. Medida: buscar ProgramData\MicroPoint y autoruns en los equipos, bloquear hashes. Fuente: primarios/anyrun/F001-ANYRUN-20261029.pdf y F002-ANYRUN-20261029.pdf. https://app.any.run/tasks/53d8309d-8070-42b7-b134-2eee1f815e1b y https://app.any.run/tasks/ce5eebef-5d93-4667-9ac7-747ea8c5d165

Texto en pantalla:
- Título: «Binarios: el sandbox confirma comportamiento de RAT»
- Etiqueta: «MALICIOSO · confianza alta»
- Tabla de 4 filas (F001 | F002):
  - Procesos: rundll32 → cmd → Setup64.exe | cmd ×6, gpupdate, UAC
  - Archivos: ProgramData\MicroPoint\WinCombo.exe | la misma carpeta y archivo
  - Registro: autorun = persistencia (T1547.001) | sin persistencia en 60 s
  - Red: 204[.]194[.]49[.]108 | 202[.]61[.]157[.]33
- Línea inferior: «F001 deja Setup64.exe → WinCombo.exe, nombres de F002: misma cadena (indicio)»
- Nota: «ANY.RUN · Windows 10 · 29/10/2026 · ~60 s · ruido de Windows descartado; IP sin C2 confirmado»

## Diapositiva 3 · R004

2:40–3:50 (70 s). Propuesta: Maurel Garcete Philippe. R004 anuncia un producto para aliviar dolor de rodilla. Tiene cero adjuntos, dos enlaces acortados y un píxel remoto de seguimiento. La URL exacta de pnreap.com registra 12 motores maliciosos y uno sospechoso en VirusTotal. Por eso clasificamos el mensaje como malicioso por el contenido remoto que incorpora, con confianza media. Las cabeceras declaran SPF y DMARC pass; autenticar el dominio no prueba que el contenido sea seguro. No afirmamos robo de credenciales ni infección. No cargamos el píxel. Fuente: capturas/R004-pnreap-verificado.jpg; cierre/R004-pnreap-verificacion.json; correos-html-resumen.json. https://www.virustotal.com/gui/url/b5964327810a7c813ae6a17ec150228e0f3c1bc77fa5dba775f7eaae5eda674d Medida: evitar carga remota de imágenes y filtrar mensajes similares.

## Diapositiva 4 · R005

3:50–4:50 (60 s). Propuesta: Maurel Garcete Philippe. El mensaje ofrece bolas de Plinko y premios. El contenido tiene tres enlaces de acción y un píxel en woondsplay.com. El dominio registra siete motores maliciosos y dos sospechosos. Las URLs exactas consultadas no aportan un informe concluyente: no trasladamos automáticamente la clasificación del dominio al mensaje. Las cabeceras declaran SPF none, DMARC none y una firma DKIM cuyo dominio no está alineado con From. None no significa fail. Amenaza posible: spam o engaño mediante enlaces; no hay un malware adjunto identificado. Conclusión: sospechoso, confianza media. Fuentes: capturas/R005-dominio-enlaces-virustotal.jpg, correos-estaticos.json, correos-html-resumen.json. https://www.virustotal.com/gui/domain/woondsplay.com Medida: reportar como sospechoso y evitar enlaces. Posible seguimiento; integridad y disponibilidad sin efecto observado.

## Diapositiva 5 · U001

4:50–5:50 (60 s). Propuesta: Rodas Sebastián. U001 es g-comeceseuatendimenton.shop. No la abrimos: usamos el escaneo histórico de urlscan del 16 de octubre. Muestra una página en portugués de consulta financiera sobre el CPF, el número fiscal de Brasil, con cuenta regresiva y un llamado a actuar. Tiene un enlace a un login externo en Netlify que no seguimos. VirusTotal: 2 alertas sobre 93 motores. urlscan se contradice: su modelo de machine learning la marca, pero su veredicto general no. Hay riesgo de ingeniería social, pero no vimos un formulario que pida credenciales. Conclusión: sospechoso, confianza media. Medida: no interactuar y verificar por el canal oficial. Fuente: capturas/U001-urlscan-imagen-archivada.jpg y U001-virustotal-url.jpg; urls/20261023T180740Z/U001.json. https://urlscan.io/result/01a1462b-bbda-773d-a9b2-fa0511ed4b52/

## Diapositiva 6 · U002 y demostración

5:50–7:30 (100 s). Propuesta: Sánchez Franco. Este caso conecta dos herramientas. En urlscan, mostrar el registro de descarga: ELF de 32 bits para MIPS, 137480 bytes. No es un script aunque la ruta termine en .sh. Copiar solo el hash visible y mostrar el informe ya existente de VT: mismo SHA-256 y tamaño, 50 motores maliciosos. Reservar 35 segundos para la demostración. Dejar abiertos antes de exponer los informes de urlscan y VirusTotal, accesibles desde los rótulos de esta diapositiva. En urlscan mostrar Downloads y su SHA-256; en VirusTotal mostrar el mismo hash y 50 detecciones. Si falla Internet, las capturas permiten explicar el caso, aunque no reemplazan el requisito de mostrar dos herramientas en vivo. Nunca abrir el destino ni pulsar Reanalyze ni descargar el archivo. SHA-256 f6c97b1e2ed02578ca1066c8235ba4f991e645f89012406c639dbccc6582eec8. Motores etiquetan Mirai/Mozi, asociados a botnets y DDoS; es atribución de terceros, no comportamiento ejecutado por nosotros. Conclusión: malicioso con confianza alta en asociación histórica y reputación. Fuentes: capturas/U002-urlscan-descarga-detalle.jpg; U002-virustotal-hash-descarga.jpg. https://urlscan.io/result/01a1464c-f4e2-70ba-8c0c-131c9851a684/ y https://www.virustotal.com/gui/file/f6c97b1e2ed02578ca1066c8235ba4f991e645f89012406c639dbccc6582eec8

## Diapositiva 7 · U003 y cierre

7:30–8:40 (70 s). Propuesta: Rodas Sebastián. U003 es pneustorebr.cfd; «pneus» significa neumáticos en portugués. La URL tiene una alerta y el dominio, seis maliciosas y dos sospechosas. Pero la captura histórica no muestra una tienda ni un formulario: es un dominio aparcado en Dynadot que devuelve error 404. El nombre puede servir para engañar, pero no alcanza para afirmar una estafa. Conclusión: sospechoso, confianza media. Cierre (20 s): de siete recursos, cuatro maliciosos y tres sospechosos, ninguno limpio. Trabajamos en dos fases: estática, sin ejecutar nada, y dinámica en sandbox para los dos binarios, que confirmó su comportamiento. Recomendamos conservar aislado, reportar y bloquear solo indicadores confirmados. Fuente: U003-urlscan-imagen-archivada.jpg y U003-virustotal-dominio.jpg, U003.json. https://urlscan.io/result/01a1460d-11c6-71b9-9818-3caec90d10c7/ y https://www.virustotal.com/gui/domain/pneustorebr.cfd

Texto en pantalla, cambiar la nota inferior por: «Resultado del set: 4 maliciosos · 3 sospechosos · binarios confirmados en sandbox».
