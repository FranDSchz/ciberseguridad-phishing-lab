# Índice de evidencias — Grupo 05

[Borrador integrado con capturas](BORRADOR-TP.md).

| Recurso | Evidencia conservada | Capturas incorporadas |
| :--- | :--- | :--- |
| F001 | Inventario, tres hashes y tamaño local; respuesta VT; [reporte PDF de ANY.RUN del 29/10](primarios/anyrun/F001-ANYRUN-20261029.pdf), vinculado por SHA-256 | Detecciones y propiedades VT; ver ficha de archivo |
| F002 | Inventario, tres hashes y tamaño local; respuesta VT; [reporte PDF de ANY.RUN del 29/10](primarios/anyrun/F002-ANYRUN-20261029.pdf), vinculado por SHA-256 | Detecciones, propiedades, historial y nombres VT; ver ficha de archivo |
| R004 | Cabeceras, autenticación declarada, estructura MIME, enlaces, consultas VT/urlscan y estados | Vistas locales de cabeceras/MIME/consultas; capturas reales VT de remitente, IP y dos enlaces |
| R005 | Cabeceras, autenticación declarada, estructura MIME, enlaces, consultas VT/urlscan y estados | Vistas locales de cabeceras/MIME/consultas; capturas reales VT de IP y dominio de enlaces |
| U001, U002, U003 | [Consultas, detalles y resumen de URLs](urls/20261023T180740Z/resumen-normalizado.json), RDAP, DNS, CT y reputación del hash asociado a U002 | [Fichas de URLs](fichas-urls.md), capturas VT/urlscan e imágenes históricas; vistas locales de registro y CT |

## Archivos fuente

- [Inventario estático previo](primarios/vm/grupo05-inventario-estatico.json) y [hashes/tipos de los binarios](primarios/vm/grupo05-archivos-estaticos.json).
- [Respuestas originales de VirusTotal de archivos](archivos-reputacion.json).
- [PDF ANY.RUN F001](primarios/anyrun/F001-ANYRUN-20261029.pdf) y [PDF ANY.RUN F002](primarios/anyrun/F002-ANYRUN-20261029.pdf); [hashes de integridad de los PDF](primarios/anyrun/SHA256SUMS). Los dos corresponden a los hashes SHA-256 de F001/F002. ANY.RUN clasifica ambos como «Malicious activity», pero sus resúmenes automáticos no equivalen a un registro completo de eventos o tráfico.
- [Extracción estática de correos](correos-estaticos.json) y [resumen HTML](correos-html-resumen.json).
- [Respuestas de dominios/IP](correos-reputacion.json) y [enlaces](enlaces-correo-reputacion.json), incluidos errores y ausencia de resultados.
- [Registro de exportación de correos desde la VM](primarios/vm/grupo05-correos-verificados-consola.log), [registro HTML](primarios/vm/grupo05-correos-html-consola.log), [registro de extracción AES](primarios/vm/grupo05-aes-consola.log).
- [Procedencia y hashes de las copias de registros](primarios/vm/procedencia-copias.json). Solo se copiaron JSON y registros textuales; no muestras, EML completos, discos de VM ni claves.

## Capturas y limitaciones

[Registro completo de imágenes](capturas/registro-capturas.json): recurso, fuente, fecha UTC, método y hash de cada JPEG. Las capturas de VirusTotal son reales y posteriores a las consultas API. Las imágenes marcadas como vistas locales derivadas muestran JSON guardado: no son el correo renderizado, la consola original ni la web del proveedor. Se conservan los HTML locales para reproducir esa presentación sin recursos externos.

Las imágenes no se editaron. Algunas vistas truncan hashes; las propiedades y JSON conservan las huellas completas. La interfaz de VT y la API pueden presentar denominadores distintos al incluir/excluir errores y formatos no admitidos; se preserva cada fuente sin ajustar cifras.

## Pendientes reales

- En la fase local inicial no se ejecutaron muestras. Los PDF añadidos el 29/10 documentan ejecuciones posteriores en ANY.RUN, un sandbox de terceros con Windows 10 y red. Su resumen automático y sus indicadores no bastan para confirmar por separado toda la cadena de procesos, que las IP sean C2, exfiltración o infección fuera del sandbox.
- No se verificaron firmas DKIM criptográficamente ni SPF contra DNS histórico; las cabeceras son declaraciones del archivo. Una pantalla con pass no cambia esa limitación.
- MXToolbox completado para ambas IP: 0 listados; R004 con 1 timeout, R005 sin timeouts. Evidencia y revisión exacta de los cinco enlaces de correo en cierre/. No prueba legitimidad de los correos.
- El histórico de las URLs acortadas solo muestra el paso a www del mismo servicio; falta evidencia del destino final de la campaña. Las búsquedas urlscan no devolvieron resultados.
- Las tres URLs independientes ya tienen fichas. En U001 no se siguió el enlace externo de login; no se comprobó captación de credenciales. U003 mostró una página aparcada en el histórico, no una tienda fraudulenta demostrada. U002 no se descargó ni ejecutó.

## Integridad

[Manifiesto vigente](manifiesto-evidencias.json) y [SHA256SUMS](SHA256SUMS). El manifiesto actualizado incorpora los dos PDF originales y los cambios del informe y de este índice. Los archivos primarios previos conservan sus hashes. Este registro local no es una firma ni un sellado de tiempo externo.

## Bloque de URLs — alcance de búsqueda y veredictos

Las búsquedas exactas iniciales devolvieron no_results; se amplió a host/IP y se seleccionaron informes con task.url exactamente coincidente. Por ello una búsqueda vacía no se interpreta como ausencia global de históricos. El detalle inicial U001 respondió 403 sin clave y se preservó; luego se obtuvo con la clave ya configurada. El timeout inicial de crt.sh también se preserva junto al resultado posterior satisfactorio.

Los detalles urlscan muestran señales distintas entre overall, urlscan y engines. Se conservan esos bloques sin convertir “No classification” en limpio. En U002 se corroboró el hash y tamaño de la descarga entre urlscan y VT; en U001/U003 se documentan DNS actual NXDOMAIN y estados RDAP, sin atribuir la causa ni descartar los históricos.

Las vistas locales de evidencia se identifican como derivadas, incluidas las de correos. La versión 3 corrige etiquetas de presentación del registro que las describían como externas; las imágenes y los JSON fuente se conservaron sin cambios.

## Entrega preparada

El informe principal de esta carpeta está en README.md. Incluye la fase estática y el suplemento de ejecución ANY.RUN del 29/10. Las evidencias originales están en este directorio; no se incluyeron muestras ni claves. La revisión exacta de enlaces de correo y MXToolbox se agregaron en cierre/.
