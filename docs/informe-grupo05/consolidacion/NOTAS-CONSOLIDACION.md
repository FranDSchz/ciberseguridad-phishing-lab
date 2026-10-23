# Revisión de consolidación

| Punto | Aporte / diferencia | Decisión en el informe consolidado |
| :--- | :--- | :--- |
| Conteo | PDF independiente: 7 maliciosos; propio anterior: 3 maliciosos y 4 sospechosos | 4 maliciosos y 3 sospechosos tras corroborar pnreap |
| R004 | Recurso remoto pnreap con 12 detecciones | Corroboración de URL exacta y dominio. Malicioso por recurso remoto, confianza media. Sin robo de credenciales confirmado |
| R005 | Dominio con 7 detecciones; URLs sin informe | Sospechoso. No se hereda automáticamente el veredicto del dominio |
| U001 / U003 | Pocas detecciones URL y motores ML 90/73 | Mantener señales contradictorias y clasificación sospechosa; no afirmar captación de credenciales |
| U002 | El PDF llama script a bin.sh | Histórico exacto: ELF MIPS; hash/tamaño coincidentes y 50 detecciones en VT |
| ValleyRAT | El PDF lo afirma como familia de ambos archivos | Atribución de terceros. Sin familia única determinada localmente ni ejecución observada |
| Fechas / edad | 78/42 días en históricos y 86/49 en consultas actuales | Conservar fecha de observación; no confundir edad histórica con edad al revisar |
| Entorno | PDF: ZIP cerrados, sin VM local y escaneos unlisted; propio: extracción en VM y GET de reportes | Documentar ambas ramas sin inventar un procedimiento único |
| URLscan | TXT registra escaneos nuevos unlisted previos del compañero | No repetirlos ni presentarlos como búsquedas propias. Distinguir los históricos public principales |
| IP y C-I-A | El PDF da por controlado el equipo y recomienda aislar/cambiar claves de forma general | Impacto potencial; respuesta condicionada a ejecución o interacción real |
| Imágenes benignas | Fuente clasifica imágenes como limpias por 0 detecciones y antigüedad | Ausencia de confirmación maliciosa, sin legítimo acreditado |
| TXT | Algunos anexos JSON están resumidos/truncados por la herramienta original | Fuentes documentales, no sustituto de las respuestas brutas preservadas |

No se modificaron el PDF original ni los TXT aportados en origen. No se generaron nuevas solicitudes de escaneo ni se ejecutó material del set.
