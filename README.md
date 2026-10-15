# Forensic Mobile Lab

**Anthony Marrero · aeternumintelligencecorp**

Aplicación de escritorio para macOS que permite adquirir y analizar datos de dispositivos autorizados, organizar expedientes, revisar artefactos y verificar integridad. Incluye interfaz Swift/AppKit, motores Python y un verificador independiente.

## Descargar

[Descargar Forensic Mobile Lab 3.2.0 para Mac](https://github.com/jessiel212/Forensic-Mobile-Lab/releases/download/v3.2.0/Forensic-Mobile-Lab-3.2.0-macOS-universal.zip) · [Guía de uso](GUIA.md) · [Cambios](RELEASE-NOTES-3.2.md)

Requiere **macOS 13 o posterior**. Ejecutables universales Apple Silicon e Intel; el conector automático iPhone está optimizado para Apple Silicon. La revisión de backups existentes está disponible en Intel.

**Versión experimental con firma local, sin notarización de Apple.** macOS puede impedir abrir una descarga. No desactives las protecciones del sistema. La firma Developer ID y la notarización siguen pendientes.

## Funciones

- Adquisición lógica autorizada, ingesta de archivos y análisis de backups existentes.
- Catálogo de artefactos, búsqueda, multimedia, comparación y reportes.
- Hashes SHA-256, manifiestos, cadena de custodia y firmas Ed25519.
- Exportación portátil y contenedores cifrados FMLX.
- Herramientas de hashing y OCR; datos procesados localmente.

No desbloquea equipos ni evita cifrado, root, sandbox o controles del dispositivo. No sustituye validación pericial, hardware especializado ni procedimientos de laboratorio. Las firmas internas verifican integridad; no son certificaciones externas.

## Código y pruebas

El repositorio contiene el código propio, pruebas con datos sintéticos, icono y avisos. No contiene expedientes, claves de firma, credenciales, dispositivos ni datos personales.

Para ejecutar pruebas del motor usa Python con Pillow. `zsh test.sh` ejecuta las pruebas Python y verifica el código Swift; necesita Xcode o sus herramientas de desarrollo en macOS. Las pruebas crean sus propios datos temporales y no conectan dispositivos.

## Compilar la aplicación

La interfaz y el verificador se compilan desde este repositorio. Los runtimes de Python/ADB y paquetes de terceros se toman de una copia descomprimida de la descarga 3.2; esta receta **no reconstruye esos runtimes desde cero**.

```sh
FML_RUNTIME_APP="/ruta/Forensic Mobile Lab.app" zsh build.sh
```

El resultado queda en `dist/Forensic-Mobile-Lab-3.2.0-macOS-universal.zip`. El proceso copia únicamente los runtimes indicados; no copia expedientes de la app ni tu biblioteca personal. No modifica la app utilizada como origen. Los conectores iPhone y WhatsApp conservan sus dependencias opcionales.

## Licencias y contribuciones

Código propio: [MIT](LICENSE). [Dependencias y licencias](DEPENDENCIES.md). Cada componente de terceros conserva sus condiciones; las fuentes complementarias se adjuntan a la versión publicada.

Para reportar errores o proponer mejoras, abre un issue con pasos reproducibles y datos sintéticos. No adjuntes expedientes, identificadores de dispositivos, claves ni información personal.
