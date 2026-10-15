# Seguridad y verificación independiente

Forensic Mobile Lab 3.2 realiza adquisiciones lógicas autorizadas. No evade el
bloqueo, el cifrado, el sandbox, root ni el bootloader; tampoco presenta como
“borrado confirmado” un archivo residual que todavía sea visible mediante ADB.

## Integridad del expediente

Cada adquisición contiene hashes SHA-256 y CRC32, un manifiesto maestro y una
cadena de eventos. `ForensicVerifier` añade una firma Ed25519 independiente que
registra cada archivo del expediente, salvo el propio sello para evitar una
dependencia circular. La clave privada local se guarda con permisos `0600` en
Application Support; la clave pública y su huella viajan dentro del sello.
El inventario firmado incluye archivos ocultos y descendientes de paquetes
`.app`. Los enlaces simbólicos se rechazan para impedir que un expediente haga
referencia silenciosamente a datos fuera de su carpeta.

Además de comprobar archivos, el motor valida el encadenamiento semántico de la
cadena de custodia, las anotaciones del examinador y la auditoría de acciones de
la aplicación. Volver a calcular un manifiesto no vuelve válida una cadena de
eventos manipulada.

Verificación desde Terminal, sin abrir la interfaz:

```bash
"/Applications/Forensic Mobile Lab.app/Contents/Resources/ForensicVerifier" \
  verify "/ruta/al/expediente"
```

## Exportación protegida

Los archivos `.fmlx` usan PBKDF2-HMAC-SHA256 (200.000 iteraciones) y bloques
AES-256-GCM autenticados de 4 MiB. La contraseña entra por entrada estándar y
nunca se guarda en el expediente ni en los argumentos del proceso.

La exportación ZIP se prepara en un archivo parcial y solo sustituye el destino
cuando termina. Los respaldos se comparan archivo por archivo mediante SHA-256.
Antes de copiar, la app comprueba el espacio libre y vuelve a sellar el caso.

```bash
printf '%s' 'contraseña-de-al-menos-12-caracteres' | \
  "/Applications/Forensic Mobile Lab.app/Contents/Resources/ForensicVerifier" \
  decrypt caso.fmlx caso-master.zip
```

## Visor y privacidad

El visor integrado no conserva cookies ni permite conexiones HTTP/HTTPS. Solo
abre recursos que resuelven dentro del expediente activo y bloquea rutas
externas aportadas por reportes manipulados. El HTML adquirido se previsualiza
en un iframe aislado sin ejecución de scripts.

Los expedientes y perfiles se crean con permisos privados. Las claves, archivos
temporales cifrados y exportaciones maestras usan permisos `0600`.

## Compatibilidad

La aplicación y el verificador son universales (`arm64` y `x86_64`). En Apple
Silicon usa Python 3.12 autocontenido; en Mac Intel usa el runtime universal
Python 3.9 y Pillow 11.3 verificados por la misma suite. El conector automático
de iPhone está optimizado para Apple Silicon; la ingesta de backups existentes
sigue disponible como alternativa autorizada.

## Distribución de macOS

El DMG de desarrollo usa firma ad-hoc y Hardened Runtime. Para distribución
pública se requiere firmar con un certificado Apple Developer ID y notarizar
con la cuenta del propietario. La compilación local no crea ni usa esas
credenciales automáticamente.
