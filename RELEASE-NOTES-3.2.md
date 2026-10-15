# Forensic Mobile Lab 3.2

- Recupera el motor de análisis avanzado y el runtime local para iPhone.
- Añade diagnóstico interno de Python, ADB, firma, privacidad, permisos y disco.
- Implementa firma Ed25519 real y estados diferenciados para casos legados.
- Implementa exportación `.fmlx` con PBKDF2 y AES-256-GCM por bloques.
- Corrige la navegación lateral mediante desplazamiento vertical.
- Añade autoridad legal, alcance autorizado e identificación del examinador.
- Protege carpetas y reportes con permisos privados.
- Evita dependencias circulares entre el manifiesto y la firma.
- Optimiza la interfaz para miles de artefactos y multimedia.
- Hace portables los expedientes mediante rutas relativas validadas y mantiene
  compatibilidad segura con rutas de la versión 3.1.
- Sella y verifica SHA-256 + Ed25519 antes de respaldar, exportar ZIP o cifrar.
- Reanuda RAW/DD solo tras comprobar el prefijo, estabilidad y hash final.
- Valida checkpoints y readquiere entradas alteradas en vez de confiar en ellas.
- Ejecuta el inventario de backups iPhone fuera del hilo de la interfaz.
- Añade un runtime universal de respaldo y Pillow compatible para Macs Intel;
  el mismo conjunto de pruebas se ejecuta en Python 3.12 y Python 3.9.
- Encadena y valida semánticamente custodia, anotaciones y auditoría de la app,
  incluso después de que alguien intente reconstruir los hashes externos.
- Registra y muestra protección, respaldos y exportaciones en la vista de
  cadena de custodia.
- Aísla el visor con almacenamiento web no persistente, bloqueo de red,
  navegación local validada e iframes sin scripts.
- Rechaza enlaces simbólicos y rutas externas en expedientes, bases de datos,
  APK, WhatsApp, backups iOS, imágenes de disco y vistas previas.
- Incluye en los sellos archivos ocultos y contenido de paquetes `.app`.
- Comprueba espacio libre antes de backups, ZIP, cifrado e iPhone, y construye
  el ZIP en una salida parcial antes de reemplazar el destino.
- Mueve comparación, búsqueda, redacción, protección e inventarios pesados
  fuera del hilo visual y permite una cancelación controlada.
- Incluye build reproducible, prueba desde DMG y pruebas adversariales de
  alteración, rutas, cifrado, reanudación y portabilidad.
- Declara motivos oficiales de privacidad para fechas de archivos y espacio en
  disco, sin seguimiento ni envío de esos datos fuera de la Mac.
- Serializa las tareas del Kit Forense, valida estabilidad durante hashing,
  rechaza fuentes enlazadas y limita OCR de imágenes excesivamente grandes.

Límite: la app realiza análisis y adquisición lógica autorizada. No desbloquea
equipos ni sustituye herramientas físicas certificadas o procedimientos del
laboratorio.
