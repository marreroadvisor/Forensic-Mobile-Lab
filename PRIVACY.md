# Privacidad de Forensic Mobile Lab

Forensic Mobile Lab procesa localmente los datos que el usuario adquiere de dispositivos y archivos seleccionados. La aplicación no transmite evidencias, informes, identificadores de dispositivos ni contenido analizado a servidores del desarrollador.

El usuario es responsable de contar con autorización legal para examinar cada dispositivo o conjunto de datos. Los resultados y copias de evidencia permanecen en la ubicación elegida por el usuario.

La aplicación integra herramientas ADB para comunicarse con dispositivos Android autorizados. No utiliza seguimiento ni publicidad.

## APIs declaradas en el manifiesto

La app consulta fechas y metadatos de archivos para ordenar casos, construir
timelines y mostrarlos al examinador (`DDA9.1`, `3B52.1`). También consulta el
espacio libre para mostrar el diagnóstico y bloquear copias que no podrían
completarse de forma segura (`85F4.1`, `E174.1`). Esa información no se envía
fuera de la Mac. La aplicación no recopila datos para seguimiento.
