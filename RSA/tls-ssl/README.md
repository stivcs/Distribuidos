
# ¿Qué es SSL/TLS?

SSL (Secure Sockets Layer) y su sucesor TLS (Transport Layer Security) son protocolos criptográficos que proporcionan comunicaciones seguras sobre una red. En este caso, se utiliza para:
* Cifrado: Proteger los datos transmitidos entre el cliente y el servidor.
* Autenticación: Verificar la identidad del servidor (y opcionalmente del cliente).
* Integridad: Asegurar que los datos no sean modificados durante la transmisión.
En este código, SSL/TLS se implementa usando el módulo ssl de Python, que envuelve los sockets para agregar una capa de seguridad.

## Requisitos

Para usar este código con SSL/TLS, necesitas:
* Certificado SSL y Clave Privada para el Servidor:
    * Un archivo de certificado (server.crt).
    * Un archivo de clave privada (server.key).
    * Estos archivos son necesarios para que el servidor pueda autenticarse y establecer una conexión segura.
* OpenSSL: Una herramienta para generar certificados autofirmados (instalada en la mayoría de sistemas Linux/Mac, o descargable para Windows).
* Python: Con los módulos ssl y cryptography instalados. Instala cryptography con:

Instale la libreria con:
```bash
  pip install cryptography
```

## Generación de Certificados Autofirmados
El código utiliza certificados autofirmados para pruebas. En un entorno de producción, deberías obtener certificados de una Autoridad Certificadora (CA) confiable. Para pruebas, sigue estos pasos:

Nota: "para instalar necesita el OpenSSL si tienes una terminal de gitbash correlos ahi"

* Generar la clave privada del servidor:
```bash
  openssl genrsa -out server.key 2048
```
Esto crea una clave privada RSA de 2048 bits en el archivo server.key.

* Generar una solicitud de certificado (CSR):
```bash
  openssl req -new -key server.key -out server.csr
```
  [+] Te pedirá información como país, organización, etc. Puedes usar valores ficticios para pruebas.

  [+] Esto genera un archivo server.csr.

* Generar un certificado autofirmado:
```bash
  openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
```
Esto crea un certificado válido por 365 días en el archivo server.crt.

### Nota
estos archivos tienen que estar en el mismo directorio de server

## Notas sobre Seguridad
* Certificados Autofirmados: El cliente usa context.verify_mode = ssl.CERT_NONE para aceptar certificados no confiables. En producción, elimina esta línea y usa context.load_verify_locations() con un certificado de CA confiable.
* IP y Puerto: Asegúrate de que la IP (192.168.60.28) y el puerto (12345) coincidan con los del servidor y estén accesibles en tu red.
* Firewall: Puede que necesites abrir el puerto 12345 en el firewall del servidor.
## Solución de Problemas
* Connection Refused: Verifica que el servidor esté corriendo y que la IP/puerto sean correctos.
* SSL Errors: Asegúrate de que los archivos server.crt y server.key existan y sean válidos.
* Mensajes no recibidos: Comprueba que los clientes estén conectados al mismo servidor.
## Authors

- [@stivcs](https://github.com/stivcs)

