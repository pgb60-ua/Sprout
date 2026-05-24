# Decisiones de diseño — Sprout

## Autenticación y contraseñas

### Argon2id para hashing de contraseñas
Se eligió Argon2id (ganador de Password Hashing Competition 2015) sobre SHA256 o bcrypt.
Argon2id combina resistencia a ataques de GPU (Argon2d) y a ataques de canal lateral (Argon2i).
Parámetros: `t=1, m=64MB, p=4`. Formato PHC con salt embebido en el hash.

### DummyHash para prevenir timing oracle
Cuando un usuario no existe, se ejecuta igualmente un hash ficticio antes de devolver error.
Sin esto, el tiempo de respuesta delataría si el usuario existe o no.

### Tokens de sesión sin JWT
Se usan tokens aleatorios (`crypto/rand`, hex, 16 bytes) con expiración almacenada en la DB.
JWT añade complejidad (firma, renovación, revocación) sin beneficio real para este proyecto.
La expiración se comprueba en cada petición al deserializar la sesión.

### Rate limiting con ventana deslizante
Máximo 5 intentos en 30 segundos, bloqueo de 30 segundos al superarlos.
El contador se resetea solo al hacer login correcto, no por tiempo.

---

## TOTP

### Implementación desde cero (RFC 6238)
HMAC-SHA1 del contador de periodos de 30 segundos, truncado a 6 dígitos.
Se implementó sin librería para entender el algoritmo.

### Tolerancia de ±1 periodo
Se verifican el código anterior, el actual y el siguiente para dar margen al desfase de reloj del usuario.

### Prevención de replay con LastCode
El último código TOTP usado se almacena en la DB. Si se reutiliza el mismo código se rechaza,
aunque siga siendo válido por tiempo.

### Flujo de login con TempToken
Si el usuario tiene TOTP activo, el login con contraseña devuelve `RequiresTOTP: true` y un TempToken temporal.
El cliente usa ese TempToken para completar el login con el código TOTP.
El TempToken expira independientemente de la sesión.

---

## Clave pública Ed25519

### Ed25519 sobre RSA
Ed25519 ofrece seguridad equivalente a RSA-3000 con claves de 32 bytes.
Más rápido, más pequeño y más difícil de implementar mal.

### Cifrado de clave privada con AES-256-GCM + Argon2id
La clave privada se cifra en disco con la contraseña del usuario.
KDF: Argon2id (mismo que passwords). Cifrado: AES-256-GCM (cifrado autenticado).
La autenticación del cifrado protege contra modificación del archivo.

### Nombre de archivo = SHA256(username)
El nombre del archivo `.key` no revela qué usuarios tienen clave registrada.

### Escritura atómica (write-then-rename)
Se escribe en un `.tmp` y luego se renombra para evitar corrupción si el proceso muere a mitad.

### Formato de archivo versionado
El archivo `.key` es un JSON con campos `version`, `kdf`, `cipher`, `salt`, `encrypted`.
Permite migrar a nuevos algoritmos en el futuro sin romper compatibilidad.

**Tradeoff documentado:** Se eligió AES-GCM sobre añadir HMAC externo porque AES-GCM
ya incluye autenticación. Añadir HMAC sería redundante.

### La contraseña de cifrado es la misma que la de login
El usuario solo introduce la contraseña una vez en el login.
Esa misma contraseña descifra la clave privada para firmar el challenge.
Pedir una contraseña distinta sería confuso y no añadiría seguridad real.

### Verificación de contraseña con ActionVerifyPassword
Para activar la clave pública, se verifica la contraseña contra el servidor antes de cifrar.
Se usa un endpoint dedicado (`ActionVerifyPassword`) en vez de `ActionLogin` para no consumir
intentos del rate limiter.

### Orden: enviar clave pública primero, luego persistir privada
Si se guarda la privada en disco antes de que el servidor confirme, puede quedar un archivo
huérfano si el servidor rechaza la clave. Invertir el orden evita esta inconsistencia.

### Borrar archivo local al desactivar
Al desactivar la autenticación por clave, se elimina el archivo `.key` del disco.
Una clave privada que ya no sirve no debería permanecer en disco.

### Challenge-response con Ed25519
Flujo de login con clave activa:
1. Login con contraseña → servidor devuelve challenge aleatorio + TempToken
2. Cliente firma el challenge con su clave privada
3. Servidor verifica la firma con la clave pública almacenada → crea sesión

---

## Sistema de roles

### Roles dinámicos
Se optó por roles dinámicos (creables en tiempo de ejecución) en vez de roles hardcodeados.
Los roles `admin` y `user` se crean por defecto al inicializar la store pero el sistema
permite crear cualquier rol adicional.

### Refactorización: roles en la DB principal
Decisión inicial: `roles.db` separada, abierta en `ReadOnly` por el servidor para prevenir
escalado de privilegios vía la API. El CLI de admin abría la DB en escritura.

**Decisión final (recomendación del profesor):** Los roles van en la DB principal (`sprout.db`)
como namespaces adicionales (`"roles"`, `"user_roles"`). El acceso a gestionar roles se
controla mediante el propio sistema de roles (solo admins pueden modificarlos), no con
permisos de SO ni con un CLI externo.

El CLI externo se elimina porque duplica lógica del servidor.

### RoleStore como paquete separado
Aunque los datos van en la DB principal, la lógica de roles permanece encapsulada en
`pkg/roles` con su propio `RoleStore`. Recibe un `store.Store` ya abierto en vez de
abrir su propia DB.
Ventaja: lógica testeable de forma independiente, desacoplada del servidor.

### Atomicidad en operaciones multi-namespace (opción A)
Al pasar de `*bolt.DB` a `store.Store`, se pierde la atomicidad de operaciones que tocan
varios namespaces (ej. `DeleteRole` borra el rol y limpia `user_roles`).
Opciones evaluadas:
- **Opción A** (aceptar inconsistencia): elegida. Limitación conocida y documentada.
- **Opción B** (añadir `Transaction` a la interfaz): evaluada e iniciada, descartada por añadir complejidad innecesaria para el scope del proyecto.
- **Opción C** (acoplarse a bbolt): rompe la abstracción.
- **Opción D** (operaciones compensatorias): demasiado compleja, propensa a errores.

---

## Seguridad de la base de datos de roles

### Firma del archivo de roles (descartada)
Se consideró firmar `roles.db` con una clave del admin para detectar modificaciones externas.
Descartada por complejidad fuera del scope del proyecto.
La protección real viene del cifrado en reposo y los permisos del SO sobre el archivo.

---

## Factores de autenticación múltiples

### Un factor a la vez (limitación actual)
Si el usuario tiene TOTP y clave pública activos simultáneamente, el servidor aplica
solo el primero que encuentra en el orden de comprobación.
Combinar ambos factores en un flujo secuencial es una mejora futura identificada.

### El usuario elige el factor (mejora futura identificada)
En vez de que el servidor decida qué factor aplicar, el servidor podría devolver
los factores disponibles y el cliente preguntaría al usuario cuál usar.

---

## Bootstrap del primer administrador

### Variable de entorno SPROUT_ADMIN
No hay forma de asignar el rol admin mediante la API sin tener ya un admin (problema del huevo y la gallina).
Solución: al arrancar el servidor, si la variable de entorno `SPROUT_ADMIN` está definida y el usuario
existe en la DB, se le asigna el rol `admin` automáticamente (si no lo tenía ya).

Flujo de uso:
1. Arrancar el servidor sin la variable → registrar el usuario deseado
2. Parar el servidor
3. Arrancar con `SPROUT_ADMIN=<usuario>` → el servidor asigna el rol admin al arrancar

Si el usuario no existe en la DB, la variable se ignora silenciosamente.
Se eligió esta opción sobre "primer usuario registrado = admin" para evitar condiciones de carrera
y dar control explícito al operador del servidor.

---

## Sistema de autorización

### Estado de admin calculado en login, no en tiempo real
El servidor incluye `IsAdmin bool` en la respuesta del login. El cliente lo guarda en
memoria y lo usa para mostrar u ocultar el menú de admin.
Si el usuario pierde el rol admin mientras tiene sesión activa, el menú seguirá visible
hasta el siguiente login — pero el servidor rechaza cualquier petición de admin con
"No autorizado" porque `requireRole` se comprueba en cada petición.
La seguridad real está en el servidor, no en el cliente.

### No se detecta pérdida de admin en tiempo real (decisión consciente)
Se consideró añadir un campo `Forbidden bool` en `api.Response` para que el servidor lo señalara
al rechazar una petición de admin, y el cliente limpiara `isAdmin` al recibirlo (patrón análogo
a `SessionExpired`). Se descartó: añade complejidad en 6 handlers y en el cliente para un caso
edge (admin se quita sus propios permisos con sesión activa) que es cosmético, no de seguridad.
El servidor ya rechaza cada petición individualmente mediante `requireRole`.

---

## Metadatos de ficheros

### Metadatos cifrados en bbolt
Los metadatos de ficheros y carpetas se almacenan en un namespace propio (`file_metadata`).
Aunque bbolt no cifra buckets ni claves, los valores se cifran antes de guardarse usando
AES-GCM y una subclave derivada de la DEK de sesión del usuario.

El valor guardado es un `gcmBlob` con `Version`, `Nonce` y `Ciphertext`.
El JSON con los campos de metadatos solo existe en claro en memoria, antes de cifrar o después
de descifrar.

La clave de cifrado de cada entrada usa el contexto del dato:
`deriveSubkey(dek, "file_metadata:"+normalizedPath, dekLen)`.
Así, los metadatos quedan integrados en el modelo de cifrado existente y no se introduce
un secreto nuevo que el usuario tenga que gestionar.

### Claves opacas para no exponer rutas
No se guardan rutas en claro como claves de bbolt.
La clave de índice se deriva con `deriveSubkey(dek, "file_metadata_index", dekLen)` y se usa
como clave HMAC-SHA256 sobre la ruta normalizada.

La clave final del registro combina el usuario con ese HMAC:
`<username>\x00<hex(HMAC(file_metadata_index, normalized-path))>`.

Esto evita entradas visibles como `alice:docs/nota.txt` dentro de `server.db`.
Limitaciones aceptadas:
- los nombres de buckets siguen siendo visibles porque bbolt no los cifra;
- el nombre de usuario sigue formando parte de la clave;
- las claves del namespace `file_timestamps` no se han migrado a HMAC y siguen usando
  `username + "\x00" + reqPath`.

### Separación entre metadatos y detección de cambios externos
El proyecto ya mantiene timestamps cifrados en `file_timestamps` mediante `storeFileTimestamp`
y `checkFileTimestamp`.
Los metadatos tienen sus propios campos `CreatedAt`, `ModifiedAt` y `AccessedAt`, pero no sustituyen
esa lógica.

Regla decidida:
- `createFile` sigue guardando el timestamp de control.
- `modifyFile` valida el timestamp antes de escribir, guarda el nuevo timestamp y actualiza `ModifiedAt`.
- `readFile` valida el timestamp antes de descifrar y actualiza `AccessedAt` si puede guardar metadatos.
- `deleteFile` borra el timestamp asociado.
- `deleteDir` borra los timestamps del árbol mediante prefijo.
- La detección de modificaciones externas sigue dependiendo de `file_timestamps`.

Los valores de `file_timestamps` están cifrados con una subclave
`deriveSubkey(baseDEK, "timestamp:"+reqPath, dekLen)`, pero sus claves de bbolt todavía exponen
usuario y ruta.

### API específica para consulta y actualización
Se añaden dos acciones:
`getFileMetadata` y `updateFileMetadata`.

La respuesta puede incluir un `FileMetadata` individual o entradas enriquecidas en listados mediante
`FileEntries`, manteniendo también `Files []string` para no romper el cliente existente.

Los metadatos incluyen:
- ruta
- nombre
- si es fichero o carpeta
- tamaño
- propietario
- permisos lógicos
- fechas de creación, modificación y acceso
- plataforma

### Metadatos creados de forma perezosa
`ensureFileMetadata` intenta cargar los metadatos existentes y, si no existen, los crea a partir
del estado actual del fichero o carpeta.
Esto permite que `getFileMetadata` y `listFiles` reparen entradas antiguas o incompletas generando
metadatos en el primer acceso.

La carpeta raíz lógica del usuario se trata como metadato virtual:
- `rootFileMetadata` genera una entrada en memoria con permisos `rwx------`;
- no se persiste en `file_metadata`;
- se usa para calcular permisos efectivos en rutas hijas.

### Permisos lógicos y rol/grupo asociado desde la API
En esta fase `updateFileMetadata` permite cambiar `Permissions`, recibido en `Request.Data`,
o asociar un rol/grupo mediante `Request.Role`.
El cliente separa ambas operaciones en opciones distintas para no mezclar la edición de permisos
lógicos con la asignación del grupo.
El rol indicado se valida con `RoleStore.RoleExists` antes de persistirse.
No se permite modificar `Owner` porque el sistema todavía no implementa compartición real,
transferencia de propiedad ni redistribución de claves entre usuarios.

### Carpeta compartida con dueño único
Se decidió implementar la compartición de forma simple: cada carpeta compartida tiene un único
dueño y solo ese usuario puede añadir o quitar miembros.

La pertenencia se modela con un rol por carpeta usando la convención `compartida_<owner>`.
Así se reutiliza el sistema de roles existente sin introducir ACLs nuevas para cada fichero.

En esta versión existe una carpeta física compartida para cada dueño bajo
`data/files/shared/<owner>`. El directorio raíz visible para los usuarios es
`compartida_<owner>` y su contenido reside en `data/files/shared/<owner>/compartida_<owner>`.
Cada carpeta compartida tiene su propia clave de cifrado y un rol `compartida_<owner>` que
gestiona la pertenencia. El dueño (`owner`) actúa como administrador de esa carpeta y es el único
capaz de añadir o quitar miembros.

Los permisos son lógicos de Sprout, no permisos reales del sistema operativo ni un mecanismo de
compartición por sí mismos.
Valores iniciales:
- ficheros: `rw-------`
- carpetas: `rwx------`

El formato aceptado tiene 9 caracteres y cada tripleta debe respetar el orden `rwx`, permitiendo
usar `-` para permisos desactivados. La primera tripleta aplica al propietario (`Owner`), la segunda
a usuarios que tengan el rol/grupo asociado al metadato (`Role`) y la tercera a otros usuarios.

No se permite modificar permisos de la carpeta raíz del usuario (`.` o ruta normalizada vacía).

### Gestión y filtrado por Etiquetas (Tags)
Los tags se han implementado como un atributo dentro de la estructura `FileMetadata`, por lo que heredan todas sus garantías de seguridad nativas.
- **Cifrado en reposo:** Los tags se cifran de forma transparente junto al resto de metadatos utilizando AES-256-GCM. La clave utilizada es una subclave derivada del contexto del dato (`dek` de sesión o `dek` de carpeta compartida). Esto significa que un atacante no puede saber qué tags se están usando ni en qué ficheros.
- **Autorización y Control de Acceso:** No hay "tags públicos". La operación de filtrar por tags está protegida por una validación de permisos de lectura (`r`) sobre la ruta en la que se inicie la búsqueda, así mismo para añadirlos se requieren permisos lógicos (como escritura).
- **Integridad de búsqueda en Carpetas Compartidas:** Tal como ocurre con la lectura de ficheros, la búsqueda de tags en una carpeta compartida (`compartida_<owner>`) resuelve primero el contexto (`resolveFileAccessContext`). Esto significa que si un miembro de la carpeta realiza el filtro por tag, usará implícitamente la clave compartida sin exponerla, y obtendrá todos los ficheros de la carpeta compartida que posean ese tag. Así, los metadatos actúan de manera colaborativa pero estrictamente acotada a quienes tienen acceso.
- **Sanitización Robusta:** Los inputs provenientes del cliente referidos a los tags se iteran para aplicar `strings.TrimSpace`, ignorar cadenas vacías, de-duplicar resultados usando un mapa interno lógico y, finalmente, ordenarlos alfabéticamente antes de enviarse o persistirse, minimizando inyección de bytes basura o redundancia ineficiente.

### Seguridad de carpetas compartidas
Cada carpeta compartida tiene su propia clave de cifrado, guardada en la DB bajo el namespace
`shared_folder_keys` y asociada al dueño. Así se evita reutilizar la DEK personal del usuario para
contenido compartido.

Las rutas compartidas se resuelven con `resolveFileAccessContext`, que distingue entre rutas
personales y rutas que empiezan por `compartida_<owner>`. Si la ruta es compartida, el servidor:
- comprueba que el usuario es el dueño o tiene el rol `compartida_<owner>`;
- usa la clave compartida de esa carpeta para cifrar y descifrar contenido;
- opera sobre `data/files/shared/<owner>/compartida_<owner>/...`;
- guarda metadatos y timestamps usando el dueño como `storageUser`.

Los elementos creados dentro de una compartida heredan permisos de grupo por defecto:
- directorios: `rwxrwx---`
- ficheros: `rw-rw----`

Además, la metadata creada en compartidas guarda el `Role` `compartida_<owner>` para que la
evaluación de permisos reconozca a los miembros como grupo autorizado. Sin ese campo, el sistema
caería en la tripleta de "otros" y bloquearía el acceso aunque el usuario fuese miembro.

El dueño es el único que puede administrar miembros. La interfaz de cliente no expone un acceso
genérico a compartir cualquier carpeta: la gestión se limita a la compartida del usuario activo,
que simplifica el modelo y reduce errores de autorización.

No se permite borrar la carpeta compartida base del dueño. Esto protege la estructura raíz que
ancla la clave compartida, la metadata y la pertenencia del grupo.

### Metadatos iniciales derivados del sistema y de la sesión
Al crear ficheros o carpetas se generan metadatos iniciales:
- `Owner`: usuario autenticado
- `CreatedAt`: `time.Now().UTC()`
- `ModifiedAt`: `time.Now().UTC()`
- `Platform`: `runtime.GOOS`
- `Name`, `Size` e `IsDir`: derivados de `os.Stat`

La ruta se normaliza antes de calcular claves, cifrar y devolver datos.
Todas las operaciones requieren sesión válida, DEK disponible mediante `getSessionKey` y ruta validada
con `safePath`.

### Permisos lógicos aplicados a operaciones de ficheros
Los permisos no son solo informativos: el servidor los consulta antes de ejecutar operaciones.
La comprobación se hace sobre el árbol de ancestros, empezando por la raíz virtual del usuario.
Si cualquier elemento del camino no concede el permiso requerido, la operación se rechaza.
Para cada elemento del árbol, el servidor elige la tripleta efectiva así:
- si el usuario autenticado es `Owner`, usa la primera tripleta;
- si no es propietario pero tiene el rol guardado en `Role`, usa la segunda tripleta;
- en el resto de casos, usa la tercera tripleta.

Esta autorización solo decide si una operación debería permitirse lógicamente. No implementa por sí
misma descubrimiento de ficheros ajenos, rutas compartidas, ficheros públicos ni redistribución de
claves para descifrar contenido; esas responsabilidades pertenecen a la funcionalidad de compartición.

Reglas aplicadas:
- `readFile` requiere permiso `r` en todos los ancestros y en el fichero.
- `modifyFile` requiere permiso `w` en todos los ancestros y en el fichero.
- `deleteFile` requiere permiso `w` en todos los ancestros y en el fichero.
- `listFiles` requiere permiso `r` en todos los ancestros y en el directorio listado.
- `createFile` y `createDir` requieren permiso `w` en todos los ancestros y en el directorio padre.
- `deleteDir` requiere permiso `w` en todos los ancestros y en el directorio eliminado.

`getFileMetadata` y `updateFileMetadata` requieren token válido, ruta segura, fichero o carpeta
existente y DEK de sesión, pero no aplican una comprobación adicional de permisos lógicos.

### Integración con operaciones de ficheros
Las operaciones existentes se amplían sin cambiar su contrato principal:
- `createFile`: crea metadatos iniciales después de escribir y guardar timestamp.
- `modifyFile`: actualiza contenido, timestamp y `ModifiedAt`.
- `readFile`: actualiza `AccessedAt`.
- `deleteFile`: elimina fichero, timestamp y metadatos.
- `createDir`: crea metadatos iniciales del directorio.
- `deleteDir`: elimina metadatos y timestamps de la carpeta y de sus hijos antes de `os.RemoveAll`.
- `listFiles`: devuelve la lista clásica y, además, entradas con metadatos.
- al borrar el último fichero o carpeta, se elimina la raíz física vacía del usuario.

### Cliente CLI
El menú de gestión de ficheros incorpora opciones para ver metadatos y modificar permisos lógicos.
La vista muestra ruta, propietario, permisos, tamaño, fechas, plataforma y si la entrada es fichero
o carpeta.

El cliente también muestra el árbol de permisos efectivos antes de leer, modificar o borrar, para
que el usuario vea qué permiso de la ruta puede bloquear la operación.

Si el servidor devuelve un error de timestamp en operaciones de lectura o modificación, el cliente
reutiliza el flujo existente para ofrecer borrar ficheros fuera de sincronía.
