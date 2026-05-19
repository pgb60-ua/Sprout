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

## Sistema de autorización

### Estado de admin calculado en login, no en tiempo real
El servidor incluye `IsAdmin bool` en la respuesta del login. El cliente lo guarda en
memoria y lo usa para mostrar u ocultar el menú de admin.
Si el usuario pierde el rol admin mientras tiene sesión activa, el menú seguirá visible
hasta el siguiente login — pero el servidor rechaza cualquier petición de admin con
"No autorizado" porque `requireRole` se comprueba en cada petición.
La seguridad real está en el servidor, no en el cliente.
