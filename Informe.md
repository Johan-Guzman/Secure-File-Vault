# Informe Técnico — Secure File Vault 
**Cifrador y descifrador de archivos con AES-256 en Java**

---

## 1. Introducción

En el marco del proyecto final de la asignatura de Ciberseguridad 2026-1, desarrollamos una aplicación de línea de comandos en Java denominada **Secure File Vault**, cuyo propósito es cifrar y descifrar archivos de cualquier tipo utilizando criptografía simétrica de nivel profesional. El programa permite al usuario proteger un archivo con una contraseña de su elección, de manera que el contenido quede completamente ilegible sin conocer esa contraseña, y posteriormente recuperar el archivo original verificando además su integridad. Para esto nos apoyamos en los estándares criptográficos **AES-256**, **PBKDF2WithHmacSHA256** y **SHA-256**, todos disponibles en la API estándar de Java (JCA/JCE).

---

## 2. Desarrollo del programa

### 2.1 Diseño de la arquitectura

Desde el inicio tomamos la decisión de separar las responsabilidades del sistema en cuatro clases bien diferenciadas, siguiendo el principio de responsabilidad única:

- **`CryptoUtils`** centraliza toda la lógica criptográfica: generación de salt e IV, derivación de clave con PBKDF2, cálculo del hash SHA-256 y conversión de bytes a hexadecimal. También define todas las constantes del proyecto (`SALT_SIZE`, `IV_SIZE`, `HASH_SIZE`, `ITERATIONS`, etc.), de modo que tanto el cifrador como el descifrador lean siempre los mismos valores sin repetir números en el código.
- **`FileEncryptor`** orquesta el proceso de cifrado: lee el archivo, genera el material criptográfico, cifra el contenido y escribe el archivo `.enc`.
- **`FileDecryptor`** realiza el proceso inverso: lee el archivo `.enc`, extrae sus partes, descifra el contenido y verifica la integridad antes de escribir el resultado.
- **`Main`** actúa como punto de entrada: presenta el menú al usuario, recopila las rutas y la contraseña, llama al módulo correspondiente y gestiona los errores de forma amigable.

Esta separación nos permitió trabajar en cada módulo de forma independiente y localizar rápidamente cualquier problema sin tener que recorrer un único archivo enorme.

### 2.2 Formato del archivo cifrado

Una de las primeras decisiones de diseño fue definir el formato binario del archivo `.enc`. Acordamos que el archivo tendría cuatro secciones contiguas escritas en el siguiente orden:

```
[salt · 16 bytes][IV · 16 bytes][hash SHA-256 · 32 bytes][datos cifrados · N bytes]
```

El **salt** y el **IV** son necesarios para reproducir exactamente la misma clave y el mismo estado inicial del cifrado al descifrar. Ambos se generan con `SecureRandom`, que es criptográficamente seguro, y se almacenan en claro en el archivo porque no son secretos: su función no es ocultar información, sino garantizar que la misma contraseña produzca resultados diferentes en cada uso. El **hash SHA-256** se calcula sobre el archivo original *antes* de cifrarlo y se almacena para que al descifrar podamos verificar que el contenido recuperado es idéntico al original, sin alteraciones.

### 2.3 Derivación de clave con PBKDF2

No utilizamos la contraseña directamente como clave AES. En su lugar, empleamos **PBKDF2WithHmacSHA256** con 65.536 iteraciones para derivar una clave de 256 bits a partir de la contraseña y el salt. Esta decisión es fundamental: si un atacante intentara adivinar la contraseña por fuerza bruta, tendría que ejecutar esas mismas 65.536 iteraciones por cada intento, lo que hace el ataque órdenes de magnitud más lento. Sin esta derivación, una contraseña corta como `"hola123"` sería trivialmente vulnerable.

### 2.4 Verificación de integridad

Al descifrar, no nos limitamos a entregar el resultado: primero calculamos el SHA-256 del contenido descifrado y lo comparamos con el hash que guardamos durante el cifrado. Si ambos coinciden, tenemos certeza de que el archivo fue recuperado correctamente y no fue alterado en ningún momento. Para esta comparación usamos `MessageDigest.isEqual` en lugar de `Arrays.equals`, ya que el primero opera en tiempo constante y evita ataques de temporización.

### 2.5 Manejo seguro de contraseñas

Utilizamos `char[]` en lugar de `String` para almacenar la contraseña en memoria. La razón es que los `String` en Java son inmutables y permanecen en el heap hasta que el recolector de basura los elimine, en un momento indeterminado. Con `char[]` podemos sobreescribir el contenido con `Arrays.fill(password, '\0')` en cuanto dejamos de necesitar la contraseña, reduciendo el tiempo que está expuesta en memoria. Esta limpieza la realizamos en un bloque `finally` para garantizar que ocurra incluso si el proceso lanza una excepción.

---

## 3. Dificultades encontradas

### 3.1 Entender por qué no se puede usar la contraseña directamente como clave

Al principio pensamos que bastaba con tomar los bytes de la contraseña y pasarlos al `SecretKeySpec`. Luego de revisar la documentación, entendimos que AES-256 exige exactamente 256 bits de clave, y que una contraseña de longitud arbitraria no cumple ese requisito directamente. Más importante aún, descubrimos que sin PBKDF2 la clave sería demasiado predecible para un atacante. Comprender el rol del salt como elemento que hace única cada derivación también nos tomó tiempo.

### 3.2 El modo CBC y el vector de inicialización

El modo CBC no fue intuitivo al principio. Entender que el IV "encadena" el primer bloque y que, sin él, dos archivos idénticos cifrados con la misma clave producirían los mismos primeros bytes fue un punto de quiebre conceptual importante. También nos costó entender por qué el IV puede almacenarse en claro junto al archivo cifrado sin comprometer la seguridad.

### 3.3 Calcular el hash antes o después del cifrado

Tuvimos una discusión sobre si el hash debía calcularse sobre el archivo original o sobre el archivo ya cifrado. Finalmente entendimos que calcularlo sobre el archivo **original** tiene más sentido: al descifrar, recalculamos el hash del resultado y lo comparamos; si coincide, sabemos que el descifrado fue correcto. Calcularlo sobre los datos cifrados no aportaría información sobre la integridad del contenido recuperado.

---

## 4. Conclusiones

El desarrollo de Secure File Vault nos permitió llevar a la práctica los conceptos teóricos de criptografía simétrica de una manera concreta y verificable. Comprendemos ahora que la seguridad de un sistema como este no depende de un único algoritmo, sino de la combinación correcta de varios mecanismos: una derivación de clave costosa computacionalmente (PBKDF2), un salt único por operación para evitar tablas precalculadas, un IV aleatorio para garantizar que el mismo contenido cifrado no produzca resultados idénticos, y un hash de integridad para detectar alteraciones o contraseñas incorrectas.

También aprendimos que la seguridad va más allá del algoritmo: el manejo cuidadoso de la contraseña en memoria, el uso de comparaciones en tiempo constante y el cierre garantizado de recursos son decisiones de implementación que marcan la diferencia entre un programa seguro y uno que, aunque use AES-256, tenga vulnerabilidades prácticas.

Consideramos que el objetivo del proyecto fue cumplido satisfactoriamente. El programa cifra y descifra archivos de cualquier tipo, verifica la integridad del contenido recuperado y maneja los errores de forma clara para el usuario final.

## Realizado por:

- Santiago Grajales Perez – A00402018
- Johan Stiven Guzmán – A00401480
- Adri Jhoanny Martinez Murillo – A00400842
