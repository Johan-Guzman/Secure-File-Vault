import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/*
 * Clase de utilidades criptográficas compartidas por todo el proyecto.
 *
 * Centralizamos aquí la generación de material criptográfico (salt, IV),
 * la derivación de claves a partir de contraseñas usando PBKDF2, el cálculo
 * del hash SHA-256 para verificación de integridad y la conversión de bytes
 * a representación hexadecimal.
 *
 * Esta clase no debe instanciarse: todos sus miembros son estáticos.
 * La utilizan tanto FileEncryptor como FileDecryptor.
 */
public final class CryptoUtils {

    // =========================================================================
    // CONSTANTES DEL PROYECTO
    //
    // Centralizamos todos los parámetros criptográficos aquí para que
    // FileEncryptor y FileDecryptor lean siempre los mismos valores.
    // Cualquier ajuste se hace en un único lugar y se propaga automáticamente
    // a todo el sistema.
    // =========================================================================
 
    /* Nombre del algoritmo de cifrado simétrico: AES (Advanced Encryption Standard).
     * Lo pasamos al construir el SecretKeySpec. */
    public static final String ALGORITHM = "AES";

    /* Transformación completa para el cifrado.
     *
     * AES          : cifrado simétrico por bloques de 128 bits.
     * CBC          : modo Cipher Block Chaining; cada bloque se combina con el
     *                bloque anterior antes de cifrarse, lo que requiere un IV inicial.
     * PKCS5Padding : rellena el último bloque hasta completar 16 bytes.
     *                Si la contraseña es incorrecta al descifrar, este padding
     *                lanzará BadPaddingException, que capturamos como señal de error. */
    public static final String CIPHER_MODE = "AES/CBC/PKCS5Padding";

    /* Algoritmo de derivación de clave a partir de contraseña.
     * PBKDF2 con HMAC-SHA-256 aplica la función de hash miles de veces
     * (ver ITERATIONS) para que derivar la clave sea computacionalmente costoso
     * y así dificultar los ataques de fuerza bruta y de diccionario. */
    public static final String KEY_ALGO = "PBKDF2WithHmacSHA256";

    /* Algoritmo de hash para verificar la integridad del archivo descifrado.
     * SHA-256 produce un resumen de 256 bits (32 bytes) prácticamente imposible
     * de invertir o colisionar intencionalmente.
     * Definimos el nombre como constante para no repetir el literal "SHA-256"
     * disperso por el código. */
    public static final String HASH_ALGO = "SHA-256";

    /* Número de iteraciones que PBKDF2 aplica internamente.
     * 65536 es el mínimo recomendado por NIST SP 800-132 para SHA-256.
     * Un atacante que intente adivinar la contraseña debe repetir estas mismas
     * iteraciones por cada intento, lo que hace los ataques de fuerza bruta
     * órdenes de magnitud más lentos. Este valor no debe reducirse. */
    public static final int ITERATIONS = 65_536;

    /* Longitud de la clave AES en bits (256 bits = 32 bytes).
     * AES-256 es la variante más segura del estándar y la que requiere el proyecto. */
    public static final int KEY_LENGTH = 256;

    /* Tamaño del salt en bytes (16 bytes = 128 bits).
     * El salt es un valor aleatorio único por cada operación de cifrado que se
     * combina con la contraseña antes de derivar la clave. Esto garantiza que la
     * misma contraseña produzca claves distintas en cada uso, lo que impide los
     * ataques con tablas precalculadas (rainbow tables). */
    public static final int SALT_SIZE = 16;

    /* Tamaño del vector de inicialización (IV) en bytes (16 bytes = 128 bits).
     * AES en modo CBC exige un IV del mismo tamaño que su bloque: 128 bits.
     * El IV debe ser único e impredecible en cada cifrado; nunca un valor fijo. */
    public static final int IV_SIZE = 16;

    /* Tamaño del hash SHA-256 en bytes (32 bytes = 256 bits).
     * Esta constante permite que FileDecryptor extraiga el hash del archivo cifrado
     * sin necesidad de escribir el número 32 directamente en el código. */
    public static final int HASH_SIZE = 32;

    // =========================================================================
    // INSTANCIA COMPARTIDA DE SecureRandom
    //
    // Creamos una sola instancia estática en lugar de construir una nueva en
    // cada llamada a generateSalt() o generateIV(). La inicialización de
    // SecureRandom implica recolectar entropía del sistema operativo, lo cual
    // es costoso si se repite innecesariamente. SecureRandom es thread-safe,
    // por lo que compartir la instancia es seguro.
    // =========================================================================
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /* Constructor privado para impedir la instanciación accidental.
     * Todas las utilidades son métodos estáticos; crear objetos de esta clase
     * no tendría sentido. Lanzamos AssertionError como capa adicional de protección. */
    private CryptoUtils() {
        throw new AssertionError("CryptoUtils no debe instanciarse.");
    }

    // =========================================================================
    // MÉTODO: deriveKey
    // =========================================================================
 
    /*
     * Deriva una clave AES de 256 bits a partir de una contraseña y un salt
     * usando PBKDF2 con HMAC-SHA-256.
     *
     * Recibimos la contraseña como char[] en lugar de String porque los String
     * en Java son inmutables: una vez creados permanecen en el heap hasta que el
     * Garbage Collector los recolecte, en un momento indeterminado. Con char[]
     * podemos sobreescribir su contenido con Arrays.fill(password, '\0') en cuanto
     * terminamos de usarlo, reduciendo el tiempo que la contraseña permanece
     * legible en memoria.
     *
     * NoSuchAlgorithmException e InvalidKeySpecException solo ocurrirían si
     * PBKDF2WithHmacSHA256 no estuviera disponible en la JVM, lo cual es imposible
     * en cualquier JDK moderno (Java 8+). Las envolvemos en IllegalStateException
     * para simplificar las firmas de los métodos que llaman a deriveKey.
     *
     * @param password  contraseña del usuario como array de caracteres; no nulo ni vacío.
     * @param salt      salt aleatorio de exactamente SALT_SIZE bytes; no nulo ni vacío.
     * @return SecretKeySpec listo para usar en Cipher.init().
     */
    public static SecretKeySpec deriveKey(char[] password, byte[] salt) {

        // Validamos las entradas: fallamos rápido con un mensaje claro en lugar
        // de propagar un NullPointerException sin contexto más adelante.
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("La contraseña no puede ser nula ni vacía.");
        }
        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException("El salt no puede ser nulo ni vacío.");
        }

        // Construimos la especificación con los cuatro parámetros que necesita PBKDF2:
        //   password   : contraseña del usuario
        //   salt       : salt aleatorio de este cifrado
        //   ITERATIONS : cuántas veces se aplica la función interna
        //   KEY_LENGTH : longitud deseada de la clave resultante en bits
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);

        try {
            // Derivamos la clave usando la fábrica correspondiente al algoritmo.
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_ALGO);
            SecretKey secretKey = factory.generateSecret(keySpec);

            // getEncoded() devuelve una COPIA de los bytes de la clave.
            byte[] encoded = secretKey.getEncoded();

            if (encoded == null || encoded.length == 0) {
                throw new IllegalStateException("No fue posible derivar una clave AES válida.");
            }

            // Construimos el SecretKeySpec que usará el Cipher.
            // SecretKeySpec hace su propia copia interna de 'encoded'.
            SecretKeySpec result = new SecretKeySpec(encoded, ALGORITHM);

            // Limpiamos 'encoded' de inmediato: SecretKeySpec ya copió el contenido
            // y mantenerlo en memoria más tiempo del necesario es un riesgo innecesario.
            Arrays.fill(encoded, (byte) 0);

            return result;

        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            // Envolvemos en excepción no chequeada porque estos algoritmos
            // son mandatorios en cualquier JVM Java 8+.
            throw new IllegalStateException("Error al derivar la clave AES: " + ex.getMessage(), ex);

        } finally {
            // ── Limpieza de la contraseña dentro de PBEKeySpec ────────────
            // PBEKeySpec guarda una copia interna de la contraseña.
            // clearPassword() la sobreescribe con ceros dentro del objeto.
            // Lo hacemos en finally para garantizar que ocurra incluso si se lanzó
            // una excepción durante la derivación.
            keySpec.clearPassword();
        }
    }

    // =========================================================================
    // MÉTODO: generateSalt
    // =========================================================================

 
    /*
     * Genera un salt aleatorio de SALT_SIZE bytes usando SecureRandom,
     * que es criptográficamente seguro.
     *
     * El salt se almacena en los primeros SALT_SIZE bytes del archivo .enc para
     * poder recuperarlo al descifrar y reproducir la misma clave derivada a partir
     * de la contraseña correcta.
     *
     * @return array de SALT_SIZE bytes aleatorios.
     */
    public static byte[] generateSalt() {
        // Reservamos el array y lo llenamos con bytes aleatorios de alta entropía.
        byte[] salt = new byte[SALT_SIZE];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    // =========================================================================
    // MÉTODO: generateIV
    // =========================================================================

    /*
     * Genera un vector de inicialización (IV) de IV_SIZE bytes usando SecureRandom.
     *
     * El IV es necesario para AES en modo CBC. Su función es garantizar que dos
     * cifrados del mismo contenido con la misma clave produzcan resultados distintos.
     * Debe ser único por cada operación de cifrado y nunca predecible; de ahí que
     * lo generemos con SecureRandom.
     *
     * El IV no es secreto: lo almacenamos en claro en el archivo .enc junto al salt
     * y lo recuperamos al descifrar.
     *
     * @return array de IV_SIZE bytes aleatorios.
     */
    public static byte[] generateIV() {
        byte[] iv = new byte[IV_SIZE];
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }

    // =========================================================================
    // MÉTODO: computeSHA256
    // =========================================================================

    /*
     * Calcula el hash SHA-256 de un bloque de datos.
     *
     * En este proyecto calculamos el hash sobre los bytes del archivo original
     * antes de cifrarlo y lo almacenamos en el .enc. Al descifrar, recalculamos
     * el hash del archivo recuperado y lo comparamos con el almacenado; si coinciden,
     * el archivo está íntegro y la contraseña era correcta.
     *
     * @param data  bytes de entrada; puede ser un array vacío, pero no nulo.
     * @return array de HASH_SIZE bytes con el resumen SHA-256.
     */
    public static byte[] computeSHA256(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Los datos de entrada no pueden ser nulos.");
        }

        try {
            // MessageDigest no es thread-safe: siempre obtenemos una instancia nueva.
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGO);

            // digest() calcula el hash de todos los bytes de 'data' en una sola llamada.
            return digest.digest(data);

        } catch (NoSuchAlgorithmException ex) {
            // SHA-256 es mandatorio en cualquier implementación Java conforme a JCA.
            // Si llegamos aquí, hay un problema grave con el entorno de ejecución.
            throw new IllegalStateException("SHA-256 no está disponible en este entorno.", ex);
        }
    }

    // =========================================================================
    // MÉTODO: bytesToHex
    // =========================================================================

    /*
     * Convierte un array de bytes a su representación en hexadecimal (minúsculas).
     * Ejemplo: [0x0A, 0x1B, 0xFF] → "0a1bff".
     *
     * Lo usamos para mostrar el hash SHA-256 en consola de forma legible y para
     * comparaciones visuales durante el desarrollo. El hash en el archivo .enc
     * se almacena como bytes crudos, no como cadena hexadecimal.
     *
     * Implementamos la conversión manualmente en lugar de usar String.format o
     * Integer.toHexString para evitar la creación de objetos intermedios innecesarios,
     * lo que resulta más eficiente con arrays grandes.
     *
     * @param bytes  array a convertir; un array vacío produce "".
     * @return cadena hexadecimal en minúsculas de longitud bytes.length * 2.
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException("El array de bytes no puede ser nulo.");
        }

        // Un array vacío produce una cadena vacía sin entrar al bucle.
        if (bytes.length == 0) {
            return "";
        }

        // Cada byte produce dos caracteres hexadecimales, por eso la longitud × 2.
        char[] hexChars   = new char[bytes.length * 2];
        char[] hexAlphabet = "0123456789abcdef".toCharArray();

        for (int i = 0; i < bytes.length; i++) {
            // '& 0xFF' convierte el byte con signo a un entero sin signo 0-255.
            int value = bytes[i] & 0xFF;

            // Los 4 bits altos (nibble superior) determinan el primer carácter hex.
            hexChars[i * 2]     = hexAlphabet[value >>> 4];

            // Los 4 bits bajos (nibble inferior) determinan el segundo carácter hex.
            hexChars[i * 2 + 1] = hexAlphabet[value & 0x0F];
        }

        return new String(hexChars);
    }
}