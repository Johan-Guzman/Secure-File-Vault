import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * Utilidades criptográficas reutilizables para el cifrado y descifrado de archivos.
 * Esta clase centraliza la generación de material criptográfico, el derivado de
 * claves desde contraseñas y algunas operaciones auxiliares que se usan en varias
 * etapas del flujo de seguridad del proyecto.
 *
 */
public final class CryptoUtils {

    /**
     * Algoritmo base para la clave simétrica del proyecto.
     */
    public static final String ALGORITHM = "AES";

    /**
     * Transformación utilizada para cifrar con AES en modo CBC y padding PKCS5.
     */
    public static final String CIPHER_MODE = "AES/CBC/PKCS5Padding";

    /**
     * Algoritmo PBKDF2 con HMAC-SHA-256 para derivar una clave desde una contraseña.
     */
    public static final String KEY_ALGO = "PBKDF2WithHmacSHA256";

    /**
     * Número de iteraciones usado por PBKDF2 para hacer más costoso el ataque por fuerza bruta.
     */
    public static final int ITERATIONS = 65536;

    /**
     * Tamaño de la clave AES en bits.
     */
    public static final int KEY_LENGTH = 256;

    /**
     * Tamaño del salt en bytes.
     */
    public static final int SALT_SIZE = 16;

    private static final int IV_SIZE = 16;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private CryptoUtils() {
        throw new AssertionError("No se debe instanciar CryptoUtils");
    }

    /**
     * Deriva una clave AES de 256 bits a partir de una contraseña y un salt.
     * @param password contraseña proporcionada por el usuario.
     * @param salt salt aleatorio que se usa para reforzar la derivación.
     * @return clave secreta AES lista para usarse en cifrado o descifrado.
     * @throws IllegalArgumentException si la contraseña o el salt son nulos o vacíos.
     * @throws IllegalStateException si no se puede generar la clave con el algoritmo indicado.
     */
    public static SecretKeySpec deriveKey(char[] password, byte[] salt) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("La contraseña no puede ser nula ni vacía.");
        }
        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException("El salt no puede ser nulo ni vacío.");
        }

        PBEKeySpec keySpec = new PBEKeySpec(
                password,
                salt,
                ITERATIONS,
                KEY_LENGTH
        );

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_ALGO);
            SecretKey secretKey = factory.generateSecret(keySpec);
            byte[] encoded = secretKey.getEncoded();

            if (encoded == null || encoded.length == 0) {
                throw new IllegalStateException(
                        "No fue posible derivar una clave AES válida."
                );
            }

            return new SecretKeySpec(encoded, ALGORITHM);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {

            throw new IllegalStateException(
                    "Error al derivar la clave AES.",
                    ex
            );

        } finally {

            // Se limpia la contraseña almacenada internamente para reducir
            // el tiempo que permanece en memoria.
            keySpec.clearPassword();
        }
    }

    /**
     * Genera un salt aleatorio de 16 bytes.
     * @return arreglo de bytes con salt criptográficamente seguro.
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_SIZE];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * Genera un vector de inicialización de 16 bytes para AES en modo CBC.
     * @return arreglo de bytes con un IV aleatorio.
     */
    public static byte[] generateIV() {
        byte[] iv = new byte[IV_SIZE];
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }

    /**
     * Calcula el hash SHA-256 de un bloque de datos.
     * El hash se utiliza posteriormente para verificar que el contenido no fue alterado.
     *
     * @param data datos de entrada sobre los que se calculará el resumen.
     * @return arreglo con el hash SHA-256 de 32 bytes.
     * @throws IllegalArgumentException si los datos son nulos.
     * @throws IllegalStateException si no está disponible SHA-256.
     */
    public static byte[] computeSHA256(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Los datos no pueden ser nulos.");
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 no está disponible en este entorno.", ex);
        }
    }

    /**
     * Convierte un arreglo de bytes a su representación hexadecimal en texto.
     * Se transforma el arreglo a hexadecimal para que pueda visualizarse fácilmente en consola
     * o almacenarse en un formato legible.
     *
     * @param bytes arreglo de bytes a convertir.
     * @return cadena hexadecimal en minúsculas.
     * @throws IllegalArgumentException si el arreglo es nulo.
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException("El arreglo de bytes no puede ser nulo.");
        }

        char[] hexChars = new char[bytes.length * 2];
        final char[] hexAlphabet = "0123456789abcdef".toCharArray();

        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xFF;
            hexChars[i * 2] = hexAlphabet[value >>> 4];
            hexChars[i * 2 + 1] = hexAlphabet[value & 0x0F];
        }

        return new String(hexChars);
    }
}
