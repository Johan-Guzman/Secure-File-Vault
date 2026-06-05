import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * Módulo de descifrado de nuestro proyecto "Secure-File-Vault".
 *
 * Recibimos un archivo .enc, extraemos el salt, el IV, el hash SHA-256
 * almacenado y los datos cifrados; reconstruimos la clave AES-256 a partir
 * de la contraseña proporcionada y desciframos el contenido con AES/CBC/PKCS5Padding.
 *
 * Antes de guardar el archivo recuperado verificamos su integridad:
 * calculamos el SHA-256 del contenido descifrado y lo comparamos con el hash
 * que FileEncryptor almacenó en el .enc. Solo escribimos el resultado si
 * ambos hashes coinciden exactamente.
 *
 * El formato del archivo .enc que leemos (definido por FileEncryptor) es:
 *
 *   Bytes  0 –  15 : salt (16 bytes)
 *   Bytes 16 –  31 : IV   (16 bytes)
 *   Bytes 32 –  63 : hash SHA-256 del archivo original (32 bytes)
 *   Bytes 64 –   N : datos cifrados con AES (longitud variable)
 *
 * Toda la lógica criptográfica está delegada en CryptoUtils; este módulo
 * solo orquesta el proceso de descifrado y maneja la lectura y escritura de archivos.
 */
public class FileDecryptor {

    /*
     * Descifra el archivo indicado y escribe el contenido original en la ruta de salida.
     *
     * El flujo completo es el siguiente:
     *   1. Leer todos los bytes del archivo .enc.
     *   2. Extraer el salt, el IV, el hash almacenado y los datos cifrados.
     *   3. Derivar la clave AES-256 con PBKDF2 a partir de la contraseña y el salt extraído.
     *   4. Descifrar los datos con AES/CBC/PKCS5Padding.
     *   5. Calcular el SHA-256 del contenido descifrado.
     *   6. Comparar el hash calculado con el hash almacenado para verificar la integridad.
     *   7. Escribir el archivo original solo si la verificación fue exitosa.
     *   8. Mostrar confirmación en consola con los hashes comparados.
     *   9. Limpiar la contraseña de la memoria.
     *
     * Gestionamos FileOutputStream con try-with-resources para garantizar que
     * el stream se cierre siempre, incluso si ocurre una excepción al escribir.
     *
     * @param inputPath   ruta del archivo cifrado (.enc); debe existir y ser legible.
     * @param outputPath  ruta donde se escribirá el archivo descifrado.
     * @param password    contraseña del usuario como char[]; se limpia con Arrays.fill
     *                    al terminar, sin importar si ocurrió un error.
     * @throws java.io.IOException  si el archivo de entrada no existe o hay errores de E/S.
     * @throws SecurityException    si el hash calculado no coincide con el almacenado.
     * @throws Exception            si ocurre cualquier otro error criptográfico interno.
     */
    public static void decryptFile(String inputPath, String outputPath, char[] password)
            throws Exception {

        // Usamos try-finally para garantizar que la contraseña SIEMPRE se limpie,
        // haya error o no. La limpieza va en 'finally', no en el bloque normal.
        try {

            // ── PASO 1: Leer el archivo cifrado completo ─────────────────────────────
            // Leemos todos los bytes del archivo .enc de una sola vez para poder
            // separar cada una de las partes que FileEncryptor guardó al cifrar.
            // Si el archivo no existe, Files.readAllBytes lanza NoSuchFileException.
            byte[] encFileData = Files.readAllBytes(Paths.get(inputPath));

            // Verificamos que el archivo tenga al menos los 64 bytes de cabecera:
            // SALT_SIZE (16) + IV_SIZE (16) + HASH_SIZE (32) = 64 bytes mínimos.
            // Si es más corto, el archivo está truncado o no es un .enc válido.
            int headerSize = CryptoUtils.SALT_SIZE + CryptoUtils.IV_SIZE + CryptoUtils.HASH_SIZE;
            if (encFileData.length < headerSize) {
                throw new IllegalArgumentException(
                        "El archivo .enc es demasiado corto: no contiene una cabecera válida.");
            }

            // ── PASO 2: Extraer el salt ───────────────────────────────────────────────
            // El salt ocupa los primeros SALT_SIZE (16) bytes del archivo .enc.
            // Lo necesitamos para reconstruir exactamente la misma clave AES que usó
            // FileEncryptor, combinándolo de nuevo con la contraseña mediante PBKDF2.
            byte[] salt = Arrays.copyOfRange(encFileData, 0, CryptoUtils.SALT_SIZE);

            // ── PASO 3: Extraer el IV ─────────────────────────────────────────────────
            // El IV está justo después del salt, en los siguientes IV_SIZE (16) bytes.
            // Sin el IV correcto el primer bloque descifrado sería basura, aunque la
            // clave sea correcta; así funciona el encadenamiento en modo CBC.
            int ivOffset = CryptoUtils.SALT_SIZE;
            byte[] iv = Arrays.copyOfRange(encFileData, ivOffset, ivOffset + CryptoUtils.IV_SIZE);

            // ── PASO 4: Extraer el hash SHA-256 almacenado ───────────────────────────
            // El hash ocupa los HASH_SIZE (32) bytes que siguen al IV.
            // Es el resumen SHA-256 del archivo ORIGINAL que FileEncryptor calculó
            // antes de cifrar. Más adelante lo usamos para comprobar que el contenido
            // que recuperamos es idéntico al que se cifró originalmente.
            int hashOffset = CryptoUtils.SALT_SIZE + CryptoUtils.IV_SIZE;
            byte[] storedHash = Arrays.copyOfRange(
                    encFileData, hashOffset, hashOffset + CryptoUtils.HASH_SIZE);

            // ── PASO 5: Extraer los datos cifrados ───────────────────────────────────
            // Todo lo que viene después de la cabecera (64 bytes) son los datos
            // cifrados por AES. Su longitud es variable y depende del archivo original.
            int dataOffset = CryptoUtils.SALT_SIZE + CryptoUtils.IV_SIZE + CryptoUtils.HASH_SIZE;
            byte[] encryptedData = Arrays.copyOfRange(encFileData, dataOffset, encFileData.length);

            // ── PASO 6: Derivar la clave AES-256 desde la contraseña ─────────────────
            // Reconstruimos la misma clave que usó FileEncryptor: aplicamos PBKDF2 con
            // la contraseña del usuario y el salt que acabamos de extraer del archivo.
            // Si la contraseña es incorrecta, la clave derivada será diferente y el
            // descifrado producirá datos inválidos (o lanzará BadPaddingException).
            SecretKeySpec key = CryptoUtils.deriveKey(password, salt);

            // ── PASO 7: Inicializar el descifrador y descifrar ───────────────────────
            // Obtenemos un Cipher configurado con la misma transformación que usó
            // FileEncryptor: AES/CBC/PKCS5Padding.
            Cipher cipher = Cipher.getInstance(CryptoUtils.CIPHER_MODE);

            // IvParameterSpec envuelve el IV para que Cipher pueda usarlo en modo CBC.
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // DECRYPT_MODE indica que este Cipher va a descifrar (no a cifrar).
            // Si la contraseña era incorrecta, doFinal lanzará BadPaddingException
            // porque el padding del último bloque no será válido.
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            // doFinal descifra todos los bytes de una vez y elimina automáticamente
            // el padding PKCS5, devolviendo el contenido original del archivo.
            byte[] decryptedData = cipher.doFinal(encryptedData);

            // ── PASO 8: Calcular el hash SHA-256 del contenido descifrado ────────────
            // Calculamos el SHA-256 sobre los bytes que acabamos de recuperar.
            // Si el descifrado fue correcto y la contraseña era la original, este hash
            // debería coincidir exactamente con el hash almacenado en el .enc.
            byte[] computedHash = CryptoUtils.computeSHA256(decryptedData);

            // ── PASO 9: Verificar la integridad del archivo ───────────────────────────
            // Comparamos el hash calculado con el hash almacenado.
            // Usamos MessageDigest.isEqual en lugar de Arrays.equals porque isEqual
            // compara en tiempo constante, sin cortocircuito, lo que evita ataques de
            // temporización (timing attacks) sobre la comparación byte a byte.
            boolean integrityOk = MessageDigest.isEqual(computedHash, storedHash);

            if (!integrityOk) {
                // Los hashes no coinciden: el archivo fue modificado después del cifrado,
                // o la contraseña generó un padding válido por coincidencia pero una
                // clave incorrecta. No escribimos el archivo para evitar guardar basura.
                throw new SecurityException(
                        "Verificacion de integridad fallida: los hashes SHA-256 no coinciden. "
                        + "El archivo puede estar corrupto o la contrasena es incorrecta.");
            }

            // PASO 10: Escribir el archivo descifrado.
            // Solo llegamos aquí si la verificación de integridad fue exitosa.
            // Usamos try-with-resources para que FileOutputStream se cierre automáticamente
            // al salir del bloque, incluso si write() lanza una excepción.
            try (FileOutputStream fos = new FileOutputStream(outputPath)) {
                fos.write(decryptedData); // contenido original recuperado
            }
            // Al salir del try anterior, fos.close() ya fue llamado automáticamente.

            // PASO 11: Confirmación al usuario.
            // Mostramos ambos hashes y el resultado de la verificación para que el usuario
            // pueda comprobar visualmente que la integridad fue verificada correctamente.
            System.out.println("");
            System.out.println("Descifrado completado exitosamente.");
            System.out.println("  Archivo generado          : " + outputPath);
            System.out.println("  Hash SHA-256 (almacenado) : "
                    + CryptoUtils.bytesToHex(storedHash));
            System.out.println("  Hash SHA-256 (calculado)  : "
                    + CryptoUtils.bytesToHex(computedHash));
            System.out.println("  Integridad verificada     : OK");
            System.out.println("");

        } finally {
            // PASO 12: Limpiar la contraseña de la memoria.
            // Arrays.fill sobreescribe cada posición con el carácter nulo '\0',
            // reduciendo el tiempo que la contraseña permanece legible en el heap.
            // El bloque finally garantiza que esto ocurra siempre, incluso si alguno
            // de los pasos anteriores lanzó una excepción.
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }
}