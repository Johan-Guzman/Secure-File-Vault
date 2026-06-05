import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

/*
 * Módulo de cifrado de nuestro proyecto "Secure-File-Vault".
 *
 * Tomamos un archivo de entrada, derivamos una clave AES-256 a partir de la
 * contraseña proporcionada, ciframos el contenido con AES/CBC/PKCS5Padding
 * y escribimos el resultado en un archivo .enc con el siguiente formato:
 *
 *   Bytes  0 –  15 : salt (16 bytes, generado aleatoriamente con SecureRandom)
 *   Bytes 16 –  31 : IV   (16 bytes, generado aleatoriamente con SecureRandom)
 *   Bytes 32 –  63 : hash SHA-256 del archivo original sin cifrar (32 bytes)
 *   Bytes 64 –   N : datos cifrados con AES (longitud variable)
 *
 * Toda la lógica criptográfica está delegada en CryptoUtils; este módulo
 * solo orquesta el proceso y maneja la escritura del archivo de salida.
 */
public class FileEncryptor {

    /*
     * En esta parte ciframos el archivo indicado y escribimos el resultado en la ruta de salida.
     *
     * El flujo completo es el siguiente:
     *   1. Leer todos los bytes del archivo original.
     *   2. Generar salt e IV aleatorios.
     *   3. Derivar la clave AES-256 con PBKDF2 a partir de la contraseña y el salt.
     *   4. Calcular el hash SHA-256 del archivo original (antes de cifrar).
     *   5. Cifrar los bytes con AES/CBC/PKCS5Padding.
     *   6. Escribir [salt][IV][hash][datos cifrados] en el archivo de salida.
     *   7. Mostrar confirmación en consola con el hash del archivo original.
     *   8. Limpiar la contraseña de la memoria.
     *
     * Gestionamos FileOutputStream con try-with-resources para garantizar que
     * el stream se cierre siempre, incluso si ocurre una excepción al escribir.
     *
     * @param inputPath   ruta del archivo original a cifrar; debe existir y ser legible.
     * @param outputPath  ruta donde se escribirá el archivo cifrado; se recomienda .enc.
     * @param password    contraseña del usuario como char[]; se limpia con Arrays.fill
     *                    al terminar, sin importar si ocurrió un error.
     * @throws IOException  si el archivo de entrada no existe o hay errores de lectura/escritura.
     * @throws Exception    si ocurre cualquier error criptográfico interno.
     */
    public static void encryptFile(String inputPath, String outputPath, char[] password)
            throws Exception {

        // Usamos try-finally para garantizar que la contraseña SIEMPRE se limpie,
        // haya error o no. La limpieza va en 'finally', no en el bloque normal.
        try {

            // ── PASO 1: Leer el archivo de entrada ───────────────────────────────
            // Files.readAllBytes carga el contenido completo en un array de bytes.
            // Si el archivo no existe, lanza NoSuchFileException (subclase de IOException).
            byte[] fileData = Files.readAllBytes(Paths.get(inputPath));

            // ── PASO 2: Generar el material criptográfico aleatorio ───────────────
            // El salt y el IV son únicos para CADA cifrado, aunque la contraseña sea
            // la misma. Esto impide comparar dos archivos cifrados con la misma clave.
            byte[] salt = CryptoUtils.generateSalt(); // 16 bytes para PBKDF2
            byte[] iv   = CryptoUtils.generateIV();   // 16 bytes para AES/CBC

            // ── PASO 3: Derivar la clave AES-256 desde la contraseña ─────────────
            // PBKDF2 combina la contraseña con el salt en 65.536 iteraciones internas
            // para producir una clave de 256 bits. Sin el salt correcto, la misma
            // contraseña produce una clave completamente diferente.
            SecretKeySpec key = CryptoUtils.deriveKey(password, salt);

            // PASO 4: Calcular el hash SHA-256 del archivo original.
            // Es importante calcularlo sobre los bytes originales, antes de cifrarlos.
            // Al descifrar, recalculamos el hash del resultado y lo comparamos con este
            // para verificar que el archivo fue recuperado correctamente.
            byte[] hash = CryptoUtils.computeSHA256(fileData);

            // ── PASO 5: Inicializar el cifrador ──────────────────────────────────
            // Cipher.getInstance recibe la transformación completa: algoritmo/modo/padding.
            Cipher cipher = Cipher.getInstance(CryptoUtils.CIPHER_MODE);

            // IvParameterSpec envuelve el IV para que Cipher pueda usarlo en modo CBC.
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // ENCRYPT_MODE indica que este Cipher va a cifrar (no a descifrar).
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

            // ── PASO 6: Cifrar el contenido del archivo ───────────────────────────
            // doFinal procesa todos los bytes de una vez y aplica el padding final.
            // El resultado ('encryptedData') tendrá un tamaño múltiplo de 16 bytes.
            byte[] encryptedData = cipher.doFinal(fileData);

            // PASO 7: Escribir el archivo .enc.
            // Usamos try-with-resources para que FileOutputStream se cierre automáticamente
            // al salir del bloque, incluso si algún write() lanza una excepción.
            //
            // El orden de escritura es el contrato del proyecto que FileDecryptor
            // debe respetar al leer:
            //   [salt 16B] [IV 16B] [hash SHA-256 32B] [datos cifrados]
            try (FileOutputStream fos = new FileOutputStream(outputPath)) {
                fos.write(salt);          // bytes  0 – 15  : salt
                fos.write(iv);            // bytes 16 – 31  : IV
                fos.write(hash);          // bytes 32 – 63  : hash del original
                fos.write(encryptedData); // bytes 64 – fin : datos cifrados
            }
            // Al salir del try anterior, fos.close() ya fue llamado automáticamente.

            // PASO 8: Confirmación al usuario.
            // Mostramos la ruta del archivo generado y el hash para que el usuario
            // pueda verificar visualmente el resultado.
            System.out.println("");
            System.out.println("Cifrado completado exitosamente.");
            System.out.println("  Archivo generado  : " + outputPath);
            System.out.println("  Hash SHA-256 (original): "
                    + CryptoUtils.bytesToHex(hash));
            System.out.println("");

        } finally {
            // PASO 9: Limpiar la contraseña de la memoria.
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
