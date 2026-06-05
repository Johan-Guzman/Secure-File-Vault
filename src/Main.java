import java.io.Console;
import java.util.Arrays;
import java.util.Scanner;

/*
 * Punto de entrada del programa Secure File Vault.
 *
 * Mostramos un menú interactivo que le permite al usuario elegir entre
 * cifrar o descifrar un archivo. Leemos la contraseña con Console.readPassword()
 * para que no sea visible en pantalla mientras se escribe.
 *
 * Al terminar, limpiamos el array de contraseña con Arrays.fill() para
 * reducir el tiempo que permanece en memoria.
 */
public class Main {

    /*
     * Método principal del programa.
     *
     * Flujo general:
     *   1. Mostramos el encabezado y el menú de opciones.
     *   2. Leemos la opción elegida por el usuario (1 = cifrar, 2 = descifrar).
     *   3. Pedimos la ruta del archivo de entrada y la ruta de salida.
     *   4. Leemos la contraseña sin mostrarla en pantalla.
     *   5. Llamamos a FileEncryptor.encrypt() o FileDecryptor.decrypt() según la opción.
     *   6. Limpiamos el array de contraseña de la memoria en el bloque finally.
     */
    public static void main(String[] args) {

        // Mostramos el encabezado del programa antes de cualquier interacción.
        imprimirEncabezado();

        // Usamos Scanner para leer las rutas de archivos (texto visible es aceptable).
        // La contraseña se leerá por separado con un método que oculta los caracteres.
        Scanner scanner = new Scanner(System.in);

        System.out.println("  [1]  Cifrar un archivo");
        System.out.println("  [2]  Descifrar un archivo");
        System.out.println("");
        System.out.print("  Elige una opcion (1 o 2): ");

        String opcion = scanner.nextLine().trim();

        // Validamos la opción antes de pedir más datos para evitar pasos innecesarios.
        if (!opcion.equals("1") && !opcion.equals("2")) {
            System.err.println("✗ Opcion no valida. Escribe 1 para cifrar o 2 para descifrar.");
            return;
        }

        // Pedimos las rutas del archivo de entrada y del archivo de salida.
        System.out.println();
        System.out.print("  Ruta del archivo de entrada : ");
        String inputPath = scanner.nextLine().trim();

        System.out.print("  Ruta del archivo de salida  : ");
        String outputPath = scanner.nextLine().trim();

        // No tiene sentido continuar si el usuario dejó alguna ruta vacía.
        if (inputPath.isEmpty() || outputPath.isEmpty()) {
            System.err.println("✗ Las rutas no pueden estar vacias.");
            return;
        }

        // Leemos la contraseña de forma segura (sin eco en pantalla).
        System.out.println();
        char[] password = leerContrasena(scanner);

        /*
         * Ejecutamos la operación elegida y manejamos los posibles errores.
         *
         * Pasamos la contraseña como char[] a los módulos de cifrado/descifrado.
         * En el bloque finally la limpiamos con Arrays.fill() como capa defensiva,
         * aunque FileEncryptor y FileDecryptor también la limpian internamente.
         */
        try {

            if (opcion.equals("1")) {
                System.out.println();
                System.out.println("  Cifrando archivo...");
                FileEncryptor.encryptFile(inputPath, outputPath, password);

            } else {
                System.out.println();
                System.out.println("  Descifrando archivo...");
                //Descomentar cuando se implemente FileDecryptor
                //FileDecryptor.decryptFile(inputPath, outputPath, password);
            }

        } catch (javax.crypto.BadPaddingException e) {
            // BadPaddingException indica que la contraseña es incorrecta:
            // AES/CBC/PKCS5Padding detecta que el padding del último bloque no es válido.
            System.err.println();
            System.err.println("✗ Contrasena incorrecta o archivo corrupto.");
            System.err.println("  Verifica que estes usando la contrasena original.");

        } catch (java.nio.file.NoSuchFileException e) {
            // El archivo de entrada no existe en la ruta que indicó el usuario.
            System.err.println();
            System.err.println("✗ Archivo no encontrado: " + e.getMessage());
            System.err.println("  Verifica que la ruta sea correcta.");

        } catch (java.io.IOException e) {
            // Problemas de lectura o escritura de archivos.
            System.err.println();
            System.err.println("✗ Error de entrada/salida: " + e.getMessage());

        } catch (Exception e) {
            // Cualquier otro error inesperado. Mostramos el mensaje técnico
            // porque durante el desarrollo universitario puede ayudar a identificar el problema.
            System.err.println();
            System.err.println("✗ Error inesperado: " + e.getMessage());

        } finally {
            // Sobreescribimos el array de contraseña con '\0' para que no permanezca
            // en memoria después de que el programa termine. Lo hacemos en finally
            // para garantizar que ocurra aunque el cifrado o descifrado haya fallado.
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    // =========================================================================
    // leerContrasena
    // =========================================================================

    /*
     * Leemos la contraseña del usuario sin mostrarla en pantalla.
     *
     * Usamos dos estrategias según el entorno de ejecución:
     *
     *   - Consola real (terminal del sistema operativo):
     *     Usamos Console.readPassword(), que oculta los caracteres mientras
     *     el usuario escribe y devuelve directamente un char[].
     *
     *   - IDE / redirección de stdin (IntelliJ, Eclipse, etc.):
     *     System.console() devuelve null cuando el IDE intercepta los streams
     *     estándar. En ese caso usamos Scanner y avisamos al usuario que la
     *     contraseña será visible en pantalla.
     *
     * En ambos casos devolvemos char[] (nunca String) para poder limpiarla
     * con Arrays.fill() cuando ya no la necesitemos.
     */
    private static char[] leerContrasena(Scanner scanner) {
        Console console = System.console();

        if (console != null) {
            // Camino normal: hay una consola real del sistema operativo.
            // readPassword() no muestra los caracteres mientras el usuario escribe.
            char[] password = console.readPassword("  Contrasena: ");

            if (password == null || password.length == 0) {
                System.err.println("✗ No se ingreso ninguna contrasena.");
                System.exit(1);
            }
            return password;

        } else {
            // Fallback para IDEs: System.console() es null porque el IDE
            // redirige stdin/stdout internamente. Advertimos al usuario
            // que la contraseña será visible mientras la escribe.
            System.out.println("  [ADVERTENCIA] Modo IDE detectado: la contrasena");
            System.out.println("  sera visible mientras la escribes.");
            System.out.print("  Contrasena: ");

            String input = scanner.nextLine();

            if (input.isEmpty()) {
                System.err.println("✗ No se ingreso ninguna contrasena.");
                System.exit(1);
            }

            // Convertimos a char[] en lugar de dejar la contraseña como String,
            // así podemos limpiarla de la memoria cuando ya no la necesitemos.
            return input.toCharArray();
        }
    }

    // =========================================================================
    // imprimirEncabezado
    // =========================================================================

    /*
     * Imprimimos el encabezado visual del programa.
     * Lo separamos en su propio método para mantener main() limpio y legible.
     */
    private static void imprimirEncabezado() {
        System.out.println();
        System.out.println("=========================================");
        System.out.println("        SECURE FILE VAULT v1.0           ");
        System.out.println("  Cifrador/Descifrador de Archivos AES   ");
        System.out.println("=========================================");
        System.out.println();
    }
}