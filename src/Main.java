import javax.crypto.spec.SecretKeySpec;


public class Main {

    public static void main(String[] args) {



        // =====================================================
        // 1. Generación de Salt
        // =====================================================
        System.out.println("1. GENERACIÓN DE SALT");

        byte[] salt1 = CryptoUtils.generateSalt();
        byte[] salt2 = CryptoUtils.generateSalt();

        System.out.println("Salt 1: " + CryptoUtils.bytesToHex(salt1));
        System.out.println("Salt 2: " + CryptoUtils.bytesToHex(salt2));

        System.out.println("Longitud Salt 1: " + salt1.length + " bytes");
        System.out.println("Longitud Salt 2: " + salt2.length + " bytes");

        System.out.println(
                "¿Son diferentes? "
                        + !CryptoUtils.bytesToHex(salt1)
                        .equals(CryptoUtils.bytesToHex(salt2))
        );

        // =====================================================
        // 2. Generación de IV
        // =====================================================
        System.out.println("\n2. GENERACIÓN DE IV");

        byte[] iv1 = CryptoUtils.generateIV();
        byte[] iv2 = CryptoUtils.generateIV();

        System.out.println("IV 1: " + CryptoUtils.bytesToHex(iv1));
        System.out.println("IV 2: " + CryptoUtils.bytesToHex(iv2));

        System.out.println("Longitud IV 1: " + iv1.length + " bytes");
        System.out.println("Longitud IV 2: " + iv2.length + " bytes");

        System.out.println(
                "¿Son diferentes? "
                        + !CryptoUtils.bytesToHex(iv1)
                        .equals(CryptoUtils.bytesToHex(iv2))
        );

        // =====================================================
        // 3. Derivación de Claves
        // =====================================================
        System.out.println("\n3. DERIVACIÓN DE CLAVES");

        char[] password = "123456".toCharArray();

        SecretKeySpec key1 =
                CryptoUtils.deriveKey(password, salt1);

        SecretKeySpec key2 =
                CryptoUtils.deriveKey(password, salt1);

        SecretKeySpec key3 =
                CryptoUtils.deriveKey(password, salt2);

        String key1Hex =
                CryptoUtils.bytesToHex(key1.getEncoded());

        String key2Hex =
                CryptoUtils.bytesToHex(key2.getEncoded());

        String key3Hex =
                CryptoUtils.bytesToHex(key3.getEncoded());

        System.out.println("Clave 1: " + key1Hex);
        System.out.println("Clave 2: " + key2Hex);
        System.out.println("Clave 3: " + key3Hex);

        System.out.println(
                "Misma contraseña + mismo salt -> misma clave: "
                        + key1Hex.equals(key2Hex)
        );

        System.out.println(
                "Misma contraseña + salt distinto -> clave distinta: "
                        + !key1Hex.equals(key3Hex)
        );

        System.out.println(
                "Longitud de clave: "
                        + key1.getEncoded().length
                        + " bytes"
        );

        // =====================================================
        // 4. SHA-256
        // =====================================================
        System.out.println("\n4. HASH SHA-256");

        byte[] hash1 =
                CryptoUtils.computeSHA256(
                        "Hola Mundo".getBytes()
                );

        byte[] hash2 =
                CryptoUtils.computeSHA256(
                        "Hola Mundo".getBytes()
                );

        byte[] hash3 =
                CryptoUtils.computeSHA256(
                        "Hola Mundo!".getBytes()
                );

        String hash1Hex =
                CryptoUtils.bytesToHex(hash1);

        String hash2Hex =
                CryptoUtils.bytesToHex(hash2);

        String hash3Hex =
                CryptoUtils.bytesToHex(hash3);

        System.out.println("Hash 1: " + hash1Hex);
        System.out.println("Hash 2: " + hash2Hex);
        System.out.println("Hash 3: " + hash3Hex);

        System.out.println(
                "Mismo texto -> mismo hash: "
                        + hash1Hex.equals(hash2Hex)
        );

        System.out.println(
                "Texto diferente -> hash diferente: "
                        + !hash1Hex.equals(hash3Hex)
        );

        System.out.println(
                "Longitud hash: "
                        + hash1.length
                        + " bytes"
        );

        // =====================================================
        // 5. Conversión Hexadecimal
        // =====================================================
        System.out.println("\n5. CONVERSIÓN HEXADECIMAL");

        byte[] ejemplo = {
                (byte) 0x0A,
                (byte) 0x1B,
                (byte) 0xFF
        };

        System.out.println(
                "Resultado esperado: 0a1bff"
        );

        System.out.println(
                "Resultado obtenido: "
                        + CryptoUtils.bytesToHex(ejemplo)
        );

        metodoPrueba();
    }


    public static void metodoPrueba(){
        try {

            FileEncryptor.encryptFile(
                    "encrypt/file.txt",
                    "decrypt/test.enc",
                    "123456".toCharArray()
            );

            System.out.println("Archivo cifrado correctamente.");

        } catch (Exception e) {

            System.err.println(
                    "Error: " + e.getMessage()
            );

            e.printStackTrace();
        }
    }

}