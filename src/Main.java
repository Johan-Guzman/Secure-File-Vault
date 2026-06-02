

import javax.crypto.spec.SecretKeySpec;

public class Main {

    public static void main(String[] args) {

        System.out.println("=== SALT ===");
        byte[] salt1 = CryptoUtils.generateSalt();
        byte[] salt2 = CryptoUtils.generateSalt();

        System.out.println("Salt 1: " + CryptoUtils.bytesToHex(salt1));
        System.out.println("Salt 2: " + CryptoUtils.bytesToHex(salt2));

        System.out.println("\n=== IV ===");
        byte[] iv1 = CryptoUtils.generateIV();
        byte[] iv2 = CryptoUtils.generateIV();

        System.out.println("IV 1: " + CryptoUtils.bytesToHex(iv1));
        System.out.println("IV 2: " + CryptoUtils.bytesToHex(iv2));

        System.out.println("\n=== DERIVE KEY ===");

        SecretKeySpec key1 =
                CryptoUtils.deriveKey(
                        "123456".toCharArray(),
                        salt1
                );

        SecretKeySpec key2 =
                CryptoUtils.deriveKey(
                        "123456".toCharArray(),
                        salt1
                );

        System.out.println(
                CryptoUtils.bytesToHex(key1.getEncoded())
        );

        System.out.println(
                CryptoUtils.bytesToHex(key2.getEncoded())
        );

        System.out.println("\n=== SHA256 ===");

        byte[] hash =
                CryptoUtils.computeSHA256(
                        "Hola Mundo".getBytes()
                );

        System.out.println(
                CryptoUtils.bytesToHex(hash)
        );

        System.out.println(
                "\nLongitud clave: "
                        + key1.getEncoded().length
        );
    }




}