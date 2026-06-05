import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileEncryptor {

    public static void encryptFile (String inputPath, String outputPath, char[] password ) throws Exception{

        //Obtenemos la ruta del archivo a cifrar
        Path path = Paths.get(inputPath);

        //Leemos lo bytes del archivo a cifrar
        byte[] fileData = Files.readAllBytes(path);

        //Generamos el valor de salt, con el metodo de CryptoUtils
        byte[] salt = CryptoUtils.generateSalt();

        //Generamos el vector, con el metodo de CryptoUtils
        byte[] iv = CryptoUtils.generateIV();

        //A continuacion creamos la clave
        SecretKeySpec key = CryptoUtils.deriveKey(password, salt);

        byte[] hash = CryptoUtils.computeSHA256(fileData);

        Cipher cipher = Cipher.getInstance(CryptoUtils.CIPHER_MODE);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);


        byte[] encryptedData = cipher.doFinal(fileData);


        FileOutputStream fos = new FileOutputStream(outputPath);

        fos.write(salt);
        fos.write(iv);
        fos.write(hash);
        fos.write(encryptedData);

    }
}
