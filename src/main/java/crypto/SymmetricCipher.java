package crypto;

import util.FileParser;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

public class SymmetricCipher {
    public static final String KEY_PARSER = "key";
    public static final String DATA_PARSER = "data";
    private static final List<String> SUPPORTED_ALGORITHMS = Arrays.asList("DES", "AES");
    private static final List<String> SUPPORTED_TRANSFORMATIONS = Arrays.asList("ECB", "CBC", "OFB", "CFB", "CTR");
    private Map<String, FileParser> parsers = new HashMap<>();
    private String algorithm;
    private String transformation;
    private Path sourceFile;
    private byte[] cipherText;
    private byte[] plainText;
//    private FileWriter writer;

    
    public void encrypt(boolean keyExists) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = keyExists ? Cipher.getInstance(getScheme()) : Cipher.getInstance(algorithm + "/" + transformation + "/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keyExists ? getKey() : generateKey(algorithm));

        cipherText = Base64.getEncoder().encode(cipher.doFinal(Files.readAllBytes(sourceFile)));
        //todo: ostatak??
    }

    public void decrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(getScheme());
        cipher.init(Cipher.DECRYPT_MODE, getKey());

        plainText = cipher.doFinal(Base64.getDecoder().decode(parsers.get(DATA_PARSER).getData()));
        //todo: ostatak??
    }

    private Key getKey() {
        return new SecretKeySpec(parsers.get(KEY_PARSER).getSecretkey().getBytes(), algorithm);
    }

    private SecretKey generateKey(String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
//        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(new SecureRandom());
        return keyGenerator.generateKey();
    }


    private String getScheme() {
        String method = parsers.get(KEY_PARSER).getMethod();
        if (!SUPPORTED_ALGORITHMS.contains(method.split("/")[0])) {
            throw new IllegalArgumentException("Nepoznati algoritam");
        }

        return method.replace("DES", "DESede") + "/NoPadding";
    }

}
