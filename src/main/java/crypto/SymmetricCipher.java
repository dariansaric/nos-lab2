package crypto;

import util.FileParser;
import util.FileWriter;

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
    private static final List<Integer> LEGAL_KEY_SIZES = Arrays.asList(128, 192, 256);
    private Map<String, FileParser> parsers = new HashMap<>();
    private Map<String, FileWriter> writers = new HashMap<>();
    private String algorithm;
    private String transformation;
    private Path sourceFile;
    private Path destinationFile;
    private byte[] cipherText;
    private byte[] plainText;
    private SecretKey key;
    private int keySize;
//    private FileWriter writer;


    //todo: upis velicine kljuca
    public byte[] encryptAndReturn(boolean keyExists) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        Cipher cipher = keyExists ? Cipher.getInstance(getScheme()) : Cipher.getInstance(algorithm + "/" + transformation + "/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keyExists ? getKey() : generateKey());
        cipherText = Base64.getEncoder().encode(cipher.doFinal(Files.readAllBytes(sourceFile)));
        return cipherText;
    }
    public void encrypt(boolean keyExists) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        encryptAndReturn(keyExists);

        FileWriter keyWriter = new FileWriter();
        keyWriter.setDescription("Secret key");
        keyWriter.setMethods(algorithm);
        keyWriter.setSecretKey(key);
//        keyWriter.writeData();

        FileWriter fileWriter = new FileWriter(destinationFile);
        fileWriter.setDescription("Crypted file");
        fileWriter.setMethods(algorithm);
        fileWriter.setFileName(destinationFile);
        fileWriter.setData(cipherText);
//        fileWriter.writeData();
    }

    public byte[] decryptAndReturn(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(getScheme());
        cipher.init(Cipher.DECRYPT_MODE, getKey());

        plainText = cipher.doFinal(Base64.getDecoder().decode(data));

        return plainText;
    }

    public void decrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
//        decryptAndReturn();
        Cipher cipher = Cipher.getInstance(getScheme());
        cipher.init(Cipher.DECRYPT_MODE, getKey());

        plainText = cipher.doFinal(Base64.getDecoder().decode(parsers.get(DATA_PARSER).getData()));
//        Files.write(destinationFile, plainText);

    }

    private Key getKey() {
        //todo: ispravno citanje kljuca
        //todo:ispravno pisanje kljuca
        return new SecretKeySpec(parsers.get(KEY_PARSER).getSecretkey().getBytes(), algorithm);
    }

    private SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);

//        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(this.keySize, new SecureRandom());

        key = keyGenerator.generateKey();
        return key;
    }

    private String getScheme() {
        String method = parsers.get(KEY_PARSER).getMethod();
        if (!SUPPORTED_ALGORITHMS.contains(method.split("/")[0])) {
            throw new IllegalArgumentException("Nepoznati algoritam");
        }

        return method.replace("DES", "DESede") + "/NoPadding";
    }

    public int getKeySize() {
        return keySize;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public byte[] getPlainText() {
        return plainText;
    }

    public void setSourceFile(Path sourceFile) {
        this.sourceFile = sourceFile;
    }

    public void setDestinationFile(Path destinationFile) {
        this.destinationFile = destinationFile;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public void setTransformation(String transformation) {
        this.transformation = transformation;
    }

    public SecretKey getSecretKey() {
        return key;
    }
}
