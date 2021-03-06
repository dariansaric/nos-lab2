package crypto;

import util.FileParser;
import util.FileWriter;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;
import java.util.HashMap;
import java.util.Map;

import static util.Constants.*;

public class SymmetricCipher {
    private Map<String, FileParser> parsers = new HashMap<>();
    private byte[] initVector;
    private String algorithm;
    private String transformation;
    private Path sourceFile;
    private Path destinationFile;
    private byte[] cipherText;
    private byte[] plainText;
    private Key key;
    private int keySize;


    byte[] encryptAndReturn(boolean keyExists) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidParameterSpecException {
        Cipher cipher = keyExists ? Cipher.getInstance(getScheme()) : Cipher.getInstance(algorithm + "/" + transformation + "/ISO10126Padding");
        if (transformation.equals(SUPPORTED_TRANSFORMATIONS.get(0))) {
            cipher.init(Cipher.ENCRYPT_MODE, keyExists ? getKey() : generateKey());
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, keyExists ? getKey() : generateKey(), keyExists ? getVector() : generateVector());
        }

        cipherText = cipher.doFinal(Files.readAllBytes(sourceFile));
        return cipherText;
    }

    private IvParameterSpec generateVector() {
        SecureRandom r = new SecureRandom();
        initVector = new byte[8];
        r.nextBytes(initVector);
        return new IvParameterSpec(initVector);
    }

    private IvParameterSpec getVector() {
        IvParameterSpec spec = new IvParameterSpec(parsers.get(KEY_PARSER).getInitializationVector());
        initVector = spec.getIV();
        return spec;
    }

    public void encrypt(boolean keyExists) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
        encryptAndReturn(keyExists);

        if (!keyExists) {
            FileWriter keyWriter = new FileWriter(Paths.get("secret-key-test.txt.key"));
            keyWriter.setDescription("Secret key");
            keyWriter.setMethods(algorithm + "/" + transformation);
            if (!transformation.equals(SUPPORTED_TRANSFORMATIONS.get(0))) {
                keyWriter.setInitializationVector(initVector);
            }
            keyWriter.setKeyLengths(keySize);
            keyWriter.setSecretKey(key);
            keyWriter.writeData();
        }

        FileWriter fileWriter = new FileWriter(destinationFile);
        fileWriter.setDescription("Crypted file");
        fileWriter.setMethods(algorithm + "/" + transformation);
        fileWriter.setFileName(destinationFile);
        fileWriter.setData(cipherText);
        fileWriter.writeData();
    }

    byte[] decryptAndReturn(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(getScheme());
        if (transformation.equals(SUPPORTED_TRANSFORMATIONS.get(0))) {
            if (key == null) {
                cipher.init(Cipher.DECRYPT_MODE, getKey());
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key);
            }
        } else {
            if (key == null) {
                cipher.init(Cipher.DECRYPT_MODE, getKey(), getVector());
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key, getVector());
            }
        }

        return cipher.doFinal(data);
    }

    public void decrypt() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException {
        decryptAndReturn(parsers.get(DATA_PARSER).getData());
//        Cipher cipher = Cipher.getInstance(getScheme());
//        if (transformation.equals(SUPPORTED_TRANSFORMATIONS.get(0))) {
//            cipher.init(Cipher.DECRYPT_MODE, getKey());
//        } else {
//            cipher.init(Cipher.DECRYPT_MODE, getKey(), getVector());
//        }
//
//        plainText = cipher.doFinal(parsers.get(DATA_PARSER).getData());
        Files.write(destinationFile, plainText);
    }

    private SecretKey getKey() {
        SecretKey key = new SecretKeySpec(parsers.get(KEY_PARSER).getSecretkey(), algorithm);
        keySize = key.getEncoded().length * 8;
        return key;
    }

    SecretKey getKey(byte[] key) {
        return new SecretKeySpec(key, algorithm);
    }

    private Key generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(this.keySize, new SecureRandom());

        key = keyGenerator.generateKey();
        return key;
    }

    private String getScheme() {
        if (parsers.get(KEY_PARSER) == null) {
            return algorithm + "/" + transformation + "/ISO10126Padding";
        }
        String method = parsers.get(KEY_PARSER).getMethod();
        String[] parts = method.split("/");
        if (!SUPPORTED_ALGORITHMS.contains(parts[0])
                || !SUPPORTED_TRANSFORMATIONS.contains(parts[1])) {
            throw new IllegalArgumentException("Nepoznati algoritam");
        }

        algorithm = parts[0];
        transformation = parts[1];
        return method + "/ISO10126Padding";
    }

    int getKeySize() {
        return keySize;
    }

    void setKeySize(int keySize) {
//        if (!LEGAL_KEY_SIZES.contains(keySize)) {
//            throw new IllegalArgumentException("invalid key size");
//        }
        this.keySize = keySize;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public byte[] getPlainText() {
        return plainText;
    }

    void setSourceFile(Path sourceFile) {
        this.sourceFile = sourceFile;
    }

    public void setDestinationFile(Path destinationFile) {
        this.destinationFile = destinationFile;
    }

    void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    void setTransformation(String transformation) {
        this.transformation = transformation;
    }

    Key getSecretKey() {
        return key;
    }

    void setSecretKey(Key key) {
        this.key = key;
    }

    void setInitVector(byte[] initVector) {
        this.initVector = initVector;
    }

    void addParser(String key, FileParser parser) {
        parsers.put(key, parser);
    }
}
