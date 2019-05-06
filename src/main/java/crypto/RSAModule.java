package crypto;

import util.FileParser;
import util.FileWriter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

import static util.Constants.SUPPORTED_RSA_KEY_LENGTHS;
import static util.Constants.SUPPORTED_TRANSFORMATIONS;

public class RSAModule {
    private Map<String, FileParser> parsers = new HashMap<>();
    private BigInteger modulus = BigInteger.ZERO;
    private BigInteger privateExponent = BigInteger.ZERO;
    private BigInteger publicExponent = BigInteger.ZERO;
    private int keyLength;
    private byte[] signature;
    private byte[] plainText;
    private byte[] initVector;
    private Path sourceFile;
    private Path destinationFile;
    private String signatureAlgorithm;
    private String encryptionAlgorithm;
    private String transformation;
    private int encryptionKeySize;

    public RSAModule(FileParser pubKeyParser, FileParser privKeyParser, FileParser signatureParser) {
        if (signatureParser != null) {
            parsers.put("signature", signatureParser);
        }

        if (privKeyParser != null) {
            parsers.put("private", privKeyParser);
            extractPrivateKey(privKeyParser);
        }

        if (pubKeyParser != null) {
            parsers.put("public", pubKeyParser);
            extractPublicKey(pubKeyParser);
        }
    }

    public RSAModule(FileParser privKeyParser, FileParser envParser) {
        parsers.put("private", privKeyParser);
        extractPrivateKey(privKeyParser);
        parsers.put("envelope", envParser);
        encryptionAlgorithm = envParser.getMethod().split("/")[0];
        setEncryptionTransformation(envParser.getMethod().split("/")[1]);
    }

    public RSAModule() {
    }

    private void extractPublicKey(FileParser pubKeyParser) {
        if (modulus.equals(BigInteger.ZERO)) {
            modulus = new BigInteger(pubKeyParser.getModulus(), 16);
        }

        publicExponent = new BigInteger(pubKeyParser.getPublicExponent(), 16);
    }

    private void extractPrivateKey(FileParser privKeyParser) {
        if (modulus.equals(BigInteger.ZERO)) {
            modulus = new BigInteger(privKeyParser.getModulus(), 16);
        }

        privateExponent = new BigInteger(privKeyParser.getPrivateExponent(), 16);
    }

    public void sign(boolean keyExists, byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException, SignatureException {
        Signature signature = Signature.getInstance(getSignatureInstance());
        PrivateKey privateKey;
        if (keyExists) {
            RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
        } else {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keyLength);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            modulus = ((RSAPublicKey) publicKey).getModulus();
            publicExponent = ((RSAPublicKey) publicKey).getPublicExponent();
            exportKey(true, "signature-pub-key.os2");
            privateKey = keyPair.getPrivate();
            privateExponent = ((RSAPrivateKey) privateKey).getPrivateExponent();
            exportKey(false, "signature-priv-key.os2");
        }

        signature.initSign(privateKey);
        signature.update(data);
        this.signature = signature.sign();

        FileWriter signWriter = new FileWriter(destinationFile);
        signWriter.setDescription("Signature");
        signWriter.setMethods(signatureAlgorithm.split("with"));
        signWriter.setFileName(sourceFile);
        signWriter.setKeyLengths(keyLength);
        signWriter.setSignature(this.signature);
        signWriter.writeData();
    }

    private void exportKey(boolean pub, String keyPath) throws IOException {
        FileWriter keyWriter = new FileWriter(Paths.get(keyPath));
        keyWriter.setDescription(pub ? "Public" : "Private" + " key");
        keyWriter.setMethods("RSA");
        keyWriter.setKeyLengths(keyLength);
        keyWriter.setModulus(modulus);
        if (pub) {
            keyWriter.setPublicExponent(publicExponent);
        } else {
            keyWriter.setPrivateExponent(privateExponent);
        }

        keyWriter.writeData();
    }

    public boolean verifySignature(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, SignatureException, InvalidKeyException {
        Signature signature = Signature.getInstance(getSignatureInstance());
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(parsers.get("signature").getSignature());
    }

    public void wrap(boolean keyExists) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
        SymmetricCipher cipher = new SymmetricCipher();
        byte[] cipherText;
        if (!parsers.containsKey("secret")) {
            cipher.setSourceFile(sourceFile);
            cipher.setAlgorithm(encryptionAlgorithm);
            cipher.setTransformation(transformation);
            if (!transformation.equals(SUPPORTED_TRANSFORMATIONS.get(0))) {
                cipher.setInitVector(initVector);
            }
            cipher.setKeySize(encryptionKeySize);
            cipherText = cipher.encryptAndReturn(false);
        } else {
            cipher.addParser("secret", parsers.get("secret"));
            cipherText = cipher.encryptAndReturn(true);
        }


        Key key = cipher.getSecretKey();

        Cipher rsa = Cipher.getInstance("RSA");
        PublicKey publicKey;
        if (keyExists) {
            RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(modulus, publicExponent);
            publicKey = KeyFactory.getInstance("RSA").generatePublic(pubSpec);
        } else {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keyLength);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            modulus = ((RSAPublicKey) publicKey).getModulus();
            publicExponent = ((RSAPublicKey) publicKey).getPublicExponent();
            exportKey(true, "envelope-pub-key.os2");
            PrivateKey privateKey = keyPair.getPrivate();
            privateExponent = ((RSAPrivateKey) privateKey).getPrivateExponent();
            exportKey(false, "envelope-priv-key.os2");
        }

        rsa.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cryptedKey = rsa.doFinal(key.getEncoded());
        FileWriter envWriter = new FileWriter(destinationFile);
        envWriter.setDescription("Envelope");
        envWriter.setMethods(encryptionAlgorithm + "/" + transformation, "RSA");
        envWriter.setKeyLengths(cipher.getKeySize(), keyLength);
        if (!transformation.equals(SUPPORTED_TRANSFORMATIONS.get(0))) {
            envWriter.setInitializationVector(initVector);
        }
        envWriter.setEnvelopeData(Base64.getEncoder().encode(cipherText));
        envWriter.setEnvelopeCryptKey(cryptedKey);
        envWriter.writeData();
    }

    public void unwrap() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, IOException, InvalidAlgorithmParameterException {
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(modulus, privateExponent));
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] key = rsa.doFinal(parsers.get("envelope").getEnvelopeCryptKey());

        SymmetricCipher cipher = new SymmetricCipher();
        cipher.setAlgorithm(encryptionAlgorithm);
        cipher.setTransformation(transformation);
        if (!transformation.equals(SUPPORTED_TRANSFORMATIONS.get(0))) {
            cipher.setInitVector(parsers.get("envelope").getInitializationVector());
        }
        cipher.setSecretKey(cipher.getKey(key));
        plainText = cipher.decryptAndReturn(parsers.get("envelope").getEnvelopeData());

        Files.write(destinationFile, plainText);
    }

    public void signEnvelope(boolean envelopeKeyExists, boolean signatureKeyExists, Path signaturePath) throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, InvalidParameterSpecException, InvalidKeySpecException, IllegalBlockSizeException, SignatureException {
        wrap(envelopeKeyExists);
        Path envPath = destinationFile;
        setDestinationFile(signaturePath);
        sign(signatureKeyExists, Files.readAllBytes(envPath));
    }

    private byte[] generateDigest() throws NoSuchAlgorithmException, IOException {
        MessageDigest digest = MessageDigest.getInstance(parsers.get("signature").getMethod());
        return digest.digest(Files.readAllBytes(sourceFile));
    }

    private int getKeyLength() {
        int len = Integer.parseInt(parsers.get("signature").getKeyLengths().get(1));
        if (!SUPPORTED_RSA_KEY_LENGTHS.contains(len)) {
            throw new IllegalArgumentException("Neispravna duljina kljuca");
        }

        return len;
    }

    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
    }

    private String getSignatureInstance() {
        if (parsers.containsKey("signature")) {
            StringJoiner joiner = new StringJoiner("with");
            List<String> methods = parsers.get("signature").getMethods();
            joiner.add(methods.get(0).replace("-", ""));
            joiner.add(methods.get(1));
            return joiner.toString();
        }

        return signatureAlgorithm;
    }

    public Path getSourceFile() {
        return sourceFile;
    }

    public void setSourceFile(Path sourceFile) {
        this.sourceFile = sourceFile;
    }

    public Path getDestinationFile() {
        return destinationFile;
    }

    public void setDestinationFile(Path destinationFile) {
        this.destinationFile = destinationFile;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public void setEncryptionAlgorithm(String encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    public void setEncryptionKeySize(int keySize) {
        encryptionKeySize = keySize;
    }

    public void addParser(String key, FileParser parser) {
        parsers.put(key, parser);
    }

    public void updateParameters() {
        extractPrivateKey(parsers.get("private"));
    }

    public void setEncryptionTransformation(String transformation) {
        this.transformation = transformation;
    }

    public void setEncryptionInitVector(byte[] initVector) {
        this.initVector = initVector;
    }
}
