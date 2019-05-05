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

public class RSAModule {
    private static final List<Integer> AVAILABLE_KEY_LENGTHS = Arrays.asList(512, 1024, 2048);
    private Map<String, FileParser> parsers = new HashMap<>();
    //    private Map<String, FileWriter> writers = new HashMap<>();
    private BigInteger modulus = BigInteger.ZERO;
    private BigInteger privateExponent = BigInteger.ZERO;
    private BigInteger publicExponent = BigInteger.ZERO;
    private int keyLength;
    private byte[] signature;
    private byte[] plainText;
    private Path sourceFile;
    private Path destinationFile;
    private String signatureAlgorithm;
    private String encryptionAlgorithm;
    private int encryptionKeySize;

    //todo: inicijalizacijski vektor
    //todo: funkcionalnost digitalne omotnice
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
        encryptionAlgorithm = envParser.getMethod();
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

    public void sign(boolean keyExists) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException, SignatureException {
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
            exportKey(true);
            privateKey = keyPair.getPrivate();
            privateExponent = ((RSAPrivateKey) privateKey).getPrivateExponent();
            exportKey(false);
        }

        signature.initSign(privateKey);
        signature.update(Files.readAllBytes(sourceFile));
        this.signature = signature.sign();

        FileWriter signWriter = new FileWriter(destinationFile);
        signWriter.setDescription("Signature");
        signWriter.setMethods(signatureAlgorithm.split("with"));
        signWriter.setFileName(sourceFile);
        signWriter.setKeyLengths(keyLength);
        signWriter.setSignature(this.signature);
        signWriter.writeData();
    }

    private void exportKey(boolean pub) throws IOException {
        FileWriter keyWriter = new FileWriter(Paths.get("./" + (pub ? "pub" : "priv") + "-key.os2"));
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

    public boolean verifySignature() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, SignatureException, InvalidKeyException {
        Signature signature = Signature.getInstance(getSignatureInstance());
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        signature.initVerify(publicKey);
        signature.update(Files.readAllBytes(sourceFile));
        return signature.verify(parsers.get("signature").getSignature());
    }

    public void wrap(boolean keyExists) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
        SymmetricCipher cipher = new SymmetricCipher();
        cipher.setSourceFile(sourceFile);
        cipher.setAlgorithm(encryptionAlgorithm);
        cipher.setTransformation("ECB");
        cipher.setKeySize(encryptionKeySize);
        byte[] cipherText = cipher.encryptAndReturn(false);
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
            exportKey(true);
            PrivateKey privateKey = keyPair.getPrivate();
            privateExponent = ((RSAPrivateKey) privateKey).getPrivateExponent();
            exportKey(false);
        }

        rsa.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cryptedKey = rsa.doFinal(key.getEncoded());
        FileWriter envWriter = new FileWriter(destinationFile);
        envWriter.setDescription("Envelope");
        envWriter.setMethods(encryptionAlgorithm, "RSA");
        envWriter.setKeyLengths(cipher.getKeySize(), keyLength);
        envWriter.setEnvelopeData(Base64.getEncoder().encode(cipherText));
        envWriter.setEnvelopeCryptKey(cryptedKey);
        envWriter.writeData();
    }

    public void unwrap() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, IOException, InvalidAlgorithmParameterException {
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(modulus, privateExponent));
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] key = rsa.doFinal(parsers.get("envelope").getEnvelopeCryptKey());
//        Key key = rsa.unwrap(parsers.get("envelope").getEnvelopeCryptKey().getBytes(), "RSA", Cipher.SECRET_KEY);

        SymmetricCipher cipher = new SymmetricCipher();
//        cipher.setSourceFile(sourceFile);
        cipher.setAlgorithm(encryptionAlgorithm);
        cipher.setTransformation("ECB");
        cipher.setSecretKey(cipher.getKey(key));
        plainText = cipher.decryptAndReturn(parsers.get("envelope").getEnvelopeData());

        Files.write(destinationFile, plainText);
    }

    private byte[] generateDigest() throws NoSuchAlgorithmException, IOException {
        MessageDigest digest = MessageDigest.getInstance(parsers.get("signature").getMethod());
        return digest.digest(Files.readAllBytes(sourceFile));
    }

    private int getKeyLength() {
        int len = Integer.parseInt(parsers.get("signature").getKeyLengths().get(1));
        if (!AVAILABLE_KEY_LENGTHS.contains(len)) {
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
}
