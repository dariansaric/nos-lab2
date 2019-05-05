package crypto;

import util.FileParser;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

public class RSAModule {
    private static final List<Integer> AVAILABLE_KEY_LENGTHS = Arrays.asList(512, 1024, 2048);
    private Map<String, FileParser> parsers = new HashMap<>();
    private BigInteger modulus = BigInteger.ZERO;
    private BigInteger privateExponent = BigInteger.ZERO;
    private BigInteger publicExponent = BigInteger.ZERO;
    //    private int keyLength;
    private byte[] signature;
    private byte[] plainText;
    private Path sourceFile;
    private String signatureAlgorithm;


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

    private void extractPublicKey(FileParser pubKeyParser) {
        if (modulus.equals(BigInteger.ZERO)) {
            modulus = BigInteger.valueOf(Integer.parseInt(pubKeyParser.getModulus()));
        }

        privateExponent = BigInteger.valueOf(Integer.parseInt(pubKeyParser.getPublicExponent()));
    }

    private void extractPrivateKey(FileParser privKeyParser) {
        if (modulus.equals(BigInteger.ZERO)) {
            modulus = BigInteger.valueOf(Integer.parseInt(privKeyParser.getModulus()));
        }

        privateExponent = BigInteger.valueOf(Integer.parseInt(privKeyParser.getPrivateExponent()));
    }

    public void sign(boolean keyExists) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException, SignatureException {
        Signature signature = Signature.getInstance(getSignatureInstance());
        PrivateKey privateKey;
        if (keyExists) {
            RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
        } else {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(getKeyLength());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            modulus = ((RSAPublicKey) publicKey).getModulus();
            publicExponent = ((RSAPublicKey) publicKey).getPublicExponent();

            privateKey = keyPair.getPrivate();
            privateExponent = ((RSAPrivateKey) privateKey).getPrivateExponent();

        }

        signature.initSign(privateKey);
        signature.update(Files.readAllBytes(sourceFile));
        this.signature = signature.sign();
        //todo:ostatak??
    }

    public void verifySignature() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, SignatureException {
        Signature signature = Signature.getInstance(getSignatureInstance());
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

        byte[] newHash = generateDigest();
        signature.update(newHash);
        boolean verified = signature.verify(parsers.get("signature").getSignature().getBytes());

        //todo: ostatak


    }

//    public void

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
}
