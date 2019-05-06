import crypto.RSAModule;
import org.apache.commons.cli.*;
import util.FileParser;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import static util.Constants.*;

public class Main {
    private static HelpFormatter formatter = new HelpFormatter();
    private static Options options = setupOptions();

    // stvaranje potpisa bez kljuca: -f sign -s test.txt -d sig.os2 -sa SHA1withRSA -rl 512
    // stvaranje potpisa s kljucem: -f sign -s test.txt -d sig.os2 -sa SHA1withRSA -rl 512 -ss signature-priv-key.os2
    // verificiranje potpisa: -f ver s test.txt -sf sig.os2 -sp signature-pub-key.os2
    // stvaranje omotnice: -f wrap -s test.txt -d envelope.os2 -ea AES -el 128 -em ECB -rl 512
    // otvaranje omotnice: -f unwrap -d test1.txt -s envelope.os2 -ss envelope-priv-key.os2
    public static void main(String[] args) {
        //TODO: parsiranje argumenata naredbenog retka


//        Path input = Paths.get(args[0]);
//        RSAModule module = new RSAModule(new FileParser(Paths.get("./pub-key.os2")),
//                new FileParser(Paths.get("./priv-key.os2")),
//                new FileParser(Paths.get("signed-data.os2")));
//        module.setSignatureAlgorithm("MD5withRSA");
//        module.setSourceFile(input);
//        module.setDestinationFile(Paths.get("./signed-data.os2"));
//        module.setKeyLength(1024);
//        module.sign(false);
//        System.out.println(module.verifySignature());

//        Path input = Paths.get(args[0]);
//        RSAModule module = new RSAModule(new FileParser(Paths.get("./pub-key.os2")), new FileParser(Paths.get("./priv-key.os2")), null);
//        RSAModule module = new RSAModule(new FileParser(Paths.get("./priv-key.os2")), new FileParser(Paths.get("./envelope.os2")));
//        RSAModule module = new RSAModule();
//        module.setSourceFile(input);
//        module.setEncryptionAlgorithm("DESede");
//        module.setKeyLength(2048);
//        module.setEncryptionKeySize(112);
//        module.setSignatureAlgorithm("SHA256withRSA");
//        module.setDestinationFile(Paths.get("./envelope.os2"));
//        module.setDestinationFile(Paths.get("./unvelope.os2"));
//        module.wrap(false);
//        module.unwrap();
//        module.signEnvelope(false, false, Paths.get("./signed-envelope.os2"));
//
//        module = new RSAModule(new FileParser(Paths.get("./signature-pub-key.os2")), null, new FileParser(Paths.get("./signed-envelope.os2")));
//        System.out.println(module.verifySignature(Files.readAllBytes(Paths.get("./envelope.os2"))));
//        module.setDestinationFile(Paths.get("./unvelope.os2"));
//        module.addParser("envelope", new FileParser(Paths.get("./envelope.os2")));
//        module.addParser("private", new FileParser(Paths.get("./envelope-priv-key.os2")));
//        module.updateParameters();
//        module.unwrap();

//        module = new RSAModule(new FileParser(Paths.get("./envelope-priv-key.os2")), new FileParser(Paths.get("./envelope.os2")));
//        module.setDestinationFile(Paths.get("./unvelope.os2"));
//        module.unwrap();

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("greska u argumentima: " + e.getMessage());
            System.exit(1);
        }
        try {
            switch (cmd.getOptionValue("f")) {
                case "sign":
                    createSignature(cmd, Paths.get(cmd.getOptionValue("s")), Paths.get("d"));
                    break;
                case "ver":
                    boolean b = verifySignature(cmd, Paths.get(cmd.getOptionValue("s")), Paths.get(cmd.getOptionValue("sf")));
                    System.out.println("Potpis je " + (b ? "" : "ne") + "valjan");
                    break;
                case "wrap":
                    wrapData(cmd, Paths.get(cmd.getOptionValue("s")), Paths.get("d"));
                    break;
                case "unwrap":
                    unwrapData(cmd, Paths.get(cmd.getOptionValue("s")), Paths.get(cmd.getOptionValue("d")));
                    break;
                case "dseal":
                    sealData(cmd);
                    break;
                case "oseal":
                    unsealData(cmd);
                    break;
                default:
                    formatter.printHelp("test", options);
            }
        } catch (Exception e) {
            System.err.println("Pogrešno zadani parametri, provjeri parametre... " + e.getMessage());
        }

    }

    private static void unsealData(CommandLine cmd) throws NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        if (verifySignature(cmd, Paths.get(cmd.getOptionValue("s")), Paths.get(cmd.getOptionValue("sf")))) {
            unwrapData(cmd, Paths.get(cmd.getOptionValue("s")), Paths.get("d"));
        }
    }

    private static void sealData(CommandLine cmd) throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, InvalidParameterSpecException, InvalidKeySpecException, IllegalBlockSizeException, SignatureException {
        wrapData(cmd, Paths.get(cmd.getOptionValue("s")), Paths.get(cmd.getOptionValue("d")));
        createSignature(cmd, Paths.get(cmd.getOptionValue("d")), Paths.get(cmd.getOptionValue("sf")));
    }

    private static void unwrapData(CommandLine cmd, Path input, Path output) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        if (!cmd.hasOption("ss")) {
            formatter.printHelp("test", options);
            System.exit(1);
        }
        Path privKey = Paths.get(cmd.getOptionValue("ss"));

        RSAModule module = new RSAModule(new FileParser(privKey), new FileParser(input));
        module.setDestinationFile(output);
        module.unwrap();
    }

    private static void wrapData(CommandLine cmd, Path input, Path output) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, InvalidKeyException, InvalidKeySpecException {
        if (!cmd.hasOption("ea")) {
            formatter.printHelp("test", options);
            System.exit(1);
        }
        String algorithm = cmd.getOptionValue("ea");

        if (!cmd.hasOption("em")) {
            formatter.printHelp("test", options);
            System.exit(1);
        }
        String transformation = cmd.getOptionValue("em");

        if (!cmd.hasOption("el")) {
            formatter.printHelp("test", options);
            System.exit(1);
        }
        int l = Integer.parseInt(cmd.getOptionValue("el"));
        if (algorithm.equals("AES") && !SUPPORTED_AES_KEY_LENGTHS.contains(l)) {
            System.err.println("Unsupported key length");
            formatter.printHelp("test", options);
            System.exit(1);
        } else if (algorithm.equals("DESede") && !SUPPORTED_3DES_KEY_LENGTHS.contains(l)) {
            System.err.println("Unsupported key length");
            formatter.printHelp("test", options);
            System.exit(1);
        }

        int ln = Integer.parseInt(cmd.getOptionValue("rl"));
        if (!SUPPORTED_RSA_KEY_LENGTHS.contains(ln)) {
            System.err.println("Unsupported key length");
            formatter.printHelp("test", options);
            System.exit(1);
        }

        RSAModule module = new RSAModule();
        module.setSourceFile(input);
        module.setDestinationFile(output);
        module.setEncryptionAlgorithm(algorithm);
        module.setEncryptionTransformation(transformation);
        module.setEncryptionKeySize(l);
        module.setKeyLength(ln);

        boolean hasPublicKey = cmd.hasOption("sp");
        if (hasPublicKey) {
            module.addParser("public", new FileParser(Paths.get(cmd.getOptionValue("sp"))));
            module.updateParameters();
            module.wrap(true);
        } else {
            module.wrap(false);
        }
//        String transformation = cmd.getOptionValue("em");

//        RSAModule module = new RSAModule(new FileParser(Paths.get("./pub-key.os2")), new FileParser(Paths.get("./priv-key.os2")), null);
//        RSAModule module = new RSAModule(new FileParser(Paths.get("./priv-key.os2")), new FileParser(Paths.get("./envelope.os2")));
//        RSAModule module = new RSAModule();
//        module.setSourceFile(input);
//        module.setEncryptionAlgorithm("DESede");
//        module.setKeyLength(2048);
//        module.setEncryptionKeySize(112);
//        module.setSignatureAlgorithm("SHA256withRSA");
//        module.setDestinationFile(Paths.get("./envelope.os2"));
//        module.setDestinationFile(Paths.get("./unvelope.os2"));
//        module.wrap(false);
//        module.unwrap();
    }

    private static boolean verifySignature(CommandLine cmd, Path input, Path sPath) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if (!cmd.hasOption("sp")) {
            formatter.printHelp("test", options);
            System.exit(1);
        }
        Path pubKey = Paths.get(cmd.getOptionValue("sp"));
        RSAModule module = new RSAModule(new FileParser(pubKey), null, new FileParser(sPath));
        return module.verifySignature(Files.readAllBytes(input));
    }

    private static void createSignature(CommandLine cmd, Path input, Path output) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if (!cmd.hasOption("sa")) {
            formatter.printHelp("test", options);
            System.exit(1);
        }
        String algorithm = cmd.getOptionValue("sa");

        if (!cmd.hasOption("rl")) {
            formatter.printHelp("test", options);
            System.exit(1);
        }
        int l = Integer.parseInt(cmd.getOptionValue("rl"));
        if (!SUPPORTED_RSA_KEY_LENGTHS.contains(l)) {
            System.err.println("Unsupported key length");
            formatter.printHelp("test", options);
            System.exit(1);
        }

        RSAModule module = new RSAModule();
        module.setSourceFile(input);
        module.setDestinationFile(output);
        module.setSignatureAlgorithm(algorithm);
        module.setKeyLength(l);

        if (cmd.hasOption("ss")) {
            module.addParser("private", new FileParser(Paths.get(cmd.getOptionValue("ss"))));
            module.updateParameters();
            module.sign(true, Files.readAllBytes(input));
        } else {
            module.sign(false, Files.readAllBytes(input));
        }


//        RSAModule module = new RSAModule(new FileParser(Paths.get("./pub-key.os2")),
//                new FileParser(Paths.get("./priv-key.os2")),
//                new FileParser(Paths.get("signed-data.os2")));
//        module.setSignatureAlgorithm("MD5withRSA");
//        module.setSourceFile(input);
//        module.setDestinationFile(Paths.get("./signed-data.os2"));
//        module.setKeyLength(1024);
//        module.sign(false);
//        System.out.println(module.verifySignature());
    }

    private static Options setupOptions() {
        Options options = new Options();
        Option function = new Option("f", "function", true, "Function to perform:\n" +
                "\tsig - create digital signature\n" +
                "\tver - verify digital signature\n" +
                "\twrap - wrap document with digital envelope\n" +
                "\tunwrap - unwrap document from digital envelope\n" +
                "\tdseal - create a digital seal\n" +
                "\toseal - open digital seal");
        function.setRequired(true);
        options.addOption(function);

        Option source = new Option("s", "source-file", true, "Path to source file, must be in working directory");
        source.setRequired(true);
        options.addOption(source);

        Option destination = new Option("d", "dest-path", true, "Path to output file, must be in working directory, will be overwritten");
        destination.setRequired(false);
        options.addOption(destination);

        Option sigPath = new Option("sf", "signature-file", true, "Path to signature file");
        sigPath.setRequired(false);
        options.addOption(sigPath);

        Option encryptionKey = new Option("e", "encryption-key", true, "Path to encryption key file");
        encryptionKey.setRequired(false);
        options.addOption(encryptionKey);

        Option sigPubKey = new Option("sp", "signature-public-key", true, "Path to digital signature public key");
        sigPubKey.setRequired(false);
        options.addOption(sigPubKey);

        Option sigPrivKey = new Option("ss", "signature-private-key", true, "Path to digital signature private key");
        sigPrivKey.setRequired(false);
        options.addOption(sigPrivKey);

        Option envPubKey = new Option("ep", "envelope-public-key", true, "Path to digital envelope public key");
        envPubKey.setRequired(false);
        options.addOption(envPubKey);

        Option envPrivKey = new Option("ss", "envelope-private-key", true, "Path to digital envelope private key");
        envPrivKey.setRequired(false);
        options.addOption(envPrivKey);

        Option hashAlg = new Option("sa", "signature-algorithm", true, "Digital signature algorithm. Supported:\n" +
                "\t-MD5withRSA\n" +
                "\t-SHA1withRSA\n" +
                "\t-SHA256withRSA\n" +
                "\t-SHA384withRSA\n" +
                "\t-SHA512withRSA");
        hashAlg.setRequired(false);
        options.addOption(hashAlg);

        Option rsaLen = new Option("rl", "rsa-key-length", true, "Key length for RSA keypair. Supported sizes: 512, 1024, 2048 bits");
        rsaLen.setRequired(false);
        options.addOption(rsaLen);

        Option enAlg = new Option("ea", "encryption-algorithm", true, "Symmetric encryption algorithm. AES and 3DES(type in 'DESede') are supported");
        enAlg.setRequired(false);
        options.addOption(enAlg);

        Option enMeth = new Option("em", "encryption-method", true, "Symmetric encryption method. ECB and CBC are supported");
        enMeth.setRequired(false);
        options.addOption(enMeth);

        Option eLen = new Option("el", "encryption-key-length", true, "Key length for symmetric encryption. Depends on the algorithm");
        eLen.setRequired(false);
        options.addOption(eLen);

        return options;
    }
}
