import crypto.RSAModule;
import util.FileParser;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

public class Main {
    public static void main(String[] args) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, IOException, SignatureException, NoSuchPaddingException, InvalidKeySpecException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
        //TODO: parsiranje argumenata naredbenog retka
        //TODO: prikaz opcija
        //TODO: parser datoteke

//        FileParser parser = new FileParser(Paths.get("./secret-key-test.txt.key"));
//        FileParser parser1 = new FileParser(Paths.get("./crypted-data.os2"));
//        Path input = Paths.get(args[0]);
//        SymmetricCipher cipher = new SymmetricCipher();
//        cipher.addParser(SymmetricCipher.KEY_PARSER, parser);
//        cipher.addParser(SymmetricCipher.DATA_PARSER, parser1);
//        cipher.setSourceFile(input);
////        cipher.setDestinationFile(Paths.get("crypted-data.os2"));
//        cipher.setDestinationFile(Paths.get("decrypted-data.os2"));
////        cipher.setAlgorithm("DESede");
////        cipher.setTransformation("CBC");
////        cipher.setKeySize(112);
////        cipher.encrypt(true);
//        cipher.decrypt();

//        Path input = Paths.get(args[0]);
//        RSAModule module = new RSAModule(new FileParser(Paths.get("./pub-key.os2")),
//                new FileParser(Paths.get("./priv-key.os2")),
//                new FileParser(Paths.get("signed-data.os2")));
////        module.setSignatureAlgorithm("MD5withRSA");
//        module.setSourceFile(input);
////        module.setDestinationFile(Paths.get("./signed-data.os2"));
////        module.setKeyLength(1024);
////        module.sign(false);
//        System.out.println(module.verifySignature());

        Path input = Paths.get(args[0]);
//        RSAModule module = new RSAModule(new FileParser(Paths.get("./pub-key.os2")), new FileParser(Paths.get("./priv-key.os2")), null);
        RSAModule module = new RSAModule(new FileParser(Paths.get("./priv-key.os2")), new FileParser(Paths.get("./envelope.os2")));
//        module.setSourceFile(input);
//        module.setEncryptionAlgorithm("DESede");
//        module.setKeyLength(1024);
//        module.setEncryptionKeySize(112);
//        module.setDestinationFile(Paths.get("./envelope.os2"));
        module.setDestinationFile(Paths.get("./unvelope.os2"));
//        module.envelop(false);
        module.unwrap();
    }
}
