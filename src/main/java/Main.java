import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        //TODO: parsiranje argumenata naredbenog retka
        //TODO: prikaz opcija
        //TODO: parser datoteke
        try {
            Cipher.getInstance("DESede/CBC/NoPadding");
            KeyGenerator g = KeyGenerator.getInstance("AES");
            g.init(128, new SecureRandom());
            System.out.println(Arrays.toString(g.generateKey().getEncoded()));
//            Cipher.ge
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }
}
