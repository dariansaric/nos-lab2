import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) {
        //TODO: parsiranje argumenata naredbenog retka
        //TODO: prikaz opcija
        //TODO: parser datoteke
        try {
            Cipher.getInstance("DESede/CBC/NoPadding");
//            Cipher.ge
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }
}
