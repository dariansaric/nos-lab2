package util;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class Constants {
    public static final List<Integer> SUPPORTED_RSA_KEY_LENGTHS = Arrays.asList(512, 1024, 2048);
    public static final List<Integer> SUPPORTED_AES_KEY_LENGTHS = Arrays.asList(128, 192, 256);
    public static final List<Integer> SUPPORTED_3DES_KEY_LENGTHS = Arrays.asList(112, 168);
    public static final List<String> SUPPORTED_ALGORITHMS = Arrays.asList("DESede", "AES");
    public static final List<String> SUPPORTED_TRANSFORMATIONS = Arrays.asList("ECB", "CBC", "OFB", "CFB", "CTR");
    static final String DESCRIPTION_KEY = "Description";
    static final String MARGIN_START = "---BEGIN OS2 CRYPTO DATA---";
    static final String MARGIN_END = "---END OS2 CRYPTO DATA---";
    static final String METHOD_KEY = "Method";
    static final String FILENAME_KEY = "File name";
    static final String KEYLENGTH_KEY = "Key length";
    static final String SECRETKEY_KEY = "Secret key";
    static final String INITVECTOR_KEY = "Initialization vector";
    static final String MODULUS_KEY = "Modulus";
    static final String PUBEXP_KEY = "Public exponent";
    static final String PRIVEXP_KEY = "Private exponent";
    static final String SIGNATURE_KEY = "Signature";
    static final String DATA_KEY = "Data";
    static final String ENVDATA_KEY = "Envelope data";
    static final String ENVCRYPT_KEY = "Envelope crypt key";
    static final int CHARS_PER_LINE = 60;

    static byte[] parseBytes(String s) {
        List<Byte> bytes = new LinkedList<>();
        for (int i = 0; i < s.length(); i += 2) {
            bytes.add((byte) Integer.parseInt(s.substring(i, i + 2), 16));
        }
        byte[] a = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); i++) {
            a[i] = bytes.get(i);
        }
        return a;
    }
}
