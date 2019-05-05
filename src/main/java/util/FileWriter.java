package util;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.StringJoiner;

import static util.Constants.*;

public class FileWriter {
    private Path file;
    private Map<String, String> fields = new LinkedHashMap<>();

    public FileWriter(Path file) {
        this.file = file;
    }

    public FileWriter() {

    }

    public static String formatString(String s) {
        StringJoiner joiner = new StringJoiner("\n\t", "\t", "\n");
        int noParts = s.length() / CHARS_PER_LINE;

        for (int i = 0; i < noParts; i++) {
            joiner.add(s.substring(i * 60, (i + 1) * 60));
        }
        joiner.add(s.substring(noParts * CHARS_PER_LINE));

        return joiner.toString();
    }

    public void writeData() throws IOException {
        StringJoiner joiner = new StringJoiner("\n", MARGIN_START + "\n", MARGIN_END + "\n");

        joiner.add(DESCRIPTION_KEY + ":");
        joiner.add(fields.get(DESCRIPTION_KEY));
        joiner.add(METHOD_KEY + ":");
        joiner.add(fields.get(METHOD_KEY));

        fields.forEach((k, v) -> {
            if (k.equals(DESCRIPTION_KEY) || k.equals(METHOD_KEY)) {
                return;
            }

            joiner.add(k + ":");
            joiner.add(v);
        });

        Files.write(file, joiner.toString().getBytes());
    }

    public void setDescription(String description) {
        fields.put(DESCRIPTION_KEY, formatString(description));
    }

    public void setMethods(String... methods) {
        StringJoiner joiner = new StringJoiner("\n\t", "\t", "\n");
        for (String m : methods) {
            joiner.add(m);
        }

        fields.put(METHOD_KEY, joiner.toString());
    }

    public void setFileName(Path fileName) {
        fields.put(FILENAME_KEY, formatString(fileName.toString()));
    }

    public void setData(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : Base64.getEncoder().encode(data)) {
            sb.append(String.format("%02X", b));
        }
        fields.put(DATA_KEY, formatString(sb.toString()));
    }

    //[58, 110, 69, -5, -41, 17, 96, 49, 20, 40, -6, -11, 28, 125, -80, 121]
    public void setSecretKey(Key key) {
        StringBuilder sb = new StringBuilder();
        for (byte b : key.getEncoded()) {
            sb.append(String.format("%02X", b));
        }
        fields.put(SECRETKEY_KEY, formatString(sb.toString()));
    }

    public void setInitializationVector(byte[] vector) {
        StringBuilder sb = new StringBuilder();
        for (byte b : vector) {
            sb.append(String.format("%02X", b));
        }
        fields.put(INITVECTOR_KEY, formatString(sb.toString()));
    }

    public void setKeyLengths(int... lengths) {
        StringJoiner joiner = new StringJoiner("\n\t", "\t", "\n");
        for (int m : lengths) {
            joiner.add(String.format("%04X", m & 0xffff));
        }

        fields.put(KEYLENGTH_KEY, joiner.toString());
    }

    public void setModulus(BigInteger modulus) {
        fields.put(MODULUS_KEY, formatString(modulus.toString(16)));
    }

    public void setPrivateExponent(BigInteger privateExponent) {
        fields.put(PRIVEXP_KEY, formatString(privateExponent.toString(16)));
    }

    public void setPublicExponent(BigInteger publicExponent) {
        fields.put(PUBEXP_KEY, formatString(publicExponent.toString(16)));
    }

    public void setSignature(byte[] signature) {
        StringBuilder sb = new StringBuilder();
        for (byte b : signature) {
            sb.append(String.format("%02X", b));
        }
        fields.put(SIGNATURE_KEY, formatString(sb.toString()));
    }

    public void setEnvelopeData(byte[] envelopeData) {
        StringBuilder sb = new StringBuilder();
        for (byte b : envelopeData) {
            sb.append(String.format("%02X", b));
        }
        fields.put(ENVDATA_KEY, formatString(sb.toString()));
    }

    public void setEnvelopeCryptKey(byte[] cryptKey) {
        StringBuilder sb = new StringBuilder();
        for (byte b : cryptKey) {
            sb.append(String.format("%02X", b));
        }
        fields.put(ENVCRYPT_KEY, formatString(sb.toString()));
    }

}
