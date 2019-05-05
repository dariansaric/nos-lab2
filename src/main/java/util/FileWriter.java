package util;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

import static util.Constants.*;

public class FileWriter {
    private Path file;
    private Map<String, String> fields = new HashMap<>();

    public FileWriter(Path file) {
        this.file = file;
    }

    public FileWriter() {

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
        fields.put(DATA_KEY, formatString(new String(data)));
    }

    public void setSecretKey(SecretKey key) {
        fields.put(SECRETKEY_KEY, formatString(key.toString()));
    }

    public void setKeyLengths(int... lengths) {
        StringJoiner joiner = new StringJoiner("\n\t", "\t", "\n");
        for (int m : lengths) {
            joiner.add(Integer.toHexString(m));
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
        fields.put(SIGNATURE_KEY, formatString(new String(signature)));
    }

    public void setEnvelopeData(byte[] envelopeData) {
        fields.put(ENVDATA_KEY, formatString(new String(envelopeData)));
    }

    public void setEnvelopeCryptKey(byte[] cryptKey) {
        fields.put(ENVCRYPT_KEY, formatString(new String(cryptKey)));
    }

    private String formatString(String s) {
        StringJoiner joiner = new StringJoiner("\n\t", "\t", "\n");
        int noParts = s.length() / CHARS_PER_LINE;

        for (int i = 0; i < noParts; i++) {
            joiner.add(s.substring(i, (i + 1) * 60));
        }
        joiner.add(s.substring(noParts * CHARS_PER_LINE));

        return joiner.toString();
    }


}
