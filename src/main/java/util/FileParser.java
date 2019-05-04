package util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import static util.Constants.*;

public class FileParser {
    private List<String> lines;
    private Map<String, String> fields = new HashMap<>();
    private StringJoiner comments = new StringJoiner("\n");

    public FileParser(Path file) throws IOException {
        if (!Files.exists(file)) {
            throw new IllegalArgumentException("Datoteka " + file + " ne postoji");
        }

        lines = Files.readAllLines(file);
            parse();
    }
    public FileParser(Path... files) throws IOException {
        for(Path f : files) {
            lines = Files.readAllLines(f);
            parse();
        }
    }

    private void parse() {
        int i = 0;
        while (!lines.get(i).equals(MARGIN_START)) {
            comments.add(lines.get(i++));
        }

        for (++i; lines.get(i).startsWith(MARGIN_END); ) {
            i = skipWhiteSpace(i);
            i = parseSimple(i + 1, lines.get(i).split(":")[0]);
//            if (lines.get(i).startsWith(DESCRIPTION_KEY)) {
//                i = parseSimple(++i, DESCRIPTION_KEY);
//                i = skipWhiteSpace(i);
//                continue;
//            }
//            if (lines.get(i).startsWith(METHOD_KEY)) {
//                i = parseSimple(++i, METHOD_KEY);
//                i = skipWhiteSpace(i);
//                continue;
//            }
//            if (lines.get(i).startsWith(FILENAME_KEY)) {
//                i = parseSimple(++i, FILENAME_KEY);
//                i = skipWhiteSpace(i);
//                continue;
//            }
//
//            if (lines.get(i).startsWith(KEYLENGTH_KEY)) {
//                i = parseSimple(++i, KEYLENGTH_KEY);
//                i = skipWhiteSpace(i);
//                continue;
//            }
//
//            if (lines.get(i).startsWith(SECRETKEY_KEY)) {
//                i = parseSimple(++i, SECRETKEY_KEY);
//                i = skipWhiteSpace(i);
//                continue;
//            }
//
//            if (lines.get(i).startsWith(INITVECTOR_KEY)) {
//                i = parseSimple(++i, INITVECTOR_KEY);
//                i = skipWhiteSpace(i);
//                continue;
//            }
//
//            if (lines.get(i).startsWith(MODULUS_KEY)) {
//                i = parseSimple(++i, MODULUS_KEY);
//                i = skipWhiteSpace(i);
//                continue;
//            }
//
//            if (lines.get(i).startsWith(PUBEXP_KEY)) {
//                i = parseSimple(++i, PUBEXP_KEY);
//                i = skipWhiteSpace(i);
//                continue;
//            }
//
//            if (lines.get(i).startsWith(PRIVEXP_KEY)) {
//                i = parseSimple(++i, PRIVEXP_KEY);
//                i = skipWhiteSpace(i);
//                continue;
//            }
//
//            if (lines.get(i).startsWith(SIGNATURE_KEY)) {
//                i = parseSimple(++i, SIGNATURE_KEY);
//                i = skipWhiteSpace(i);
//                continue;
//            }
//
//            if (lines.get(i).startsWith(DATA_KEY)) {
//                i = parseSimple(++i, DATA_KEY);
//                i = skipWhiteSpace(i);
//                continue;
//            }
//
//            if (lines.get(i).startsWith(ENVDATA_KEY)) {
//                i = parseSimple(++i, ENVDATA_KEY);
//                i = skipWhiteSpace(i);
//                continue;
//            }
//
//            if (lines.get(i).startsWith(ENVCRYPT_KEY)) {
//                i = parseSimple(++i, ENVCRYPT_KEY);
//                i = skipWhiteSpace(i);
//            }
        }

        for (; i < lines.size(); i++) {
            comments.add(lines.get(i));
        }
    }


    private int parseSimple(int i, String key) {
        if (!fields.containsKey(key)) {
            fields.put(key, "");
        }
        for (; (lines.get(i).startsWith("\t") || lines.get(i).isEmpty()) && !lines.get(i).equals(MARGIN_END); i++) {
            if (!lines.get(i).isEmpty()) {
                fields.put(key, fields.get(key) + "\n" + lines.get(i));
            }
        }

        return i;
    }

    private int skipWhiteSpace(int i) {
        while (lines.get(i).isEmpty()) {
            i++;
        }
        return i;
    }

    public List<String> getMethods() {
        String[] methods = fields.get(METHOD_KEY).split("\n");
        return Arrays.asList(methods);
    }

    public String getMethod() {
        return getMethods().get(0);
    }

    public String getDescription() {
        return fields.get(DESCRIPTION_KEY);
    }

    public String getFilename() {
        return fields.get(FILENAME_KEY);
    }

    public String getData() {
        StringBuilder builder = new StringBuilder();
        for (String s : fields.get(DATA_KEY).split("\n")) {
            builder.append(s);
        }

        return builder.toString();
    }

    public String getSecretkey() {
        StringBuilder builder = new StringBuilder();
        for (String s : fields.get(SECRETKEY_KEY).split("\n")) {
            builder.append(s);
        }

        return builder.toString();
    }

    public String getModulus() {
        StringBuilder builder = new StringBuilder();
        for (String s : fields.get(MODULUS_KEY).split("\n")) {
            builder.append(s);
        }

        return builder.toString();
    }

    public String getPrivateExponent() {
        StringBuilder builder = new StringBuilder();
        for (String s : fields.get(PRIVEXP_KEY).split("\n")) {
            builder.append(s);
        }

        return builder.toString();
    }

    public String getPublicExponent() {
        StringBuilder builder = new StringBuilder();
        for (String s : fields.get(PUBEXP_KEY).split("\n")) {
            builder.append(s);
        }

        return builder.toString();
    }

    public String getInitializationVector() {
        StringBuilder builder = new StringBuilder();
        for (String s : fields.get(INITVECTOR_KEY).split("\n")) {
            builder.append(s);
        }

        return builder.toString();
    }

    public String getSignature() {
        StringBuilder builder = new StringBuilder();
        for (String s : fields.get(SIGNATURE_KEY).split("\n")) {
            builder.append(s);
        }

        return builder.toString();
    }

    public String getEnvelopeData() {
        StringBuilder builder = new StringBuilder();
        for (String s : fields.get(ENVDATA_KEY).split("\n")) {
            builder.append(s);
        }

        return builder.toString();
    }

    public String getEnvelopeCryptKey() {
        StringBuilder builder = new StringBuilder();
        for (String s : fields.get(ENVCRYPT_KEY).split("\n")) {
            builder.append(s);
        }

        return builder.toString();
    }

    public List<String> getKeyLengths() {
        return Arrays.asList(fields.get(KEYLENGTH_KEY).split("\n"));
    }

    public String getKeyLength() {
        return getKeyLengths().get(0);
    }


}
