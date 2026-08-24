package com.auditlog.hashing;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Deterministic JSON serialization, so that the same logical payload always produces the same bytes
 * and therefore the same hash.
 *
 * <p>Hashing a payload by calling {@code toString()} on a map is the most common way to build a hash
 * chain that fails verification at random: key order is unspecified, whitespace varies, and number
 * formatting differs across languages and JDK versions.
 *
 * <h2>Format: audit-canonical-json v1</h2>
 *
 * <ul>
 *   <li>Object keys sorted by UTF-16 code unit ({@link String#compareTo}), matching RFC 8785.
 *   <li>No insignificant whitespace.
 *   <li>Strings escaped minimally: the two-character escapes for quote, backslash, backspace, tab,
 *       newline, form feed and carriage return; all other control characters as a six-character
 *       &#92;u escape. Non-ASCII characters are emitted literally as UTF-8.
 *   <li>Duplicate object keys are rejected rather than silently last-wins.
 *   <li><strong>Numbers must be integers</strong> in the range ±(2^53 - 1).
 * </ul>
 *
 * <p>The number restriction is the one deliberate narrowing of RFC 8785. Canonicalizing arbitrary
 * IEEE-754 doubles requires reproducing ECMAScript's shortest-round-trip formatting exactly, which
 * is subtle and easy to get wrong in a way that only shows up as a corrupt chain months later.
 * Audit payloads have no legitimate need for floats: monetary amounts belong in minor units or a
 * decimal string, and anything else can be sent as a string. Because the accepted subset is a
 * strict subset of RFC 8785, output here is byte-identical to a compliant JCS implementation for
 * every value we accept.
 */
public final class CanonicalJson {

    /** Beyond this, IEEE-754 doubles lose integer precision and JSON consumers disagree. */
    public static final long MAX_SAFE_INTEGER = 9007199254740991L;

    public static final long MIN_SAFE_INTEGER = -9007199254740991L;

    private static final ObjectMapper MAPPER = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

    private CanonicalJson() {}

    public static JsonNode parse(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            throw new CanonicalJsonException("payload is not valid JSON: " + e.getOriginalMessage(), e);
        }
    }

    public static byte[] canonicalize(JsonNode node) {
        return canonicalString(node).getBytes(StandardCharsets.UTF_8);
    }

    public static String canonicalString(JsonNode node) {
        StringBuilder out = new StringBuilder();
        write(node, out, "");
        return out.toString();
    }

    /** Reads a JSON string and returns its canonical form in one step. */
    public static byte[] canonicalize(String json) {
        return canonicalize(parse(json));
    }

    private static void write(JsonNode node, StringBuilder out, String path) {
        if (node == null || node.isNull()) {
            out.append("null");
            return;
        }
        switch (node.getNodeType()) {
            case OBJECT -> writeObject((ObjectNode) node, out, path);
            case ARRAY -> writeArray(node, out, path);
            case STRING -> writeString(node.textValue(), out);
            case NUMBER -> writeNumber(node, out, path);
            case BOOLEAN -> out.append(node.booleanValue() ? "true" : "false");
            default ->
                throw new CanonicalJsonException(
                        "unsupported JSON node type " + node.getNodeType() + " at " + describe(path));
        }
    }

    private static void writeObject(ObjectNode node, StringBuilder out, String path) {
        List<String> names = new ArrayList<>();
        for (Iterator<String> it = node.fieldNames(); it.hasNext(); ) {
            names.add(it.next());
        }
        Collections.sort(names);

        out.append('{');
        boolean first = true;
        for (String name : names) {
            if (!first) {
                out.append(',');
            }
            first = false;
            writeString(name, out);
            out.append(':');
            write(node.get(name), out, path + "/" + JsonPointers.escape(name));
        }
        out.append('}');
    }

    private static void writeArray(JsonNode node, StringBuilder out, String path) {
        out.append('[');
        for (int i = 0; i < node.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            write(node.get(i), out, path + "/" + i);
        }
        out.append(']');
    }

    private static void writeNumber(JsonNode node, StringBuilder out, String path) {
        if (node.isFloatingPointNumber()) {
            BigDecimal value = node.decimalValue();
            throw new CanonicalJsonException(
                    "floating point number %s at %s is not allowed; send it as a string or an integer in minor units"
                            .formatted(value.toPlainString(), describe(path)));
        }
        BigInteger value = node.bigIntegerValue();
        if (value.compareTo(BigInteger.valueOf(MAX_SAFE_INTEGER)) > 0
                || value.compareTo(BigInteger.valueOf(MIN_SAFE_INTEGER)) < 0) {
            throw new CanonicalJsonException("integer %s at %s is outside the safe range ±(2^53-1); send it as a string"
                    .formatted(value, describe(path)));
        }
        out.append(value.toString());
    }

    private static void writeString(String value, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\t' -> out.append("\\t");
                case '\n' -> out.append("\\n");
                case '\f' -> out.append("\\f");
                case '\r' -> out.append("\\r");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    private static String describe(String path) {
        return path.isEmpty() ? "the payload root" : path;
    }

    /** Convenience for callers holding a plain map rather than a parsed tree. */
    public static JsonNode toNode(Map<String, ?> map) {
        return MAPPER.valueToTree(map);
    }
}
