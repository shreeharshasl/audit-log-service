package com.auditlog.hashing;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Removes JSON Pointer paths from a payload while keeping remaining commitments verifiable.
 *
 * <p>Dropping the last child of an object would otherwise leave {@code {}}, which the flattener
 * treats as an {@code EMPTY_OBJECT} leaf that was never committed. After each removal this class
 * prunes empty objects and arrays that were not empty in the original payload. Array elements are
 * replaced with {@code null} rather than compacted, because compacting would renumber later indexes
 * and make every subsequent commitment look altered.
 */
public final class PayloadRedactor {

    private PayloadRedactor() {}

    public static JsonNode removePaths(JsonNode payload, List<String> pointers) {
        if (payload == null || !payload.isObject()) {
            throw new CanonicalJsonException("payload must be a JSON object");
        }
        if (pointers == null || pointers.isEmpty()) {
            throw new IllegalArgumentException("at least one path is required");
        }

        Set<String> originalEmptyLeaves = emptyLeafPaths(payload, "");
        ObjectNode root = payload.deepCopy();
        for (String pointer : uniquePointers(pointers)) {
            if (!removePointer(root, pointer)) {
                throw new IllegalArgumentException("path not present in payload: " + pointer);
            }
        }
        prune(root, "", originalEmptyLeaves);
        return root;
    }

    private static List<String> uniquePointers(List<String> pointers) {
        return new ArrayList<>(new LinkedHashSet<>(pointers));
    }

    private static boolean removePointer(ObjectNode root, String pointer) {
        requirePointer(pointer);
        String[] tokens = pointer.substring(1).split("/", -1);
        if (tokens.length == 1 && tokens[0].isEmpty()) {
            throw new IllegalArgumentException("cannot redact the document root");
        }

        JsonNode current = root;
        for (int i = 0; i < tokens.length - 1; i++) {
            current = child(current, JsonPointers.unescape(tokens[i]));
            if (current == null) {
                return false;
            }
        }

        String last = JsonPointers.unescape(tokens[tokens.length - 1]);
        if (current.isObject()) {
            ObjectNode object = (ObjectNode) current;
            if (!object.has(last)) {
                return false;
            }
            object.remove(last);
            return true;
        }
        if (current.isArray()) {
            Integer index = arrayIndex(last);
            if (index == null || index < 0 || index >= current.size()) {
                return false;
            }
            ((ArrayNode) current).set(index, NullNode.getInstance());
            return true;
        }
        return false;
    }

    private static JsonNode child(JsonNode parent, String token) {
        if (parent.isObject()) {
            JsonNode child = parent.get(token);
            return child == null || child.isMissingNode() ? null : child;
        }
        if (parent.isArray()) {
            Integer index = arrayIndex(token);
            if (index == null || index < 0 || index >= parent.size()) {
                return null;
            }
            return parent.get(index);
        }
        return null;
    }

    /**
     * RFC 6901: an array index is a decimal integer with no leading zeros, except {@code "0"}
     * itself.
     */
    private static Integer arrayIndex(String token) {
        if (token.isEmpty()) {
            return null;
        }
        if (token.length() > 1 && token.startsWith("0")) {
            return null;
        }
        try {
            return Integer.parseInt(token);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static void requirePointer(String pointer) {
        if (pointer == null || pointer.isBlank()) {
            throw new IllegalArgumentException("path is required");
        }
        if (!pointer.startsWith("/")) {
            throw new IllegalArgumentException("path must be a JSON Pointer starting with /: " + pointer);
        }
    }

    private static Set<String> emptyLeafPaths(JsonNode node, String path) {
        Set<String> out = new HashSet<>();
        collectEmptyLeaves(node, path, out);
        return out;
    }

    private static void collectEmptyLeaves(JsonNode node, String path, Set<String> out) {
        if (node.isObject()) {
            if (node.isEmpty()) {
                out.add(path);
                return;
            }
            node.fields()
                    .forEachRemaining(entry -> collectEmptyLeaves(
                            entry.getValue(), path + "/" + JsonPointers.escape(entry.getKey()), out));
            return;
        }
        if (node.isArray()) {
            if (node.isEmpty()) {
                out.add(path);
                return;
            }
            for (int i = 0; i < node.size(); i++) {
                collectEmptyLeaves(node.get(i), path + "/" + i, out);
            }
        }
    }

    /**
     * @return true when this node should be dropped from its parent
     */
    private static boolean prune(JsonNode node, String path, Set<String> keepEmpty) {
        if (node.isObject()) {
            ObjectNode object = (ObjectNode) node;
            List<String> names = new ArrayList<>();
            object.fieldNames().forEachRemaining(names::add);
            for (String name : names) {
                String childPath = path + "/" + JsonPointers.escape(name);
                if (prune(object.get(name), childPath, keepEmpty)) {
                    object.remove(name);
                }
            }
            return object.isEmpty() && !keepEmpty.contains(path);
        }
        if (node.isArray()) {
            ArrayNode array = (ArrayNode) node;
            for (int i = 0; i < array.size(); i++) {
                prune(array.get(i), path + "/" + i, keepEmpty);
            }
            return array.isEmpty() && !keepEmpty.contains(path);
        }
        return false;
    }
}
