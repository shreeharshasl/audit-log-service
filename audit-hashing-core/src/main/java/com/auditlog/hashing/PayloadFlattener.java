package com.auditlog.hashing;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

import com.auditlog.hashing.PayloadLeaf.LeafKind;
import com.fasterxml.jackson.databind.JsonNode;

/** Walks a payload into the flat, sorted list of positions that get individually committed. */
public final class PayloadFlattener {

    private final PayloadLimits limits;

    public PayloadFlattener(PayloadLimits limits) {
        this.limits = limits;
    }

    public PayloadFlattener() {
        this(PayloadLimits.DEFAULT);
    }

    /**
     * @return leaves ordered by path, which is also the order the payload root commits to
     */
    public List<PayloadLeaf> flatten(JsonNode payload) {
        if (payload == null || payload.isNull()) {
            throw new CanonicalJsonException("payload must be a JSON object, got null");
        }
        if (!payload.isObject()) {
            throw new CanonicalJsonException("payload must be a JSON object, got " + payload.getNodeType());
        }

        byte[] canonical = CanonicalJson.canonicalize(payload);
        if (canonical.length > limits.maxCanonicalBytes()) {
            throw new CanonicalJsonException("payload canonical form is %d bytes, limit is %d"
                    .formatted(canonical.length, limits.maxCanonicalBytes()));
        }

        List<PayloadLeaf> leaves = new ArrayList<>();
        collect(payload, "", 0, leaves);
        leaves.sort(Comparator.comparing(PayloadLeaf::path));
        return List.copyOf(leaves);
    }

    private void collect(JsonNode node, String path, int depth, List<PayloadLeaf> out) {
        if (depth > limits.maxDepth()) {
            throw new CanonicalJsonException(
                    "payload nesting exceeds depth limit of %d at %s".formatted(limits.maxDepth(), path));
        }
        if (out.size() > limits.maxLeaves()) {
            throw new CanonicalJsonException("payload exceeds the limit of %d fields".formatted(limits.maxLeaves()));
        }

        switch (node.getNodeType()) {
            case OBJECT -> {
                if (node.isEmpty()) {
                    out.add(new PayloadLeaf(path, LeafKind.EMPTY_OBJECT, "{}"));
                    return;
                }
                for (Iterator<String> it = node.fieldNames(); it.hasNext(); ) {
                    String name = it.next();
                    collect(node.get(name), path + "/" + JsonPointers.escape(name), depth + 1, out);
                }
            }
            case ARRAY -> {
                if (node.isEmpty()) {
                    out.add(new PayloadLeaf(path, LeafKind.EMPTY_ARRAY, "[]"));
                    return;
                }
                for (int i = 0; i < node.size(); i++) {
                    collect(node.get(i), path + "/" + i, depth + 1, out);
                }
            }
            case STRING -> {
                String text = node.textValue();
                if (text.length() > limits.maxStringLength()) {
                    throw new CanonicalJsonException("string at %s is %d characters, limit is %d"
                            .formatted(path, text.length(), limits.maxStringLength()));
                }
                out.add(leaf(path, LeafKind.STRING, node));
            }
            case NUMBER -> out.add(leaf(path, LeafKind.INTEGER, node));
            case BOOLEAN -> out.add(leaf(path, LeafKind.BOOLEAN, node));
            case NULL -> out.add(new PayloadLeaf(path, LeafKind.NULL, "null"));
            default ->
                throw new CanonicalJsonException("unsupported JSON node type " + node.getNodeType() + " at " + path);
        }
    }

    private static PayloadLeaf leaf(String path, LeafKind kind, JsonNode node) {
        return new PayloadLeaf(path, kind, CanonicalJson.canonicalString(node));
    }

    /** Canonical UTF-8 bytes of a leaf value, as fed into its commitment. */
    static byte[] valueBytes(PayloadLeaf leaf) {
        return leaf.canonicalValue().getBytes(StandardCharsets.UTF_8);
    }
}
