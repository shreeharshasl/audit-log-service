package com.auditlog.hashing;

/**
 * RFC 6901 JSON Pointer escaping for field paths.
 *
 * <p>Field paths are part of what each commitment covers, so the escaping has to be unambiguous:
 * without it, a key literally named {@code "a/b"} and a nested {@code {"a":{"b":...}}} would produce
 * the same path and could be substituted for one another.
 */
public final class JsonPointers {

    private JsonPointers() {}

    public static String escape(String token) {
        return token.replace("~", "~0").replace("/", "~1");
    }

    public static String unescape(String token) {
        return token.replace("~1", "/").replace("~0", "~");
    }
}
