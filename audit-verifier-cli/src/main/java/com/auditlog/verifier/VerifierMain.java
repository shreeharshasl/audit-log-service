package com.auditlog.verifier;

/**
 * Entry point for the offline bundle verifier.
 *
 * <p>Bundle verification lands with the Scenario B export work; this currently only reports the hash
 * format it would verify against.
 */
public final class VerifierMain {

    private VerifierMain() {}

    public static void main(String[] args) {
        System.out.println("audit-verifier (hash format v" + com.auditlog.hashing.HashFormat.VERSION + ")");
        System.out.println("Bundle verification is not implemented yet.");
    }
}
