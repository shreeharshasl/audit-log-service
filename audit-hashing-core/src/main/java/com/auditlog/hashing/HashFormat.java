package com.auditlog.hashing;

/**
 * Version marker for the hash construction.
 *
 * <p>The version is mixed into every digest and stored on every record. If the scheme ever has to
 * change, old records stay verifiable under the rules that were in force when they were written,
 * instead of the whole chain appearing to break on the day of the upgrade.
 */
public final class HashFormat {

    public static final int VERSION = 1;

    /** Value used as the predecessor hash of the very first record. */
    public static final String GENESIS_CHAIN_HASH = "0".repeat(64);

    public static byte[] genesisChainHash() {
        return new byte[32];
    }

    private HashFormat() {}
}
