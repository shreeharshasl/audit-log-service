/**
 * Domain kernel for tamper-evident hashing.
 *
 * <p>Pure Java: no Spring, no JDBC, no persistence annotations. The offline verifier depends on
 * this package and nothing else, so a recipient recomputes exactly the bytes the service computed.
 *
 * <p>Kept as a single package on purpose. Splitting it would force callers to import internals, and
 * the public surface is the hash construction itself, not a set of subdomains.
 */
package com.auditlog.hashing;
