/**
 * Spring Boot application: HTTP adapters, application services, and JDBC persistence around {@code
 * audit-hashing-core}.
 *
 * <p>Dependency rule: {@code controller} → {@code service} → {@code repository}. The hashing core
 * is imported inward; Spring and JDBC types do not leak into the hashing core.
 */
package com.auditlog.service;
