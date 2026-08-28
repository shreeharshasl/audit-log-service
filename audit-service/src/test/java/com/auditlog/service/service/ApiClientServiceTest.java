package com.auditlog.service.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.auditlog.hashing.Hex;
import com.auditlog.service.config.AuditProperties;
import com.auditlog.service.model.ApiClient;
import com.auditlog.service.model.ApiRole;
import com.auditlog.service.model.NewAuditEvent;
import com.auditlog.service.repository.ApiClientRepository;

@ExtendWith(MockitoExtension.class)
class ApiClientServiceTest {

    private static final Instant NOW = Instant.parse("2026-06-01T12:00:00Z");

    @Mock
    private ApiClientRepository clients;

    @Mock
    private AuditEventService events;

    @Test
    @DisplayName("SHA-256 of the same key is stable and lowercase hex")
    void keyHashIsStableHex() {
        assertThat(ApiKeyHasher.hash("test-admin-key-not-for-production"))
                .isEqualTo(ApiKeyHasher.hash("test-admin-key-not-for-production"))
                .hasSize(64)
                .matches("[0-9a-f]{64}");
        assertThat(ApiKeyHasher.hash("a")).isNotEqualTo(ApiKeyHasher.hash("b"));
        Hex.decode(ApiKeyHasher.hash("any"));
    }

    @Test
    @DisplayName("an unknown stored role is rejected")
    void unknownStoredRoleIsRejected() {
        assertThatThrownBy(() -> ApiRole.fromStored("NOPE")).isInstanceOf(IllegalStateException.class);
        assertThat(ApiRole.APPEND.authority()).isEqualTo("ROLE_APPEND");
        assertThat(ApiRole.fromStored("READ")).isEqualTo(ApiRole.READ);
    }

    @Test
    @DisplayName("a blank bootstrap key does not seed a client")
    void blankBootstrapKeySkipsSeed() {
        service("").ensureBootstrapClient();
        verify(clients, never()).insert(any());
        verify(clients, never()).updateCredentials(any(), any(), any());
    }

    @Test
    @DisplayName("a missing bootstrap client is inserted with every role")
    void missingBootstrapClientIsInserted() {
        when(clients.findByName(ApiClientService.BOOTSTRAP_CLIENT_NAME)).thenReturn(Optional.empty());

        service("secret").ensureBootstrapClient();

        ArgumentCaptor<ApiClient> captor = ArgumentCaptor.forClass(ApiClient.class);
        verify(clients).insert(captor.capture());
        assertThat(captor.getValue().name()).isEqualTo("bootstrap");
        assertThat(captor.getValue().roles()).isEqualTo(EnumSet.allOf(ApiRole.class));
        assertThat(captor.getValue().keyHashHex()).isEqualTo(ApiKeyHasher.hash("secret"));
        assertThat(captor.getValue().enabled()).isTrue();
    }

    @Test
    @DisplayName("an unchanged bootstrap client is left alone")
    void unchangedBootstrapClientIsNotUpdated() {
        ApiClient existing = new ApiClient(
                UUID.fromString("11111111-1111-1111-1111-111111111111"),
                "bootstrap",
                ApiKeyHasher.hash("secret"),
                EnumSet.allOf(ApiRole.class),
                true,
                NOW);
        when(clients.findByName("bootstrap")).thenReturn(Optional.of(existing));

        service("secret").ensureBootstrapClient();

        verify(clients, never()).insert(any());
        verify(clients, never()).updateCredentials(any(), any(), any());
    }

    @Test
    @DisplayName("a rotated bootstrap key updates the stored hash")
    void rotatedBootstrapKeyIsUpdated() {
        UUID id = UUID.fromString("11111111-1111-1111-1111-111111111111");
        ApiClient existing =
                new ApiClient(id, "bootstrap", ApiKeyHasher.hash("old"), EnumSet.allOf(ApiRole.class), true, NOW);
        when(clients.findByName("bootstrap")).thenReturn(Optional.of(existing));

        service("new").ensureBootstrapClient();

        verify(clients).updateCredentials(eq(id), eq(ApiKeyHasher.hash("new")), eq(EnumSet.allOf(ApiRole.class)));
    }

    @Test
    @DisplayName("authenticate ignores blank keys")
    void authenticateIgnoresBlankKeys() {
        assertThat(service("secret").authenticate(" ")).isEmpty();
        assertThat(service("secret").authenticate(null)).isEmpty();
        verify(clients, never()).findEnabledByKeyHash(any());
    }

    @Test
    @DisplayName("authenticate looks up the hash of a present key")
    void authenticateLooksUpHash() {
        when(clients.findEnabledByKeyHash(ApiKeyHasher.hash("secret"))).thenReturn(Optional.empty());
        assertThat(service("x").authenticate("secret")).isEmpty();
        verify(clients).findEnabledByKeyHash(ApiKeyHasher.hash("secret"));
    }

    @Test
    @DisplayName("privileged actions append typed events for the acting client")
    void privilegedActionsAppendTypedEvents() {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        PrivilegedActionAuditor auditor = new PrivilegedActionAuditor(events, clock);
        UUID exportId = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

        auditor.redacted("bootstrap", 3, List.of("/amount"));
        auditor.policyUpdated("bootstrap", 30);
        auditor.retentionApplied("bootstrap", 1, 30);
        auditor.exportCreated("bootstrap", exportId, 1, 2);
        auditor.exportRead("bootstrap", exportId, 1, 2);

        ArgumentCaptor<NewAuditEvent> captor = ArgumentCaptor.forClass(NewAuditEvent.class);
        verify(events, org.mockito.Mockito.times(5)).append(captor.capture());
        List<NewAuditEvent> recorded = captor.getAllValues();
        assertThat(recorded)
                .extracting(NewAuditEvent::eventType)
                .containsExactly(
                        PrivilegedActionAuditor.REDACTION,
                        PrivilegedActionAuditor.RETENTION_POLICY,
                        PrivilegedActionAuditor.RETENTION_APPLY,
                        PrivilegedActionAuditor.EXPORT_CREATE,
                        PrivilegedActionAuditor.EXPORT_READ);
        assertThat(recorded).allMatch(event -> event.actorId().equals("bootstrap"));
        assertThat(recorded.get(0).resourceId()).isEqualTo("3");
        assertThat(recorded.get(3).resourceId()).isEqualTo(exportId.toString());
    }

    @Test
    @DisplayName("a disabled bootstrap client is re-enabled on startup")
    void disabledBootstrapClientIsReenabled() {
        UUID id = UUID.fromString("11111111-1111-1111-1111-111111111111");
        ApiClient existing =
                new ApiClient(id, "bootstrap", ApiKeyHasher.hash("secret"), Set.of(ApiRole.READ), false, NOW);
        when(clients.findByName("bootstrap")).thenReturn(Optional.of(existing));

        service("secret").ensureBootstrapClient();

        verify(clients).updateCredentials(eq(id), eq(ApiKeyHasher.hash("secret")), eq(EnumSet.allOf(ApiRole.class)));
    }

    private ApiClientService service(String bootstrapKey) {
        AuditProperties properties = new AuditProperties(
                new AuditProperties.Payload(8, 256, 65536, 8192),
                new AuditProperties.Query(50, 200),
                new AuditProperties.Security(bootstrapKey, true));
        return new ApiClientService(clients, properties, Clock.fixed(NOW, ZoneOffset.UTC));
    }
}
