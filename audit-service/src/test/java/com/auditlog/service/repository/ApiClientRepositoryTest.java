package com.auditlog.service.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import com.auditlog.service.model.ApiClient;
import com.auditlog.service.model.ApiRole;

@ExtendWith(MockitoExtension.class)
class ApiClientRepositoryTest {

    @Mock
    private JdbcTemplate jdbc;

    @Mock
    private ResultSet resultSet;

    @Mock
    private Array sqlArray;

    @Test
    @DisplayName("roles stored as Object[] are still mapped")
    @SuppressWarnings("unchecked")
    void objectArrayRolesAreMapped() throws SQLException {
        when(sqlArray.getArray()).thenReturn(new Object[] {"APPEND", "READ"});
        when(resultSet.getObject("client_id", UUID.class))
                .thenReturn(UUID.fromString("11111111-1111-1111-1111-111111111111"));
        when(resultSet.getString("name")).thenReturn("bootstrap");
        when(resultSet.getString("key_hash")).thenReturn("aa".repeat(32));
        when(resultSet.getArray("roles")).thenReturn(sqlArray);
        when(resultSet.getBoolean("enabled")).thenReturn(true);
        when(resultSet.getObject("created_at", OffsetDateTime.class))
                .thenReturn(OffsetDateTime.of(2026, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC));
        when(jdbc.query(anyString(), any(RowMapper.class), eq("hash"))).thenAnswer(invocation -> {
            RowMapper<ApiClient> mapper = invocation.getArgument(1);
            return List.of(mapper.mapRow(resultSet, 0));
        });

        ApiClient client =
                new ApiClientRepository(jdbc).findEnabledByKeyHash("hash").orElseThrow();

        assertThat(client.roles()).containsExactlyInAnyOrder(ApiRole.APPEND, ApiRole.READ);
    }

    @Test
    @DisplayName("roles stored as String[] are mapped in order")
    @SuppressWarnings("unchecked")
    void stringArrayRolesAreMapped() throws SQLException {
        when(sqlArray.getArray()).thenReturn(new String[] {"VERIFY"});
        when(resultSet.getObject("client_id", UUID.class))
                .thenReturn(UUID.fromString("11111111-1111-1111-1111-111111111111"));
        when(resultSet.getString("name")).thenReturn("verifier");
        when(resultSet.getString("key_hash")).thenReturn("bb".repeat(32));
        when(resultSet.getArray("roles")).thenReturn(sqlArray);
        when(resultSet.getBoolean("enabled")).thenReturn(true);
        when(resultSet.getObject("created_at", OffsetDateTime.class))
                .thenReturn(OffsetDateTime.of(2026, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC));
        when(jdbc.query(anyString(), any(RowMapper.class), eq("verifier"))).thenAnswer(invocation -> {
            RowMapper<ApiClient> mapper = invocation.getArgument(1);
            return List.of(mapper.mapRow(resultSet, 0));
        });

        ApiClient client = new ApiClientRepository(jdbc).findByName("verifier").orElseThrow();

        assertThat(client.roles()).containsExactly(ApiRole.VERIFY);
        assertThat(client.enabled()).isTrue();
    }

    @Test
    @DisplayName("insert binds the client including its roles")
    void insertBindsClient() throws SQLException {
        Connection connection = mock(Connection.class);
        PreparedStatement statement = mock(PreparedStatement.class);
        when(connection.prepareStatement(anyString())).thenReturn(statement);
        when(connection.createArrayOf(eq("text"), any())).thenReturn(sqlArray);
        when(jdbc.execute(any(ConnectionCallback.class))).thenAnswer(invocation -> {
            ConnectionCallback<?> callback = invocation.getArgument(0);
            return callback.doInConnection(connection);
        });

        new ApiClientRepository(jdbc)
                .insert(new ApiClient(
                        UUID.fromString("11111111-1111-1111-1111-111111111111"),
                        "bootstrap",
                        "aa".repeat(32),
                        Set.of(ApiRole.APPEND),
                        true,
                        Instant.parse("2026-01-01T00:00:00Z")));

        verify(statement).setString(2, "bootstrap");
        verify(statement).setBoolean(5, true);
    }

    @Test
    @DisplayName("update credentials replaces the hash and roles")
    void updateCredentialsReplacesHashAndRoles() throws SQLException {
        Connection connection = mock(Connection.class);
        PreparedStatement statement = mock(PreparedStatement.class);
        when(connection.prepareStatement(anyString())).thenReturn(statement);
        when(connection.createArrayOf(eq("text"), any())).thenReturn(sqlArray);
        when(jdbc.execute(any(ConnectionCallback.class))).thenAnswer(invocation -> {
            ConnectionCallback<?> callback = invocation.getArgument(0);
            return callback.doInConnection(connection);
        });

        UUID id = UUID.fromString("11111111-1111-1111-1111-111111111111");
        new ApiClientRepository(jdbc).updateCredentials(id, "bb".repeat(32), Set.of(ApiRole.READ));

        verify(statement).setString(1, "bb".repeat(32));
        verify(statement).setObject(3, id);
    }
}
