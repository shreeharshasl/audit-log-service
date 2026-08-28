package com.auditlog.service.repository;

import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import com.auditlog.service.model.ApiClient;
import com.auditlog.service.model.ApiRole;

@Repository
public class ApiClientRepository {

    private static final String SELECT_COLUMNS =
            "SELECT client_id, name, key_hash, roles, enabled, created_at FROM api_client";

    private final JdbcTemplate jdbc;

    public ApiClientRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<ApiClient> findEnabledByKeyHash(String keyHashHex) {
        return jdbc.query(SELECT_COLUMNS + " WHERE key_hash = ? AND enabled = true", MAPPER, keyHashHex).stream()
                .findFirst();
    }

    public Optional<ApiClient> findByName(String name) {
        return jdbc.query(SELECT_COLUMNS + " WHERE name = ?", MAPPER, name).stream()
                .findFirst();
    }

    public void insert(ApiClient client) {
        jdbc.execute((ConnectionCallback<Void>) connection -> {
            try (PreparedStatement statement = connection.prepareStatement(
                    """
                    INSERT INTO api_client (client_id, name, key_hash, roles, enabled, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """)) {
                bind(statement, client, connection);
                statement.executeUpdate();
                return null;
            }
        });
    }

    public void updateCredentials(UUID clientId, String keyHashHex, Set<ApiRole> roles) {
        jdbc.execute((ConnectionCallback<Void>) connection -> {
            try (PreparedStatement statement = connection.prepareStatement(
                    """
                    UPDATE api_client
                    SET key_hash = ?, roles = ?, enabled = true
                    WHERE client_id = ?
                    """)) {
                statement.setString(1, keyHashHex);
                statement.setArray(2, connection.createArrayOf("text", roleNames(roles)));
                statement.setObject(3, clientId);
                statement.executeUpdate();
                return null;
            }
        });
    }

    private static void bind(PreparedStatement statement, ApiClient client, Connection connection) throws SQLException {
        statement.setObject(1, client.clientId());
        statement.setString(2, client.name());
        statement.setString(3, client.keyHashHex());
        statement.setArray(4, connection.createArrayOf("text", roleNames(client.roles())));
        statement.setBoolean(5, client.enabled());
        statement.setObject(6, OffsetDateTime.ofInstant(client.createdAt(), ZoneOffset.UTC));
    }

    private static String[] roleNames(Set<ApiRole> roles) {
        return roles.stream().map(ApiRole::name).toArray(String[]::new);
    }

    private static final RowMapper<ApiClient> MAPPER = (rs, rowNum) -> new ApiClient(
            rs.getObject("client_id", UUID.class),
            rs.getString("name"),
            rs.getString("key_hash"),
            roles(rs),
            rs.getBoolean("enabled"),
            rs.getObject("created_at", OffsetDateTime.class).toInstant());

    private static Set<ApiRole> roles(ResultSet rs) throws SQLException {
        Array array = rs.getArray("roles");
        Object raw = array.getArray();
        String[] names = raw instanceof String[] strings
                ? strings
                : Arrays.stream((Object[]) raw).map(Object::toString).toArray(String[]::new);
        Set<ApiRole> roles = new LinkedHashSet<>();
        for (String name : names) {
            roles.add(ApiRole.fromStored(name));
        }
        return roles;
    }
}
