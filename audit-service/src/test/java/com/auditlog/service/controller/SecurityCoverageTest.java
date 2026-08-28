package com.auditlog.service.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.auditlog.service.model.ApiClient;
import com.auditlog.service.model.ApiRole;
import com.auditlog.service.service.ApiClientService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

class SecurityCoverageTest {

    private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("a missing or blank key is left anonymous")
    void missingKeyStaysAnonymous() throws Exception {
        ApiClientService clients = mock(ApiClientService.class);
        AuthenticationEntryPoint entryPoint = mock(AuthenticationEntryPoint.class);
        ApiKeyAuthenticationFilter filter = new ApiKeyAuthenticationFilter(clients, entryPoint);
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), chain);

        verify(clients, never()).authenticate(any());
        verify(entryPoint, never()).commence(any(), any(), any());
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("an unknown key is 401 and does not continue")
    void unknownKeyIsUnauthorized() throws Exception {
        ApiClientService clients = mock(ApiClientService.class);
        AuthenticationEntryPoint entryPoint = mock(AuthenticationEntryPoint.class);
        when(clients.authenticate("bad")).thenReturn(Optional.empty());
        ApiKeyAuthenticationFilter filter = new ApiKeyAuthenticationFilter(clients, entryPoint);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(ApiKeyAuthenticationFilter.HEADER, "bad");
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        verify(entryPoint).commence(eq(request), any(), any(BadCredentialsException.class));
        assertThat(chain.getRequest()).isNull();
    }

    @Test
    @DisplayName("a valid key authenticates the named client")
    void validKeyAuthenticates() throws Exception {
        ApiClientService clients = mock(ApiClientService.class);
        when(clients.authenticate("good"))
                .thenReturn(Optional.of(new ApiClient(
                        UUID.fromString("11111111-1111-1111-1111-111111111111"),
                        "reader",
                        "aa".repeat(32),
                        Set.of(ApiRole.READ),
                        true,
                        Instant.parse("2026-01-01T00:00:00Z"))));
        ApiKeyAuthenticationFilter filter =
                new ApiKeyAuthenticationFilter(clients, mock(AuthenticationEntryPoint.class));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(ApiKeyAuthenticationFilter.HEADER, "good");
        MockFilterChain chain = new MockFilterChain() {
            @Override
            public void doFilter(
                    jakarta.servlet.ServletRequest servletRequest, jakarta.servlet.ServletResponse servletResponse) {
                assertThat(SecurityContextHolder.getContext()
                                .getAuthentication()
                                .getName())
                        .isEqualTo("reader");
                assertThat(SecurityContextHolder.getContext()
                                .getAuthentication()
                                .getAuthorities())
                        .extracting(Object::toString)
                        .containsExactly("ROLE_READ");
            }
        };

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("X-API-Key wins when Bearer is also present")
    void headerWinsOverBearer() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(ApiKeyAuthenticationFilter.HEADER, "from-header");
        request.addHeader("Authorization", "Bearer from-bearer");
        assertThat(ApiKeyAuthenticationFilter.extractKey(request)).isEqualTo("from-header");
    }

    void bearerTokenIsExtracted() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer secret-key");
        assertThat(ApiKeyAuthenticationFilter.extractKey(request)).isEqualTo("secret-key");
    }

    @Test
    @DisplayName("an empty Bearer token is treated as absent")
    void emptyBearerIsAbsent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer ");
        assertThat(ApiKeyAuthenticationFilter.extractKey(request)).isNull();
    }

    @Test
    @DisplayName("an already-authenticated request is not re-read")
    void alreadyAuthenticatedSkipsLookup() throws Exception {
        SecurityContextHolder.getContext()
                .setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                        "existing", null, AuthorityUtils.createAuthorityList("ROLE_READ")));
        ApiClientService clients = mock(ApiClientService.class);
        ApiKeyAuthenticationFilter filter =
                new ApiKeyAuthenticationFilter(clients, mock(AuthenticationEntryPoint.class));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(ApiKeyAuthenticationFilter.HEADER, "ignored");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verify(clients, never()).authenticate(any());
    }

    @Test
    @DisplayName("an anonymous token does not skip API key lookup")
    void anonymousTokenDoesNotSkipLookup() throws Exception {
        SecurityContextHolder.getContext()
                .setAuthentication(new AnonymousAuthenticationToken(
                        "anon", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        ApiClientService clients = mock(ApiClientService.class);
        when(clients.authenticate("good")).thenReturn(Optional.empty());
        AuthenticationEntryPoint entryPoint = mock(AuthenticationEntryPoint.class);
        ApiKeyAuthenticationFilter filter = new ApiKeyAuthenticationFilter(clients, entryPoint);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(ApiKeyAuthenticationFilter.HEADER, "good");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verify(clients).authenticate("good");
        verify(entryPoint).commence(any(), any(), any());
    }

    @Test
    @DisplayName("401 and 403 bodies use the API error envelope")
    void jsonHandlersUseApiErrorEnvelope() throws Exception {
        JsonAuthenticationEntryPoint entryPoint = new JsonAuthenticationEntryPoint(mapper);
        MockHttpServletResponse unauthorized = new MockHttpServletResponse();
        entryPoint.commence(new MockHttpServletRequest(), unauthorized, new BadCredentialsException("invalid API key"));
        JsonNode unauthorizedBody = mapper.readTree(unauthorized.getContentAsByteArray());
        assertThat(unauthorized.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(unauthorizedBody.get("error").asText()).isEqualTo("unauthorized");
        assertThat(unauthorizedBody.get("message").asText()).isEqualTo("invalid API key");

        MockHttpServletResponse unauthorizedBlank = new MockHttpServletResponse();
        entryPoint.commence(new MockHttpServletRequest(), unauthorizedBlank, new BadCredentialsException(" "));
        assertThat(mapper.readTree(unauthorizedBlank.getContentAsByteArray())
                        .get("message")
                        .asText())
                .isEqualTo("authentication is required");

        JsonAccessDeniedHandler denied = new JsonAccessDeniedHandler(mapper);
        MockHttpServletResponse forbidden = new MockHttpServletResponse();
        denied.handle(new MockHttpServletRequest(), forbidden, new AccessDeniedException("no"));
        JsonNode forbiddenBody = mapper.readTree(forbidden.getContentAsByteArray());
        assertThat(forbidden.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(forbiddenBody.get("error").asText()).isEqualTo("forbidden");
    }

    @Test
    @DisplayName("the current client name is the authenticated principal")
    void currentClientNameRequiresAuthentication() {
        assertThatThrownBy(CurrentApiClient::name).isInstanceOf(IllegalStateException.class);

        SecurityContextHolder.getContext()
                .setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                        "bootstrap", null, AuthorityUtils.createAuthorityList("ROLE_READ")));
        assertThat(CurrentApiClient.name()).isEqualTo("bootstrap");
    }
}
