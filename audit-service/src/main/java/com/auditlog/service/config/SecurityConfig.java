package com.auditlog.service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auditlog.service.controller.ApiKeyAuthenticationFilter;
import com.auditlog.service.controller.JsonAccessDeniedHandler;
import com.auditlog.service.controller.JsonAuthenticationEntryPoint;
import com.auditlog.service.service.ApiClientService;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public ApiKeyAuthenticationFilter apiKeyAuthenticationFilter(
            ApiClientService clients, JsonAuthenticationEntryPoint entryPoint) {
        return new ApiKeyAuthenticationFilter(clients, entryPoint);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            AuditProperties properties,
            ApiKeyAuthenticationFilter apiKeyFilter,
            JsonAuthenticationEntryPoint entryPoint,
            JsonAccessDeniedHandler accessDeniedHandler)
            throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .exceptionHandling(exceptions ->
                        exceptions.authenticationEntryPoint(entryPoint).accessDeniedHandler(accessDeniedHandler))
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/actuator/health", "/actuator/health/**")
                            .permitAll();
                    if (properties.security().openDocs()) {
                        auth.requestMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs", "/v3/api-docs/**")
                                .permitAll();
                    }
                    auth.requestMatchers(HttpMethod.GET, "/").authenticated();
                    auth.requestMatchers(HttpMethod.POST, "/v1/audit-events").hasRole("APPEND");
                    auth.requestMatchers(HttpMethod.GET, "/v1/audit-events", "/v1/audit-events/*")
                            .hasRole("READ");
                    auth.requestMatchers(HttpMethod.POST, "/v1/audit-events/*/redactions")
                            .hasRole("REDACT");
                    auth.requestMatchers(HttpMethod.GET, "/v1/chain/verify").hasRole("VERIFY");
                    auth.requestMatchers("/v1/retention/**").hasRole("RETAIN");
                    auth.requestMatchers("/v1/exports", "/v1/exports/**").hasRole("EXPORT");
                    auth.requestMatchers("/v1/compliance/**").hasRole("COMPLIANCE");
                    auth.anyRequest().authenticated();
                })
                .addFilterBefore(apiKeyFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
