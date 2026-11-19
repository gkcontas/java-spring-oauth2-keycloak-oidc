package com.gkcontas.documents.security;

import com.gkcontas.documents.config.KeycloakProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.authorization.AuthorityAuthorizationManager.hasAuthority;

/**
 * The API side: stateless, bearer tokens only, no CSRF (there is no cookie to
 * ride on), deny by default.
 *
 * <p>Two chains over the same documents. {@code /api/**} validates the JWT
 * locally; {@code /api/introspected/**} asks Keycloak about every token. They
 * exist side by side only to compare the two in one process.
 *
 * <p>Scope and role are different questions. Creating a document needs the
 * {@code documents:write} scope (the client was allowed to ask for it) <em>and</em>
 * the {@code editor} role (the user is allowed to do it).
 */
@Configuration
public class ResourceServerConfig {

    static final String READ = "SCOPE_documents:read";
    static final String WRITE = "SCOPE_documents:write";

    @Bean
    @Order(1)
    SecurityFilterChain introspectedApiChain(HttpSecurity http, KeycloakProperties properties,
                                             AuthMetrics metrics) throws Exception {
        http.securityMatcher("/api/introspected/**")
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .requestCache(cache -> cache.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/api/introspected/documents/**").hasAuthority(READ)
                        .anyRequest().denyAll())
                .oauth2ResourceServer(rs -> rs.opaqueToken(opaque -> opaque
                        .introspector(new KeycloakOpaqueTokenIntrospector(properties, metrics))));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain apiChain(HttpSecurity http, JwtDecoder jwtDecoder, KeycloakProperties properties) throws Exception {
        KeycloakAuthorities authorities = new KeycloakAuthorities(properties.audience());
        String admin = "ROLE_" + properties.audience() + ":admin";

        http.securityMatcher("/api/**")
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .requestCache(cache -> cache.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/api/me").authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/documents/**").hasAuthority(READ)
                        .requestMatchers(HttpMethod.POST, "/api/documents")
                        .access(AuthorizationManagers.allOf(hasAuthority(WRITE), hasAuthority("ROLE_editor")))
                        .requestMatchers(HttpMethod.DELETE, "/api/documents/*")
                        .access(AuthorizationManagers.allOf(hasAuthority(WRITE), hasAuthority(admin)))
                        .anyRequest().denyAll())
                .oauth2ResourceServer(rs -> rs.jwt(jwt -> jwt
                        .decoder(jwtDecoder)
                        .jwtAuthenticationConverter(token ->
                                new JwtAuthenticationToken(token, authorities.from(token.getClaims()),
                                        token.getClaimAsString("preferred_username") != null
                                                ? token.getClaimAsString("preferred_username")
                                                : token.getSubject()))));
        return http.build();
    }
}
