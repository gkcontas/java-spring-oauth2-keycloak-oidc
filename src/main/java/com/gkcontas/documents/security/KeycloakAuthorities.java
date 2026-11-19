package com.gkcontas.documents.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Turns Keycloak claims into Spring authorities. Shared by the JWT path and the
 * introspection path, so both see the same authorities for the same token.
 *
 * <ul>
 *   <li>{@code scope} becomes {@code SCOPE_x}: what the <em>client</em> may do on the user's behalf;</li>
 *   <li>{@code realm_access.roles} becomes {@code ROLE_x}: what the <em>user</em> may do;</li>
 *   <li>{@code resource_access.<audience>.roles} becomes {@code ROLE_<audience>:x}. Client roles
 *       of any other client are ignored: {@code admin} of another application means nothing here.</li>
 * </ul>
 *
 * Spring's default converter reads only {@code scope}; the roles Keycloak puts
 * in the token are silently dropped without this.
 */
public final class KeycloakAuthorities {

    private final String audience;

    public KeycloakAuthorities(String audience) {
        this.audience = audience;
    }

    public Collection<GrantedAuthority> from(Map<String, Object> claims) {
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        for (String scope : scopes(claims.get("scope"))) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
        }
        for (String role : roles(claims.get("realm_access"))) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
        }
        if (claims.get("resource_access") instanceof Map<?, ?> resourceAccess) {
            for (String role : roles(resourceAccess.get(audience))) {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + audience + ":" + role));
            }
        }
        return authorities;
    }

    private static List<String> scopes(Object claim) {
        if (claim instanceof String text && !text.isBlank()) {
            return List.of(text.trim().split("\\s+"));
        }
        if (claim instanceof Collection<?> values) {
            return values.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    private static List<String> roles(Object access) {
        if (access instanceof Map<?, ?> map && map.get("roles") instanceof Collection<?> roles) {
            return roles.stream().map(String::valueOf).toList();
        }
        return List.of();
    }
}
