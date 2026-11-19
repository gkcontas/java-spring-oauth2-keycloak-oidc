package com.gkcontas.documents.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakAuthoritiesTest {

    private final KeycloakAuthorities authorities = new KeycloakAuthorities("docs-api");

    @Test
    void mapsScopesRealmRolesAndOnlyTheClientRolesOfThisApi() {
        Map<String, Object> claims = Map.of(
                "scope", "openid documents:read",
                "realm_access", Map.of("roles", List.of("reader", "editor")),
                "resource_access", Map.of(
                        "docs-api", Map.of("roles", List.of("admin")),
                        "other-app", Map.of("roles", List.of("admin", "owner"))));

        assertThat(names(claims)).containsExactlyInAnyOrder(
                "SCOPE_openid", "SCOPE_documents:read", "ROLE_reader", "ROLE_editor", "ROLE_docs-api:admin");
    }

    @Test
    void scopeAsListIsAcceptedToo() {
        assertThat(names(Map.of("scope", List.of("documents:read")))).containsExactly("SCOPE_documents:read");
    }

    @Test
    void missingOrMalformedClaimsGiveNoAuthorities() {
        assertThat(names(Map.of())).isEmpty();
        assertThat(names(Map.of("realm_access", "reader", "resource_access", Map.of("docs-api", "admin"),
                "scope", " "))).isEmpty();
    }

    @Test
    void realmRoleNamedLikeAClientRoleDoesNotBecomeTheClientRole() {
        assertThat(names(Map.of("realm_access", Map.of("roles", List.of("admin")))))
                .containsExactly("ROLE_admin")
                .doesNotContain("ROLE_docs-api:admin");
    }

    private List<String> names(Map<String, Object> claims) {
        return authorities.from(claims).stream().map(GrantedAuthority::getAuthority).toList();
    }
}
