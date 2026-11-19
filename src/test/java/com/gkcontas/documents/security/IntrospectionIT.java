package com.gkcontas.documents.security;

import com.gkcontas.documents.IntegrationTestBase;
import com.gkcontas.documents.support.Keycloak;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The same token, validated two ways. Locally, Keycloak is consulted for the
 * keys once; by introspection, on every request - which is what makes a logout
 * effective at once.
 */
class IntrospectionIT extends IntegrationTestBase {

    @Test
    void introspectionAsksKeycloakOnEveryRequestAndJwtDoesNot() {
        String bob = KC.login("bob", "").accessToken();
        get("/api/documents", bob);
        long jwks = metrics.jwksFetches();
        long introspections = metrics.introspections();

        for (int i = 0; i < 10; i++) {
            assertThat(get("/api/documents", bob).status()).isEqualTo(200);
            assertThat(get("/api/introspected/documents", bob).status()).isEqualTo(200);
        }

        assertThat(metrics.jwksFetches()).isEqualTo(jwks);
        assertThat(metrics.introspections()).isEqualTo(introspections + 10);
    }

    @Test
    void afterLogoutTheJwtStillWorksUntilItExpiresButIntrospectionRefusesIt() {
        Keycloak.Tokens bob = KC.login("bob", "");
        assertThat(get("/api/introspected/documents", bob.accessToken()).status()).isEqualTo(200);

        assertThat(KC.logout(bob, "docs-cli")).isEqualTo(204);

        assertThat(get("/api/documents", bob.accessToken()).status()).isEqualTo(200);
        assertThat(get("/api/introspected/documents", bob.accessToken()).status()).isEqualTo(401);
    }

    @Test
    void activeIsNotEnoughTheAudienceIsCheckedToo() {
        // Keycloak answers active=true for any valid token of the realm.
        String bobAtOtherApp = KC.login("bob", "other-app", "").accessToken();

        assertThat(get("/api/introspected/documents", bobAtOtherApp).status()).isEqualTo(401);
    }

    @Test
    void introspectedRoutesOnlyRead() {
        String alice = KC.login("alice", "documents:write").accessToken();

        assertThat(call("POST", "/api/introspected/documents", alice, "{}").status()).isEqualTo(403);
        assertThat(get("/api/introspected/documents/1", null).status()).isEqualTo(401);
    }
}
