package com.gkcontas.documents.web;

import com.gkcontas.documents.IntegrationTestBase;
import com.gkcontas.documents.support.Browser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The BFF renews the access token {@code refresh-skew} (30 s) before it
 * expires. A token that lives longer than that is reused; one that lives less
 * is renewed before every single call - Spring's default skew is 60 s, so this
 * is what happens to any token of a minute or less.
 */
class RefreshSkewIT extends IntegrationTestBase {

    @AfterEach
    void restoreLifespan() {
        // An attribute left out of the PUT is kept by Keycloak, so it is reset explicitly to the realm's 300 s.
        KC.updateClient("docs-web", client -> client.withObjectProperty("attributes").put("access.token.lifespan", "300"));
    }

    @Test
    void tokenLivingLongerThanTheSkewIsReused() {
        setAccessTokenLifespan(120);
        Browser browser = login();
        long before = metrics.tokenRefreshes();

        for (int i = 0; i < 5; i++) {
            assertThat(browser.get(appUrl() + "/web/documents").status()).isEqualTo(200);
        }

        assertThat(metrics.tokenRefreshes() - before).isZero();
    }

    @Test
    void tokenLivingLessThanTheSkewIsRefreshedOnEveryCall() {
        setAccessTokenLifespan(20);
        Browser browser = login();
        long before = metrics.tokenRefreshes();

        for (int i = 0; i < 5; i++) {
            assertThat(browser.get(appUrl() + "/web/documents").status()).isEqualTo(200);
        }

        assertThat(metrics.tokenRefreshes() - before).isEqualTo(5);
    }

    @Test
    void whenTheRefreshTokenIsRevokedTheBffAsksForANewLogin() {
        setAccessTokenLifespan(20);
        Browser browser = login();
        // Revoke without back-channel: the session is gone at Keycloak, the local one survives.
        KC.updateClient("docs-web", client -> client.withObjectProperty("attributes").put("backchannel.logout.url", ""));
        try {
            KC.logoutUser("alice");

            Browser.Response response = browser.get(appUrl() + "/web/documents");

            assertThat(response.status()).isEqualTo(401);
            assertThat(response.body()).contains("reauthentication_required", "invalid_grant");
        } finally {
            KC.updateClient("docs-web", client -> client.withObjectProperty("attributes")
                    .put("backchannel.logout.url", backChannelLogoutUrl()));
        }
    }

    private static void setAccessTokenLifespan(int seconds) {
        KC.updateClient("docs-web", client -> client.withObjectProperty("attributes")
                .put("access.token.lifespan", String.valueOf(seconds)));
    }

    private static Browser login() {
        Browser browser = new Browser();
        assertThat(browser.navigate(appUrl() + "/web/me", "alice", "alice").status()).isEqualTo(200);
        return browser;
    }
}
