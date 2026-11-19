package com.gkcontas.documents.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.gkcontas.documents.IntegrationTestBase;
import com.gkcontas.documents.support.Browser;
import com.gkcontas.documents.support.Keycloak;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/** The backend for frontend, driven like a browser: session cookie only, tokens stay on the server. */
class WebLoginIT extends IntegrationTestBase {

    @Test
    void loginUsesPkceEvenThoughTheClientIsConfidential() {
        Browser browser = new Browser();

        Browser.Response toApp = browser.get(appUrl() + "/web/me");
        assertThat(toApp.status()).isEqualTo(302);
        Browser.Response toKeycloak = browser.get(appUrl() + "/oauth2/authorization/keycloak");
        Map<String, String> authorize = Keycloak.query(toKeycloak.location());

        assertThat(toKeycloak.location()).startsWith(KC.realmUrl());
        assertThat(authorize).containsEntry("client_id", "docs-web")
                .containsEntry("code_challenge_method", "S256")
                .containsKeys("code_challenge", "state", "nonce");
    }

    @Test
    void afterLoginTheBrowserGetsDataButNeverATokenAndTheApiIsCalledWithTheUsersToken() throws Exception {
        Browser browser = login("alice");

        Browser.Response me = browser.get(appUrl() + "/web/me");
        Browser.Response documents = browser.get(appUrl() + "/web/documents");

        JsonNode meJson = JSON.readTree(me.body());
        assertThat(meJson.path("username").asText()).isEqualTo("alice");
        assertThat(meJson.path("hasRefreshToken").asBoolean()).isTrue();
        assertThat(me.body()).doesNotContain("eyJ");
        assertThat(documents.status()).isEqualTo(200);
        assertThat(JSON.readTree(documents.body()).size()).isGreaterThanOrEqualTo(2);
        assertThat(documents.body()).doesNotContain("eyJ");
    }

    @Test
    void unauthenticatedNavigationGoesToLoginAndXhrGets401() {
        Browser browser = new Browser();

        assertThat(browser.get(appUrl() + "/web/documents").location())
                .endsWith("/oauth2/authorization/keycloak");
        assertThat(browser.get(appUrl() + "/web/documents", "X-Requested-With", "XMLHttpRequest").status())
                .isEqualTo(401);
    }

    @Test
    void logoutNeedsTheCsrfToken() {
        Browser browser = login("bob");

        assertThat(browser.postForm(appUrl() + "/logout", Map.of()).status()).isEqualTo(403);
        assertThat(browser.get(appUrl() + "/web/me").status()).isEqualTo(200);
    }

    @Test
    void rpInitiatedLogoutEndsTheLocalAndTheKeycloakSession() throws Exception {
        Browser browser = login("bob");
        int sessionsBefore = KC.sessionCount("bob");

        Browser.Response logout = browser.postForm(appUrl() + "/logout", Map.of(), csrf(browser));
        Map<String, String> endSession = Keycloak.query(logout.location());
        assertThat(logout.location()).startsWith(KC.realmUrl() + "/protocol/openid-connect/logout");
        assertThat(endSession).containsKey("id_token_hint")
                .containsEntry("post_logout_redirect_uri", appUrl() + "/");

        Browser.Response backHome = browser.get(logout.location());
        assertThat(backHome.location()).isEqualTo(appUrl() + "/");
        assertThat(KC.sessionCount("bob")).isEqualTo(sessionsBefore - 1);
        assertThat(browser.get(appUrl() + "/web/me").status()).isEqualTo(302);
    }

    @Test
    void signingOutOfAnotherApplicationOfTheSameSsoSessionEndsTheLocalSession() {
        Browser browser = login("alice");
        // Same browser, second application: single sign-on, no login form this time.
        Keycloak.Tokens cli = KC.login(browser, "alice", "docs-cli", "");
        assertThat(claims(cli.accessToken()).path("sid").asText())
                .isEqualTo(claims(cli.idToken()).path("sid").asText());

        assertThat(KC.logout(cli, "docs-cli")).isEqualTo(204);

        await().atMost(Duration.ofSeconds(5))
                .until(() -> browser.get(appUrl() + "/web/me").status() == 302);
    }

    @Test
    void eachSessionEndedAtKeycloakEndsItsLocalSessionEvenWithANewCsrfToken() {
        Browser laptop = login("bob");
        Browser phone = login("bob");
        // The laptop's session now holds a CSRF token the login never saw.
        assertThat(laptop.get(appUrl() + "/web/csrf").status()).isEqualTo(200);

        KC.endSessions("bob");

        await().atMost(Duration.ofSeconds(5)).until(() ->
                laptop.get(appUrl() + "/web/me").status() == 302 && phone.get(appUrl() + "/web/me").status() == 302);
    }

    @Test
    void signingTheUserOutAtKeycloakNotifiesOnlyOneOfTheirSessions() {
        // Keycloak 26.0.7: "sign out" of a user ends all of their sessions at Keycloak, but sends a
        // back-channel logout for one of them only. The other local session lives on until its
        // tokens can no longer be refreshed.
        KC.endSessions("bob"); // leftovers of other tests would be candidates too
        Browser laptop = login("bob");
        Browser phone = login("bob");

        KC.logoutUser("bob");

        assertThat(KC.sessionCount("bob")).isZero();
        await().pollDelay(Duration.ofSeconds(2)).atMost(Duration.ofSeconds(5)).until(() -> true);
        long stillLoggedIn = java.util.stream.Stream.of(laptop, phone)
                .filter(browser -> browser.get(appUrl() + "/web/me").status() == 200)
                .count();
        assertThat(stillLoggedIn).isEqualTo(1);
    }

    private static Browser login(String username) {
        Browser browser = new Browser();
        Browser.Response response = browser.navigate(appUrl() + "/web/me", username, username);
        assertThat(response.status()).isEqualTo(200);
        return browser;
    }

    private static String[] csrf(Browser browser) throws Exception {
        JsonNode token = JSON.readTree(browser.get(appUrl() + "/web/csrf").body());
        return new String[]{token.path("headerName").asText(), token.path("token").asText()};
    }
}
