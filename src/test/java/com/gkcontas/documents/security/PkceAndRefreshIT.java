package com.gkcontas.documents.security;

import com.gkcontas.documents.IntegrationTestBase;
import com.gkcontas.documents.support.Browser;
import com.gkcontas.documents.support.Keycloak;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The authorization server's half of the protocol, as this realm configures
 * it: PKCE S256 required, codes single use, refresh tokens rotated.
 */
class PkceAndRefreshIT extends IntegrationTestBase {

    @Test
    void codeExchangedWithTheRightVerifierGivesTokens() {
        Keycloak.Code code = KC.code("bob", "docs-cli", "");

        Keycloak.Result result = KC.exchange(code, code.verifier());

        assertThat(result.status()).isEqualTo(200);
        assertThat(result.json().path("access_token").asText()).isNotBlank();
    }

    @Test
    void stolenCodeWithoutTheVerifierIsUseless() {
        Keycloak.Code code = KC.code("bob", "docs-cli", "");

        Keycloak.Result noVerifier = KC.exchange(code, null);

        assertThat(noVerifier.status()).isEqualTo(400);
        assertThat(noVerifier.json().path("error").asText()).isEqualTo("invalid_grant");
    }

    @Test
    void wrongVerifierIsRejected() {
        Keycloak.Code code = KC.code("bob", "docs-cli", "");

        Keycloak.Result wrong = KC.exchange(code, Keycloak.randomUrlSafe(48));

        assertThat(wrong.status()).isEqualTo(400);
        assertThat(wrong.json().path("error").asText()).isEqualTo("invalid_grant");
    }

    @Test
    void codeIsSingleUse() {
        Keycloak.Code code = KC.code("bob", "docs-cli", "");
        assertThat(KC.exchange(code, code.verifier()).status()).isEqualTo(200);

        Keycloak.Result replay = KC.exchange(code, code.verifier());

        assertThat(replay.status()).isEqualTo(400);
        assertThat(replay.json().path("error").asText()).isEqualTo("invalid_grant");
    }

    @Test
    void authorizationRequestWithoutChallengeIsRefused() {
        Browser.Response response = new Browser().get(
                KC.authorizeUrl("docs-cli", Keycloak.CLI_REDIRECT, "", Map.of()));

        // Keycloak sends the error back to the client's redirect URI.
        assertThat(response.status()).isEqualTo(302);
        assertThat(Keycloak.query(response.location()))
                .containsEntry("error", "invalid_request")
                .containsKey("error_description");
    }

    @Test
    void plainChallengeIsRefusedWhenS256IsRequired() {
        String verifier = Keycloak.randomUrlSafe(48);
        Browser.Response response = new Browser().get(KC.authorizeUrl("docs-cli", Keycloak.CLI_REDIRECT, "",
                Map.of("code_challenge", verifier, "code_challenge_method", "plain")));

        assertThat(Keycloak.query(response.location())).containsEntry("error", "invalid_request");
    }

    @Test
    void passwordGrantIsDisabled() {
        Keycloak.Result result = KC.passwordGrant("bob", "docs-cli");

        assertThat(result.status()).isIn(400, 401);
        assertThat(result.json().path("error").asText()).isEqualTo("unauthorized_client");
    }

    @Test
    void refreshTokenIsRotatedAndTheOldOneStopsWorking() {
        Keycloak.Tokens tokens = KC.login("bob", "");

        Keycloak.Result first = KC.refresh(tokens.refreshToken(), "docs-cli");
        assertThat(first.status()).isEqualTo(200);
        assertThat(first.json().path("refresh_token").asText()).isNotEqualTo(tokens.refreshToken());

        Keycloak.Result reuse = KC.refresh(tokens.refreshToken(), "docs-cli");
        assertThat(reuse.status()).isEqualTo(400);
        assertThat(reuse.json().path("error").asText()).isEqualTo("invalid_grant");
    }

    @Test
    void refreshTokenOfAnotherClientIsRejected() {
        Keycloak.Tokens tokens = KC.login("bob", "");

        Keycloak.Result result = KC.refresh(tokens.refreshToken(), "other-app");

        assertThat(result.status()).isEqualTo(400);
        assertThat(result.json().path("error").asText()).isEqualTo("invalid_grant");
    }
}
