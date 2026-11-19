package com.gkcontas.documents.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class AccessTokenTypeValidatorTest {

    private final AccessTokenTypeValidator validator = new AccessTokenTypeValidator();

    @Test
    void acceptsKeycloakAccessTokens() {
        assertThat(validator.validate(jwt("Bearer")).hasErrors()).isFalse();
    }

    @Test
    void rejectsIdTokensLogoutTokensAndTokensWithoutType() {
        assertThat(validator.validate(jwt("ID")).hasErrors()).isTrue();
        assertThat(validator.validate(jwt("Logout")).hasErrors()).isTrue();
        assertThat(validator.validate(jwt(null)).hasErrors()).isTrue();
    }

    private static Jwt jwt(String typ) {
        Jwt.Builder builder = Jwt.withTokenValue("t").header("alg", "RS256").subject("s")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60));
        if (typ != null) {
            builder.claim("typ", typ);
        }
        return builder.build();
    }
}
