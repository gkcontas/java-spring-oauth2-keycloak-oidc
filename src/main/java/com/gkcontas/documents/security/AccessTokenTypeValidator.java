package com.gkcontas.documents.security;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Keycloak signs access tokens, ID tokens and logout tokens with the same key
 * and the same issuer. Signature and issuer alone cannot tell them apart; the
 * {@code typ} claim can. An ID token is proof of authentication for the client
 * that requested it, never an authorisation to call an API.
 */
public class AccessTokenTypeValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error NOT_AN_ACCESS_TOKEN =
            new OAuth2Error("invalid_token", "The token is not an access token", null);

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        return "Bearer".equals(jwt.getClaimAsString("typ"))
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(NOT_AN_ACCESS_TOKEN);
    }
}
