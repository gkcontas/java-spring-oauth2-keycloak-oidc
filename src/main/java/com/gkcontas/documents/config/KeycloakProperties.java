package com.gkcontas.documents.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * Everything the application needs to know about the identity provider. The
 * application never sees a password or a private key: it trusts the issuer and
 * fetches the public keys from it.
 *
 * @param realmUrl             the issuer; must match the {@code iss} claim exactly
 * @param audience             the client id this API answers to; tokens without it in {@code aud} are rejected
 * @param clockSkew            tolerance for {@code exp}/{@code nbf} between this host and Keycloak
 * @param jwksCacheTtl         how long the key set is reused before being fetched again
 * @param jwksMinRefetchInterval minimum time between two fetches forced by an unknown {@code kid}
 * @param jwksOutageTolerance  how long stale keys keep being served while Keycloak is unreachable
 * @param introspection        credentials of the API client used for token introspection
 * @param refreshSkew          how long before expiry the web client renews the access token
 * @param selfUrl              base URL the BFF uses to call this application's own API
 */
@Validated
@ConfigurationProperties("app.keycloak")
public record KeycloakProperties(
        @NotBlank(message = "app.keycloak.realm-url is required") String realmUrl,
        @NotBlank(message = "app.keycloak.audience is required") String audience,
        @NotNull(message = "app.keycloak.clock-skew is required") Duration clockSkew,
        @NotNull(message = "app.keycloak.jwks-cache-ttl is required") Duration jwksCacheTtl,
        @NotNull(message = "app.keycloak.jwks-min-refetch-interval is required") Duration jwksMinRefetchInterval,
        @NotNull(message = "app.keycloak.jwks-outage-tolerance is required") Duration jwksOutageTolerance,
        @NotNull(message = "app.keycloak.introspection is required") Introspection introspection,
        @NotNull(message = "app.keycloak.refresh-skew is required") Duration refreshSkew,
        @NotBlank(message = "app.keycloak.self-url is required") String selfUrl) {

    public record Introspection(
            @NotBlank(message = "app.keycloak.introspection.client-id is required") String clientId,
            @NotBlank(message = "app.keycloak.introspection.client-secret is required") String clientSecret) {
    }

    public String jwksUri() {
        return realmUrl + "/protocol/openid-connect/certs";
    }

    public String introspectionUri() {
        return realmUrl + "/protocol/openid-connect/token/introspect";
    }
}
