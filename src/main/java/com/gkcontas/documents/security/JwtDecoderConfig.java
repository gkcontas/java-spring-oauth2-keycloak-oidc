package com.gkcontas.documents.security;

import com.gkcontas.documents.config.KeycloakProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.RateLimitReachedException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.Collection;

/**
 * The resource server's token decoder, built by hand so every knob is visible.
 *
 * <p>Keys: fetched from the JWKS endpoint, cached for {@code jwks-cache-ttl}. A
 * token with an unknown {@code kid} forces a new fetch (that is how a rotated
 * key is picked up), but no more than once per {@code jwks-min-refetch-interval}:
 * otherwise anyone could make this API hammer Keycloak by sending tokens with
 * made-up key ids. If Keycloak is unreachable when the cache expires, the old
 * keys keep being used for {@code jwks-outage-tolerance}.
 *
 * <p>Algorithm: RS256 only, never read from the token header.
 *
 * <p>Claims: issuer, expiry with clock skew, audience and token type. Spring
 * Boot checks the audience only when {@code audiences} is configured; without
 * it, a token Keycloak issued to any other client of the realm is accepted.
 */
@Configuration
public class JwtDecoderConfig {

    @Bean
    JWKSource<SecurityContext> jwkSource(KeycloakProperties properties, AuthMetrics metrics) throws MalformedURLException {
        return JWKSourceBuilder.create(URI.create(properties.jwksUri()).toURL(), new CountingResourceRetriever(metrics))
                .cache(properties.jwksCacheTtl().toMillis(), 2_000)
                .rateLimited(properties.jwksMinRefetchInterval().toMillis())
                .outageTolerant(properties.jwksOutageTolerance().toMillis())
                .refreshAheadCache(false)
                .retrying(false)
                .build();
    }

    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource, KeycloakProperties properties) {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource));
        // Claims are checked by Spring's validators below, with readable errors.
        processor.setJWTClaimsSetVerifier((claims, context) -> {
        });

        NimbusJwtDecoder decoder = new NimbusJwtDecoder(processor);
        decoder.setJwtValidator(accessTokenValidator(properties));
        return token -> {
            try {
                return decoder.decode(token);
            } catch (BadJwtException e) {
                throw e;
            } catch (JwtException e) {
                // A made-up kid forces a JWKS fetch; past the rate limit Nimbus refuses with
                // RateLimitReachedException, which Spring reports as a server error (500). It is
                // the token that is bad: answer 401, and let real outages stay 500.
                if (causedBy(e, RateLimitReachedException.class)) {
                    throw new BadJwtException("Unknown signing key", e);
                }
                throw e;
            }
        };
    }

    private static boolean causedBy(Throwable error, Class<? extends Throwable> type) {
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (type.isInstance(cause)) {
                return true;
            }
        }
        return false;
    }

    static OAuth2TokenValidator<Jwt> accessTokenValidator(KeycloakProperties properties) {
        return new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(properties.clockSkew()),
                new JwtIssuerValidator(properties.realmUrl()),
                new JwtClaimValidator<Collection<String>>(JwtClaimNames.AUD,
                        aud -> aud != null && aud.contains(properties.audience())),
                new AccessTokenTypeValidator());
    }
}
