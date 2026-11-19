package com.gkcontas.documents.security;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

/**
 * Counts every call this application makes to the identity provider. These are
 * the numbers that tell local validation and introspection apart: how often
 * Keycloak is on the request path.
 */
@Component
public class AuthMetrics {

    private final Counter jwksFetches;
    private final Counter introspections;
    private final Counter tokenRefreshes;

    public AuthMetrics(MeterRegistry registry) {
        this.jwksFetches = Counter.builder("auth.jwks.fetches")
                .description("HTTP requests to the JWKS endpoint")
                .register(registry);
        this.introspections = Counter.builder("auth.introspection.requests")
                .description("HTTP requests to the introspection endpoint")
                .register(registry);
        this.tokenRefreshes = Counter.builder("auth.token.refreshes")
                .description("Refresh token grants sent by the web client")
                .register(registry);
    }

    public void jwksFetched() {
        jwksFetches.increment();
    }

    public void introspected() {
        introspections.increment();
    }

    public void tokenRefreshed() {
        tokenRefreshes.increment();
    }

    public long jwksFetches() {
        return (long) jwksFetches.count();
    }

    public long introspections() {
        return (long) introspections.count();
    }

    public long tokenRefreshes() {
        return (long) tokenRefreshes.count();
    }
}
