package com.gkcontas.documents.security;

import com.gkcontas.documents.config.KeycloakProperties;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.Collection;
import java.util.List;

/**
 * Asks Keycloak, on every request, whether the token is still active.
 *
 * <p>This is what makes revocation immediate: a token whose session was logged
 * out is inactive at once, while the same token as a JWT keeps being accepted
 * until it expires. The price is a network call to the identity provider on
 * the request path, and no answer at all when the provider is down.
 *
 * <p>An active token is not enough: Keycloak answers {@code active: true} for
 * any token of the realm, so the audience still has to be checked here.
 */
public class KeycloakOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final OpaqueTokenIntrospector delegate;
    private final KeycloakAuthorities authorities;
    private final String audience;
    private final AuthMetrics metrics;

    public KeycloakOpaqueTokenIntrospector(KeycloakProperties properties, AuthMetrics metrics) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(Duration.ofSeconds(1));
        requestFactory.setReadTimeout(Duration.ofSeconds(2));
        RestTemplate rest = new RestTemplate(requestFactory);
        rest.getInterceptors().add(new BasicAuthenticationInterceptor(
                properties.introspection().clientId(), properties.introspection().clientSecret()));
        this.delegate = new SpringOpaqueTokenIntrospector(properties.introspectionUri(), rest);
        this.authorities = new KeycloakAuthorities(properties.audience());
        this.audience = properties.audience();
        this.metrics = metrics;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        metrics.introspected();
        OAuth2AuthenticatedPrincipal principal = delegate.introspect(token);
        if (!audienceOf(principal.getAttribute("aud")).contains(audience)) {
            throw new BadOpaqueTokenException("The token was not issued for " + audience);
        }
        if (!"Bearer".equals(String.valueOf(principal.getAttributes().get("typ")))) {
            throw new BadOpaqueTokenException("The token is not an access token");
        }
        return new DefaultOAuth2AuthenticatedPrincipal(principal.getName(), principal.getAttributes(),
                authorities.from(principal.getAttributes()));
    }

    private static Collection<String> audienceOf(Object aud) {
        if (aud instanceof Collection<?> values) {
            return values.stream().map(String::valueOf).toList();
        }
        return aud == null ? List.of() : List.of(String.valueOf(aud));
    }
}
