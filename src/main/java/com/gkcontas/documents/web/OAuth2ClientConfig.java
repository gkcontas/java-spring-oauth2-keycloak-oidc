package com.gkcontas.documents.web;

import com.gkcontas.documents.config.KeycloakProperties;
import com.gkcontas.documents.security.AuthMetrics;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizationCodeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.DelegatingOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.web.client.RestClient;

/**
 * How the BFF gets a usable access token for the logged-in user.
 *
 * <p>The refresh provider renews the access token when it is within
 * {@code refresh-skew} of expiring. Spring's default is 60 s: with an access
 * token that lives 60 s or less, every single call is preceded by a refresh
 * grant, and with refresh token rotation each one also replaces the refresh
 * token. The skew has to be well below the token lifetime.
 */
@Configuration
public class OAuth2ClientConfig {

    static final String REGISTRATION = "keycloak";

    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository registrations,
                                                          OAuth2AuthorizedClientRepository authorizedClients,
                                                          KeycloakProperties properties,
                                                          AuthMetrics metrics) {
        RestClientRefreshTokenTokenResponseClient refreshClient = new RestClientRefreshTokenTokenResponseClient();
        OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> countingRefreshClient = request -> {
            metrics.tokenRefreshed();
            return refreshClient.getTokenResponse(request);
        };

        RefreshTokenOAuth2AuthorizedClientProvider refresh = new RefreshTokenOAuth2AuthorizedClientProvider();
        refresh.setClockSkew(properties.refreshSkew());
        refresh.setAccessTokenResponseClient(countingRefreshClient);

        DefaultOAuth2AuthorizedClientManager manager =
                new DefaultOAuth2AuthorizedClientManager(registrations, authorizedClients);
        manager.setAuthorizedClientProvider(new DelegatingOAuth2AuthorizedClientProvider(
                new AuthorizationCodeOAuth2AuthorizedClientProvider(), refresh));
        return manager;
    }

    /**
     * Calls this application's own API with the user's access token, the way a
     * BFF calls the services behind it. The token never leaves the server.
     */
    @Bean
    RestClient documentsApi(RestClient.Builder builder, OAuth2AuthorizedClientManager manager,
                            OAuth2AuthorizedClientRepository authorizedClients, KeycloakProperties properties) {
        OAuth2ClientHttpRequestInterceptor interceptor = new OAuth2ClientHttpRequestInterceptor(manager);
        interceptor.setClientRegistrationIdResolver(request -> REGISTRATION);
        // When the refresh token is rejected (session ended at Keycloak), forget the
        // stored tokens so the next request goes through login again.
        interceptor.setAuthorizationFailureHandler(
                OAuth2ClientHttpRequestInterceptor.authorizationFailureHandler(authorizedClients));
        return builder.baseUrl(properties.selfUrl()).requestInterceptor(interceptor).build();
    }
}
