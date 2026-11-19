package com.gkcontas.documents.web;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.oidc.session.InMemoryOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;

/**
 * The browser side, a backend for frontend: the browser holds only a session
 * cookie, and the tokens stay in the server session.
 *
 * <ul>
 *   <li><b>PKCE on a confidential client.</b> Spring sends {@code code_challenge} only for
 *       public clients by default; {@code docs-web} has a secret, and Keycloak is configured to
 *       require S256 from it anyway, so the customizer is mandatory here.</li>
 *   <li><b>RP-initiated logout.</b> {@code POST /logout} ends the local session and sends the
 *       browser to Keycloak's end-session endpoint with {@code id_token_hint}, so the single
 *       sign-on session ends too.</li>
 *   <li><b>Back-channel logout.</b> When the session ends at Keycloak (another application,
 *       an administrator), Keycloak posts a signed logout token here and the linked local sessions
 *       are invalidated directly, see {@link BackChannelLogoutHandler}.</li>
 *   <li><b>CSRF on</b>, since the session cookie is sent automatically by the browser. The
 *       frontend reads the token from {@code GET /web/csrf} and echoes it in {@code X-CSRF-TOKEN}.</li>
 * </ul>
 */
@Configuration
public class WebSecurityConfig {

    /** Links each local session to the Keycloak session ({@code sid}) it came from. */
    @Bean
    OidcSessionRegistry oidcSessionRegistry() {
        return new InMemoryOidcSessionRegistry();
    }

    @Bean
    @Order(3)
    SecurityFilterChain webChain(HttpSecurity http, ClientRegistrationRepository registrations,
                                 OidcSessionRegistry oidcSessions, LocalSessions localSessions) throws Exception {
        DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(
                registrations, OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

        OidcClientInitiatedLogoutSuccessHandler logoutSuccess = new OidcClientInitiatedLogoutSuccessHandler(registrations);
        logoutSuccess.setPostLogoutRedirectUri("{baseUrl}/");

        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/error").permitAll()
                        .requestMatchers("/web/**").authenticated()
                        .anyRequest().denyAll())
                .oauth2Login(login -> login
                        .authorizationEndpoint(endpoint -> endpoint.authorizationRequestResolver(resolver)))
                .oauth2Client(Customizer.withDefaults())
                .oidcLogout(logout -> logout.backChannel(backChannel -> backChannel
                        .logoutHandler(new BackChannelLogoutHandler(oidcSessions, localSessions))))
                .logout(logout -> logout.logoutSuccessHandler(logoutSuccess))
                .csrf(Customizer.withDefaults())
                .exceptionHandling(errors -> errors
                        // An XHR from the frontend gets 401 instead of a redirect to the login page.
                        .defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"))
                        // Anything else is a navigation: straight to Keycloak. Spring's own choice
                        // depends on the Accept header, and a client that sends none would get 401.
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/oauth2/authorization/" + OAuth2ClientConfig.REGISTRATION),
                                AnyRequestMatcher.INSTANCE));
        return http.build();
    }
}
