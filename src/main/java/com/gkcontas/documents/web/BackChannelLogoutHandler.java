package com.gkcontas.documents.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/**
 * Ends the local sessions linked to the Keycloak session named in a validated
 * logout token ({@code sid}, or every session of {@code sub}).
 *
 * <p>Spring's default handler does it with an HTTP call to this application's
 * own {@code POST /logout}, carrying the session cookie and the CSRF token
 * captured at login. That call goes through the whole filter chain, CSRF
 * check included, and when it is refused (403) the user stays logged in here
 * after logging out at Keycloak - Keycloak got its 200 and does not retry.
 * Invalidating the session directly has no such dependency.
 */
@Slf4j
public class BackChannelLogoutHandler implements LogoutHandler {

    private final OidcSessionRegistry registry;
    private final LocalSessions sessions;

    public BackChannelLogoutHandler(OidcSessionRegistry registry, LocalSessions sessions) {
        this.registry = registry;
        this.sessions = sessions;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof OidcLogoutToken token)) {
            return;
        }
        int linked = 0;
        int invalidated = 0;
        for (OidcSessionInformation session : registry.removeSessionInformation(token)) {
            linked++;
            if (sessions.invalidate(session.getSessionId())) {
                invalidated++;
            }
        }
        log.info("Back-channel logout for sid={} sub={}: {} linked session(s), {} invalidated",
                token.getSessionId(), token.getSubject(), linked, invalidated);
    }
}
