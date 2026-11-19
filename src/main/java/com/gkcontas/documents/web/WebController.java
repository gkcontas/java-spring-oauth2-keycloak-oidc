package com.gkcontas.documents.web;

import com.gkcontas.documents.api.DocumentResponse;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The browser-facing endpoints. They return the user's identity and data, never
 * a token: access, refresh and ID tokens live in the server session.
 */
@RestController
public class WebController {

    private final RestClient documentsApi;

    public WebController(RestClient documentsApi) {
        this.documentsApi = documentsApi;
    }

    public record WebMe(String username, String subject, String sessionId, List<String> authorities,
                        List<String> scopes, Instant accessTokenExpiresAt, boolean hasRefreshToken) {
    }

    @GetMapping("/")
    public Map<String, String> home() {
        return Map.of("login", "/oauth2/authorization/" + OAuth2ClientConfig.REGISTRATION,
                "me", "/web/me", "documents", "/web/documents");
    }

    @GetMapping("/web/me")
    public WebMe me(@AuthenticationPrincipal OidcUser user,
                    @RegisteredOAuth2AuthorizedClient(OAuth2ClientConfig.REGISTRATION) OAuth2AuthorizedClient client) {
        return new WebMe(user.getPreferredUsername(), user.getSubject(), user.getClaimAsString("sid"),
                user.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList(),
                client.getAccessToken().getScopes().stream().sorted().toList(),
                client.getAccessToken().getExpiresAt(), client.getRefreshToken() != null);
    }

    /** For the frontend to send back in {@code X-CSRF-TOKEN} on state-changing requests. */
    @GetMapping("/web/csrf")
    public Map<String, String> csrf(CsrfToken token) {
        return Map.of("headerName", token.getHeaderName(), "token", token.getToken());
    }

    /** Calls the API with the user's token, refreshing it first when it is about to expire. */
    @GetMapping("/web/documents")
    public List<DocumentResponse> documents() {
        return documentsApi.get().uri("/api/documents").retrieve()
                .body(new ParameterizedTypeReference<>() {
                });
    }

    @ExceptionHandler(ClientAuthorizationException.class)
    ResponseEntity<Map<String, String>> reauthenticate(ClientAuthorizationException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "reauthentication_required", "reason", e.getError().getErrorCode()));
    }
}
