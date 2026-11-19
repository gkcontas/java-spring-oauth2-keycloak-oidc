package com.gkcontas.documents.api;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

/** What the API knows about the caller, straight from the validated token. */
@RestController
public class MeController {

    public record Me(String subject, String username, String client, List<String> audience,
                     List<String> authorities, Instant expiresAt) {
    }

    @GetMapping("/api/me")
    public Me me(JwtAuthenticationToken authentication) {
        var jwt = authentication.getToken();
        return new Me(jwt.getSubject(), authentication.getName(), jwt.getClaimAsString("azp"), jwt.getAudience(),
                authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().toList(),
                jwt.getExpiresAt());
    }
}
