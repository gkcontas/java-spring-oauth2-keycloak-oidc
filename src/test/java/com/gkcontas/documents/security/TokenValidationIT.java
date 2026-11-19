package com.gkcontas.documents.security;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.gkcontas.documents.IntegrationTestBase;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A valid signature from the right issuer is necessary and not sufficient.
 * Each case here is a token that would be accepted by a decoder configured with
 * nothing but the issuer URI.
 */
class TokenValidationIT extends IntegrationTestBase {

    @Test
    void tokenIssuedToAnotherClientIsRejectedByAudience() {
        String bobAtOtherApp = KC.login("bob", "other-app", "").accessToken();

        assertThat(claims(bobAtOtherApp).path("aud").toString()).doesNotContain("docs-api");
        Api response = get("/api/me", bobAtOtherApp);
        assertThat(response.status()).isEqualTo(401);
        assertThat(response.wwwAuthenticate()).contains("The aud claim is not valid");
    }

    @Test
    void audienceResolveAddsThisApiToAnotherClientsTokenSoScopesStillMatter() {
        // Keycloak's "roles" scope carries an "audience resolve" mapper: alice holds a docs-api
        // client role, so a token she gets from other-app - which never asked for documents - has
        // aud docs-api anyway. The audience check passes; the scope check is what stops it.
        String aliceAtOtherApp = KC.login("alice", "other-app", "").accessToken();

        assertThat(claims(aliceAtOtherApp).path("azp").asText()).isEqualTo("other-app");
        assertThat(claims(aliceAtOtherApp).path("aud").toString()).contains("docs-api");
        assertThat(get("/api/me", aliceAtOtherApp).status()).isEqualTo(200);
        assertThat(get("/api/documents", aliceAtOtherApp).status()).isEqualTo(403);
        assertThat(call("DELETE", "/api/documents/2", aliceAtOtherApp, null).status()).isEqualTo(403);
    }

    @Test
    void idTokenIsNotAnAccessToken() {
        String idToken = KC.login("alice", "").idToken();

        assertThat(claims(idToken).path("typ").asText()).isEqualTo("ID");
        assertThat(get("/api/me", idToken).status()).isEqualTo(401);
    }

    @Test
    void idTokenWithThisApiAsAudienceIsStillRejectedByType() throws Exception {
        // Same claims an ID token would carry, audience forced to docs-api: only the typ check is left.
        RSAKey key = new RSAKeyGenerator(2048).keyID(activeKid()).generate();
        String forged = sign(key, JWSAlgorithm.RS256, claimsFor("ID"));
        assertThat(get("/api/me", forged).status()).isEqualTo(401);
    }

    @Test
    void tamperedPayloadFailsTheSignature() {
        String bob = KC.login("bob", "").accessToken();
        String[] parts = bob.split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8)
                .replace("\"reader\"", "\"editor\"");
        String tampered = parts[0] + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "." + parts[2];

        assertThat(get("/api/documents", tampered).status()).isEqualTo(401);
    }

    @Test
    void ownKeyWithKeycloaksKidIsRejected() throws Exception {
        RSAKey attacker = new RSAKeyGenerator(2048).keyID(activeKid()).generate();

        assertThat(get("/api/documents", sign(attacker, JWSAlgorithm.RS256, claimsFor("Bearer"))).status())
                .isEqualTo(401);
    }

    @Test
    void algNoneIsRejected() {
        String header = b64("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payload = b64(claimsFor("Bearer").toString());

        assertThat(get("/api/documents", header + "." + payload + ".").status()).isEqualTo(401);
    }

    @Test
    void hmacSignedWithThePublicKeyIsRejected() throws Exception {
        // Algorithm confusion: a verifier that trusts the header's "alg" would check this HMAC
        // with the RSA public key - which everyone can download - as the secret.
        byte[] publicKey = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(KC.realmUrl() + "/protocol/openid-connect/certs")).build(),
                HttpResponse.BodyHandlers.ofByteArray()).body();
        byte[] secret = java.util.Arrays.copyOf(publicKey, Math.max(64, publicKey.length));
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(activeKid()).build(),
                JWTClaimsSet.parse(claimsFor("Bearer").toString()));
        jwt.sign(new MACSigner(secret));

        assertThat(get("/api/documents", jwt.serialize()).status()).isEqualTo(401);
    }

    @Test
    void tokenFromAnotherIssuerIsRejected() throws Exception {
        ObjectNode claims = claimsFor("Bearer");
        claims.put("iss", "http://evil.example/realms/docs");
        RSAKey attacker = new RSAKeyGenerator(2048).keyID(activeKid()).generate();

        Api response = get("/api/documents", sign(attacker, JWSAlgorithm.RS256, claims));
        assertThat(response.status()).isEqualTo(401);
    }

    private static ObjectNode claimsFor(String typ) {
        long now = Instant.now().getEpochSecond();
        ObjectNode claims = JSON.createObjectNode();
        claims.put("iss", KC.realmUrl());
        claims.putArray("aud").add("docs-api");
        claims.put("sub", "00000000-0000-0000-0000-000000000000");
        claims.put("typ", typ);
        claims.put("azp", "docs-cli");
        claims.put("scope", "openid documents:read documents:write");
        claims.put("preferred_username", "mallory");
        claims.set("realm_access", JSON.valueToTree(Map.of("roles", List.of("reader", "editor"))));
        claims.put("iat", now);
        claims.put("exp", now + 300);
        return claims;
    }

    private static String sign(RSAKey key, JWSAlgorithm alg, ObjectNode claims) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(alg).keyID(key.getKeyID()).type(JOSEObjectType.JWT).build(),
                JWTClaimsSet.parse(claims.toString()));
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private static String activeKid() {
        return header(KC.clientCredentials("report-job", "report-job-secret")).path("kid").asText();
    }

    private static String b64(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
