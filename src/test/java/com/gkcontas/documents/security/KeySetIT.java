package com.gkcontas.documents.security;

import com.gkcontas.documents.IntegrationTestBase;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.time.Duration;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * How the key set is fetched: once for many requests, again on an unknown key
 * id (rotation), and not once per forged key id. The test profile allows a
 * forced fetch every 2 s instead of 30 s.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeySetIT extends IntegrationTestBase {

    @Test
    @Order(1)
    void keySetIsFetchedOnceForManyRequests() {
        String bob = KC.login("bob", "").accessToken();
        assertThat(get("/api/documents", bob).status()).isEqualTo(200);
        long before = metrics.jwksFetches();

        for (int i = 0; i < 100; i++) {
            assertThat(get("/api/documents", bob).status()).isEqualTo(200);
        }

        assertThat(metrics.jwksFetches()).isEqualTo(before);
    }

    @Test
    @Order(2)
    void forgedKeyIdsDoNotTurnIntoOneFetchEach() throws Exception {
        RSAKey attacker = new RSAKeyGenerator(2048).generate();
        long before = metrics.jwksFetches();
        long start = System.nanoTime();

        for (int i = 0; i < 200; i++) {
            assertThat(get("/api/documents", forgedWithKid(attacker, UUID.randomUUID().toString())).status())
                    .isEqualTo(401);
        }

        // Nimbus lets two fetches through per rate-limit window (2 s here) and refuses the rest;
        // a flood that straddles a window boundary sees one window more.
        long windows = Duration.ofNanos(System.nanoTime() - start).toMillis() / 2_000 + 2;
        assertThat(metrics.jwksFetches() - before).isLessThanOrEqualTo(2 * windows).isLessThan(200);
    }

    @Test
    @Order(3)
    void rotatedKeyIsPickedUpOnFirstUseAndOldTokensKeepWorking() {
        String before = KC.login("bob", "").accessToken();
        String oldKid = header(before).path("kid").asText();
        assertThat(get("/api/documents", before).status()).isEqualTo(200);

        String newKid = KC.rotateSigningKey();
        String after = KC.login("bob", "").accessToken();
        assertThat(newKid).isNotEqualTo(oldKid);
        assertThat(header(after).path("kid").asText()).isEqualTo(newKid);

        long fetches = metrics.jwksFetches();
        // Within the rate-limit window the new kid cannot be fetched yet; afterwards it is, once.
        await().atMost(Duration.ofSeconds(10)).pollInterval(Duration.ofMillis(250))
                .until(() -> get("/api/documents", after).status() == 200);
        assertThat(metrics.jwksFetches()).isGreaterThan(fetches);
        assertThat(get("/api/documents", before).status()).isEqualTo(200);
    }

    private static String forgedWithKid(RSAKey key, String kid) throws Exception {
        long now = System.currentTimeMillis();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(KC.realmUrl()).audience("docs-api").subject("mallory")
                .claim("typ", "Bearer").claim("scope", "documents:read")
                .issueTime(new Date(now)).expirationTime(new Date(now + 300_000))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).type(JOSEObjectType.JWT).build(),
                claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }
}
