package com.gkcontas.documents.support;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The OAuth side of the tests: real authorization code flows with PKCE through
 * Keycloak's login page, plus the admin API for what a test needs to change in
 * the realm. There is no password grant in this realm, and none here.
 */
public class Keycloak {

    public static final String CLI_REDIRECT = "http://localhost:8765/callback";
    public static final String OTHER_APP_REDIRECT = "http://localhost:8766/callback";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String baseUrl;
    private final String realm;
    private final HttpClient http = HttpClient.newHttpClient();

    public Keycloak(String baseUrl, String realm) {
        this.baseUrl = baseUrl;
        this.realm = realm;
    }

    public record Tokens(String accessToken, String refreshToken, String idToken) {
    }

    /** The code and the verifier, before the exchange: what PKCE tests need to tamper with. */
    public record Code(String code, String verifier, String clientId, String redirectUri) {
    }

    public String realmUrl() {
        return baseUrl + "/realms/" + realm;
    }

    public Tokens login(String username, String clientId, String extraScope) {
        return login(new Browser(), username, clientId, extraScope);
    }

    public Tokens login(Browser browser, String username, String clientId, String extraScope) {
        Code code = code(browser, username, clientId, extraScope);
        JsonNode json = exchange(code, code.verifier()).json();
        return new Tokens(json.path("access_token").asText(), json.path("refresh_token").asText(),
                json.path("id_token").asText());
    }

    public Tokens login(String username, String extraScope) {
        return login(username, "docs-cli", extraScope);
    }

    public Code code(String username, String clientId, String extraScope) {
        return code(new Browser(), username, clientId, extraScope);
    }

    /** In an existing browser: with a live Keycloak session there, single sign-on skips the form. */
    public Code code(Browser browser, String username, String clientId, String extraScope) {
        String verifier = randomUrlSafe(48);
        String redirectUri = clientId.equals("other-app") ? OTHER_APP_REDIRECT : CLI_REDIRECT;
        Browser.Response response = browser.navigate(authorizeUrl(clientId, redirectUri, extraScope,
                Map.of("code_challenge", challenge(verifier), "code_challenge_method", "S256")), username, username);
        String location = response.location();
        if (location == null || !location.contains("code=")) {
            throw new IllegalStateException("no code in " + location + " (" + response.status() + ")");
        }
        String code = query(location).get("code");
        return new Code(code, verifier, clientId, redirectUri);
    }

    public String authorizeUrl(String clientId, String redirectUri, String extraScope, Map<String, String> extra) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", clientId);
        params.put("redirect_uri", redirectUri);
        params.put("scope", ("openid " + extraScope).trim());
        params.put("state", randomUrlSafe(12));
        params.putAll(extra);
        return realmUrl() + "/protocol/openid-connect/auth?" + Browser.form(params);
    }

    public Result exchange(Code code, String verifier) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code.code());
        form.put("redirect_uri", code.redirectUri());
        form.put("client_id", code.clientId());
        if (verifier != null) {
            form.put("code_verifier", verifier);
        }
        return post(realmUrl() + "/protocol/openid-connect/token", form, null);
    }

    public Result refresh(String refreshToken, String clientId) {
        return post(realmUrl() + "/protocol/openid-connect/token",
                Map.of("grant_type", "refresh_token", "refresh_token", refreshToken, "client_id", clientId), null);
    }

    /** Resource owner password grant, which OAuth 2.1 removes. Disabled on every client of the realm. */
    public Result passwordGrant(String username, String clientId) {
        return post(realmUrl() + "/protocol/openid-connect/token",
                Map.of("grant_type", "password", "client_id", clientId, "username", username, "password", username), null);
    }

    public String clientCredentials(String clientId, String secret) {
        return post(realmUrl() + "/protocol/openid-connect/token",
                Map.of("grant_type", "client_credentials", "client_id", clientId, "client_secret", secret), null)
                .json().path("access_token").asText();
    }

    /** Ends the single sign-on session, as a native client does on sign-out. */
    public int logout(Tokens tokens, String clientId) {
        return post(realmUrl() + "/protocol/openid-connect/logout",
                Map.of("client_id", clientId, "refresh_token", tokens.refreshToken()), null).status();
    }

    // ---------------------------------------------------------------- admin API

    public void logoutUser(String username) {
        admin("POST", "/users/" + userId(username) + "/logout", null);
    }

    /** Ends each session of the user on its own; Keycloak sends one back-channel logout per session. */
    public void endSessions(String username) {
        for (JsonNode session : admin("GET", "/users/" + userId(username) + "/sessions", null).json()) {
            admin("DELETE", "/sessions/" + session.path("id").asText(), null);
        }
    }

    public int sessionCount(String username) {
        return admin("GET", "/users/" + userId(username) + "/sessions", null).json().size();
    }

    public String userId(String username) {
        return admin("GET", "/users?exact=true&username=" + username, null).json().get(0).path("id").asText();
    }

    public void updateClient(String clientId, java.util.function.Consumer<ObjectNode> change) {
        JsonNode client = admin("GET", "/clients?clientId=" + clientId, null).json().get(0);
        ObjectNode copy = client.deepCopy();
        change.accept(copy);
        admin("PUT", "/clients/" + client.path("id").asText(), copy.toString());
    }

    /** A new RSA key with a higher priority: from now on, tokens are signed with it. */
    public String rotateSigningKey() {
        String realmId = admin("GET", "", null).json().path("id").asText();
        String component = """
                {"name":"rotated-%d","providerId":"rsa-generated","providerType":"org.keycloak.keys.KeyProvider",
                 "parentId":"%s","config":{"priority":["%d"],"keySize":["2048"],"active":["true"],"enabled":["true"],
                 "algorithm":["RS256"]}}""".formatted(System.nanoTime(), realmId, 1000 + RANDOM.nextInt(1000));
        admin("POST", "/components", component);
        JsonNode keys = admin("GET", "/keys", null).json();
        return keys.path("active").path("RS256").asText();
    }

    public Result admin(String method, String path, String body) {
        String token = post(baseUrl + "/realms/master/protocol/openid-connect/token",
                Map.of("grant_type", "password", "client_id", "admin-cli", "username", "admin", "password", "admin"),
                null).json().path("access_token").asText();
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/" + realm + path))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        Result result = send(builder);
        if (result.status() >= 400) {
            throw new IllegalStateException(method + " " + path + " -> " + result.status() + " " + result.body());
        }
        return result;
    }

    public record Result(int status, String body) {
        public JsonNode json() {
            try {
                return body == null || body.isBlank() ? JSON.createObjectNode() : JSON.readTree(body);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    private Result post(String url, Map<String, String> form, String bearer) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(Browser.form(form)));
        if (bearer != null) {
            builder.header("Authorization", "Bearer " + bearer);
        }
        return send(builder);
    }

    private Result send(HttpRequest.Builder builder) {
        try {
            HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            return new Result(response.statusCode(), response.body());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    public static Map<String, String> query(String url) {
        Map<String, String> params = new LinkedHashMap<>();
        String query = URI.create(url).getRawQuery();
        if (query == null) {
            return params;
        }
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            params.put(java.net.URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                    kv.length > 1 ? java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
        }
        return params;
    }

    public static String challenge(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String randomUrlSafe(int bytes) {
        byte[] random = new byte[bytes];
        RANDOM.nextBytes(random);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(random);
    }

    static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
