package com.gkcontas.documents;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gkcontas.documents.security.AuthMetrics;
import com.gkcontas.documents.support.Keycloak;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

/**
 * One Keycloak for the whole suite, started from a static initialiser. Not
 * {@code @Testcontainers}: Spring caches application contexts across test
 * classes, and a container tied to a class is stopped while a cached context
 * still points at it.
 *
 * <p>The application runs on a port chosen here, before Keycloak starts, so
 * that the realm can be pointed at it: Keycloak calls the application back
 * for back-channel logout. That also means a single application context for
 * the suite - a second one would want the same port.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@ActiveProfiles("test")
public abstract class IntegrationTestBase {

    protected static final String REALM = "docs";
    protected static final int APP_PORT = freePort();
    protected static final ObjectMapper JSON = new ObjectMapper();

    @SuppressWarnings("resource")
    static final GenericContainer<?> KEYCLOAK = new GenericContainer<>("quay.io/keycloak/keycloak:26.0.7")
            .withExposedPorts(8080)
            .withCommand("start-dev", "--import-realm")
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withCopyFileToContainer(MountableFile.forHostPath("keycloak/docs-realm.json"),
                    "/opt/keycloak/data/import/docs-realm.json")
            // Back-channel logout: Keycloak calls the application on the host through the Docker
            // gateway, the same way docker-compose.yml does it.
            .withExtraHost("host.docker.internal", "host-gateway")
            .waitingFor(Wait.forHttp("/realms/" + REALM + "/.well-known/openid-configuration")
                    .forPort(8080)
                    .withStartupTimeout(Duration.ofMinutes(3)));

    protected static final Keycloak KC;

    static {
        KEYCLOAK.start();
        KC = new Keycloak("http://" + KEYCLOAK.getHost() + ":" + KEYCLOAK.getMappedPort(8080), REALM);
        // The imported realm points docs-web at localhost:8080; the suite runs elsewhere.
        KC.updateClient("docs-web", client -> {
            client.putArray("redirectUris").add(appUrl() + "/login/oauth2/code/keycloak");
            client.withObjectProperty("attributes").put("post.logout.redirect.uris", appUrl() + "/");
            client.withObjectProperty("attributes").put("backchannel.logout.url",
                    backChannelLogoutUrl());
        });
    }

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER).build();

    @Autowired
    protected AuthMetrics metrics;

    protected static String backChannelLogoutUrl() {
        return "http://host.docker.internal:" + APP_PORT + "/logout/connect/back-channel/keycloak";
    }

    protected static String keycloakLogs() {
        return KEYCLOAK.getLogs();
    }

    protected static String appUrl() {
        return "http://localhost:" + APP_PORT;
    }

    @DynamicPropertySource
    static void keycloak(DynamicPropertyRegistry registry) {
        registry.add("server.port", () -> APP_PORT);
        registry.add("app.keycloak.realm-url", KC::realmUrl);
    }

    protected record Api(int status, String body, String wwwAuthenticate) {
        public JsonNode json() {
            try {
                return JSON.readTree(body);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    protected static Api call(String method, String path, String token, String jsonBody) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(appUrl() + path))
                .method(method, jsonBody == null ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(jsonBody))
                .header("Content-Type", "application/json");
        if (token != null) {
            builder.header("Authorization", "Bearer " + token);
        }
        try {
            HttpResponse<String> response = HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            return new Api(response.statusCode(), response.body(),
                    response.headers().firstValue("WWW-Authenticate").orElse(""));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    protected static Api get(String path, String token) {
        return call("GET", path, token, null);
    }

    protected static JsonNode claims(String jwt) {
        try {
            return JSON.readTree(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    protected static JsonNode header(String jwt) {
        try {
            return JSON.readTree(new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[0]), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static int freePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
