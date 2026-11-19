package com.gkcontas.documents.support;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * A minimal browser: keeps cookies, never follows redirects on its own.
 *
 * <p>Keycloak marks its cookies {@code Secure} even over plain HTTP. Browsers
 * treat {@code http://localhost} as a secure context and send them anyway;
 * {@link java.net.CookieManager} does not, hence this small jar. Everything
 * runs on localhost, so cookies are kept by name only.
 */
public class Browser {

    private static final Pattern LOGIN_FORM = Pattern.compile("<form id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"");

    private final HttpClient http = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private final Map<String, String> cookies = new LinkedHashMap<>();

    public record Response(int status, HttpResponse<String> raw) {
        public String body() {
            return raw.body();
        }

        public String location() {
            return raw.headers().firstValue("Location").orElse(null);
        }

        public String header(String name) {
            return raw.headers().firstValue(name).orElse(null);
        }
    }

    public Response get(String url, String... headers) {
        return send(HttpRequest.newBuilder(URI.create(url)).GET(), headers);
    }

    public Response postForm(String url, Map<String, String> form, String... headers) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form(form)));
        return send(builder, headers);
    }

    /** Follows redirects, filling Keycloak's login form when it shows up. */
    public Response navigate(String url, String username, String password) {
        String current = url;
        for (int hop = 0; hop < 15; hop++) {
            Response response = get(current);
            if (response.status() == 200 && response.body().contains("kc-form-login")) {
                response = submitLogin(response.body(), username, password);
            }
            if (response.status() < 300 || response.status() >= 400) {
                return response;
            }
            current = URI.create(current).resolve(response.location()).toString();
            if (current.contains("/callback?")) {
                return response; // redirect URI of a native client: nobody listens there
            }
        }
        throw new IllegalStateException("too many redirects from " + url);
    }

    public Response submitLogin(String loginPage, String username, String password) {
        Matcher matcher = LOGIN_FORM.matcher(loginPage);
        if (!matcher.find()) {
            throw new IllegalStateException("login form not found");
        }
        String action = matcher.group(1).replace("&amp;", "&");
        return postForm(action, Map.of("username", username, "password", password, "credentialId", ""));
    }

    public String cookie(String name) {
        return cookies.get(name);
    }

    public boolean hasCookie(String name) {
        return cookies.containsKey(name);
    }

    public static String form(Map<String, String> fields) {
        return fields.entrySet().stream()
                .map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
                .collect(Collectors.joining("&"));
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private Response send(HttpRequest.Builder builder, String... headers) {
        for (int i = 0; i + 1 < headers.length; i += 2) {
            builder.header(headers[i], headers[i + 1]);
        }
        if (!cookies.isEmpty()) {
            builder.header("Cookie", cookies.entrySet().stream()
                    .map(e -> e.getKey() + "=" + e.getValue()).collect(Collectors.joining("; ")));
        }
        try {
            HttpResponse<String> response = http.send(builder.timeout(Duration.ofSeconds(15)).build(),
                    HttpResponse.BodyHandlers.ofString());
            response.headers().allValues("Set-Cookie").forEach(this::store);
            return new Response(response.statusCode(), response);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private void store(String setCookie) {
        String[] parts = setCookie.split(";");
        String[] pair = parts[0].split("=", 2);
        String name = pair[0].trim();
        String value = pair.length > 1 ? pair[1].trim() : "";
        boolean expired = value.isEmpty();
        for (String attribute : parts) {
            String a = attribute.trim().toLowerCase();
            if (a.equals("max-age=0") || a.startsWith("expires=thu, 01 jan 1970") || a.startsWith("expires=thu, 01-jan-1970")) {
                expired = true;
            }
        }
        if (expired) {
            cookies.remove(name);
        } else {
            cookies.put(name, value);
        }
    }
}
