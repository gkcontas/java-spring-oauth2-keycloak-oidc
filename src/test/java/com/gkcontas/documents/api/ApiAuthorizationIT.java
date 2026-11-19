package com.gkcontas.documents.api;

import com.gkcontas.documents.IntegrationTestBase;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Scope is what the client may ask for; role is what the user may do. */
class ApiAuthorizationIT extends IntegrationTestBase {

    private static final String NEW_DOCUMENT = """
            {"title":"Quarterly plan","content":"Draft","owner":"mallory"}""";

    @Test
    void readerReadsWithTheReadScope() {
        String bob = KC.login("bob", "").accessToken();

        assertThat(get("/api/documents", bob).status()).isEqualTo(200);
        assertThat(get("/api/documents/1", bob).json().path("title").asText()).isEqualTo("Onboarding guide");
    }

    @Test
    void editorWithWriteScopeCreatesAndTheOwnerComesFromTheToken() {
        String alice = KC.login("alice", "documents:write").accessToken();

        Api created = call("POST", "/api/documents", alice, NEW_DOCUMENT);

        assertThat(created.status()).isEqualTo(201);
        assertThat(created.json().path("owner").asText()).isEqualTo("alice");
    }

    @Test
    void editorRoleWithoutTheWriteScopeIsForbidden() {
        String alice = KC.login("alice", "").accessToken();

        assertThat(claims(alice).path("realm_access").path("roles").toString()).contains("editor");
        assertThat(call("POST", "/api/documents", alice, NEW_DOCUMENT).status()).isEqualTo(403);
    }

    @Test
    void writeScopeWithoutTheEditorRoleIsForbidden() {
        // Keycloak grants an optional scope to whoever asks; the scope alone says nothing about the user.
        String bob = KC.login("bob", "documents:write").accessToken();

        assertThat(claims(bob).path("scope").asText()).contains("documents:write");
        assertThat(call("POST", "/api/documents", bob, NEW_DOCUMENT).status()).isEqualTo(403);
    }

    @Test
    void deleteNeedsTheClientRoleOfThisApiNotOfAnotherClient() {
        String alice = KC.login("alice", "documents:write").accessToken();
        String bob = KC.login("bob", "documents:write").accessToken();
        long id = call("POST", "/api/documents", alice, NEW_DOCUMENT).json().path("id").asLong();

        // bob is "admin" of other-app; the claim is in his token, and means nothing here.
        assertThat(claims(bob).path("resource_access").path("other-app").path("roles").toString()).contains("admin");
        assertThat(call("DELETE", "/api/documents/" + id, bob, null).status()).isEqualTo(403);
        assertThat(call("DELETE", "/api/documents/" + id, alice, null).status()).isEqualTo(204);
        assertThat(get("/api/documents/" + id, alice).status()).isEqualTo(404);
    }

    @Test
    void meShowsTheAuthoritiesMappedFromKeycloakClaims() {
        String alice = KC.login("alice", "").accessToken();
        String bob = KC.login("bob", "").accessToken();

        assertThat(get("/api/me", alice).json().path("authorities")).extracting(Object::toString)
                .contains("\"ROLE_docs-api:admin\"", "\"ROLE_editor\"", "\"ROLE_reader\"", "\"SCOPE_documents:read\"");
        assertThat(get("/api/me", bob).body()).doesNotContain("admin");
        assertThat(get("/api/me", bob).json().path("username").asText()).isEqualTo("bob");
    }

    @Test
    void serviceAccountReadsButCannotWrite() {
        String job = KC.clientCredentials("report-job", "report-job-secret");

        assertThat(claims(job).path("azp").asText()).isEqualTo("report-job");
        assertThat(get("/api/documents", job).status()).isEqualTo(200);
        assertThat(call("POST", "/api/documents", job, NEW_DOCUMENT).status()).isEqualTo(403);
    }

    @Test
    void withoutTokenIsUnauthorizedAndUnknownRoutesAreDenied() {
        String alice = KC.login("alice", "documents:write").accessToken();

        Api anonymous = get("/api/documents", null);
        assertThat(anonymous.status()).isEqualTo(401);
        assertThat(anonymous.wwwAuthenticate()).startsWith("Bearer");
        assertThat(get("/api/admin/anything", alice).status()).isEqualTo(403);
        assertThat(call("PUT", "/api/documents/1", alice, NEW_DOCUMENT).status()).isEqualTo(403);
    }

    @Test
    void validationMessagesAreInEnglish() {
        String alice = KC.login("alice", "documents:write").accessToken();

        Api invalid = call("POST", "/api/documents", alice, "{\"title\":\" \",\"content\":\"\"}");

        assertThat(invalid.status()).isEqualTo(400);
        assertThat(invalid.json().path("details").toString())
                .contains("content: content must not be blank", "title: title must not be blank");
    }
}
