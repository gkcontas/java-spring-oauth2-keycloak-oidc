package com.gkcontas.documents.api;

import com.gkcontas.documents.document.DocumentStore;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.util.List;

/**
 * The same read endpoints answer under {@code /api} (JWT validated locally) and
 * {@code /api/introspected} (token introspected at Keycloak). Which one applies
 * is decided by the security chain, not here.
 */
@RestController
public class DocumentController {

    private final DocumentStore store;

    public DocumentController(DocumentStore store) {
        this.store = store;
    }

    @GetMapping({"/api/documents", "/api/introspected/documents"})
    public List<DocumentResponse> list() {
        return store.findAll().stream().map(DocumentResponse::of).toList();
    }

    @GetMapping({"/api/documents/{id}", "/api/introspected/documents/{id}"})
    public DocumentResponse get(@PathVariable long id) {
        return store.find(id).map(DocumentResponse::of)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "document not found"));
    }

    @PostMapping("/api/documents")
    public ResponseEntity<DocumentResponse> create(@Valid @RequestBody CreateDocumentRequest request,
                                                   Authentication authentication) {
        DocumentResponse created = DocumentResponse.of(
                store.create(request.title(), request.content(), authentication.getName()));
        return ResponseEntity.created(URI.create("/api/documents/" + created.id())).body(created);
    }

    @DeleteMapping("/api/documents/{id}")
    public ResponseEntity<Void> delete(@PathVariable long id) {
        if (!store.delete(id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "document not found");
        }
        return ResponseEntity.noContent().build();
    }
}
