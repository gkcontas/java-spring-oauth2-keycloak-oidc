package com.gkcontas.documents.api;

import com.gkcontas.documents.document.Document;

import java.time.Instant;

public record DocumentResponse(long id, String title, String content, String owner, Instant createdAt) {

    public static DocumentResponse of(Document document) {
        return new DocumentResponse(document.getId(), document.getTitle(), document.getContent(),
                document.getOwner(), document.getCreatedAt());
    }
}
