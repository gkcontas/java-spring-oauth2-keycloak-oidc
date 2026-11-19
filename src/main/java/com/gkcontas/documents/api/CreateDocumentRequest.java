package com.gkcontas.documents.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateDocumentRequest(
        @NotBlank(message = "title must not be blank")
        @Size(max = 200, message = "title must have at most 200 characters")
        String title,
        @NotBlank(message = "content must not be blank")
        @Size(max = 10000, message = "content must have at most 10000 characters")
        String content) {
}
