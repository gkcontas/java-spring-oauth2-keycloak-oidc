package com.gkcontas.documents.document;

import lombok.Builder;
import lombok.Value;

import java.time.Instant;

@Value
@Builder
public class Document {
    long id;
    String title;
    String content;
    /** Username of whoever created it, taken from the token, never from the payload. */
    String owner;
    Instant createdAt;
}
