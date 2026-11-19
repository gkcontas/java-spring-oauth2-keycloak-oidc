package com.gkcontas.documents.document;

import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/** In memory on purpose: the subject here is who may call, not where data lives. */
@Component
public class DocumentStore {

    private final Map<Long, Document> documents = new ConcurrentHashMap<>();
    private final AtomicLong ids = new AtomicLong();
    private final Clock clock;

    public DocumentStore(Clock clock) {
        this.clock = clock;
        create("Onboarding guide", "How to get access to the systems.", "system");
        create("Security policy", "Tokens are validated by the resource server.", "system");
        create("Release notes", "Version 1.0.0.", "system");
    }

    public Document create(String title, String content, String owner) {
        long id = ids.incrementAndGet();
        Document document = Document.builder()
                .id(id).title(title).content(content).owner(owner).createdAt(clock.instant())
                .build();
        documents.put(id, document);
        return document;
    }

    public List<Document> findAll() {
        return documents.values().stream().sorted(Comparator.comparingLong(Document::getId)).toList();
    }

    public Optional<Document> find(long id) {
        return Optional.ofNullable(documents.get(id));
    }

    public boolean delete(long id) {
        return documents.remove(id) != null;
    }
}
