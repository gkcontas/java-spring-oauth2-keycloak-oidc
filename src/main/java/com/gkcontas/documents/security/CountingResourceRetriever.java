package com.gkcontas.documents.security;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;

import java.io.IOException;
import java.net.URL;

/** Fetches the key set with short timeouts and counts every fetch. */
class CountingResourceRetriever implements ResourceRetriever {

    private final ResourceRetriever delegate = new DefaultResourceRetriever(1_000, 2_000, 512 * 1024);
    private final AuthMetrics metrics;

    CountingResourceRetriever(AuthMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    public Resource retrieveResource(URL url) throws IOException {
        metrics.jwksFetched();
        return delegate.retrieveResource(url);
    }
}
