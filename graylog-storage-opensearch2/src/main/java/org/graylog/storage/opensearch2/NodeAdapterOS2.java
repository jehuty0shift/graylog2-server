package org.graylog.storage.opensearch2;

import org.opensearch.client.RestHighLevelClient;
import org.opensearch.client.core.MainResponse;
import org.graylog2.indexer.cluster.NodeAdapter;

import javax.inject.Inject;
import java.util.Optional;

public class NodeAdapterOS2 implements NodeAdapter {
    private final OpensearchGraylogClient client;

    @Inject
    public NodeAdapterOS2(OpensearchGraylogClient client) {
        this.client = client;
    }

    @Override
    public Optional<String> version() {
        final MainResponse result = client.execute(RestHighLevelClient::info,
                "Unable to retrieve Elasticsearch version from node");
        return Optional.of(result.getVersion().getNumber());
    }
}
