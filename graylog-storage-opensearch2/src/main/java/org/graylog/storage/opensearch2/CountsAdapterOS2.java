package org.graylog.storage.opensearch2;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.graylog2.indexer.counts.CountsAdapter;

import javax.inject.Inject;
import java.util.List;

public class CountsAdapterOS2 implements CountsAdapter {
    private final OpensearchClient client;

    @Inject
    public CountsAdapterOS2(OpensearchClient client) {
        this.client = client;
    }

    @Override
    public long totalCount(List<String> indices) {
        final SearchSourceBuilder query = new SearchSourceBuilder()
                .query(QueryBuilders.matchAllQuery())
                .size(0)
                .trackTotalHits(true);
        final SearchRequest searchRequest = new SearchRequest(indices.toArray(new String[0]))
                .source(query);

        final SearchResponse result = client.search(searchRequest, "Fetching message count failed for indices ");

        return result.getHits().getTotalHits().value;
    }
}
