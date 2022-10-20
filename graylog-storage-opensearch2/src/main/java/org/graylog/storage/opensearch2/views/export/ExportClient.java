package org.graylog.storage.opensearch2.views.export;

import org.graylog.plugins.views.search.export.ExportException;
import org.graylog.storage.opensearch2.OpensearchClient;
import org.graylog.storage.opensearch2.ThrowingBiFunction;
import org.graylog2.indexer.ElasticsearchException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.RestHighLevelClient;

import javax.inject.Inject;
import java.io.IOException;

public class ExportClient {
    private final OpensearchClient client;

    @Inject
    public ExportClient(OpensearchClient client) {
        this.client = client;
    }

    public SearchResponse search(SearchRequest request, String errorMessage) {
        try {
            return this.client.search(request, errorMessage);
        } catch (Exception e) {
            throw wrapException(e);
        }
    }

    private ExportException wrapException(Exception e) {
        return new ExportException("Unable to complete export: ", new ElasticsearchException(e));
    }

    public SearchResponse singleSearch(SearchRequest request, String errorMessage) {
        try {
            return this.client.singleSearch(request, errorMessage);
        } catch (Exception e) {
            throw wrapException(e);
        }
    }

    public <R> R execute(ThrowingBiFunction<RestHighLevelClient, RequestOptions, R, IOException> fn, String errorMessage) {
        try {
            return this.client.execute(fn, errorMessage);
        } catch (Exception e) {
            throw wrapException(e);
        }
    }
}
