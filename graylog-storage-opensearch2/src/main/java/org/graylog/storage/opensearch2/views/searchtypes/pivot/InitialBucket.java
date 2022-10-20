package org.graylog.storage.opensearch2.views.searchtypes.pivot;

import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.search.aggregations.Aggregations;
import org.opensearch.search.aggregations.bucket.MultiBucketsAggregation;

import java.io.IOException;

public class InitialBucket implements MultiBucketsAggregation.Bucket {
    private final long docCount;
    private final Aggregations aggregations;

    private InitialBucket(long docCount, Aggregations aggregations) {
        this.docCount = docCount;
        this.aggregations = aggregations;
    }

    public static InitialBucket create(SearchResponse searchResponse) {
        return new InitialBucket(searchResponse.getHits().getTotalHits().value, searchResponse.getAggregations());
    }

    @Override
    public Object getKey() {
        throw new IllegalStateException("Not implemented!");
    }

    @Override
    public String getKeyAsString() {
        throw new IllegalStateException("Not implemented!");
    }

    @Override
    public long getDocCount() {
        return this.docCount;
    }

    @Override
    public Aggregations getAggregations() {
        return this.aggregations;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
        throw new IllegalStateException("Not implemented!");
    }
}

