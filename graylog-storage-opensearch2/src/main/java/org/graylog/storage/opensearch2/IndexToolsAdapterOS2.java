package org.graylog.storage.opensearch2;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.client.core.CountRequest;
import org.opensearch.client.core.CountResponse;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.aggregations.AggregationBuilders;
import org.opensearch.search.aggregations.bucket.filter.Filter;
import org.opensearch.search.aggregations.bucket.filter.FilterAggregationBuilder;
import org.opensearch.search.aggregations.bucket.histogram.DateHistogramInterval;
import org.opensearch.search.aggregations.bucket.histogram.ParsedDateHistogram;
import org.opensearch.search.aggregations.bucket.terms.Terms;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.graylog2.indexer.IndexToolsAdapter;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.streams.Stream;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import javax.inject.Inject;
import java.time.ZonedDateTime;
import java.util.*;

import static org.opensearch.index.query.QueryBuilders.*;

public class IndexToolsAdapterOS2 implements IndexToolsAdapter {
    private static final String AGG_DATE_HISTOGRAM = "source_date_histogram";
    private static final String AGG_MESSAGE_FIELD = "message_field";
    private static final String AGG_FILTER = "message_filter";
    private final OpensearchGraylogClient client;

    @Inject
    public IndexToolsAdapterOS2(OpensearchGraylogClient client) {
        this.client = client;
    }

    @Override
    public Map<DateTime, Map<String, Long>> fieldHistogram(String fieldName, Set<String> indices, Optional<Set<String>> includedStreams, long interval) {
        final BoolQueryBuilder queryBuilder = buildStreamIdFilter(includedStreams);

        final FilterAggregationBuilder the_filter = AggregationBuilders.filter(AGG_FILTER, queryBuilder)
                .subAggregation(AggregationBuilders.dateHistogram(AGG_DATE_HISTOGRAM)
                        .field("timestamp")
                        .subAggregation(AggregationBuilders.terms(AGG_MESSAGE_FIELD).field(fieldName))
                        .fixedInterval(new DateHistogramInterval(interval + "ms"))
                        // We use "min_doc_count" here to avoid empty buckets in the histogram result.
                        // This is needed to avoid out-of-memory errors when creating a histogram for a really large
                        // date range. See: https://github.com/Graylog2/graylog-plugin-archive/issues/59
                        .minDocCount(1L));

        final SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder()
                .query(QueryBuilders.matchAllQuery())
                .aggregation(the_filter);

        final SearchRequest searchRequest = new SearchRequest()
                .source(searchSourceBuilder)
                .indices(indices.toArray(new String[0]));
        final SearchResponse searchResult = client.search(searchRequest, "Unable to retrieve field histogram.");

        final Filter filterAggregation = searchResult.getAggregations().get(AGG_FILTER);
        final ParsedDateHistogram dateHistogram = filterAggregation.getAggregations().get(AGG_DATE_HISTOGRAM);


        final List<ParsedDateHistogram.ParsedBucket> histogramBuckets = (List<ParsedDateHistogram.ParsedBucket>)dateHistogram.getBuckets();
        final Map<DateTime, Map<String, Long>> result = Maps.newHashMapWithExpectedSize(histogramBuckets.size());

        for (ParsedDateHistogram.ParsedBucket bucket : histogramBuckets) {
            final ZonedDateTime zonedDateTime = (ZonedDateTime) bucket.getKey();
            final DateTime date = new DateTime(zonedDateTime.toInstant().toEpochMilli()).toDateTime(DateTimeZone.UTC);

            final Terms sourceFieldAgg = bucket.getAggregations().get(AGG_MESSAGE_FIELD);
            final List<? extends Terms.Bucket> termBuckets = sourceFieldAgg.getBuckets();

            final HashMap<String, Long> termCounts = Maps.newHashMapWithExpectedSize(termBuckets.size());

            for (Terms.Bucket termBucket : termBuckets) {
                termCounts.put(termBucket.getKeyAsString(), termBucket.getDocCount());
            }

            result.put(date, termCounts);
        }

        return ImmutableMap.copyOf(result);
    }

    @Override
    public long count(Set<String> indices, Optional<Set<String>> includedStreams) {
        final CountRequest request = new CountRequest(indices.toArray(new String[0]), buildStreamIdFilter(includedStreams))
                .indicesOptions(IndicesOptions.fromOptions(true, false, true, false));

        final CountResponse result = client.execute((c, requestOptions) -> c.count(request, requestOptions), "Unable to count documents of index.");

        return result.getCount();
    }

    private BoolQueryBuilder buildStreamIdFilter(Optional<Set<String>> includedStreams) {
        final BoolQueryBuilder queryBuilder = boolQuery().must(matchAllQuery());

        // If the included streams are not present, we do not filter on streams
        if (includedStreams.isPresent()) {
            final Set<String> streams = includedStreams.get();
            final BoolQueryBuilder filterBuilder = boolQuery();

            // If the included streams set contains the default stream, we also want all documents which do not
            // have any stream assigned. Those documents have basically been in the "default stream" which didn't
            // exist in Graylog <2.2.0.
            if (streams.contains(Stream.DEFAULT_STREAM_ID)) {
                filterBuilder.should(boolQuery().mustNot(existsQuery(Message.FIELD_STREAMS)));
            }

            // Only select messages which are assigned to the given streams
            filterBuilder.should(termsQuery(Message.FIELD_STREAMS, streams));

            queryBuilder.filter(filterBuilder);
        }

        return queryBuilder;
    }
}
