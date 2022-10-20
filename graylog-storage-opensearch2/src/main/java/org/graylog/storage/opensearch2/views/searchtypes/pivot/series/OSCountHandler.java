/**
 * This file is part of Graylog.
 *
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog.storage.opensearch2.views.searchtypes.pivot.series;

import org.graylog.plugins.views.search.searchtypes.pivot.Pivot;
import org.graylog.plugins.views.search.searchtypes.pivot.PivotSpec;
import org.graylog.plugins.views.search.searchtypes.pivot.series.Count;
import org.graylog.storage.opensearch2.views.searchtypes.OSGeneratedQueryContext;
import org.graylog.storage.opensearch2.views.searchtypes.pivot.OSPivot;
import org.graylog.storage.opensearch2.views.searchtypes.pivot.OSPivotSeriesSpecHandler;
import org.jooq.lambda.tuple.Tuple2;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.search.aggregations.*;
import org.opensearch.search.aggregations.bucket.MultiBucketsAggregation;
import org.opensearch.search.aggregations.metrics.ValueCount;
import org.opensearch.search.aggregations.metrics.ValueCountAggregationBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

public class OSCountHandler extends OSPivotSeriesSpecHandler<Count, ValueCount> {
    private static final Logger LOG = LoggerFactory.getLogger(OSCountHandler.class);

    @Nonnull
    @Override
    public Optional<AggregationBuilder> doCreateAggregation(String name, Pivot pivot, Count count, OSPivot searchTypeHandler, OSGeneratedQueryContext queryContext) {
        final String field = count.field();
        if (field == null) {
            // doc_count is always present in elasticsearch's bucket aggregations, no need to add it
            return Optional.empty();
        } else {
            // the request was for a field count, we have to add a value_count sub aggregation
            final ValueCountAggregationBuilder value = AggregationBuilders.count(name).field(field);
            record(queryContext, pivot, count, name, ValueCount.class);
            return Optional.of(value);
        }
    }

    @Override
    public Stream<Value> doHandleResult(Pivot pivot,
                                        Count count,
                                        SearchResponse searchResult,
                                        ValueCount valueCount,
                                        OSPivot searchTypeHandler,
                                        OSGeneratedQueryContext esGeneratedQueryContext) {
        final Object value;
        if (valueCount == null) {
            LOG.error("Unexpected null aggregation result, returning 0 for the count. This is a bug.");
            value = 0;
        } else if (valueCount instanceof MultiBucketsAggregation.Bucket) {
            value = ((MultiBucketsAggregation.Bucket) valueCount).getDocCount();
        } else if (valueCount instanceof Aggregations) {
            value = searchResult.getHits().getTotalHits().value;
        } else {
            value = valueCount.getValue();
        }
        return Stream.of(Value.create(count.id(), Count.NAME, value));
    }

    @Override
    protected Aggregation extractAggregationFromResult(Pivot pivot, PivotSpec spec, HasAggregations aggregations, OSGeneratedQueryContext queryContext) {
        final Tuple2<String, Class<? extends Aggregation>> objects = aggTypes(queryContext, pivot).getTypes(spec);
        if (objects == null) {
            if (aggregations instanceof MultiBucketsAggregation.Bucket) {
                return createValueCount((MultiBucketsAggregation.Bucket) aggregations);
            }
        } else {
            // try to saved sub aggregation type. this might fail if we refer to the total result of the entire result instead of a specific
            // value_count aggregation. we'll handle that special case in doHandleResult above
            return aggregations.getAggregations().get(objects.v1);
        }

        return null;
    }

    private Aggregation createValueCount(MultiBucketsAggregation.Bucket aggregations) {
        final Long docCount = aggregations.getDocCount();
        return new ValueCount() {
            @Override
            public long getValue() {
                return docCount;
            }

            @Override
            public double value() {
                return docCount;
            }

            @Override
            public String getValueAsString() {
                return docCount.toString();
            }

            @Override
            public String getName() {
                return null;
            }

            @Override
            public String getType() {
                return null;
            }

            @Override
            public Map<String, Object> getMetadata() {
                return null;
            }

            @Override
            public XContentBuilder toXContent(XContentBuilder xContentBuilder, Params params) throws IOException {
                return null;
            }
        };
    }
}

