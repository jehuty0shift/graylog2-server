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
package org.graylog.storage.opensearch2.views.searchtypes.pivot;

import org.graylog.plugins.views.search.engine.GeneratedQueryContext;
import org.graylog.plugins.views.search.engine.SearchTypeHandler;
import org.graylog.plugins.views.search.searchtypes.pivot.BucketSpec;
import org.graylog.plugins.views.search.searchtypes.pivot.BucketSpecHandler;
import org.graylog.plugins.views.search.searchtypes.pivot.Pivot;
import org.graylog.plugins.views.search.searchtypes.pivot.PivotSpec;
import org.graylog.storage.opensearch2.views.searchtypes.OSGeneratedQueryContext;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.search.aggregations.Aggregation;
import org.opensearch.search.aggregations.AggregationBuilder;
import org.opensearch.search.aggregations.HasAggregations;
import org.opensearch.search.aggregations.bucket.MultiBucketsAggregation;

import java.util.stream.Stream;

public abstract class OSPivotBucketSpecHandler<SPEC_TYPE extends BucketSpec, AGGREGATION_RESULT extends Aggregation>
        implements BucketSpecHandler<SPEC_TYPE, AggregationBuilder, SearchResponse, AGGREGATION_RESULT, OSPivot, OSGeneratedQueryContext> {

    protected OSPivot.AggTypes aggTypes(OSGeneratedQueryContext queryContext, Pivot pivot) {
        return (OSPivot.AggTypes) queryContext.contextMap().get(pivot.id());
    }

    protected void record(OSGeneratedQueryContext queryContext, Pivot pivot, PivotSpec spec, String name, Class<? extends Aggregation> aggregationClass) {
        aggTypes(queryContext, pivot).record(spec, name, aggregationClass);
    }

    protected Aggregation extractAggregationFromResult(Pivot pivot, PivotSpec spec, HasAggregations aggregations, OSGeneratedQueryContext queryContext) {
        return aggTypes(queryContext, pivot).getSubAggregation(spec, aggregations);
    }

    @SuppressWarnings("unchecked")
    @Override
    public Stream<Bucket> handleResult(Pivot pivot, BucketSpec bucketSpec, Object queryResult, Object aggregationResult, SearchTypeHandler searchTypeHandler, GeneratedQueryContext queryContext) {
        return doHandleResult(pivot, (SPEC_TYPE) bucketSpec, (SearchResponse) queryResult, (AGGREGATION_RESULT) aggregationResult, (OSPivot) searchTypeHandler, (OSGeneratedQueryContext) queryContext);
    }

    @Override
    public abstract Stream<Bucket> doHandleResult(Pivot pivot, SPEC_TYPE bucketSpec, SearchResponse searchResult, AGGREGATION_RESULT aggregation_result, OSPivot searchTypeHandler, OSGeneratedQueryContext queryContext);

    public static class Bucket {

        private final String key;
        private final MultiBucketsAggregation.Bucket bucket;

        public Bucket(String key, MultiBucketsAggregation.Bucket bucket) {
            this.key = key;
            this.bucket = bucket;
        }

        public static Bucket create(String key, MultiBucketsAggregation.Bucket aggregation) {
            return new Bucket(key, aggregation);
        }

        public String key() {
            return key;
        }

        public MultiBucketsAggregation.Bucket aggregation() {
            return bucket;
        }
    }
}
