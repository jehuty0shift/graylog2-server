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
package org.graylog.storage.opensearch2.views.searchtypes.pivot.buckets;

import org.graylog.plugins.views.search.Query;
import org.graylog.plugins.views.search.searchtypes.pivot.*;
import org.graylog.plugins.views.search.searchtypes.pivot.buckets.Time;
import org.graylog.storage.opensearch2.views.searchtypes.OSGeneratedQueryContext;
import org.graylog.storage.opensearch2.views.searchtypes.pivot.OSPivot;
import org.graylog.storage.opensearch2.views.searchtypes.pivot.OSPivotBucketSpecHandler;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.search.aggregations.AggregationBuilder;
import org.opensearch.search.aggregations.AggregationBuilders;
import org.opensearch.search.aggregations.BucketOrder;
import org.opensearch.search.aggregations.bucket.histogram.DateHistogramAggregationBuilder;
import org.opensearch.search.aggregations.bucket.histogram.DateHistogramInterval;
import org.opensearch.search.aggregations.bucket.histogram.ParsedDateHistogram;

import javax.annotation.Nonnull;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

public class OSTimeHandler extends OSPivotBucketSpecHandler<Time, ParsedDateHistogram> {
    @Nonnull
    @Override
    public Optional<AggregationBuilder> doCreateAggregation(String name, Pivot pivot, Time timeSpec, OSPivot searchTypeHandler, OSGeneratedQueryContext esGeneratedQueryContext, Query query) {
        final DateHistogramInterval dateHistogramInterval = new DateHistogramInterval(timeSpec.interval().toDateInterval(query.effectiveTimeRange(pivot)).toString());
        final Optional<BucketOrder> ordering = orderForPivot(pivot, timeSpec, esGeneratedQueryContext);
        final DateHistogramAggregationBuilder builder = AggregationBuilders.dateHistogram(name)
                .field(timeSpec.field())
                .order(ordering.orElse(BucketOrder.key(true)))
                .format("date_time");

        setInterval(builder, dateHistogramInterval);
        record(esGeneratedQueryContext, pivot, timeSpec, name, ParsedDateHistogram.class);

        return Optional.of(builder);
    }

    private void setInterval(DateHistogramAggregationBuilder builder, DateHistogramInterval interval) {
        if (DateHistogramAggregationBuilder.DATE_FIELD_UNITS.get(interval.toString()) != null) {
            builder.calendarInterval(interval);
        } else {
            builder.fixedInterval(interval);
        }
    }


    private Optional<BucketOrder> orderForPivot(Pivot pivot, Time timeSpec, OSGeneratedQueryContext esGeneratedQueryContext) {
        return pivot.sort()
                .stream()
                .map(sortSpec -> {
                    if (sortSpec instanceof PivotSort && timeSpec.field().equals(sortSpec.field())) {
                        return sortSpec.direction().equals(SortSpec.Direction.Ascending) ? BucketOrder.key(true) : BucketOrder.key(false);
                    }
                    if (sortSpec instanceof SeriesSort) {
                        final Optional<SeriesSpec> matchingSeriesSpec = pivot.series()
                                .stream()
                                .filter(series -> series.literal().equals(sortSpec.field()))
                                .findFirst();
                        return matchingSeriesSpec
                                .map(seriesSpec -> {
                                    if (seriesSpec.literal().equals("count()")) {
                                        return sortSpec.direction().equals(SortSpec.Direction.Ascending) ? BucketOrder.count(true) : BucketOrder.count(false);
                                    }
                                    return BucketOrder.aggregation(esGeneratedQueryContext.seriesName(seriesSpec, pivot), sortSpec.direction().equals(SortSpec.Direction.Ascending));
                                })
                                .orElse(null);
                    }

                    return null;
                })
                .filter(Objects::nonNull)
                .findFirst();
    }

    @Override
    public Stream<Bucket> doHandleResult(Pivot pivot,
                                         Time bucketSpec,
                                         SearchResponse searchResult,
                                         ParsedDateHistogram dateHistogramAggregation,
                                         OSPivot searchTypeHandler,
                                         OSGeneratedQueryContext esGeneratedQueryContext) {
        return dateHistogramAggregation.getBuckets().stream()
                .map(dateHistogram -> Bucket.create(dateHistogram.getKeyAsString(), dateHistogram));
    }
}
