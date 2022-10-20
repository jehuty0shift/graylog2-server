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
import org.graylog.plugins.views.search.searchtypes.pivot.series.SumOfSquares;
import org.graylog.storage.opensearch2.views.searchtypes.OSGeneratedQueryContext;
import org.graylog.storage.opensearch2.views.searchtypes.pivot.OSPivot;
import org.graylog.storage.opensearch2.views.searchtypes.pivot.OSPivotSeriesSpecHandler;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.search.aggregations.AggregationBuilder;
import org.opensearch.search.aggregations.AggregationBuilders;
import org.opensearch.search.aggregations.metrics.ExtendedStats;
import org.opensearch.search.aggregations.metrics.ExtendedStatsAggregationBuilder;

import javax.annotation.Nonnull;
import java.util.Optional;
import java.util.stream.Stream;

public class OSSumOfSquaresHandler extends OSPivotSeriesSpecHandler<SumOfSquares, ExtendedStats> {
    @Nonnull
    @Override
    public Optional<AggregationBuilder> doCreateAggregation(String name, Pivot pivot, SumOfSquares sumOfSquaresSpec, OSPivot searchTypeHandler, OSGeneratedQueryContext queryContext) {
        final ExtendedStatsAggregationBuilder sumOfSquares = AggregationBuilders.extendedStats(name).field(sumOfSquaresSpec.field());
        record(queryContext, pivot, sumOfSquaresSpec, name, ExtendedStats.class);
        return Optional.of(sumOfSquares);
    }

    @Override
    public Stream<Value> doHandleResult(Pivot pivot, SumOfSquares pivotSpec,
                                        SearchResponse searchResult,
                                        ExtendedStats sumOfSquaresAggregation,
                                        OSPivot searchTypeHandler,
                                        OSGeneratedQueryContext esGeneratedQueryContext) {
        return Stream.of(OSPivotSeriesSpecHandler.Value.create(pivotSpec.id(), SumOfSquares.NAME, sumOfSquaresAggregation.getSumOfSquares()));
    }
}
