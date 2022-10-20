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
import org.graylog.plugins.views.search.searchtypes.pivot.series.Percentile;
import org.graylog.storage.opensearch2.views.searchtypes.OSGeneratedQueryContext;
import org.graylog.storage.opensearch2.views.searchtypes.pivot.OSPivot;
import org.graylog.storage.opensearch2.views.searchtypes.pivot.OSPivotSeriesSpecHandler;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.search.aggregations.AggregationBuilder;
import org.opensearch.search.aggregations.AggregationBuilders;
import org.opensearch.search.aggregations.metrics.Percentiles;
import org.opensearch.search.aggregations.metrics.PercentilesAggregationBuilder;

import javax.annotation.Nonnull;
import java.util.Optional;
import java.util.stream.Stream;

public class OSPercentilesHandler extends OSPivotSeriesSpecHandler<Percentile, Percentiles> {
    @Nonnull
    @Override
    public Optional<AggregationBuilder> doCreateAggregation(String name, Pivot pivot, Percentile percentileSpec, OSPivot searchTypeHandler, OSGeneratedQueryContext queryContext) {
        final PercentilesAggregationBuilder percentiles = AggregationBuilders.percentiles(name).field(percentileSpec.field()).percentiles(percentileSpec.percentile());
        record(queryContext, pivot, percentileSpec, name, Percentiles.class);
        return Optional.of(percentiles);
    }

    @Override
    public Stream<Value> doHandleResult(Pivot pivot,
                                        Percentile pivotSpec,
                                        SearchResponse searchResult,
                                        Percentiles percentilesAggregation,
                                        OSPivot searchTypeHandler,
                                        OSGeneratedQueryContext queryContext) {
        Double percentile = percentilesAggregation.percentile(pivotSpec.percentile());
        return Stream.of(OSPivotSeriesSpecHandler.Value.create(pivotSpec.id(), Percentile.NAME, percentile));
    }
}
