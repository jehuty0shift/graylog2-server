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
package org.graylog.storage.opensearch2;

import com.google.inject.Scopes;
import com.google.inject.TypeLiteral;
import com.google.inject.assistedinject.FactoryModuleBuilder;
import com.google.inject.binder.LinkedBindingBuilder;
import com.google.inject.binder.ScopedBindingBuilder;
import com.google.inject.multibindings.MapBinder;
import org.graylog.plugins.views.ViewsModule;
import org.graylog.plugins.views.search.SearchType;
import org.graylog.plugins.views.search.engine.GeneratedQueryContext;
import org.graylog.plugins.views.search.engine.QueryBackend;
import org.graylog.plugins.views.search.export.ExportBackend;
import org.graylog.plugins.views.search.searchtypes.MessageList;
import org.graylog.plugins.views.search.searchtypes.events.EventList;
import org.graylog.plugins.views.search.searchtypes.pivot.BucketSpec;
import org.graylog.plugins.views.search.searchtypes.pivot.Pivot;
import org.graylog.plugins.views.search.searchtypes.pivot.SeriesSpec;
import org.graylog.plugins.views.search.searchtypes.pivot.buckets.DateRangeBucket;
import org.graylog.plugins.views.search.searchtypes.pivot.buckets.Time;
import org.graylog.plugins.views.search.searchtypes.pivot.buckets.Values;
import org.graylog.plugins.views.search.searchtypes.pivot.series.*;
import org.graylog.storage.opensearch2.views.export.OpensearchExportBackend;
import org.graylog.storage.opensearch2.views.export.RequestStrategy;
import org.graylog.storage.opensearch2.views.searchtypes.OSGeneratedQueryContext;
import org.graylog.storage.opensearch2.views.searchtypes.OpensearchBackend;
import org.graylog.storage.opensearch2.views.searchtypes.pivot.*;
import org.graylog.storage.opensearch2.views.searchtypes.pivot.buckets.OSDateRangeHandler;
import org.graylog.storage.opensearch2.views.searchtypes.pivot.buckets.OSTimeHandler;
import org.graylog.storage.opensearch2.views.searchtypes.pivot.buckets.OSValuesHandler;
import org.graylog.storage.opensearch2.views.searchtypes.pivot.series.*;
import org.graylog2.plugin.BackendVersion;
import org.opensearch.search.aggregations.Aggregation;

public class ViewsESBackendModule extends ViewsModule {
    @Override
    protected void configure() {
        install(new FactoryModuleBuilder().build(OSGeneratedQueryContext.Factory.class));

        bindForVersion(BackendVersion.fromOS(Opensearch2Plugin.SUPPORTED_ES_VERSION), new TypeLiteral<QueryBackend<? extends GeneratedQueryContext>>() {})
                .to(OpensearchBackend.class);

        registerESSearchTypeHandler(MessageList.NAME, OSMessageList.class);
        registerESSearchTypeHandler(EventList.NAME, OSEventList.class);
        registerESSearchTypeHandler(Pivot.NAME, OSPivot.class).in(Scopes.SINGLETON);

        registerPivotSeriesHandler(Average.NAME, OSAverageHandler.class);
        registerPivotSeriesHandler(Cardinality.NAME, OSCardinalityHandler.class);
        registerPivotSeriesHandler(Count.NAME, OSCountHandler.class);
        registerPivotSeriesHandler(Max.NAME, OSMaxHandler.class);
        registerPivotSeriesHandler(Min.NAME, OSMinHandler.class);
        registerPivotSeriesHandler(StdDev.NAME, OSStdDevHandler.class);
        registerPivotSeriesHandler(Sum.NAME, OSSumHandler.class);
        registerPivotSeriesHandler(SumOfSquares.NAME, OSSumOfSquaresHandler.class);
        registerPivotSeriesHandler(Variance.NAME, OSVarianceHandler.class);
        registerPivotSeriesHandler(Percentile.NAME, OSPercentilesHandler.class);

        registerPivotBucketHandler(Values.NAME, OSValuesHandler.class);
        registerPivotBucketHandler(Time.NAME, OSTimeHandler.class);
        registerPivotBucketHandler(DateRangeBucket.NAME, OSDateRangeHandler.class);

        bindExportBackend().to(OpensearchExportBackend.class);
        bindRequestStrategy().to(org.graylog.storage.opensearch2.views.export.SearchAfter.class);
    }

    private LinkedBindingBuilder<RequestStrategy> bindRequestStrategy() {
        return bind(RequestStrategy.class);
    }

    private LinkedBindingBuilder<ExportBackend> bindExportBackend() {
        return bindExportBackend(Opensearch2Plugin.SUPPORTED_ES_VERSION);
    }

    private MapBinder<String, OSPivotBucketSpecHandler<? extends BucketSpec, ? extends Aggregation>> pivotBucketHandlerBinder() {
        return MapBinder.newMapBinder(binder(),
                TypeLiteral.get(String.class),
                new TypeLiteral<OSPivotBucketSpecHandler<? extends BucketSpec, ? extends Aggregation>>() {});

    }

    private void registerPivotBucketHandler(
            String name,
            Class<? extends OSPivotBucketSpecHandler<? extends BucketSpec, ? extends Aggregation>> implementation
    ) {
        pivotBucketHandlerBinder().addBinding(name).to(implementation);
    }

    protected MapBinder<String, OSPivotSeriesSpecHandler<? extends SeriesSpec, ? extends Aggregation>> pivotSeriesHandlerBinder() {
        return MapBinder.newMapBinder(binder(),
                TypeLiteral.get(String.class),
                new TypeLiteral<>() {
                });

    }

    private void registerPivotSeriesHandler(
            String name,
            Class<? extends OSPivotSeriesSpecHandler<? extends SeriesSpec, ? extends Aggregation>> implementation
    ) {
        pivotSeriesHandlerBinder().addBinding(name).to(implementation);
    }

    private MapBinder<String, OSSearchTypeHandler<? extends SearchType>> esSearchTypeHandlerBinder() {
        return MapBinder.newMapBinder(binder(),
                TypeLiteral.get(String.class),
                new TypeLiteral<>() {
                });
    }

    private ScopedBindingBuilder registerESSearchTypeHandler(String name, Class<? extends OSSearchTypeHandler<? extends SearchType>> implementation) {
        return esSearchTypeHandlerBinder().addBinding(name).to(implementation);
    }
}
