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
package org.graylog.plugins.sidecar.services;

import com.mongodb.client.model.Filters;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.graylog.plugins.sidecar.rest.models.Collector;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.PaginatedDbService;
import org.graylog2.database.PaginatedList;
import org.graylog2.search.SearchQuery;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Singleton
public class CollectorService extends PaginatedDbService<Collector> {
    public static final String COLLECTION_NAME = "sidecar_collectors";

    @Inject
    public CollectorService(MongoConnection mongoConnection,
                            MongoJackObjectMapperProvider mapper) {
        super(mongoConnection, mapper, Collector.class, COLLECTION_NAME);
    }

    @Nullable
    public Collector find(String id) {
        return db.findOne(Filters.eq("_id", new ObjectId(id)));
    }

    @Nullable
    public Collector findByName(String name) {
        return db.findOne(Filters.eq("name", name));
    }

    @Nullable
    public Collector findByNameAndOs(String name, String operatingSystem) {
        return db.findOne(
                Filters.and(
                        Filters.eq("name", name),
                        Filters.eq("node_operating_system", operatingSystem))
        );
    }

    @Nullable
    public Collector findByNameExcludeId(String name, String id) {
        return db.findOne(
                Filters.and(
                    Filters.eq("name", name),
                    Filters.ne("_id", new ObjectId(id)))
        );
    }

    public long count() {
        return db.countDocuments();
    }

    public List<Collector> allFilter(Predicate<Collector> filter) {
        try (final Stream<Collector> collectorsStream = streamAll()) {
            final Stream<Collector> filteredStream = filter == null ? collectorsStream : collectorsStream.filter(filter);
            return filteredStream.collect(Collectors.toList());
        }
    }

    public List<Collector> all() {
        return allFilter(null);
    }

    public PaginatedList<Collector> findPaginated(SearchQuery searchQuery, int page, int perPage, String sortField, String order) {
        final Bson dbQuery = searchQuery.toDBQuery();
        final Bson sortBuilder = getSortBuilder(order, sortField);
        return findPaginatedWithQueryAndSort(dbQuery, sortBuilder, page, perPage);
    }

    public Collector fromRequest(Collector request) {
        return Collector.create(
                null,
                request.name(),
                request.serviceType(),
                request.nodeOperatingSystem(),
                request.executablePath(),
                request.executeParameters(),
                request.validationParameters(),
                request.defaultTemplate());
    }

    public Collector fromRequest(String id, Collector request) {
        final Collector collector = fromRequest(request);
        return collector.toBuilder()
                .id(id)
                .build();
    }

    @Nullable
    public Collector copy(String id, String name) {
        Collector collector = find(id);
        return collector == null ? null : collector.toBuilder()
                .id(null)
                .name(name)
                .build();
    }
}
