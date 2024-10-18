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
package org.graylog2.lookup.db;

import com.google.common.collect.ImmutableList;
import com.mongodb.BasicDBObject;
import com.mongodb.client.FindIterable;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.result.UpdateResult;
import org.bson.UuidRepresentation;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.PaginatedList;
import org.graylog2.events.ClusterEventBus;
import org.graylog2.lookup.dto.LookupTableDto;
import org.graylog2.lookup.events.LookupTablesDeleted;
import org.graylog2.lookup.events.LookupTablesUpdated;
import org.mongojack.JacksonMongoCollection;

import javax.inject.Inject;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class DBLookupTableService {
    private final JacksonMongoCollection<LookupTableDto> db;
    private final ClusterEventBus clusterEventBus;

    @Inject
    public DBLookupTableService(MongoConnection mongoConnection,
                                MongoJackObjectMapperProvider mapper,
                                ClusterEventBus clusterEventBus) {
        this.db = JacksonMongoCollection.builder().withObjectMapper(mapper.get()).build(mongoConnection.getMongoDatabase(), "lut_tables",
                LookupTableDto.class,
                UuidRepresentation.STANDARD);

        this.clusterEventBus = clusterEventBus;

        db.createIndex(new BasicDBObject("name", 1), new IndexOptions().unique(true));
    }

    public Optional<LookupTableDto> get(String idOrName) {
        try {
            return Optional.ofNullable(db.findOneById(new ObjectId(idOrName)));
        } catch (IllegalArgumentException e) {
            // not an ObjectId, try again with name
            return Optional.ofNullable(db.findOne(Filters.eq("name", idOrName)));

        }
    }

    public LookupTableDto save(LookupTableDto table) {
        UpdateResult save = db.save(table);
        final LookupTableDto savedLookupTable = db.findOneById(save.getUpsertedId());

        clusterEventBus.post(LookupTablesUpdated.create(savedLookupTable));

        return savedLookupTable;
    }

    public Collection<LookupTableDto> findAll() {
        return Collections.unmodifiableList(db.find().into(new ArrayList<>()));
    }

    public Collection<LookupTableDto> findByNames(Collection<String> names) {
        final Bson query = Filters.in("name", names);
        final FindIterable<LookupTableDto> dbCursor = db.find(query);
        return Collections.unmodifiableList(dbCursor.into(new ArrayList<>()));
    }

    public PaginatedList<LookupTableDto> findPaginated(Bson query, Bson sort, int page, int perPage) {
        List<LookupTableDto> paginated = db.find(query)
                .sort(sort)
                .limit(perPage)
                .skip(perPage * Math.max(0, page - 1)).into(new ArrayList<>());
        return new PaginatedList<>(Collections.unmodifiableList(paginated), paginated.size(), page, perPage);
    }

    public Collection<LookupTableDto> findByCacheIds(Collection<String> cacheIds) {
        final Bson query = Filters.in("cache", cacheIds.stream().map(ObjectId::new).collect(Collectors.toList()));
        return Collections.unmodifiableList(db.find(query).into(new ArrayList<>()));
    }

    public Collection<LookupTableDto> findByDataAdapterIds(Collection<String> dataAdapterIds) {
        final Bson query = Filters.in("data_adapter", dataAdapterIds.stream().map(ObjectId::new).collect(Collectors.toList()));
        return Collections.unmodifiableCollection(db.find(query).into(new ArrayList<>()));
    }

    public void delete(String idOrName) {
        final Optional<LookupTableDto> lookupTableDto = get(idOrName);
        lookupTableDto
                .map(LookupTableDto::id)
                .map(ObjectId::new)
                .ifPresent(db::removeById);
        lookupTableDto.ifPresent(lookupTable -> clusterEventBus.post(LookupTablesDeleted.create(lookupTable)));
    }

    public void forEach(Consumer<? super LookupTableDto> action) {
        db.find().forEach(action);
    }
}
