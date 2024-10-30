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

import com.mongodb.BasicDBObject;
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
import org.graylog2.lookup.dto.CacheDto;
import org.graylog2.lookup.events.CachesDeleted;
import org.graylog2.lookup.events.CachesUpdated;
import org.mongojack.JacksonMongoCollection;

import javax.inject.Inject;
import java.util.*;
import java.util.stream.Collectors;

public class DBCacheService {
    private final JacksonMongoCollection<CacheDto> db;
    private final ClusterEventBus clusterEventBus;

    @Inject
    public DBCacheService(MongoConnection mongoConnection,
                          MongoJackObjectMapperProvider mapper,
                          ClusterEventBus clusterEventBus) {

        this.db = JacksonMongoCollection.builder().withObjectMapper(mapper.get()).build(mongoConnection.getMongoDatabase(), "lut_caches",
                CacheDto.class,
                UuidRepresentation.STANDARD);
        this.clusterEventBus = clusterEventBus;

        db.createIndex(new BasicDBObject("name", 1), new IndexOptions().unique(true));
    }

    public Optional<CacheDto> get(String idOrName) {
        try {
            return Optional.ofNullable(db.findOneById(new ObjectId(idOrName)));
        } catch (IllegalArgumentException e) {
            // not an ObjectId, try again with name
            return Optional.ofNullable(db.findOne(Filters.eq("name", idOrName)));
        }
    }

    public CacheDto save(CacheDto table) {
        UpdateResult save = db.save(table);
        final CacheDto savedCache = db.findOneById(save.getUpsertedId());
        clusterEventBus.post(CachesUpdated.create(savedCache.id()));

        return savedCache;
    }

    public PaginatedList<CacheDto> findPaginated(Bson query, Bson sort, int page, int perPage) {
        List<CacheDto> paginated = db.find(query)
                .sort(sort)
                .limit(perPage)
                .skip(perPage * Math.max(0, page - 1)).into(new ArrayList<>());
        return new PaginatedList<>(Collections.unmodifiableList(paginated), paginated.size(), page, perPage);
    }


    public void delete(String idOrName) {
        final Optional<CacheDto> cacheDto = get(idOrName);
        cacheDto.map(CacheDto::id)
                .map(ObjectId::new)
                .ifPresent(db::removeById);
        cacheDto.ifPresent(cache -> clusterEventBus.post(CachesDeleted.create(cache.id())));
    }

    public Collection<CacheDto> findByIds(Set<String> idSet) {
        final Bson query = Filters.in("_id", idSet.stream().map(ObjectId::new).collect(Collectors.toList()));
        return Collections.unmodifiableList(db.find(query).into(new ArrayList<>()));
    }

    public Collection<CacheDto> findAll() {
        return Collections.unmodifiableList(db.find().into(new ArrayList<>()));
    }
}
