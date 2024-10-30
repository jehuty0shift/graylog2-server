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
package org.graylog.plugins.views.search.db;

import com.google.common.collect.Streams;
import com.mongodb.BasicDBObject;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.ReplaceOptions;
import com.mongodb.client.result.InsertOneResult;
import org.bson.UuidRepresentation;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.graylog.plugins.views.search.Search;
import org.graylog.plugins.views.search.SearchRequirements;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.PaginatedList;
import org.mongojack.JacksonMongoCollection;

import javax.inject.Inject;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This class is a helper to implement a basic Mongojack-based database service that allows CRUD operations on a single DTO type.
 *
 * <p>
 * Subclasses can add more sophisticated search methods by access the protected "db" property.<br/>
 * Indices can be added in the constructor.
 * </p>
 */
public class SearchDbService {
    protected final JacksonMongoCollection<Search> db;
    private final SearchRequirements.Factory searchRequirementsFactory;

    @Inject
    protected SearchDbService(MongoConnection mongoConnection,
                              MongoJackObjectMapperProvider mapper,
                              SearchRequirements.Factory searchRequirementsFactory) {
        this.searchRequirementsFactory = searchRequirementsFactory;
        db = JacksonMongoCollection.builder().withObjectMapper(mapper.get()).build(mongoConnection.getMongoDatabase(), "searches",Search.class, UuidRepresentation.STANDARD);
        db.createIndex(new BasicDBObject("created_at", 1), new IndexOptions().unique(false));
    }

    public Optional<Search> get(String id) {
        return Optional.ofNullable(db.findOneById(new ObjectId(id)))
                .map(this::requirementsForSearch);
    }

    public Search save(Search search) {
        final Search searchToSave = requirementsForSearch(search);
        if (searchToSave.id() != null) {
            db.replaceOne(Filters.eq("_id", new ObjectId(search.id())),
                    searchToSave,new ReplaceOptions().upsert(true));

            return searchToSave;
        }

        final InsertOneResult save = db.insertOne(searchToSave);
        return db.findOne(Filters.eq("_id", save.getInsertedId()));
    }

    public PaginatedList<Search> findPaginated(Bson search, Bson sort, int page, int perPage) {

        final List<Search> paginated = db.find(search)
                .sort(sort)
                .limit(perPage)
                .skip(perPage * Math.max(0, page - 1)).into(new ArrayList<>());

        return new PaginatedList<>(
                Collections.unmodifiableList(paginated),
                paginated.size(),
                page,
                perPage
        );
    }

    public void delete(String id) {
        db.removeById(new ObjectId(id));
    }

    public Collection<Search> findByIds(Set<String> idSet) {
        return Collections.unmodifiableList(db.find(Filters.in("_id", idSet.stream().map(ObjectId::new).collect(Collectors.toList()))).into(new ArrayList<>()));
    }

    public Stream<Search> streamAll() {
        return Streams.stream(db.find()).map(this::requirementsForSearch);
    }

    private Search requirementsForSearch(Search search) {
        return searchRequirementsFactory.create(search)
                .rebuildRequirements(Search::requires, (s, newRequirements) -> s.toBuilder().requires(newRequirements).build());
    }
}
