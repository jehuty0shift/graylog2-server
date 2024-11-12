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
package org.graylog.security.authzroles;

import com.google.common.collect.ImmutableSet;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Projections;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.PaginatedDbService;
import org.graylog2.database.PaginatedList;
import org.graylog2.search.SearchQuery;
import org.graylog2.shared.users.UserService;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@Singleton
public class PaginatedAuthzRolesService extends PaginatedDbService<AuthzRoleDTO> {
    private static final String COLLECTION_NAME = "roles";

    private final MongoCollection<Document> dbCollection;
    private final UserService userService;

    @Inject
    public PaginatedAuthzRolesService(MongoConnection mongoConnection,
                                      UserService userService,
                                      MongoJackObjectMapperProvider mapper) {
        super(mongoConnection, mapper, AuthzRoleDTO.class, COLLECTION_NAME);
        this.dbCollection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME);
        this.userService = userService;
    }

    public long count() {
        return dbCollection.countDocuments();
    }

    public ImmutableSet<String> getAllRoleIds() {
        // Use a MongoCollection query here to avoid the mongojack deserializing and object creation overhead
        final FindIterable<Document> docs = dbCollection.find().projection(Projections.include("_id"));

        return StreamSupport.stream(docs.spliterator(), false)
                .map(doc -> doc.get("_id", ObjectId.class).toHexString())
                .collect(ImmutableSet.toImmutableSet());
    }

    public List<AuthzRoleDTO> findByIds(Collection<String> ids) {
        return db.find(Filters.in("_id", ids.stream().map(ObjectId::new).collect(Collectors.toList()))).into(new ArrayList<>());
    }

    public PaginatedList<AuthzRoleDTO> findPaginated(SearchQuery searchQuery, int page,
                                                     int perPage, String sortField, String order) {
        final Bson dbQuery = searchQuery.toDBQuery();
        final Bson sortBuilder = getSortBuilder(order, sortField);
        return findPaginatedWithQueryAndSort(dbQuery, sortBuilder, page, perPage);
    }

    public PaginatedList<AuthzRoleDTO> findPaginatedByIds(SearchQuery searchQuery,
                                                          int page,
                                                          int perPage,
                                                          String sortField,
                                                          String order,
                                                          Set<String> roleIds) {
        final Bson dbQuery = buildRoleIdsQuery(searchQuery, roleIds);
        final Bson sortBuilder = getSortBuilder(order, sortField);

        return findPaginatedWithQueryAndSort(dbQuery, sortBuilder, page, perPage);
    }

    public PaginatedList<AuthzRoleDTO> findPaginatedByIdsWithFilter(SearchQuery searchQuery,
                                                                    Predicate<AuthzRoleDTO> filter,
                                                                    int page,
                                                                    int perPage,
                                                                    String sortField,
                                                                    String order,
                                                                    Set<String> roleIds) {
        final Bson dbQuery = buildRoleIdsQuery(searchQuery, roleIds);
        final Bson sortBuilder = getSortBuilder(order, sortField);

        return findPaginatedWithQueryFilterAndSort(dbQuery, filter, sortBuilder, page, perPage);
    }

    @Override
    public int delete(String id) {
        final Optional<AuthzRoleDTO> role = get(id);
        final int delete = super.delete(id);
        if (delete > 0) {
            role.ifPresent(r -> userService.dissociateAllUsersFromRole(r.toLegacyRole()));
        }
        return delete;
    }

    private Bson buildRoleIdsQuery(SearchQuery searchQuery, Set<String> roleIds) {
        return Filters.and(Filters.in("_id", roleIds.stream().map(ObjectId::new).collect(Collectors.toList())), searchQuery.toDBQuery());
    }
}
