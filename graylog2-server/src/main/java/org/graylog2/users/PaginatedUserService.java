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
package org.graylog2.users;

import com.mongodb.client.model.Filters;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.PaginatedDbService;
import org.graylog2.database.PaginatedList;
import org.graylog2.search.SearchQuery;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkArgument;
import static org.apache.http.util.TextUtils.isBlank;

@Singleton
public class PaginatedUserService extends PaginatedDbService<UserOverviewDTO> {
    private static final String COLLECTION_NAME = "users";

    @Inject
    public PaginatedUserService(MongoConnection mongoConnection,
                                MongoJackObjectMapperProvider mapper) {
        super(mongoConnection, mapper, UserOverviewDTO.class, COLLECTION_NAME);
    }

    public long count() {
        return db.countDocuments();
    }

    public PaginatedList<UserOverviewDTO> findPaginated(SearchQuery searchQuery, int page,
                                                        int perPage, String sortField, String order) {
        final Bson dbQuery = searchQuery.toDBQuery();
        final Bson sortBuilder = getSortBuilder(order, sortField);
        return findPaginatedWithQueryAndSort(dbQuery, sortBuilder, page, perPage);
    }

    public PaginatedList<UserOverviewDTO> findPaginatedByUserId(SearchQuery searchQuery, int page,
                                                                int perPage, String sortField, String order,
                                                                Set<String> userIds) {
        final Bson dbQuery = Filters.and(searchQuery.toDBQuery(),
                Filters.in("_id", userIds.stream().map(ObjectId::new).collect(Collectors.toList())));
        final Bson sortBuilder = getSortBuilder(order, sortField);
        return findPaginatedWithQueryAndSort(dbQuery, sortBuilder, page, perPage);
    }

    public PaginatedList<UserOverviewDTO> findPaginatedByRole(SearchQuery searchQuery, int page,
                                                              int perPage, String sortField, String order,
                                                              Set<String> roleIds) {
        final Bson dbQuery = Filters.and(searchQuery.toDBQuery(),
                Filters.in(UserImpl.ROLES, roleIds));
        final Bson sortBuilder = getSortBuilder(order, sortField);
        return findPaginatedWithQueryAndSort(dbQuery, sortBuilder, page, perPage);
    }

    public PaginatedList<UserOverviewDTO> findPaginatedByAuthServiceBackend(SearchQuery searchQuery,
                                                                            int page,
                                                                            int perPage,
                                                                            String sortField,
                                                                            String order,
                                                                            String authServiceBackendId) {
        checkArgument(!isBlank(authServiceBackendId), "authServiceBackendId cannot be blank");

        final Bson query = Filters.and(
                Filters.eq(UserImpl.AUTH_SERVICE_ID, Optional.of(authServiceBackendId)),
                searchQuery.toDBQuery()
        );
        return findPaginatedWithQueryAndSort(query, getSortBuilder(order, sortField), page, perPage);
    }
}
