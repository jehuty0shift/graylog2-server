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
package org.graylog2.streams;

import org.bson.conversions.Bson;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.PaginatedDbService;
import org.graylog2.database.PaginatedList;
import org.graylog2.search.SearchQuery;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.function.Predicate;

@Singleton
public class PaginatedStreamService extends PaginatedDbService<StreamDTO> {
    private static final String COLLECTION_NAME = "streams";

    @Inject
    public PaginatedStreamService(MongoConnection mongoConnection,
                                  MongoJackObjectMapperProvider mapper)
    {
        super(mongoConnection, mapper, StreamDTO.class, COLLECTION_NAME);
    }

    public long count() {
        return db.countDocuments();
    }

    public PaginatedList<StreamDTO> findPaginated(SearchQuery searchQuery, Predicate<StreamDTO> filter, int page,
                                                  int perPage, String sortField, String order) {
        final Bson dbQuery = searchQuery.toDBQuery();
        final Bson sortBuilder = getSortBuilder(order, sortField);
        return findPaginatedWithQueryFilterAndSort(dbQuery, filter, sortBuilder, page, perPage);
    }
}
