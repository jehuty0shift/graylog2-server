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
package org.graylog.scheduler;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Sorts;
import one.util.streamex.StreamEx;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.PaginatedDbService;
import org.graylog2.database.PaginatedList;

import javax.inject.Inject;
import java.util.*;
import java.util.function.Function;

public class DBJobDefinitionService extends PaginatedDbService<JobDefinitionDto> {
    private static final String COLLECTION_NAME = "scheduler_job_definitions";

    private final ObjectMapper objectMapper;

    @Inject
    public DBJobDefinitionService(MongoConnection mongoConnection, MongoJackObjectMapperProvider mapper) {
        super(mongoConnection, mapper, JobDefinitionDto.class, COLLECTION_NAME);
        this.objectMapper = mapper.get();
    }

    public PaginatedList<JobDefinitionDto> getAllPaginated(String sortByField, int page, int perPage) {
        return findPaginatedWithQueryAndSort(Filters.empty(), Sorts.ascending(sortByField), page, perPage);
    }

    /**
     * Returns the job definition that has the given config field value.
     *
     * @param configField the config field
     * @param value       the value of the config field
     * @return the job definition with the given config field, or an empty optional
     */
    public Optional<JobDefinitionDto> getByConfigField(String configField, Object value) {
        final String field = String.format(Locale.US, "%s.%s", JobDefinitionDto.FIELD_CONFIG, configField);
        return Optional.ofNullable(db.findOne(Filters.eq(field, value)));
    }

    /**
     * Returns all job definitions that have the given config field values, grouped by config field value.
     *
     * @param configField the config field
     * @param values      the values of the config field
     * @return the job definitions grouped by the given values
     */
    public Map<String, List<JobDefinitionDto>> getAllByConfigField(String configField, Collection<? extends Object> values) {
        final String field = String.format(Locale.US, "%s.%s", JobDefinitionDto.FIELD_CONFIG, configField);

        return StreamEx.of(db.find(Filters.in(field, values)).spliterator()).groupingBy(configFieldGroup(configField));
    }

    private Function<JobDefinitionDto, String> configFieldGroup(final String key) {
        // Since JobDefinitionDto#config() is a pluggable interface type and we don't have methods we can access,
        // convert the value to a JsonNode and access the group key with that.
        return jobDefinition -> objectMapper.convertValue(jobDefinition.config(), JsonNode.class).path(key).asText();
    }
}
