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
package org.graylog.events.processor;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableSet;
import com.mongodb.BasicDBObject;
import com.mongodb.client.model.*;
import com.mongodb.client.result.UpdateResult;
import org.bson.Document;
import org.bson.UuidRepresentation;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.MongoDBUpsertRetryer;
import org.joda.time.DateTime;
import org.mongojack.JacksonMongoCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Strings.isNullOrEmpty;
import static java.util.Objects.requireNonNull;
import static org.graylog.events.processor.EventProcessorStateDto.*;

/**
 * Manages database state for {@link EventProcessor}s.
 */
// This class does NOT use PaginatedDbService because we don't want to allow overwriting records via "save()"
// and other methods.
public class DBEventProcessorStateService {
    private static final Logger LOG = LoggerFactory.getLogger(DBEventProcessorStateService.class);
    private static final String COLLECTION_NAME = "event_processor_state";

    private final JacksonMongoCollection<EventProcessorStateDto> db;

    @Inject
    public DBEventProcessorStateService(MongoConnection mongoConnection,
                                        MongoJackObjectMapperProvider mapper) {
        this.db = JacksonMongoCollection.builder().withObjectMapper(mapper.get()).build(mongoConnection.getMongoDatabase(), COLLECTION_NAME, EventProcessorStateDto.class, UuidRepresentation.STANDARD);

        List<Document> indexes = db.listIndexes().into( new ArrayList<>());
        // There should only be one state document for each event processor.
        if (indexes.size() < 3) {
            db.createIndex(new BasicDBObject(FIELD_EVENT_DEFINITION_ID, 1), new IndexOptions().unique(true).background(true));
            db.createIndex(new BasicDBObject(FIELD_MIN_PROCESSED_TIMESTAMP, 1), new IndexOptions().background(true));
            db.createIndex(new BasicDBObject(FIELD_MAX_PROCESSED_TIMESTAMP, 1), new IndexOptions().background(true));
        }
    }

    /**
     * Loads the event processor state for the given event definition ID.
     *
     * @param eventDefinitionId the event definition ID to load the state for
     * @return filled optional with the state object if one exists, empty optional otherwise
     */
    @VisibleForTesting
    Optional<EventProcessorStateDto> findByEventDefinitionId(String eventDefinitionId) {
        checkArgument(!isNullOrEmpty(eventDefinitionId), "eventDefinitionId cannot be null or empty");

        return Optional.ofNullable(db.findOne(Filters.eq(FIELD_EVENT_DEFINITION_ID, eventDefinitionId)));
    }

    /**
     * Returns a set of event processor state objects where the event definition ID matches one of the ones in the given
     * set of IDs and the maximum processed timestamp is greater or equals the given timestamp.
     *
     * @param eventDefinitionIds set of event definition IDs
     * @param maxTimestamp       the threshold for the maximum processed timestamp
     * @return set of state objects or empty set when no object matches
     */
    public ImmutableSet<EventProcessorStateDto> findByEventDefinitionsAndMaxTimestamp(Set<String> eventDefinitionIds, DateTime maxTimestamp) {
        checkArgument(eventDefinitionIds != null && !eventDefinitionIds.isEmpty(), "eventDefinitionIds cannot be null or empty");
        checkArgument(maxTimestamp != null, "maxTimestamp cannot be null");

        final Bson query = Filters.and(
                Filters.in(FIELD_EVENT_DEFINITION_ID, eventDefinitionIds),
                Filters.gte(FIELD_MAX_PROCESSED_TIMESTAMP, maxTimestamp)
        );

        return ImmutableSet.copyOf(db.find(query).iterator());
    }

    /**
     * Creates a new or updates an existing event processor state record for the values in the given DTO.
     *
     * @param dto state DTO
     * @return the created or updated record
     */
    public Optional<EventProcessorStateDto> setState(EventProcessorStateDto dto) {
        return setState(dto.eventDefinitionId(), dto.minProcessedTimestamp(), dto.maxProcessedTimestamp());
    }

    /**
     * Creates a new or updates an existing event processor state record for the given values.
     *
     * @param eventDefinitionId     the related event definition ID
     * @param maxProcessedTimestamp the maximum processed timestamp
     * @return the created or updated record
     */
    public Optional<EventProcessorStateDto> setState(String eventDefinitionId,
                                                     DateTime minProcessedTimestamp,
                                                     DateTime maxProcessedTimestamp) {
        checkArgument(!isNullOrEmpty(eventDefinitionId), "eventDefinitionId cannot be null or empty");
        checkArgument(minProcessedTimestamp != null, "minProcessedTimestamp cannot be null");
        checkArgument(maxProcessedTimestamp != null, "maxProcessedTimestamp cannot be null");
        checkArgument(maxProcessedTimestamp.isAfter(minProcessedTimestamp), "minProcessedTimestamp must be older than maxProcessedTimestamp");

        LOG.debug("Update event processor state for <{}> with min processed timestamp of <{}> max processed timestamp of <{}>",
                eventDefinitionId, minProcessedTimestamp, maxProcessedTimestamp);

        // The state record must always keep the oldest minProcessedTimestamp and the newest maxProcessedTimestamp
        // regardless of the value min/max timestamp arguments.
        // Example: If the minProcessedTimestamp argument is newer than the value in the existing record, we don't
        // want to change it. The other way around for the maxProcessedTimestamp.
        // That's why we are using the $min and $max operations for the update query.
        final Bson update = Updates.combine(Updates.set(FIELD_EVENT_DEFINITION_ID, eventDefinitionId),
                // Our current mongojack implementation doesn't offer $min/$max helper
                Updates.min(FIELD_MIN_PROCESSED_TIMESTAMP, minProcessedTimestamp),
                Updates.max(FIELD_MAX_PROCESSED_TIMESTAMP, maxProcessedTimestamp));

        return Optional.ofNullable(MongoDBUpsertRetryer.run(() -> { UpdateResult result = db.updateOne(
                // We have a unique index on the eventDefinitionId so this query is enough
                Filters.eq(FIELD_EVENT_DEFINITION_ID, eventDefinitionId),
                update, new UpdateOptions().upsert(true));
                if (result.wasAcknowledged()) {
                    return db.findOne(Filters.eq(FIELD_EVENT_DEFINITION_ID, eventDefinitionId));
                } else {
                    return null;
                }
        }));
    }

    /**
     * Delete state objects for the given event definition ID.
     *
     * @param id the object ID to delete
     * @return the number of objects that have been deleted
     */
    public int deleteByEventDefinitionId(String id) {
        return findByEventDefinitionId(id)
                .map(dto -> (int)db.removeById(new ObjectId(requireNonNull(dto.id()))).getDeletedCount())
                .orElse(0);
    }
}
