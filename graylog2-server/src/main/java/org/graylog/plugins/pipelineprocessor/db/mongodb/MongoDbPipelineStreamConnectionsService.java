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
package org.graylog.plugins.pipelineprocessor.db.mongodb;

import com.mongodb.BasicDBObject;
import com.mongodb.MongoException;
import com.mongodb.client.FindIterable;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Sorts;
import com.mongodb.client.result.UpdateResult;
import org.bson.UuidRepresentation;
import org.bson.conversions.Bson;
import org.graylog.plugins.pipelineprocessor.db.PipelineStreamConnectionsService;
import org.graylog.plugins.pipelineprocessor.events.PipelineConnectionsChangedEvent;
import org.graylog.plugins.pipelineprocessor.rest.PipelineConnections;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.NotFoundException;
import org.graylog2.events.ClusterEventBus;
import org.mongojack.JacksonMongoCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class MongoDbPipelineStreamConnectionsService implements PipelineStreamConnectionsService {
    private static final Logger log = LoggerFactory.getLogger(MongoDbPipelineStreamConnectionsService.class);

    private static final String COLLECTION = "pipeline_processor_pipelines_streams";
    private static final String STREAM_ID_KEY = "stream_id";

    private final JacksonMongoCollection<PipelineConnections> dbCollection;
    private final ClusterEventBus clusterBus;

    @Inject
    public MongoDbPipelineStreamConnectionsService(MongoConnection mongoConnection,
                                                   MongoJackObjectMapperProvider mapper,
                                                   ClusterEventBus clusterBus) {
        this.dbCollection = JacksonMongoCollection.builder().withObjectMapper(mapper.get()).build(
                mongoConnection.getMongoDatabase(), COLLECTION,
                PipelineConnections.class,
                UuidRepresentation.STANDARD);
        this.clusterBus = clusterBus;
        dbCollection.createIndex(Sorts.ascending(STREAM_ID_KEY), new IndexOptions().unique(true));
    }

    @Override
    public PipelineConnections save(PipelineConnections connections) {
        PipelineConnections existingConnections = dbCollection.findOne(Filters.eq(STREAM_ID_KEY, connections.streamId()));
        if (existingConnections == null) {
            existingConnections = PipelineConnections.create(null, connections.streamId(), Collections.emptySet());
        }

        final PipelineConnections toSave = existingConnections.toBuilder()
                .pipelineIds(connections.pipelineIds()).build();
        final UpdateResult save = dbCollection.save(toSave);

        final PipelineConnections savedConnections = dbCollection.findOneById(save.getUpsertedId());
        clusterBus.post(PipelineConnectionsChangedEvent.create(savedConnections.streamId(), savedConnections.pipelineIds()));

        return savedConnections;
    }

    @Override
    public PipelineConnections load(String streamId) throws NotFoundException {
        final PipelineConnections oneById = dbCollection.findOne(Filters.eq(STREAM_ID_KEY, streamId));
        if (oneById == null) {
            throw new NotFoundException("No pipeline connections with for stream " + streamId);
        }
        return oneById;
    }

    @Override
    public Set<PipelineConnections> loadAll() {
        try {
            FindIterable<PipelineConnections> connections = dbCollection.find();
            return Collections.unmodifiableSet(connections.into(new HashSet<>()));
        } catch (MongoException e) {
            log.error("Unable to load pipeline connections", e);
            return Collections.emptySet();
        }
    }

    @Override
    public Set<PipelineConnections> loadByPipelineId(String pipelineId) {
        // Thanks, MongoJack!
        // https://github.com/mongojack/mongojack/issues/12

        final Bson query = new BasicDBObject( "pipeline_ids", pipelineId);
        try  {
            FindIterable<PipelineConnections> pipelineConnections = dbCollection.find(query);
            return Collections.unmodifiableSet(pipelineConnections.into(new HashSet<>()));
        } catch (MongoException e) {
            log.error("Unable to load pipeline connections for pipeline ID " + pipelineId, e);
            return Collections.emptySet();
        }
    }

    @Override
    public void delete(String streamId) {
        try {
            final PipelineConnections connections = load(streamId);
            final Set<String> pipelineIds = connections.pipelineIds();

            dbCollection.removeById(connections.id());
            clusterBus.post(PipelineConnectionsChangedEvent.create(streamId, pipelineIds));
        } catch (NotFoundException e) {
            log.debug("No connections found for stream " + streamId);
        }
    }
}
