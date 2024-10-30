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

import com.mongodb.MongoException;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Sorts;
import com.mongodb.client.result.UpdateResult;
import org.bson.UuidRepresentation;
import org.bson.conversions.Bson;
import org.graylog.plugins.pipelineprocessor.db.PipelineDao;
import org.graylog.plugins.pipelineprocessor.db.PipelineService;
import org.graylog.plugins.pipelineprocessor.events.PipelinesChangedEvent;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.NotFoundException;
import org.graylog2.events.ClusterEventBus;
import org.mongojack.JacksonMongoCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;

public class MongoDbPipelineService implements PipelineService {
    private static final Logger log = LoggerFactory.getLogger(MongoDbPipelineService.class);

    private static final String COLLECTION = "pipeline_processor_pipelines";

    private final JacksonMongoCollection<PipelineDao> dbCollection;
    private final ClusterEventBus clusterBus;

    @Inject
    public MongoDbPipelineService(MongoConnection mongoConnection,
                                  MongoJackObjectMapperProvider mapper,
                                  ClusterEventBus clusterBus) {
        this.dbCollection = JacksonMongoCollection.builder().withObjectMapper(mapper.get()).build(
                mongoConnection.getMongoDatabase(), COLLECTION, PipelineDao.class, UuidRepresentation.STANDARD);
        this.clusterBus = clusterBus;
        dbCollection.createIndex(Sorts.ascending("title"), new IndexOptions().unique(true));
    }

    @Override
    public PipelineDao save(PipelineDao pipeline) {
        final UpdateResult save = dbCollection.save(pipeline);
        final PipelineDao savedPipeline = dbCollection.findOne(Filters.eq("_id",save.getUpsertedId()));

        clusterBus.post(PipelinesChangedEvent.updatedPipelineId(savedPipeline.id()));

        return savedPipeline;
    }

    @Override
    public PipelineDao load(String id) throws NotFoundException {
        final PipelineDao pipeline = dbCollection.findOneById(id);
        if (pipeline == null) {
            throw new NotFoundException("No pipeline with id " + id);
        }
        return pipeline;
    }

    @Override
    public PipelineDao loadByName(String name) throws NotFoundException {
        final Bson query = Filters.eq("title", name);
        final PipelineDao pipeline = dbCollection.findOne(query);
        if (pipeline == null) {
            throw new NotFoundException("No pipeline with name " + name);
        }
        return pipeline;
    }

    @Override
    public Collection<PipelineDao> loadAll() {
        try {
            return Collections.unmodifiableSet(dbCollection.find().into(new HashSet<>()));
        } catch (MongoException e) {
            log.error("Unable to load pipelines", e);
            return Collections.emptySet();
        }
    }

    @Override
    public void delete(String id) {
        dbCollection.removeById(id);
        clusterBus.post(PipelinesChangedEvent.deletedPipelineId(id));
    }
}
