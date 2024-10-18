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

import com.mongodb.BasicDBObject;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.Updates;
import com.mongodb.client.result.UpdateResult;
import org.bson.Document;
import org.bson.UuidRepresentation;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.CollectionName;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.NotFoundException;
import org.graylog2.outputs.OutputRegistry;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.database.ValidationException;
import org.graylog2.plugin.streams.Output;
import org.graylog2.rest.models.streams.outputs.requests.CreateOutputRequest;
import org.mongojack.JacksonMongoCollection;

import javax.inject.Inject;
import java.util.*;

public class OutputServiceImpl implements OutputService {
    private final JacksonMongoCollection<OutputImpl> coll;
    private final MongoCollection<Document> dbCollection;
    private final StreamService streamService;
    private final OutputRegistry outputRegistry;

    @Inject
    public OutputServiceImpl(MongoConnection mongoConnection,
                             MongoJackObjectMapperProvider mapperProvider,
                             StreamService streamService,
                             OutputRegistry outputRegistry) {
        this.streamService = streamService;
        final String collectionName = OutputImpl.class.getAnnotation(CollectionName.class).value();
        this.dbCollection = mongoConnection.getMongoDatabase().getCollection(collectionName);
        this.coll = JacksonMongoCollection.builder().withObjectMapper((mapperProvider.get())).build(mongoConnection.getMongoDatabase(), collectionName, OutputImpl.class, UuidRepresentation.STANDARD);
        this.outputRegistry = outputRegistry;
    }

    @Override
    public Output load(String streamOutputId) throws NotFoundException {
        final Output output = coll.findOneById(streamOutputId);
        if (output == null) {
            throw new NotFoundException("Couldn't find output with id " + streamOutputId);
        }

        return output;
    }

    @Override
    public Set<Output> loadAll() {
        return Collections.unmodifiableSet(coll.find().into(new HashSet<>()));
    }

    @Override
    public Set<Output> loadByIds(Collection<String> ids) {
        final Bson query = Filters.in(OutputImpl.FIELD_ID, ids);
        return Collections.unmodifiableSet(coll.find(query).into(new HashSet<>()));
    }

    @Override
    public Output create(Output request) throws ValidationException {
        final OutputImpl outputImpl = implOrFail(request);
        final UpdateResult writeResult = coll.save(outputImpl);

        return coll.findOneById(writeResult.getUpsertedId());
    }

    @Override
    public Output create(CreateOutputRequest request, String userId) throws ValidationException {
        return create(OutputImpl.create(new ObjectId().toHexString(), request.title(), request.type(), userId, request.configuration(),
                Tools.nowUTC().toDate(), request.contentPack()));
    }

    @Override
    public void destroy(Output model) throws NotFoundException {
        coll.removeById(model.getId());
        outputRegistry.removeOutput(model);
        streamService.removeOutputFromAllStreams(model);
    }

    @Override
    public Output update(String id, Map<String, Object> deltas) {
        List<Bson> updates = new ArrayList<>();
        for (Map.Entry<String, Object> fields : deltas.entrySet()) {
            updates.add(Updates.set(fields.getKey(), fields.getValue()));
        }

        return coll.findOneAndUpdate(Filters.eq(OutputImpl.FIELD_ID, new ObjectId(id)), updates, new FindOneAndUpdateOptions().upsert(false));
    }

    @Override
    public long count() {
        return coll.countDocuments();
    }

    @Override
    public Map<String, Long> countByType() {
        final Map<String, Long> outputsCountByType = new HashMap<>();
        FindIterable<Document> outputTypes = dbCollection.find(new BasicDBObject(OutputImpl.FIELD_TYPE, 1));
        for (Document outputType : outputTypes) {
                final String type = (String) outputType.get(OutputImpl.FIELD_TYPE);
                if (type != null) {
                    final Long oldValue = outputsCountByType.get(type);
                    final Long newValue = (oldValue == null) ? 1 : oldValue + 1;
                    outputsCountByType.put(type, newValue);
                }
            }


        return outputsCountByType;
    }

    private OutputImpl implOrFail(Output output) {
        final OutputImpl outputImpl;
        if (output instanceof OutputImpl) {
            outputImpl = (OutputImpl) output;
            return outputImpl;
        } else {
            throw new IllegalArgumentException("Supplied output must be of implementation type OutputImpl, not " + output.getClass());
        }
    }
}
