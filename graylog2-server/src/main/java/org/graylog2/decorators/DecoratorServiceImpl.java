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
package org.graylog2.decorators;

import com.google.common.base.Strings;
import com.mongodb.client.model.Filters;
import com.mongodb.client.result.UpdateResult;
import org.bson.UuidRepresentation;
import org.bson.types.ObjectId;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.CollectionName;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.NotFoundException;
import org.mongojack.JacksonMongoCollection;

import javax.inject.Inject;
import java.util.*;

import static com.google.common.base.Preconditions.checkArgument;

public class DecoratorServiceImpl implements DecoratorService {
    private final JacksonMongoCollection<DecoratorImpl> coll;

    @Inject
    public DecoratorServiceImpl(MongoConnection mongoConnection, MongoJackObjectMapperProvider mongoJackObjectMapperProvider) {
        final String collectionName = DecoratorImpl.class.getAnnotation(CollectionName.class).value();
        this.coll = JacksonMongoCollection.builder().withObjectMapper(mongoJackObjectMapperProvider.get()).build(mongoConnection.getMongoDatabase(),collectionName, DecoratorImpl.class, UuidRepresentation.STANDARD);
    }

    @Override
    public List<Decorator> findForStream(String streamId) {
        return Collections.unmodifiableList(coll.find(Filters.eq(DecoratorImpl.FIELD_STREAM, Optional.of(streamId))).into(new ArrayList<>()));
    }

    @Override
    public List<Decorator> findForGlobal() {
        return Collections.unmodifiableList(coll.find(Filters.or(
            Filters.exists(DecoratorImpl.FIELD_STREAM,false),
            Filters.eq(DecoratorImpl.FIELD_STREAM, Optional.empty())
        )).into(new ArrayList<>()));
    }

    @Override
    public Decorator findById(String decoratorId) throws NotFoundException {
        final Decorator result = coll.findOneById(decoratorId);
        if (result == null) {
            throw new NotFoundException("Decorator with id " + decoratorId + " not found.");
        }

        return result;
    }

    @Override
    public List<Decorator> findAll() {
        return Collections.unmodifiableList(coll.find().into(new ArrayList<>()));
    }

    @Override
    public Decorator create(String type, Map<String, Object> config, String stream, int order) {
        return DecoratorImpl.create(type, config, Optional.of(stream), order);
    }

    @Override
    public Decorator create(String type, Map<String, Object> config, int order) {
        return DecoratorImpl.create(type, config, order);
    }

    @Override
    public Decorator save(Decorator decorator) {
        checkArgument(decorator instanceof DecoratorImpl, "Argument must be an instance of DecoratorImpl, not %s", decorator.getClass());
        if (!Strings.isNullOrEmpty(decorator.id())) {
            return this.coll.findOneAndReplace(Filters.eq("_id",new ObjectId(decorator.id())), (DecoratorImpl)decorator);
        }
        UpdateResult result = this.coll.save((DecoratorImpl) decorator);
        return coll.findOneById(result.getUpsertedId());
    }

    @Override
    public int delete(String id) {
        return (int)this.coll.removeById(id).getDeletedCount();
    }

}
