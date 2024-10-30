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

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
import com.mongodb.client.AggregateIterable;
import com.mongodb.client.model.Accumulators;
import com.mongodb.client.model.Aggregates;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Sorts;
import org.bson.types.ObjectId;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.NotFoundException;
import org.graylog2.database.PersistedServiceImpl;
import org.graylog2.events.ClusterEventBus;
import org.graylog2.plugin.database.ValidationException;
import org.graylog2.plugin.streams.Stream;
import org.graylog2.plugin.streams.StreamRule;
import org.graylog2.rest.resources.streams.rules.requests.CreateStreamRuleRequest;
import org.graylog2.streams.events.StreamsChangedEvent;

import javax.annotation.Nullable;
import javax.inject.Inject;
import java.util.*;
import java.util.stream.Collectors;

public class StreamRuleServiceImpl extends PersistedServiceImpl implements StreamRuleService {
    private final ClusterEventBus clusterEventBus;

    @Inject
    public StreamRuleServiceImpl(MongoConnection mongoConnection,
                                 ClusterEventBus clusterEventBus) {
        super(mongoConnection);
        collection(StreamRuleImpl.class).createIndex(Sorts.ascending(StreamRuleImpl.FIELD_STREAM_ID));
        this.clusterEventBus = clusterEventBus;
    }

    @Override
    public StreamRule load(String id) throws NotFoundException {
        BasicDBObject o = (BasicDBObject) get(StreamRuleImpl.class, new ObjectId(id));

        if (o == null) {
            throw new NotFoundException("Couldn't find stream rule with ID" + id);
        }

        return new StreamRuleImpl((ObjectId) o.get("_id"), o.toMap());
    }

    @Override
    public List<StreamRule> loadForStream(Stream stream) {
        return loadForStreamId(stream.getId());
    }

    @Override
    public StreamRule create(Map<String, Object> data) {
        return new StreamRuleImpl(data);
    }

    @Override
    public StreamRule create(@Nullable String streamId, CreateStreamRuleRequest cr) {
        Map<String, Object> streamRuleData = Maps.newHashMap();
        streamRuleData.put(StreamRuleImpl.FIELD_TYPE, cr.type());
        streamRuleData.put(StreamRuleImpl.FIELD_VALUE, cr.value());
        streamRuleData.put(StreamRuleImpl.FIELD_FIELD, cr.field());
        streamRuleData.put(StreamRuleImpl.FIELD_INVERTED, cr.inverted());
        streamRuleData.put(StreamRuleImpl.FIELD_DESCRIPTION, cr.description());

        if (streamId != null) {
            streamRuleData.put(StreamRuleImpl.FIELD_STREAM_ID, new ObjectId(streamId));
        }

        return new StreamRuleImpl(streamRuleData);
    }

    @Override
    public StreamRule copy(@Nullable String streamId, StreamRule streamRule) {
        Map<String, Object> streamRuleData = Maps.newHashMap();
        streamRuleData.put(StreamRuleImpl.FIELD_TYPE, streamRule.getType().toInteger());
        streamRuleData.put(StreamRuleImpl.FIELD_VALUE, streamRule.getValue());
        streamRuleData.put(StreamRuleImpl.FIELD_FIELD, streamRule.getField());
        streamRuleData.put(StreamRuleImpl.FIELD_INVERTED, streamRule.getInverted());
        streamRuleData.put(StreamRuleImpl.FIELD_DESCRIPTION, streamRule.getDescription());

        if (streamId != null) {
            streamRuleData.put(StreamRuleImpl.FIELD_STREAM_ID, new ObjectId(streamId));
        }

        return new StreamRuleImpl(streamRuleData);
    }

    @Override
    public String save(StreamRule streamRule) throws ValidationException {
        final String streamId = streamRule.getStreamId();
        final String savedStreamRuleId = super.save(streamRule);
        clusterEventBus.post(StreamsChangedEvent.create(streamId));

        return savedStreamRuleId;
    }

    @Override
    public Set<String> save(Collection<StreamRule> streamRules) throws ValidationException {
        final ImmutableSet.Builder<String> streamIds = ImmutableSet.builder();
        final ImmutableSet.Builder<String> streamRuleIds = ImmutableSet.builder();
        for (StreamRule streamRule : streamRules) {
            final String streamId = streamRule.getStreamId();
            final String savedStreamRuleId = super.save(streamRule);
            streamIds.add(streamId);
            streamRuleIds.add(savedStreamRuleId);
        }
        clusterEventBus.post(StreamsChangedEvent.create(streamIds.build()));

        return streamRuleIds.build();
    }

    @Override
    public int destroy(StreamRule streamRule) {
        final String streamId = streamRule.getStreamId();
        final int deletedStreamRules = super.destroy(streamRule);
        clusterEventBus.post(StreamsChangedEvent.create(streamId));

        return deletedStreamRules;
    }

    @Override
    public List<StreamRule> loadForStreamId(String streamId) {
        ObjectId id = new ObjectId(streamId);
        final List<StreamRule> streamRules = new ArrayList<>();
        final List<DBObject> respStreamRules = query(StreamRuleImpl.class,
                Filters.eq(StreamRuleImpl.FIELD_STREAM_ID, id));

        for (DBObject streamRule : respStreamRules) {
            streamRules.add(toStreamRule(streamRule));
        }

        return streamRules;
    }

    @Override
    public Map<String, List<StreamRule>> loadForStreamIds(Collection<String> streamIds) {
        final List<ObjectId> objectIds = streamIds.stream()
            .map(ObjectId::new)
            .collect(Collectors.toList());

        final List<DBObject> respStreamRules = query(StreamRuleImpl.class,
            Filters.in(StreamRuleImpl.FIELD_STREAM_ID, objectIds));

        return respStreamRules.stream()
            .map(this::toStreamRule)
            .collect(Collectors.groupingBy(StreamRule::getStreamId));
    }

    @Override
    public long totalStreamRuleCount() {
        return totalCount(StreamRuleImpl.class);
    }

    @Override
    public long streamRuleCount(String streamId) {
        return streamRuleCount(new ObjectId(streamId));
    }

    private long streamRuleCount(ObjectId streamId) {
        return count(StreamRuleImpl.class, new BasicDBObject(StreamRuleImpl.FIELD_STREAM_ID, streamId));
    }

    @Override
    public Map<String, Long> streamRuleCountByStream() {
        final ImmutableMap.Builder<String, Long> streamRules = ImmutableMap.builder();
        AggregateIterable<BasicDBObject> results = collection(StreamImpl.class).aggregate(List.of(Aggregates.group("$stream_id", Accumulators.sum("count",1))));
        for(BasicDBObject result: results) {
            ObjectId streamId = result.getObjectId("_id");
            int count = result.getInt("count");
            streamRules.put(streamId.toHexString(), Long.valueOf(count));
        }
        return streamRules.build();
    }

    @SuppressWarnings("unchecked")
    private StreamRule toStreamRule(DBObject dbObject) {
        final Map<String, Object> fields = dbObject.toMap();
        return new StreamRuleImpl((ObjectId) dbObject.get("_id"), fields);
    }
}
