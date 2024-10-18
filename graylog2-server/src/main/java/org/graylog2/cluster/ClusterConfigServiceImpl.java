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
package org.graylog2.cluster;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableSet;
import com.google.common.eventbus.EventBus;
import com.mongodb.WriteConcern;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.FindOneAndReplaceOptions;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Sorts;
import com.mongodb.client.result.DeleteResult;
import org.bson.UuidRepresentation;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.events.ClusterEventBus;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.system.NodeId;
import org.graylog2.security.SafeChainingClassLoader;
import org.graylog2.security.UnauthorizedClassLoadingException;
import org.graylog2.shared.utilities.AutoValueUtils;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.mongojack.JacksonMongoCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.Set;

import static com.google.common.base.MoreObjects.firstNonNull;
import static com.google.common.base.Preconditions.checkNotNull;

public class ClusterConfigServiceImpl implements ClusterConfigService {
    private static final Logger LOG = LoggerFactory.getLogger(ClusterConfigServiceImpl.class);

    @VisibleForTesting
    static final String COLLECTION_NAME = "cluster_config";

    private final JacksonMongoCollection<ClusterConfig> dbCollection;
    private final NodeId nodeId;
    private final ObjectMapper objectMapper;
    private final SafeChainingClassLoader chainingClassLoader;
    private final EventBus clusterEventBus;

    @Inject
    public ClusterConfigServiceImpl(final MongoJackObjectMapperProvider mapperProvider,
                                    final MongoConnection mongoConnection,
                                    final NodeId nodeId,
                                    final SafeChainingClassLoader chainingClassLoader,
                                    final ClusterEventBus clusterEventBus) {
        this(JacksonMongoCollection.builder().withObjectMapper(mapperProvider.get()).build(prepareCollection(mongoConnection), ClusterConfig.class, UuidRepresentation.STANDARD),
                nodeId, mapperProvider.get(), chainingClassLoader, clusterEventBus);
    }

    private ClusterConfigServiceImpl(final JacksonMongoCollection<ClusterConfig> dbCollection,
                                     final NodeId nodeId,
                                     final ObjectMapper objectMapper,
                                     final SafeChainingClassLoader chainingClassLoader,
                                     final EventBus clusterEventBus) {
        this.nodeId = checkNotNull(nodeId);
        this.dbCollection = checkNotNull(dbCollection);
        this.objectMapper = checkNotNull(objectMapper);
        this.chainingClassLoader = chainingClassLoader;
        this.clusterEventBus = checkNotNull(clusterEventBus);
    }

    @VisibleForTesting
    static MongoCollection<ClusterConfig> prepareCollection(final MongoConnection mongoConnection) {

        MongoCollection<ClusterConfig> mongoCollection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, ClusterConfig.class);

        mongoCollection.createIndex(Sorts.ascending("type"), new IndexOptions().name("unique_type").unique(true));
        mongoCollection.withWriteConcern(WriteConcern.JOURNALED);

        return mongoCollection;
    }

    private <T> T extractPayload(Object payload, Class<T> type) {
        try {
            return objectMapper.convertValue(payload, type);
        } catch (IllegalArgumentException e) {
            LOG.error("Error while deserializing payload", e);
            return null;
        }
    }

    @Override
    public <T> T get(String key, Class<T> type) {
        ClusterConfig config = dbCollection.findOne(Filters.eq("type", key));

        if (config == null) {
            LOG.debug("Couldn't find cluster config of type {}", key);
            return null;
        }

        T result = extractPayload(config.payload(), type);
        if (result == null) {
            LOG.error("Couldn't extract payload from cluster config (type: {})", key);
        }

        return result;
    }

    @Override
    public <T> T get(Class<T> type) {
        return get(type.getCanonicalName(), type);
    }

    @Override
    public <T> T getOrDefault(Class<T> type, T defaultValue) {
        return firstNonNull(get(type), defaultValue);
    }

    @Override
    public <T> void write(T payload) {
        if (payload == null) {
            LOG.debug("Payload was null. Skipping.");
            return;
        }

        String canonicalClassName = AutoValueUtils.getCanonicalName(payload.getClass());
        write(canonicalClassName, payload);
    }

    @Override
    public <T> void write(String key, T payload) {
        if (payload == null) {
            LOG.debug("Payload was null. Skipping.");
            return;
        }

        ClusterConfig clusterConfig = ClusterConfig.create(key, payload, nodeId.toString());

        dbCollection.findOneAndReplace(Filters.eq("type", key), clusterConfig, new FindOneAndReplaceOptions().upsert(true));

        ClusterConfigChangedEvent event = ClusterConfigChangedEvent.create(
                DateTime.now(DateTimeZone.UTC), nodeId.toString(), key);
        clusterEventBus.post(event);
    }

    @Override
    public <T> int remove(Class<T> type) {
        final String canonicalName = type.getCanonicalName();
        final DeleteResult result = dbCollection.deleteMany(Filters.eq("type", canonicalName));
        return (int) result.getDeletedCount();
    }

    @Override
    public Set<Class<?>> list() {
        final ImmutableSet.Builder<Class<?>> classes = ImmutableSet.builder();


        for (ClusterConfig clusterConfig : dbCollection.find()) {
                final String type = clusterConfig.type();
                try {
                    final Class<?> cls = chainingClassLoader.loadClassSafely(type);
                    classes.add(cls);
                } catch (ClassNotFoundException e) {
                    LOG.debug("Couldn't find configuration class \"{}\"", type, e);
                } catch (UnauthorizedClassLoadingException e) {
                    LOG.error("Class {} is not allowed to be loaded",type);
                }
            }


        return classes.build();
    }
}
