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
package org.graylog2.events;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.eventbus.DeadEvent;
import com.google.common.eventbus.EventBus;
import com.google.common.eventbus.Subscribe;
import com.mongodb.BasicDBList;
import com.mongodb.MongoException;
import com.mongodb.WriteConcern;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Sorts;
import com.mongodb.client.model.Updates;
import org.bson.UuidRepresentation;
import org.bson.conversions.Bson;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.plugin.periodical.Periodical;
import org.graylog2.plugin.system.NodeId;
import org.graylog2.security.SafeChainingClassLoader;
import org.graylog2.security.UnauthorizedClassLoadingException;
import org.graylog2.shared.utilities.AutoValueUtils;
import org.mongojack.JacksonMongoCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.Objects;

import static com.google.common.base.Preconditions.checkNotNull;

public class ClusterEventPeriodical extends Periodical {
    private static final Logger LOG = LoggerFactory.getLogger(ClusterEventPeriodical.class);

    @VisibleForTesting
    static final String COLLECTION_NAME = "cluster_events";

    private final JacksonMongoCollection<ClusterEvent> dbCollection;
    private final NodeId nodeId;
    private final ObjectMapper objectMapper;
    private final EventBus serverEventBus;
    private final SafeChainingClassLoader chainingClassLoader;

    @Inject
    public ClusterEventPeriodical(final MongoJackObjectMapperProvider mapperProvider,
                                  final MongoConnection mongoConnection,
                                  final NodeId nodeId,
                                  final SafeChainingClassLoader safeChainingClassLoader,
                                  final EventBus serverEventBus,
                                  final ClusterEventBus clusterEventBus) {
        this(JacksonMongoCollection.builder().withObjectMapper(mapperProvider.get()).build(prepareCollection(mongoConnection), ClusterEvent.class, UuidRepresentation.STANDARD),
                nodeId,
                mapperProvider.get(),
                safeChainingClassLoader,
                serverEventBus,
                clusterEventBus);
    }

    private ClusterEventPeriodical(final JacksonMongoCollection<ClusterEvent> dbCollection,
                           final NodeId nodeId,
                           final ObjectMapper objectMapper,
                           final SafeChainingClassLoader safeChainingClassLoader,
                           final EventBus serverEventBus,
                           final ClusterEventBus clusterEventBus) {
        this.nodeId = checkNotNull(nodeId);
        this.dbCollection = checkNotNull(dbCollection);
        this.objectMapper = checkNotNull(objectMapper);
        this.chainingClassLoader = safeChainingClassLoader;
        this.serverEventBus = checkNotNull(serverEventBus);

        checkNotNull(clusterEventBus).registerClusterEventSubscriber(this);
    }

    @VisibleForTesting
    static MongoCollection<ClusterEvent> prepareCollection(final MongoConnection mongoConnection) {
        final MongoDatabase db = mongoConnection.getMongoDatabase();

        MongoCollection<ClusterEvent> coll = db.getCollection(COLLECTION_NAME, ClusterEvent.class).withWriteConcern(WriteConcern.JOURNALED);

        coll.createIndex(Sorts.orderBy(
                Sorts.ascending("timestamp"),
                Sorts.ascending("producer"),
                Sorts.ascending("consumers")));


        return coll;
    }

    @Override
    public boolean runsForever() {
        return false;
    }

    @Override
    public boolean stopOnGracefulShutdown() {
        return true;
    }

    @Override
    public boolean masterOnly() {
        return false;
    }

    @Override
    public boolean startOnThisNode() {
        return true;
    }

    @Override
    public boolean isDaemon() {
        return true;
    }

    @Override
    public int getInitialDelaySeconds() {
        return 0;
    }

    @Override
    public int getPeriodSeconds() {
        return 1;
    }

    @Override
    protected Logger getLogger() {
        return LOG;
    }

    @Override
    public void doRun() {
        LOG.debug("Opening MongoDB cursor on \"{}\"", COLLECTION_NAME);
        try {
            FindIterable<ClusterEvent> cursor = eventCursor(nodeId);
            if (LOG.isTraceEnabled()) {
                LOG.trace("MongoDB query plan: {}", cursor.explain());
            }

            for (ClusterEvent clusterEvent : cursor) {
                LOG.trace("Processing cluster event: {}", clusterEvent);

                Object payload = extractPayload(clusterEvent.payload(), clusterEvent.eventClass());
                if (payload != null) {
                    serverEventBus.post(payload);
                } else {
                    LOG.warn("Couldn't extract payload of cluster event with ID <{}>", clusterEvent.id());
                    LOG.debug("Invalid payload in cluster event: {}", clusterEvent);
                }

                updateConsumers(clusterEvent.id(), nodeId);
            }
        } catch (Exception e) {
            LOG.warn("Error while reading cluster events from MongoDB, retrying.", e);
        }
    }

    @Subscribe
    public void publishClusterEvent(Object event) {
        if (event instanceof DeadEvent) {
            LOG.debug("Skipping DeadEvent on cluster event bus");
            return;
        }

        final String className = AutoValueUtils.getCanonicalName(event.getClass());
        final ClusterEvent clusterEvent = ClusterEvent.create(nodeId.toString(), className, event);

        try {
            final String id = Objects.requireNonNull(dbCollection.save(clusterEvent, WriteConcern.JOURNALED).getUpsertedId()).asObjectId().getValue().toHexString();
            LOG.debug("Published cluster event with ID <{}> and type <{}>", id, className);
        } catch (MongoException e) {
            LOG.error("Couldn't publish cluster event of type <" + className + ">", e);
        }
    }

    private FindIterable<ClusterEvent> eventCursor(NodeId nodeId) {
        // Resorting to ugly MongoDB Java Client because of https://github.com/devbliss/mongojack/issues/88
        final BasicDBList consumersList = new BasicDBList();
        consumersList.add(nodeId.toString());
        final Bson query = Filters.nin("consumers", consumersList);

        return dbCollection.find(query).sort(Sorts.ascending("timestamp"));
    }

    private void updateConsumers(final String eventId, final NodeId nodeId) {
        dbCollection.updateById(eventId, Updates.addToSet("consumers", nodeId.toString()));
    }

    private Object extractPayload(Object payload, String eventClass) {
        try {
            final Class<?> clazz = chainingClassLoader.loadClassSafely(eventClass);
            return objectMapper.convertValue(payload, clazz);
        } catch (ClassNotFoundException e) {
            LOG.debug("Couldn't load class <" + eventClass + "> for event", e);
            return null;
        } catch (IllegalArgumentException e) {
            LOG.debug("Error while deserializing payload", e);
            return null;
        }catch (UnauthorizedClassLoadingException e) {
            LOG.error("Class {} is not allowed to be loaded", eventClass);
            return null;
        }
    }
}
