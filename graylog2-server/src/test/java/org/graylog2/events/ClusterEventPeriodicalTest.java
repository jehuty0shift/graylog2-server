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
import com.google.common.collect.ImmutableMap;
import com.google.common.eventbus.DeadEvent;
import com.google.common.eventbus.EventBus;
import com.google.common.eventbus.Subscribe;
import com.mongodb.WriteConcern;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;
import org.graylog.testing.mongodb.MongoDBInstance;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.plugin.system.NodeId;
import org.graylog2.security.SafeChainingClassLoader;
import org.graylog2.security.SafeClassesProvider;
import org.graylog2.shared.bindings.providers.ObjectMapperProvider;
import org.graylog2.shared.plugins.ChainingClassLoader;
import org.graylog2.system.debug.DebugEvent;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.joda.time.DateTimeZone;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class ClusterEventPeriodicalTest {
    @Rule
    public final MongoDBInstance mongodb = MongoDBInstance.createForClass();
    private static final DateTime TIME = new DateTime(2015, 4, 1, 0, 0, DateTimeZone.UTC);

    @Rule
    public final MockitoRule mockitoRule = MockitoJUnit.rule();

    private final ObjectMapper objectMapper = new ObjectMapperProvider().get();

    @Mock
    private NodeId nodeId;
    @Spy
    private EventBus serverEventBus;
    @Spy
    private ClusterEventBus clusterEventBus;
    private MongoConnection mongoConnection;
    private ClusterEventPeriodical clusterEventPeriodical;

    @Before
    public void setUpService() throws Exception {
        DateTimeUtils.setCurrentMillisFixed(TIME.getMillis());

        this.mongoConnection = mongodb.mongoConnection();

        MongoJackObjectMapperProvider provider = new MongoJackObjectMapperProvider(objectMapper);
        when(nodeId.toString()).thenReturn("ID");

        this.clusterEventPeriodical = new ClusterEventPeriodical(
                provider,
                mongodb.mongoConnection(),
                nodeId,
                new SafeChainingClassLoader(new ChainingClassLoader(getClass().getClassLoader()), SafeClassesProvider.allLdpInternal()),
                serverEventBus,
                clusterEventBus
        );
    }

    @After
    public void tearDown() {
        DateTimeUtils.setCurrentMillisSystem();
        mongoConnection.getMongoDatabase().drop();
    }

    @Test
    public void clusterEventServiceRegistersItselfWithClusterEventBus() throws Exception {
        verify(clusterEventBus, times(1)).registerClusterEventSubscriber(clusterEventPeriodical);
    }

    @Test
    public void runHandlesInvalidPayloadsGracefully() throws Exception {
        Document event = new Document();

        event.put("timestamp", TIME.getMillis());
        event.put("producer", "TEST-PRODUCER");
        event.put("consumers", Collections.emptyList());
        event.put("event_class", SimpleEvent.class.getCanonicalName());
        event.put("payload", ImmutableMap.of("HAHA", "test"));

        @SuppressWarnings("deprecation") final MongoCollection<Document> collection = mongoConnection.getMongoDatabase().getCollection(ClusterEventPeriodical.COLLECTION_NAME, Document.class);
        collection.insertOne(event);

        assertThat(collection.countDocuments()).isEqualTo(1L);

        clusterEventPeriodical.run();

        assertThat(collection.countDocuments()).isEqualTo(1L);

        @SuppressWarnings("unchecked") final List<String> consumers = (List<String>) collection.find().first().get("consumers");
        assertThat(consumers).containsExactly(nodeId.toString());

        verify(serverEventBus, never()).post(any());
        verify(clusterEventBus, never()).post(any());
    }

    @Test
    public void serverEventBusDispatchesTypedEvents() throws Exception {
        final SimpleEventHandler handler = new SimpleEventHandler();
        serverEventBus.register(handler);

        Document event = new Document()
                .append("timestamp", TIME.getMillis())
                .append("producer", "TEST-PRODUCER")
                .append("consumers", Collections.emptyList())
                .append("event_class", SimpleEvent.class.getCanonicalName())
                .append("payload", ImmutableMap.of("payload", "test"));
        @SuppressWarnings("deprecation") final MongoCollection<Document> collection = mongoConnection.getMongoDatabase().getCollection(ClusterEventPeriodical.COLLECTION_NAME);
        assertThat(collection.countDocuments()).isEqualTo(0L);
        assertThat(collection.insertOne(event).wasAcknowledged()).isTrue();
        assertThat(collection.countDocuments()).isEqualTo(1L);
        assertThat(handler.invocations).hasValue(0);

        clusterEventPeriodical.run();

        assertThat(handler.invocations).hasValue(1);
        assertThat(collection.countDocuments()).isEqualTo(1L);

        @SuppressWarnings("unchecked") final List<String> consumers = (List<String>) collection.find().first().get("consumers");
        assertThat(consumers).containsExactly(nodeId.toString());

        verify(serverEventBus, times(1)).post(any(SimpleEvent.class));
        verify(clusterEventBus, never()).post(any());
    }

    @Test
    public void runHandlesAutoValueCorrectly() throws Exception {
        final DebugEvent event = DebugEvent.create("Node ID", TIME, "test");
        Document dbObject = new Document()
                .append("timestamp", TIME.getMillis())
                .append("producer", "TEST-PRODUCER")
                .append("consumers", Collections.emptyList())
                .append("event_class", DebugEvent.class.getCanonicalName())
                .append("payload", objectMapper.convertValue(event, Map.class));

        @SuppressWarnings("deprecation") final MongoCollection<Document> collection = mongoConnection.getMongoDatabase().getCollection(ClusterEventPeriodical.COLLECTION_NAME);
        collection.insertOne(dbObject);

        assertThat(collection.countDocuments()).isEqualTo(1L);

        clusterEventPeriodical.run();

        assertThat(collection.countDocuments()).isEqualTo(1L);

        @SuppressWarnings("unchecked") final List<String> consumers = (List<String>) collection.find().first().get("consumers");
        assertThat(consumers).containsExactly(nodeId.toString());

        verify(serverEventBus, times(1)).post(event);
        verify(clusterEventBus, never()).post(event);
    }

    @Test
    public void testRun() throws Exception {
        Document event = new Document()
                .append("timestamp", TIME.getMillis())
                .append("producer", "TEST-PRODUCER")
                .append("consumers", Collections.emptyList())
                .append("event_class", SimpleEvent.class.getCanonicalName())
                .append("payload", ImmutableMap.of("payload", "test"));

        @SuppressWarnings("deprecation") final MongoCollection<Document> collection = mongoConnection.getMongoDatabase().getCollection(ClusterEventPeriodical.COLLECTION_NAME);
        collection.insertOne(event);

        assertThat(collection.countDocuments()).isEqualTo(1L);

        clusterEventPeriodical.run();

        assertThat(collection.countDocuments()).isEqualTo(1L);

        @SuppressWarnings("unchecked") final List<String> consumers = (List<String>) collection.find().first().get("consumers");
        assertThat(consumers).containsExactly(nodeId.toString());

        verify(serverEventBus, times(1)).post(new SimpleEvent("test"));
        verify(clusterEventBus, never()).post(event);
    }

    @Test
    public void testPublishClusterEvent() throws Exception {
        @SuppressWarnings("deprecation")
        MongoCollection<Document> collection = mongoConnection.getMongoDatabase().getCollection(ClusterEventPeriodical.COLLECTION_NAME);
        SimpleEvent event = new SimpleEvent("test");

        assertThat(collection.countDocuments()).isEqualTo(0L);

        clusterEventPeriodical.publishClusterEvent(event);

        verify(clusterEventBus, never()).post(any());
        assertThat(collection.countDocuments()).isEqualTo(1L);

        Document dbObject = collection.find().first();

        assertThat((String) dbObject.get("producer")).isEqualTo(nodeId.toString());
        assertThat((String) dbObject.get("event_class")).isEqualTo(SimpleEvent.class.getCanonicalName());

        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) dbObject.get("payload");
        assertThat(payload).containsEntry("payload", "test");
    }

    @Test
    public void publishClusterEventHandlesAutoValueCorrectly() throws Exception {
        @SuppressWarnings("deprecation")
        MongoCollection<Document> collection = mongoConnection.getMongoDatabase().getCollection(ClusterEventPeriodical.COLLECTION_NAME);
        DebugEvent event = DebugEvent.create("Node ID", "Test");

        assertThat(collection.countDocuments()).isEqualTo(0L);

        clusterEventPeriodical.publishClusterEvent(event);

        verify(clusterEventBus, never()).post(any());
        assertThat(collection.countDocuments()).isEqualTo(1L);

        Document dbObject = collection.find().first();

        assertThat((String) dbObject.get("producer")).isEqualTo(nodeId.toString());
        assertThat((String) dbObject.get("event_class")).isEqualTo(DebugEvent.class.getCanonicalName());
    }

    @Test
    public void publishClusterEventSkipsDeadEvent() throws Exception {
        @SuppressWarnings("deprecation")
        MongoCollection<Document> collection = mongoConnection.getMongoDatabase().getCollection(ClusterEventPeriodical.COLLECTION_NAME);
        DeadEvent event = new DeadEvent(clusterEventBus, new SimpleEvent("test"));

        assertThat(collection.countDocuments()).isEqualTo(0L);

        clusterEventPeriodical.publishClusterEvent(event);

        verify(clusterEventBus, never()).post(any());
        assertThat(collection.countDocuments()).isEqualTo(0L);
    }

    @Test
    public void prepareCollectionCreatesIndexesOnExistingCollection() throws Exception {
        @SuppressWarnings("deprecation")
        MongoCollection original = mongoConnection.getMongoDatabase().getCollection(ClusterEventPeriodical.COLLECTION_NAME);
        original.dropIndexes();
        assertThat(original.getNamespace().getCollectionName()).isEqualTo(ClusterEventPeriodical.COLLECTION_NAME);
        assertThat(original.listIndexes().into(new ArrayList<>())).hasSize(1);

        MongoCollection collection = ClusterEventPeriodical.prepareCollection(mongoConnection);
        assertThat(collection.getNamespace().getCollectionName()).isEqualTo(ClusterEventPeriodical.COLLECTION_NAME);
        assertThat(collection.listIndexes().into(new ArrayList())).hasSize(2);
        assertThat(collection.getWriteConcern()).isEqualTo(WriteConcern.JOURNALED);
    }

    @Test
    public void prepareCollectionCreatesCollectionIfItDoesNotExist() throws Exception {
        @SuppressWarnings("deprecation") final MongoDatabase database = mongoConnection.getMongoDatabase();
        database.getCollection(ClusterEventPeriodical.COLLECTION_NAME).drop();
        assertThat(database.listCollectionNames().into(new ArrayList<>()).stream().anyMatch(c -> c.equals(ClusterEventPeriodical.COLLECTION_NAME))).isFalse();
        MongoCollection collection = ClusterEventPeriodical.prepareCollection(mongoConnection);

        assertThat(collection.getNamespace().getCollectionName()).isEqualTo(ClusterEventPeriodical.COLLECTION_NAME);
        assertThat(collection.listIndexes().into(new ArrayList<>())).hasSize(2);
        assertThat(collection.getWriteConcern()).isEqualTo(WriteConcern.JOURNALED);
    }

    public static class SimpleEventHandler {
        final AtomicInteger invocations = new AtomicInteger();

        @Subscribe
        @SuppressWarnings("unused")
        public void handleSimpleEvent(SimpleEvent event) {
            invocations.incrementAndGet();
        }
    }
}
