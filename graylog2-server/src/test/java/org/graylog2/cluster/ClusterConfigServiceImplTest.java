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
import com.google.common.eventbus.Subscribe;
import com.mongodb.BasicDBObject;
import com.mongodb.BasicDBObjectBuilder;
import com.mongodb.WriteConcern;
import com.mongodb.client.MongoCollection;
import one.util.streamex.StreamEx;
import org.graylog.testing.mongodb.MongoDBInstance;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.events.ClusterEventBus;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.system.NodeId;
import org.graylog2.security.SafeChainingClassLoader;
import org.graylog2.security.SafeClassesProvider;
import org.graylog2.shared.bindings.providers.ObjectMapperProvider;
import org.graylog2.shared.plugins.ChainingClassLoader;
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
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

public class ClusterConfigServiceImplTest {
    @Rule
    public final MongoDBInstance mongodb = MongoDBInstance.createForClass();

    private static final DateTime TIME = new DateTime(2015, 4, 1, 0, 0, DateTimeZone.UTC);
    private static final String COLLECTION_NAME = ClusterConfigServiceImpl.COLLECTION_NAME;

    @Rule
    public final MockitoRule mockitoRule = MockitoJUnit.rule();

    private final ObjectMapper objectMapper = new ObjectMapperProvider().get();

    @Mock
    private NodeId nodeId;
    @Spy
    private ClusterEventBus clusterEventBus;
    private MongoConnection mongoConnection;
    private ClusterConfigService clusterConfigService;

    @Before
    public void setUpService() throws Exception {
        DateTimeUtils.setCurrentMillisFixed(TIME.getMillis());

        this.mongoConnection = mongodb.mongoConnection();

        MongoJackObjectMapperProvider provider = new MongoJackObjectMapperProvider(objectMapper);
        when(nodeId.toString()).thenReturn("ID");

        this.clusterConfigService = new ClusterConfigServiceImpl(
                provider,
                mongodb.mongoConnection(),
                nodeId,
                new SafeChainingClassLoader(new ChainingClassLoader(getClass().getClassLoader()), SafeClassesProvider.allLdpInternal()),
                clusterEventBus
        );
    }

    @After
    public void tearDown() {
        DateTimeUtils.setCurrentMillisSystem();
        mongoConnection.getMongoDatabase().drop();
    }

    @Test
    public void getReturnsExistingConfig() throws Exception {
        BasicDBObject dbObject = (BasicDBObject) new BasicDBObjectBuilder()
                .add("type", CustomConfig.class.getCanonicalName())
                .add("payload", Collections.singletonMap("text", "TEST"))
                .add("last_updated", TIME.toString())
                .add("last_updated_by", "ID")
                .get();
        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        collection.insertOne(dbObject);

        assertThat(collection.countDocuments()).isEqualTo(1L);

        CustomConfig customConfig = clusterConfigService.get(CustomConfig.class);
        assertThat(customConfig.text).isEqualTo("TEST");
    }

    @Test
    public void getReturnsNullOnNonExistingConfig() throws Exception {
        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        assertThat(collection.countDocuments()).isZero();

        assertThat(clusterConfigService.get(CustomConfig.class)).isNull();
    }

    @Test
    public void getReturnsNullOnInvalidPayload() throws Exception {
        BasicDBObject dbObject = (BasicDBObject) new BasicDBObjectBuilder()
                .add("type", CustomConfig.class.getCanonicalName())
                .add("payload", "wrong payload")
                .add("last_updated", TIME.toString())
                .add("last_updated_by", "ID")
                .get();
        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        collection.insertOne(dbObject);

        assertThat(collection.countDocuments()).isEqualTo(1L);

        assertThat(clusterConfigService.get(CustomConfig.class)).isNull();
    }

    @Test
    public void getWithKeyReturnsExistingConfig() throws Exception {
        BasicDBObject dbObject = (BasicDBObject) new BasicDBObjectBuilder()
                .add("type", "foo")
                .add("payload", Collections.singletonMap("text", "TEST"))
                .add("last_updated", TIME.toString())
                .add("last_updated_by", "ID")
                .get();
        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        collection.insertOne(dbObject);

        assertThat(collection.countDocuments()).isEqualTo(1L);

        CustomConfig customConfig = clusterConfigService.get("foo", CustomConfig.class);
        assertThat(customConfig).isInstanceOf(CustomConfig.class);
        assertThat(customConfig.text).isEqualTo("TEST");
    }

    @Test
    public void getWithKeyReturnsNullOnNonExistingConfig() throws Exception {
        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        assertThat(collection.countDocuments()).isZero();

        assertThat(clusterConfigService.get("foo", CustomConfig.class)).isNull();
    }

    @Test
    public void getOrDefaultReturnsExistingConfig() throws Exception {
        BasicDBObject dbObject = (BasicDBObject) new BasicDBObjectBuilder()
                .add("type", CustomConfig.class.getCanonicalName())
                .add("payload", Collections.singletonMap("text", "TEST"))
                .add("last_updated", TIME.toString())
                .add("last_updated_by", "ID")
                .get();
        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        collection.insertOne(dbObject);

        assertThat(collection.countDocuments()).isEqualTo(1L);

        CustomConfig defaultValue = new CustomConfig();
        defaultValue.text = "DEFAULT";

        CustomConfig customConfig = clusterConfigService.getOrDefault(CustomConfig.class, defaultValue);
        assertThat(customConfig.text).isEqualTo("TEST");
    }

    @Test
    public void getOrDefaultReturnsDefaultValueOnNonExistingConfig() throws Exception {
        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        assertThat(collection.countDocuments()).isZero();

        CustomConfig defaultValue = new CustomConfig();
        defaultValue.text = "DEFAULT";

        assertThat(clusterConfigService.getOrDefault(CustomConfig.class, defaultValue)).isSameAs(defaultValue);
    }

    @Test
    public void getOrDefaultReturnsDefaultValueOnInvalidPayload() throws Exception {
        BasicDBObject dbObject = (BasicDBObject) new BasicDBObjectBuilder()
                .add("type", CustomConfig.class.getCanonicalName())
                .add("payload", "wrong payload")
                .add("last_updated", TIME.toString())
                .add("last_updated_by", "ID")
                .get();
        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        collection.insertOne(dbObject);

        assertThat(collection.countDocuments()).isEqualTo(1L);

        CustomConfig defaultValue = new CustomConfig();
        defaultValue.text = "DEFAULT";

        assertThat(clusterConfigService.getOrDefault(CustomConfig.class, defaultValue)).isSameAs(defaultValue);
    }

    @Test
    public void writeIgnoresNull() throws Exception {
        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        assertThat(collection.countDocuments()).isZero();

        clusterConfigService.write(null);

        assertThat(collection.countDocuments()).isZero();
    }

    @Test
    public void writePersistsClusterConfig() throws Exception {
        CustomConfig customConfig = new CustomConfig();
        customConfig.text = "TEST";

        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        assertThat(collection.countDocuments()).isZero();

        clusterConfigService.write(customConfig);

        assertThat(collection.countDocuments()).isEqualTo(1L);

        BasicDBObject dbObject = collection.find().first();
        assertThat((String) dbObject.get("type")).isEqualTo(CustomConfig.class.getCanonicalName());
        assertThat((String) dbObject.get("last_updated_by")).isEqualTo("ID");
    }

    @Test
    public void writeWithCustomKeyPersistsClusterConfig() throws Exception {
        CustomConfig customConfig = new CustomConfig();
        customConfig.text = "TEST";

        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        assertThat(collection.countDocuments()).isZero();

        clusterConfigService.write("foobar", customConfig);

        assertThat(collection.countDocuments()).isEqualTo(1L);

        BasicDBObject dbObject = collection.find().first();
        assertThat((String) dbObject.get("type")).isEqualTo("foobar");
        assertThat((String) dbObject.get("last_updated_by")).isEqualTo("ID");
    }

    @Test
    public void writeUpdatesExistingClusterConfig() throws Exception {
        CustomConfig customConfig = new CustomConfig();
        customConfig.text = "TEST";

        BasicDBObject seedObject = (BasicDBObject) new BasicDBObjectBuilder()
                .add("type", CustomConfig.class.getCanonicalName())
                .add("payload", Collections.singletonMap("text", "ORIGINAL"))
                .add("last_updated", TIME.toString())
                .add("last_updated_by", "NOT ID")
                .get();
        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        collection.insertOne(seedObject);
        assertThat(collection.countDocuments()).isEqualTo(1L);

        clusterConfigService.write(customConfig);

        assertThat(collection.countDocuments()).isEqualTo(1L);

        BasicDBObject dbObject = collection.find().first();
        assertThat((String) dbObject.get("type")).isEqualTo(CustomConfig.class.getCanonicalName());
        assertThat((String) dbObject.get("last_updated_by")).isEqualTo("ID");

        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) dbObject.get("payload");

        assertThat(payload).containsEntry("text", "TEST");
    }

    @Test
    public void writePostsClusterConfigChangedEvent() throws Exception {
        CustomConfig customConfig = new CustomConfig();
        customConfig.text = "TEST";

        final ClusterConfigChangedEventHandler eventHandler = new ClusterConfigChangedEventHandler();
        clusterEventBus.registerClusterEventSubscriber(eventHandler);

        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        assertThat(collection.countDocuments()).isZero();

        clusterConfigService.write(customConfig);

        assertThat(collection.countDocuments()).isEqualTo(1L);
        assertThat(eventHandler.event).isNotNull();
        assertThat(eventHandler.event.nodeId()).isEqualTo("ID");
        assertThat(eventHandler.event.type()).isEqualTo(CustomConfig.class.getCanonicalName());

        clusterEventBus.unregister(eventHandler);
    }


    @Test
    public void prepareCollectionCreatesIndexesOnExistingCollection() throws Exception {
        @SuppressWarnings("deprecation")
        MongoCollection<BasicDBObject> original = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        original.dropIndexes();
        assertThat(original.getNamespace().getCollectionName()).isEqualTo(COLLECTION_NAME);
        assertThat(original.listIndexes().into(new ArrayList<>())).hasSize(1);

        MongoCollection<ClusterConfig> collection = ClusterConfigServiceImpl.prepareCollection(mongoConnection);
        assertThat(collection.getNamespace().getCollectionName()).isEqualTo(COLLECTION_NAME);
        assertThat(collection.listIndexes().into(new ArrayList<>())).hasSize(2);
        assertThat(collection.getWriteConcern()).isEqualTo(WriteConcern.JOURNALED);
    }

    @Test
    public void prepareCollectionCreatesCollectionIfItDoesNotExist() throws Exception {
        mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME).drop();
        assertThat(StreamEx.of(mongoConnection.getMongoDatabase().listCollectionNames()).anyMatch(s -> s.equals(COLLECTION_NAME))).isFalse();
        MongoCollection<ClusterConfig> collection = ClusterConfigServiceImpl.prepareCollection(mongoConnection);

        assertThat(collection.getNamespace().getCollectionName()).isEqualTo(COLLECTION_NAME);
        assertThat(collection.listIndexes().into(new ArrayList<>())).hasSize(2);
        assertThat(collection.getWriteConcern()).isEqualTo(WriteConcern.JOURNALED);
    }

    @Test
    public void removeDoesNothingIfConfigDoesNotExist() throws Exception {
        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);

        assertThat(collection.countDocuments()).isZero();
        assertThat(clusterConfigService.remove(CustomConfig.class)).isEqualTo(0);
    }

    @Test
    public void removeSuccessfullyRemovesConfig() throws Exception {
        BasicDBObject dbObject = (BasicDBObject) new BasicDBObjectBuilder()
                .add("type", CustomConfig.class.getCanonicalName())
                .add("payload", Collections.singletonMap("text", "TEST"))
                .add("last_updated", TIME.toString())
                .add("last_updated_by", "ID")
                .get();
        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        collection.insertOne(dbObject);

        assertThat(collection.countDocuments()).isEqualTo(1L);
        assertThat(clusterConfigService.remove(CustomConfig.class)).isEqualTo(1);
        assertThat(collection.countDocuments()).isZero();
    }

    @Test
    public void listReturnsAllClasses() throws Exception {
        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        collection.insertOne((BasicDBObject) new BasicDBObjectBuilder()
                .add("type", CustomConfig.class.getCanonicalName())
                .add("payload", Collections.singletonMap("text", "TEST"))
                .add("last_updated", TIME.toString())
                .add("last_updated_by", "ID")
                .get());
        collection.insertOne((BasicDBObject) new BasicDBObjectBuilder()
                .add("type", AnotherCustomConfig.class.getCanonicalName())
                .add("payload", Collections.singletonMap("text", "TEST"))
                .add("last_updated", TIME.toString())
                .add("last_updated_by", "ID")
                .get());

        assertThat(collection.countDocuments()).isEqualTo(2L);
        assertThat(clusterConfigService.list())
                .hasSize(2)
                .containsOnly(CustomConfig.class, AnotherCustomConfig.class);
    }

    @Test
    public void listIgnoresInvalidClasses() throws Exception {
        @SuppressWarnings("deprecation")
        final MongoCollection<BasicDBObject> collection = mongoConnection.getMongoDatabase().getCollection(COLLECTION_NAME, BasicDBObject.class);
        collection.insertOne((BasicDBObject) new BasicDBObjectBuilder()
                .add("type", CustomConfig.class.getCanonicalName())
                .add("payload", Collections.singletonMap("text", "TEST"))
                .add("last_updated", TIME.toString())
                .add("last_updated_by", "ID")
                .get());
        collection.insertOne((BasicDBObject) new BasicDBObjectBuilder()
                .add("type", "invalid.ClassName")
                .add("payload", Collections.emptyMap())
                .add("last_updated", TIME.toString())
                .add("last_updated_by", "ID")
                .get());

        assertThat(collection.countDocuments()).isEqualTo(2L);
        assertThat(clusterConfigService.list())
                .hasSize(1)
                .containsOnly(CustomConfig.class);
    }

    public static class ClusterConfigChangedEventHandler {
        public volatile ClusterConfigChangedEvent event;

        @SuppressWarnings("unused")
        @Subscribe
        public void handleSimpleEvent(ClusterConfigChangedEvent event) {
            this.event = ClusterConfigChangedEvent.create(
                    event.date(),
                    event.nodeId(),
                    event.type()
            );
        }
    }
}
