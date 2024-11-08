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
package org.graylog2.indexer.indexset;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Sorts;
import com.mongodb.client.result.DeleteResult;
import com.mongodb.client.result.UpdateResult;
import org.bson.UuidRepresentation;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.events.ClusterEventBus;
import org.graylog2.indexer.indexset.events.IndexSetCreatedEvent;
import org.graylog2.indexer.indexset.events.IndexSetDeletedEvent;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.streams.StreamService;
import org.mongojack.JacksonMongoCollection;

import javax.inject.Inject;
import java.util.*;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkState;
import static java.util.Objects.requireNonNull;

public class MongoIndexSetService implements IndexSetService {
    private static final String COLLECTION_NAME = "index_sets";

    private final JacksonMongoCollection<IndexSetConfig> collection;
    private final ClusterConfigService clusterConfigService;
    private final ClusterEventBus clusterEventBus;
    private final StreamService streamService;

    @Inject
    public MongoIndexSetService(MongoConnection mongoConnection,
                                MongoJackObjectMapperProvider objectMapperProvider,
                                StreamService streamService,
                                ClusterConfigService clusterConfigService,
                                ClusterEventBus clusterEventBus) {
        this(JacksonMongoCollection.builder().withObjectMapper(objectMapperProvider.get()).build(
                mongoConnection.getMongoDatabase(),COLLECTION_NAME,
                IndexSetConfig.class,
                UuidRepresentation.STANDARD),
                streamService,
                clusterConfigService,
                clusterEventBus);
    }

    @VisibleForTesting
    protected MongoIndexSetService(JacksonMongoCollection<IndexSetConfig> collection,
                                   StreamService streamService,
                                   ClusterConfigService clusterConfigService,
                                   ClusterEventBus clusterEventBus) {
        this.collection = requireNonNull(collection);
        this.streamService = streamService;
        this.clusterConfigService = clusterConfigService;
        this.clusterEventBus = requireNonNull(clusterEventBus);

        this.collection.createIndex(Sorts.ascending(IndexSetConfig.FIELD_INDEX_PREFIX), new IndexOptions().unique(true));
        this.collection.createIndex(Sorts.descending(IndexSetConfig.FIELD_CREATION_DATE));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<IndexSetConfig> get(String id) {
        return get(new ObjectId(id));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<IndexSetConfig> get(ObjectId id) {
        final Bson query = Filters.eq("_id", id);
        final IndexSetConfig indexSetConfig = collection.findOne(query);

        return Optional.ofNullable(indexSetConfig);
    }

    @Override
    public IndexSetConfig getDefault() {
        final DefaultIndexSetConfig defaultIndexSetConfig = clusterConfigService.get(DefaultIndexSetConfig.class);

        checkState(defaultIndexSetConfig != null, "No default index set configured. This is a bug!");

        final String indexSetId = defaultIndexSetConfig.defaultIndexSetId();
        return get(indexSetId)
                .orElseThrow(() -> new IllegalStateException("Couldn't find default index set <" + indexSetId + ">. This is a bug!"));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<IndexSetConfig> findOne(Bson query) {
        return Optional.ofNullable(collection.findOne(query));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<IndexSetConfig> findAll() {
        return Collections.unmodifiableList(collection.find().sort(Sorts.ascending("title")).into(new ArrayList<>()));
    }

    @Override
    public List<IndexSetConfig> findByIds(Set<String> ids) {
        return Collections.unmodifiableList(collection.find(Filters.in("_id",
                        ids.stream()
                                .map(ObjectId::new)
                                .collect(Collectors.toList())))
                .into(new ArrayList<>()));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<IndexSetConfig> findPaginated(Set<String> indexSetIds, int limit, int skip) {
        final List<Bson> idQuery = indexSetIds.stream()
                .map(id -> Filters.eq("_id", new ObjectId(id)))
                .collect(Collectors.toList());

        final Bson query = Filters.or(idQuery);

        return Collections.unmodifiableList(collection.find(query)
                .sort(Sorts.ascending("title"))
                .skip(skip)
                .limit(limit)
                .into(new ArrayList<>()));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public IndexSetConfig save(IndexSetConfig indexSetConfig) {
        final UpdateResult writeResult = collection.save(indexSetConfig);
        final IndexSetConfig savedObject;
        if (indexSetConfig.id() == null && writeResult.getUpsertedId() != null) {
            savedObject = collection.findOneById(writeResult.getUpsertedId());
        } else {
            savedObject = indexSetConfig;
        }

        final IndexSetCreatedEvent createdEvent = IndexSetCreatedEvent.create(savedObject);
        clusterEventBus.post(createdEvent);

        return savedObject;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int delete(String id) {
        return delete(new ObjectId(id));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int delete(ObjectId id) {
        if (!isDeletable(id)) {
            return 0;
        }

        final Bson query = Filters.eq("_id", id);
        final DeleteResult writeResult = collection.deleteOne(query);

        final int removedEntries = (int)writeResult.getDeletedCount();
        if (removedEntries > 0) {
            final IndexSetDeletedEvent deletedEvent = IndexSetDeletedEvent.create(id.toHexString());
            clusterEventBus.post(deletedEvent);
        }

        return removedEntries;
    }

    private boolean isDeletable(ObjectId id) {
        return streamService.loadAllWithIndexSet(id.toHexString()).isEmpty();
    }
}
