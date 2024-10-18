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
package org.graylog2.contentpacks;

import com.google.common.collect.ImmutableCollection;
import com.google.common.collect.ImmutableMultimap;
import com.google.common.collect.ImmutableSet;
import com.mongodb.BasicDBObject;
import com.mongodb.DuplicateKeyException;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.result.DeleteResult;
import com.mongodb.client.result.InsertOneResult;
import org.bson.UuidRepresentation;
import org.bson.conversions.Bson;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.contentpacks.model.ContentPack;
import org.graylog2.contentpacks.model.Identified;
import org.graylog2.contentpacks.model.ModelId;
import org.graylog2.contentpacks.model.Revisioned;
import org.graylog2.database.MongoConnection;
import org.mongojack.JacksonMongoCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.*;

@Singleton
public class ContentPackPersistenceService {
    public static final String COLLECTION_NAME = "content_packs";

    private final JacksonMongoCollection<ContentPack> dbCollection;
    private static final Logger LOG = LoggerFactory.getLogger(ContentPackPersistenceService.class);

    @Inject
    public ContentPackPersistenceService(final MongoJackObjectMapperProvider mapperProvider,
                                         final MongoConnection mongoConnection) {
        this(JacksonMongoCollection.builder().withObjectMapper(mapperProvider.get()).build(mongoConnection.getMongoDatabase(), COLLECTION_NAME,
                ContentPack.class, UuidRepresentation.STANDARD));
    }

    ContentPackPersistenceService(final JacksonMongoCollection<ContentPack> dbCollection) {
        this.dbCollection = dbCollection;

        try {
            dbCollection.createIndex(new BasicDBObject(Identified.FIELD_META_ID, 1).append(Revisioned.FIELD_META_REVISION, 1), new IndexOptions().unique(true));
        } catch (DuplicateKeyException e) {
            // Ignore - this can happen if this runs before the migration of old content packs
        }
    }

    public Set<ContentPack> loadAll() {
        return Collections.unmodifiableSet(dbCollection.find().into(new HashSet<>()));
    }

    public Set<ContentPack> loadAllLatest() {
        final Set<ContentPack> allContentPacks = loadAll();
        final ImmutableMultimap.Builder<ModelId, ContentPack> byIdBuilder = ImmutableMultimap.builder();
        for (ContentPack contentPack : allContentPacks) {
            byIdBuilder.put(contentPack.id(), contentPack);
        }

        final ImmutableMultimap<ModelId, ContentPack> contentPacksById = byIdBuilder.build();
        final ImmutableSet.Builder<ContentPack> latestContentPacks = ImmutableSet.builderWithExpectedSize(contentPacksById.keySet().size());
        for (ModelId id : contentPacksById.keySet()) {
            final ImmutableCollection<ContentPack> contentPacks = contentPacksById.get(id);
            final ContentPack latestContentPackRevision = Collections.max(contentPacks, Comparator.comparingInt(Revisioned::revision));
            latestContentPacks.add(latestContentPackRevision);
        }

        return latestContentPacks.build();
    }

    public Set<ContentPack> findAllById(ModelId id) {
        return Collections.unmodifiableSet(dbCollection.find(Filters.eq(Identified.FIELD_META_ID, id)).into(new HashSet<>()));
    }

    public Optional<ContentPack> findByIdAndRevision(ModelId id, int revision) {
        final Bson query = Filters.and(Filters.eq(Identified.FIELD_META_ID, id), Filters.eq(Revisioned.FIELD_META_REVISION, revision));
        return Optional.ofNullable(dbCollection.findOne(query));
    }

    public Optional<ContentPack> insert(final ContentPack pack) {
        if (findByIdAndRevision(pack.id(), pack.revision()).isPresent()) {
            LOG.debug("Content pack already found: id: {} revision: {}. Did not insert!", pack.id(), pack.revision());
            return Optional.empty();
        }
        final InsertOneResult result = dbCollection.insertOne(pack);
        return Optional.of(dbCollection.findOneById(result.getInsertedId()));
    }

    public int deleteById(ModelId id) {
        final Bson query = Filters.eq(Identified.FIELD_META_ID, id);
        final DeleteResult dr = dbCollection.deleteMany(query);
        return (int) dr.getDeletedCount();
    }

    public int deleteByIdAndRevision(ModelId id, int revision) {
        final Bson query = Filters.and(Filters.eq(Identified.FIELD_META_ID, id), Filters.eq(Revisioned.FIELD_META_REVISION, revision));
        final DeleteResult dr = dbCollection.deleteMany(query);
        return (int) dr.getDeletedCount();
    }
}
