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

import com.mongodb.BasicDBObject;
import com.mongodb.client.model.Filters;
import com.mongodb.client.result.DeleteResult;
import com.mongodb.client.result.InsertOneResult;
import org.bson.UuidRepresentation;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.contentpacks.model.ContentPackInstallation;
import org.graylog2.contentpacks.model.ModelId;
import org.graylog2.contentpacks.model.entities.NativeEntityDescriptor;
import org.graylog2.database.MongoConnection;
import org.graylog2.rest.models.system.contentpacks.responses.ContentPackMetadata;
import org.mongojack.JacksonMongoCollection;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.*;
import java.util.stream.Collectors;

@Singleton
public class ContentPackInstallationPersistenceService {
    private static final String COLLECTION_NAME = "content_packs_installations";

    private final JacksonMongoCollection<ContentPackInstallation> dbCollection;

    @Inject
    public ContentPackInstallationPersistenceService(final MongoJackObjectMapperProvider mapperProvider,
                                                     final MongoConnection mongoConnection) {
        this(JacksonMongoCollection.builder().withObjectMapper(mapperProvider.get()).build(mongoConnection.getMongoDatabase(), COLLECTION_NAME,
                ContentPackInstallation.class, UuidRepresentation.STANDARD));
    }

    ContentPackInstallationPersistenceService(final JacksonMongoCollection<ContentPackInstallation> dbCollection) {
        this.dbCollection = dbCollection;

        dbCollection.createIndex(new BasicDBObject(ContentPackInstallation.FIELD_CONTENT_PACK_ID, 1));
        dbCollection.createIndex(new BasicDBObject(ContentPackInstallation.FIELD_CONTENT_PACK_ID, 1).append(ContentPackInstallation.FIELD_CONTENT_PACK_REVISION, 1));
    }

    public Set<ContentPackInstallation> loadAll() {
        return Collections.unmodifiableSet(dbCollection.find().into(new HashSet<>()));
    }

    public Set<ContentPackInstallation> findByContentPackIds(Set<ModelId> ids) {
        final Set<String> stringIds = ids.stream().map(ModelId::toString).collect(Collectors.toSet());
        final Bson query = Filters.in(ContentPackInstallation.FIELD_CONTENT_PACK_ID, stringIds);
        return Collections.unmodifiableSet(dbCollection.find(query).into(new HashSet<>()));
    }

    public Optional<ContentPackInstallation> findById(ObjectId id) {
        final ContentPackInstallation installation = dbCollection.findOneById(id);
        return Optional.ofNullable(installation);
    }

    public Set<ContentPackInstallation> findByContentPackIdAndRevision(ModelId id, int revision) {
        final Bson query = Filters.and(
                Filters.eq(ContentPackInstallation.FIELD_CONTENT_PACK_ID, id),
                Filters.eq(ContentPackInstallation.FIELD_CONTENT_PACK_REVISION, revision));
        return Collections.unmodifiableSet(dbCollection.find(query).into(new HashSet<>()));

    }

    public Set<ContentPackInstallation> findByContentPackId(ModelId id) {
        final Bson query = Filters.eq(ContentPackInstallation.FIELD_CONTENT_PACK_ID, id);
        return Collections.unmodifiableSet(dbCollection.find(query).into(new HashSet<>()));
    }

    public ContentPackInstallation insert(final ContentPackInstallation installation) {
        InsertOneResult result = dbCollection.insertOne(installation);
        return dbCollection.findOneById(result.getInsertedId());
    }

    public int deleteById(ObjectId id) {
        final DeleteResult writeResult = dbCollection.removeById(id);
        return (int) writeResult.getDeletedCount();
    }

    public Map<ModelId, Map<Integer, ContentPackMetadata>> getInstallationMetadata(Set<ModelId> ids) {
        final Set<ContentPackInstallation> contentPackInstallations = findByContentPackIds(ids);
        Map<ModelId, Map<Integer, ContentPackMetadata>> installationMetaData = new HashMap<>();
        for (ContentPackInstallation installation : contentPackInstallations) {
            Map<Integer, ContentPackMetadata> metadataMap = installationMetaData.get(installation.contentPackId());
            if (metadataMap == null) {
                metadataMap = new HashMap<>();
            }
            ContentPackMetadata metadata = metadataMap.get(installation.contentPackRevision());
            int count = 1;
            if (metadata != null) {
                count = metadata.installationCount() + 1;
            }
            ContentPackMetadata newMetadata = ContentPackMetadata.create(count);
            metadataMap.put(installation.contentPackRevision(), newMetadata);
            installationMetaData.put(installation.contentPackId(), metadataMap);
        }
        return installationMetaData;
    }

    /**
     * Returns the number of installations the given content pack entity ID is used in.
     *
     * @param entityId the native entity ID
     * @return number of installations
     */
    public long countInstallationOfEntityById(ModelId entityId) {
        final String field = String.format(Locale.ROOT, "%s.%s", ContentPackInstallation.FIELD_ENTITIES, NativeEntityDescriptor.FIELD_META_ID);

        return dbCollection.countDocuments(Filters.eq(field, entityId));
    }

    public long countInstallationOfEntityByIdAndFoundOnSystem(ModelId entityId) {
        final Bson query = Filters.elemMatch(ContentPackInstallation.FIELD_ENTITIES,
                Filters.and(
                        Filters.eq(NativeEntityDescriptor.FIELD_ENTITY_FOUND_ON_SYSTEM, true),
                        Filters.eq(NativeEntityDescriptor.FIELD_META_ID, entityId.id())));

        return dbCollection.countDocuments(query);
    }
}
