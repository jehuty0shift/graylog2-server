/**
 * This file is part of Graylog.
 * <p>
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * <p>
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p>
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog2.indexer.fieldtypes;

import com.google.common.collect.ImmutableMap;
import com.mongodb.BasicDBObject;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.FindOneAndReplaceOptions;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.result.UpdateResult;
import org.bson.UuidRepresentation;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;
import org.graylog2.bindings.providers.MongoJackObjectMapperProvider;
import org.graylog2.database.MongoConnection;
import org.graylog2.database.MongoDBUpsertRetryer;
import org.graylog2.streams.StreamService;
import org.mongojack.JacksonMongoCollection;

import javax.inject.Inject;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Manages the "index_field_types" MongoDB collection.
 */
public class IndexFieldTypesService {
    private static final String FIELDS_FIELD_NAMES = String.format(Locale.US, "%s.%s", IndexFieldTypesDTO.FIELD_FIELDS, FieldTypeDTO.FIELD_NAME);

    private final JacksonMongoCollection<IndexFieldTypesDTO> db;
    private final StreamService streamService;

    @Inject
    public IndexFieldTypesService(MongoConnection mongoConnection,
                                  StreamService streamService,
                                  MongoJackObjectMapperProvider objectMapperProvider) {
        this.streamService = streamService;
        this.db = JacksonMongoCollection.builder().withObjectMapper(objectMapperProvider.get()).build(mongoConnection.getMongoDatabase(), "index_field_types",
                IndexFieldTypesDTO.class,
                UuidRepresentation.STANDARD);

        this.db.createIndex(new BasicDBObject(ImmutableMap.of(
                IndexFieldTypesDTO.FIELD_INDEX_NAME, 1,
                IndexFieldTypesDTO.FIELD_INDEX_SET_ID, 1
        )), new IndexOptions().unique(true));
        this.db.createIndex(new BasicDBObject(IndexFieldTypesDTO.FIELD_INDEX_NAME, 1), new IndexOptions().unique(true));
        this.db.createIndex(new BasicDBObject(FIELDS_FIELD_NAMES, 1));
        this.db.createIndex(new BasicDBObject(IndexFieldTypesDTO.FIELD_INDEX_SET_ID, 1));
    }

    public Optional<IndexFieldTypesDTO> get(String idOrIndexName) {
        try {
            return Optional.ofNullable(db.findOneById(new ObjectId(idOrIndexName)));
        } catch (IllegalArgumentException e) {
            // Not an ObjectId, try again with index_name
            return Optional.ofNullable(db.findOne(Filters.eq(IndexFieldTypesDTO.FIELD_INDEX_NAME, idOrIndexName)));
        }
    }

    public IndexFieldTypesDTO save(IndexFieldTypesDTO dto) {
        final UpdateResult save = db.save(dto);
        IndexFieldTypesDTO.Builder builder = IndexFieldTypesDTO.builder()
                .indexName(dto.indexName())
                .indexSetId(dto.indexSetId())
                .fields(dto.fields())
                .id(Objects.requireNonNull(save.getUpsertedId()).asObjectId().getValue().toHexString());
        return builder.build();
    }

    public Optional<IndexFieldTypesDTO> upsert(IndexFieldTypesDTO dto) {
        final IndexFieldTypesDTO update = MongoDBUpsertRetryer.run(() -> db.findOneAndReplace(
                Filters.and(
                        Filters.eq(IndexFieldTypesDTO.FIELD_INDEX_NAME, dto.indexName()),
                        Filters.eq(IndexFieldTypesDTO.FIELD_INDEX_SET_ID, dto.indexSetId())
                ),
                dto, new FindOneAndReplaceOptions().upsert(true)));


        return Optional.ofNullable(update);
    }

    public void delete(String idOrIndexName) {
        try {
            db.removeById(new ObjectId(idOrIndexName));
        } catch (IllegalArgumentException e) {
            // Not an ObjectId, try again with index_name
            db.deleteOne(Filters.eq(IndexFieldTypesDTO.FIELD_INDEX_NAME, idOrIndexName));
        }
    }

    public Collection<IndexFieldTypesDTO> findForIndexSet(String indexSetId) {
        return findByQuery(Filters.eq(IndexFieldTypesDTO.FIELD_INDEX_SET_ID, indexSetId));
    }

    public Collection<IndexFieldTypesDTO> findForIndexSets(Collection<String> indexSetIds) {
        return findByQuery(
                Filters.in(IndexFieldTypesDTO.FIELD_INDEX_SET_ID, indexSetIds)
        );
    }

    public Collection<IndexFieldTypesDTO> findForIndexName(Collection<String> indexNames) {
        return findByQuery(
                Filters.in(IndexFieldTypesDTO.FIELD_INDEX_NAME, indexNames)
        );
    }

    public Collection<IndexFieldTypesDTO> findForFieldNames(Collection<String> fieldNames) {
        return findByQuery(Filters.in(FIELDS_FIELD_NAMES, fieldNames));
    }

    public Collection<IndexFieldTypesDTO> findForFieldNamesAndIndices(Collection<String> fieldNames, Collection<String> indexNames) {
        final Bson query = Filters.and(
                Filters.in(IndexFieldTypesDTO.FIELD_INDEX_NAME, indexNames),
                Filters.in(FIELDS_FIELD_NAMES, fieldNames)
        );

        return findByQuery(query);
    }

    public Collection<IndexFieldTypesDTO> findForStreamIds(Collection<String> streamIds) {
        final Set<String> indexSetIds = streamService.loadByIds(streamIds)
                .stream()
                .filter(Objects::nonNull)
                .map(stream -> stream.getIndexSet().getConfig().id())
                .collect(Collectors.toSet());

        return findForIndexSets(indexSetIds);
    }

    public Collection<IndexFieldTypesDTO> findAll() {
        return findByQuery(Filters.empty());
    }

    private Collection<IndexFieldTypesDTO> findByQuery(Bson query) {
        return Collections.unmodifiableList(db.find(query).into(new ArrayList<>()));
    }
}
