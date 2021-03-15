package org.graylog2.indexer.fieldtypes.kefla;

import com.mongodb.MongoClient;
import com.mongodb.WriteConcern;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.IndexOptions;
import org.bson.Document;
import org.bson.codecs.configuration.CodecRegistries;
import org.bson.codecs.configuration.CodecRegistry;
import org.graylog2.database.MongoConnection;
import org.graylog2.indexer.fieldtypes.kefla.codec.KeflaCodecProvider;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Singleton;

import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkNotNull;

@Singleton
public class KeflaService {

    private static final String KEFLA_MASTER_MAPPINGS = "kefla_master_mappings";
    private static final Logger LOG = LoggerFactory.getLogger(KeflaService.class);
    private final MongoCollection<KIndexMapping> kIMCollection;
    private final Map<String, Set<String>> fieldsByStreamIdMap;


    @Inject
    public KeflaService(MongoConnection mongoConnection) {

        CodecRegistry cRegistry = CodecRegistries.fromRegistries(CodecRegistries.fromProviders(new KeflaCodecProvider()), MongoClient.getDefaultCodecRegistry());
        kIMCollection = checkNotNull(mongoConnection).getMongoDatabase()
                .getCollection(KEFLA_MASTER_MAPPINGS)
                .withWriteConcern(WriteConcern.JOURNALED)
                .withDocumentClass(KIndexMapping.class)
                .withCodecRegistry(cRegistry);

        kIMCollection.createIndex(new Document("stream_fields.stream_id", 1), new IndexOptions().background(true).name("stream_id_index"));

        fieldsByStreamIdMap = new HashMap<>();

        kIMCollection.find().forEach((Consumer<? super KIndexMapping>) k -> {
            k.getStreamFieldsMap().entrySet().stream().forEach(
                    e -> {
                        Set<String> fields = fieldsByStreamIdMap.getOrDefault(e.getKey(), new HashSet<>(e.getValue().size()));
                        fields.addAll(e.getValue());
                        fieldsByStreamIdMap.putIfAbsent(e.getKey(), fields);
                    }
            );
        });

        LOG.info("Kefla service loaded {} streams", fieldsByStreamIdMap.size());

    }


    public Map<String, Set<String>> fieldByStreamId(Collection<String> streamIds, Collection<String> indexNamesToUpdate) {
        kIMCollection.find(Filters.in("index", indexNamesToUpdate)).forEach((Consumer<? super KIndexMapping>) k -> {
            k.getStreamFieldsMap().entrySet().stream().forEach(
                    e -> {
                        Set<String> fields = fieldsByStreamIdMap.getOrDefault(e.getKey(), new HashSet<>(e.getValue().size()));
                        fields.addAll(e.getValue());
                        fieldsByStreamIdMap.putIfAbsent(e.getKey(), fields);
                    }
            );
        });

        Map<String, Set<String>> fieldByStreamSubMap = new HashMap<>();

        streamIds.stream().forEach(e -> fieldByStreamSubMap.put(e, fieldsByStreamIdMap.getOrDefault(e, Collections.emptySet())));

        return fieldByStreamSubMap;
    }

    public Map<String, KIndexMapping> getKeflaFieldList(Collection<String> streamIds) {
        List<KIndexMapping> kIMList = new ArrayList<>();
        DateTime dt = DateTime.now(DateTimeZone.UTC);
        LOG.info("trying to find fields for streamIds {} at {}", streamIds, dt.toString());
        if (kIMCollection.countDocuments() > 2000) {
            kIMCollection.find(Filters.in("stream_fields.stream_id", streamIds)).batchSize(2000).into(kIMList);
        } else {
            kIMCollection.find().batchSize(2000).into(kIMList);
        }

        LOG.info("found {} KIndexMapping in {} ms", kIMList.size(), DateTime.now(DateTimeZone.UTC).getMillis() - dt.getMillis());
        return kIMList.stream().collect(Collectors.toMap(t -> t.getIndex(), t -> t));
    }


}
