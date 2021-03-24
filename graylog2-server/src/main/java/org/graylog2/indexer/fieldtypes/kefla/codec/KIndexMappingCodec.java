package org.graylog2.indexer.fieldtypes.kefla.codec;

import com.mongodb.MongoClient;
import org.bson.BsonReader;
import org.bson.BsonWriter;
import org.bson.Document;
import org.bson.codecs.Codec;
import org.bson.codecs.DecoderContext;
import org.bson.codecs.DocumentCodec;
import org.bson.codecs.EncoderContext;
import org.bson.codecs.configuration.CodecRegistries;
import org.bson.codecs.configuration.CodecRegistry;
import org.graylog2.indexer.fieldtypes.kefla.KIndexMapping;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Date;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Created by jehuty0shift on 18/09/19.
 */
public class KIndexMappingCodec implements Codec<KIndexMapping> {

    private static Logger LOG = LoggerFactory.getLogger(KIndexMappingCodec.class);

    private Codec<Document> documentCodec;

    public KIndexMappingCodec() {
        CodecRegistry cRegistry = CodecRegistries.fromRegistries(CodecRegistries.fromProviders(new KeflaCodecProvider()), MongoClient.getDefaultCodecRegistry());
        documentCodec = new DocumentCodec(cRegistry);
    }

    @Override
    public KIndexMapping decode(BsonReader bsonReader, DecoderContext decoderContext) {
        DateTime dt = DateTime.now(DateTimeZone.UTC);
        Document document = documentCodec.decode(bsonReader, decoderContext);

        KIndexMapping kIM = new KIndexMapping(document.getString("index"), document.getString("kId"));

        List<Document> streamFields = document.getList("stream_fields", Document.class);

        for (Document strFDoc : streamFields) {
            StreamFieldsHolder strFHolder = StreamFieldsHolderCodec.fromDocument(strFDoc);
            kIM.addFieldsForStream(strFHolder.streamId, strFHolder.fields);
        }

        kIM.setUpdateDate(document.getDate("update_date").toInstant());

        final String index = "graylog2_3713";
        if(kIM.getIndex().equals(index)) {
            LOG.info("creating KIM for index {} took {} ms",index, DateTime.now(DateTimeZone.UTC).getMillis() - dt.getMillis());
        }
        return kIM;
    }

    @Override
    public void encode(BsonWriter bsonWriter, KIndexMapping kIndexMapping, EncoderContext encoderContext) {
        Document document = new Document();

        if(kIndexMapping.getkId() == null) {
            LOG.warn("cannot insert this kIndexMapping {}", kIndexMapping.toString());
        }

        document.put("index",kIndexMapping.getIndex());
        document.put("kId",kIndexMapping.getkId());
        document.put("update_date", Date.from(kIndexMapping.getUpdateDate()));

        List<StreamFieldsHolder> sfHolders = new ArrayList<>(kIndexMapping.getStreamFieldsMap().size());
        for(Map.Entry<String, Set<String>> strFieldsEntry : kIndexMapping.getStreamFieldsMap().entrySet()) {
            final String streamId = strFieldsEntry.getKey();
            final List<String> fields = new ArrayList<>(strFieldsEntry.getValue());
            sfHolders.add(new StreamFieldsHolder(streamId,fields));
        }

        document.put("stream_fields",sfHolders);

        documentCodec.encode(bsonWriter, document, encoderContext);
    }

    @Override
    public Class<KIndexMapping> getEncoderClass() {
        return KIndexMapping.class;
    }
}
