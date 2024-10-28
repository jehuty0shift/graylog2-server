package org.graylog.storage.opensearch2;

import jakarta.json.stream.JsonGenerator;
import org.graylog2.plugin.BackendVersion;
import org.graylog2.plugin.Message;
import org.joda.time.DateTime;
import org.opensearch.client.json.JsonpDeserializable;
import org.opensearch.client.json.JsonpMapper;
import org.opensearch.client.json.JsonpSerializable;
import org.opensearch.client.json.jsonb.JsonbJsonpMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Map;

import static org.graylog2.plugin.Tools.ES_DATE_FORMAT_FORMATTER;
import static org.graylog2.plugin.Tools.buildElasticSearchTimeFormat;

@JsonpDeserializable
public class JsonpMessage implements JsonpSerializable {
    private static final Logger LOG = LoggerFactory.getLogger(JsonpMessage.class);
    private final Message message;
    private final BackendVersion version;
    private static final char KEY_REPLACEMENT_CHAR = '_';


    public JsonpMessage(final Message message, BackendVersion version) {
        this.message = message;
        this.version = version;
    }


    @Override
    public void serialize(JsonGenerator generator, JsonpMapper mapper) {
        generator.writeStartObject();


        for (Map.Entry<String, Object> entry : message.getFieldsEntries()) {
            final String key = entry.getKey();
            if (key.equals(Message.FIELD_ID)) {
                continue;
            }

            final Object value = entry.getValue();
            if (Message.FIELD_TIMESTAMP.equals(key)) {
                final Instant timestampValue = (Instant) value;
                generator.write(Message.FIELD_TIMESTAMP, buildElasticSearchTimeFormat(timestampValue, version));
                continue;
            }

            if (key.contains(".")) {
                final String newKey = key.replace('.', KEY_REPLACEMENT_CHAR);
                // If the message already contains the transformed key, we skip the field and emit a warning.
                if (!message.hasField(newKey)) {
                    generator.writeKey(newKey);
                    mapper.serialize(value, generator);
                } else {
                    LOG.warn("Keys must not contain a \".\" character! Ignoring field \"{}\"=\"{}\" in message [{}] - Unable to replace \".\" with a \"{}\" because of key conflict: \"{}\"=\"{}\"",
                            key, value, message.getId(), KEY_REPLACEMENT_CHAR, newKey, message.getField(newKey));
                    LOG.debug("Full message with \".\" in message key: {}", message);
                }
            } else {
                //we trust thot-consistency to not have overwritten the key here.
                generator.writeKey(key);
                mapper.serialize(value, generator);
            }

        }

        if (message.getStreamIds().size() > 1) {
            generator.writeStartArray(Message.FIELD_STREAMS);
            for (String streamId : message.getStreamIds()) {
                generator.write(streamId);
            }
            generator.writeEnd();
        } else if (message.getStreamIds().size() == 1) {
            generator.write(Message.FIELD_STREAMS, message.getStreamIds().iterator().next());
        }

        generator.writeEnd();
    }

    public String toJSonString() {
        try (StringWriter writer = new StringWriter()) {
            JsonbJsonpMapper mapper = new JsonbJsonpMapper();
            try (JsonGenerator generator = mapper.jsonProvider().createGenerator(writer)) {
                serialize(generator, mapper);
            }
            return writer.toString();
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
