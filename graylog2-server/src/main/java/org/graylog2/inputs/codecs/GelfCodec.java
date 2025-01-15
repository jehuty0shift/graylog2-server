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
package org.graylog2.inputs.codecs;

import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.google.inject.assistedinject.Assisted;
import org.apache.commons.lang3.StringUtils;
import org.graylog2.inputs.codecs.gelf.GELFMessage;
import org.graylog2.inputs.transports.TcpTransport;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.Tools;
import org.graylog2.plugin.configuration.Configuration;
import org.graylog2.plugin.configuration.ConfigurationRequest;
import org.graylog2.plugin.configuration.fields.ConfigurationField;
import org.graylog2.plugin.configuration.fields.NumberField;
import org.graylog2.plugin.inputs.annotations.Codec;
import org.graylog2.plugin.inputs.annotations.ConfigClass;
import org.graylog2.plugin.inputs.annotations.FactoryClass;
import org.graylog2.plugin.inputs.codecs.AbstractCodec;
import org.graylog2.plugin.inputs.codecs.CodecAggregator;
import org.graylog2.plugin.inputs.transports.NettyTransport;
import org.graylog2.plugin.journal.RawMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.inject.Inject;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@Codec(name = "gelf", displayName = "GELF")
public class GelfCodec extends AbstractCodec {
    private static final Logger log = LoggerFactory.getLogger(GelfCodec.class);
    private static final String CK_DECOMPRESS_SIZE_LIMIT = "decompress_size_limit";
    private static final int DEFAULT_DECOMPRESS_SIZE_LIMIT = 8388608;
    private static final String PREFIX_INVALID_MESSAGE = "GELF message <%s> %s";
    private static final String MESSAGE_KEY = "short_message";
    private static final String LEVEL_KEY = "level";
    private static final String FACILITY_KEY = "facility";
    private static final String EMPTY_FIELD_WARNING_KEY = "ovh_warn_empty_field";
    private static final String EMPTY_FIELD_WARNING_VALUE = "These values have no or empty keys: ";
    private static final String MALFORMED_FIELDS_KEY = "ovh_warn_malformed_field";
    private static final String MALFORMED_FIELDS_VALUE = "These fields are malformed: ";

    private final GelfChunkAggregator aggregator;
    private static final ObjectMapper objectMapper = JsonMapper.builder()
            .enable(
                    JsonReadFeature.ALLOW_UNESCAPED_CONTROL_CHARS,
                    JsonReadFeature.ALLOW_TRAILING_COMMA)
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            .build();
    private final long decompressSizeLimit;

    @Inject
    public GelfCodec(@Assisted Configuration configuration, GelfChunkAggregator aggregator) {
        super(configuration);
        this.aggregator = aggregator;
        this.decompressSizeLimit = configuration.getInt(CK_DECOMPRESS_SIZE_LIMIT, DEFAULT_DECOMPRESS_SIZE_LIMIT);
    }

    private static String stringValue(final JsonNode json, final String fieldName) {
        if (json != null) {
            final JsonNode value = json.get(fieldName);

            if (value != null) {
                return value.asText();
            }
        }
        return null;
    }

    private static long longValue(final JsonNode json, final String fieldName) {
        if (json != null) {
            final JsonNode value = json.get(fieldName);

            if (value != null) {
                return value.asLong(-1L);
            }
        }
        return -1L;
    }

    private static int intValue(final JsonNode json, final String fieldName) {
        if (json != null) {
            final JsonNode value = json.get(fieldName);

            if (value != null) {
                return value.asInt(-1);
            }
        }
        return -1;
    }

    private static BigDecimal timestampValue(final JsonNode json) {
        final JsonNode value = json.path(Message.FIELD_TIMESTAMP);
        if (value.isNumber()) {
            return value.isBigDecimal() ? value.decimalValue() : BigDecimal.valueOf(value.asDouble(-1.0));
        } else if (value.isTextual()) {
            try {
                return new BigDecimal(value.asText());
            } catch (NumberFormatException e) {
                log.debug("Unable to parse timestamp", e);
                return BigDecimal.valueOf(-1.0);
            }
        } else {
            return BigDecimal.valueOf(-1.0);
        }
    }


    private GELFMessage.Type getGELFType(byte[] payload) {
        if (payload.length < GELFMessage.Type.HEADER_SIZE) {
            throw new IllegalStateException("GELF message is too short. Not even the type header would fit.");
        }
        return GELFMessage.Type.determineType(payload[0], payload[1]);
    }

    private byte[] getJson(byte[] payload, long maxBytes) {
        try {
            switch (getGELFType(payload)) {
                case ZLIB:
                    return Tools.decompressZlibToByte(payload, maxBytes);
                case GZIP:
                    return Tools.decompressGzipToByte(payload, maxBytes);
                case UNCOMPRESSED:
                    return payload;
                case CHUNKED:
                case UNSUPPORTED:
                    throw new IllegalStateException("Unknown GELF type. Not supported.");
            }
        } catch (final IOException e) {
            // Note that the UnsupportedEncodingException thrown by 'new String' can never happen because UTF-8
            // is a mandatory JRE encoding which is always present. So we only need to mention the decompress exceptions here.
            throw new IllegalStateException("Failed to decompress the GELF message payload", e);
        }
        return new byte[0];
    }

    @Nullable
    @Override
    public Message decode(@Nonnull final RawMessage rawMessage) {
        final byte[] jsonBytes = getJson(rawMessage.getPayload(), decompressSizeLimit);

        final JsonNode node;

        try {
            node = objectMapper.readTree(jsonBytes);
            if (node == null) {
                throw new IOException("null result");
            }
        } catch (final Exception e) {
            throw new IllegalStateException("JSON is null/could not be parsed. Could not parse JSON, first 400 characters: " +
                    StringUtils.abbreviate(new String(jsonBytes, StandardCharsets.UTF_8), 403), e);
        }

        validateGELFMessage(node, rawMessage);

        final List<String> malformedFields = new ArrayList<>();
        final List<String> emptyFields = new ArrayList<>();

        // Timestamp.
        final BigDecimal messageTimestamp = timestampValue(node);
        final Instant timestamp;
        if (messageTimestamp.doubleValue() <= 0) {
            timestamp = Instant.ofEpochMilli(rawMessage.getTimestamp().getMillis());
        } else {
            // we treat this as a unix timestamp
            timestamp = Tools.InstantFromBigDecimal(messageTimestamp);
        }

        final Message message = new Message(
                stringValue(node, MESSAGE_KEY),
                stringValue(node, "host"),
                timestamp
        );

        message.addField(Message.FIELD_FULL_MESSAGE, stringValue(node, "full_message"));

        final String file = stringValue(node, "file");

        if (file != null && !file.isEmpty()) {
            message.addField("file", file);
        }

        final long line = longValue(node, "line");
        if (line > -1) {
            message.addField("line", line);
        }

        // Level is set by server if not specified by client.
        final int level = intValue(node, LEVEL_KEY);
        if (level > -1) {
            message.addField(LEVEL_KEY, level);
        }

        // Facility is set by server if not specified by client.
        final String facility = stringValue(node, FACILITY_KEY);
        if (facility != null && !facility.isEmpty()) {
            message.addField(FACILITY_KEY, facility);
        }

        // Add additional data if there is some.
        final Iterator<Map.Entry<String, JsonNode>> fields = node.fields();

        while (fields.hasNext()) {
            final Map.Entry<String, JsonNode> entry = fields.next();

            String key = entry.getKey();

            final JsonNode value = entry.getValue();

            // Do not index useless GELF "version" field.
            if ("version".equals(key)) {
                continue;
            }

            // Don't include GELF syntax underscore in message field key.
            if (key.startsWith("_")) {
                key = key.substring(1);
            } else {
                // We already set short_message and host as message and source. Do not add as fields again. Also ensure we don't add them as malformed
                addMalformedIfInvalid(key,malformedFields);
            }

            // if key contains just "_" or spaces, we discard the content of the value
            if (key.isBlank()) {
                emptyFields.add((value == null || value.isNull()) ? "<NULL>" : value.toString());
                continue;
            }

            // We already set short_message and host as message and source. Do not add as fields again.
            if (MESSAGE_KEY.equals(key) ||
                    "host".equals(key) ||
                    Message.FIELD_FULL_MESSAGE.equals(key)
            ) {
                continue;
            }

            // Skip standard or already set fields.
            if (message.getField(key) != null || (Message.RESERVED_FIELDS.contains(key) && !Message.RESERVED_SETTABLE_FIELDS.contains(key))) {
                continue;
            }


            // Convert JSON containers to Strings, and pick a suitable number representation.
            final Object fieldValue;
            if (value.isContainerNode()) {
                fieldValue = value.toString();
            } else if (value.isFloatingPointNumber()) {
                fieldValue = value.asDouble();
            } else if (value.isIntegralNumber()) {
                fieldValue = value.asLong();
            } else if (value.isNull()) {
                log.debug("Field [{}] is NULL. Skipping.", key);
                continue;
            } else if (value.isTextual()) {
                fieldValue = value.asText();
            } else {
                log.debug("Field [{}] has unknown value type. Skipping.", key);
                continue;
            }

            message.addField(key, fieldValue);
        }

        if (log.isTraceEnabled() && !malformedFields.isEmpty()) {
            log.trace("{}: {} {}",MALFORMED_FIELDS_KEY, MALFORMED_FIELDS_VALUE, "[".concat(String.join(", ", malformedFields)).concat("]"));
        }

        if (!emptyFields.isEmpty()) {
                message.addField(EMPTY_FIELD_WARNING_KEY, EMPTY_FIELD_WARNING_VALUE + "[".concat(String.join(", ", emptyFields)).concat("]"));
        }

        return message;
    }

    private void addMalformedIfInvalid(final String key, final List<String> malformedFields) {
        if (MESSAGE_KEY.equals(key) ||
                "host".equals(key) ||
                "line".equals(key) ||
                LEVEL_KEY.equals(key) ||
                FACILITY_KEY.equals(key) ||
                "X-OVH-INPUT".equals(key) || //to remove when fixed in flowgger.
                Message.FIELD_FULL_MESSAGE.equals(key) ||
                Message.RESERVED_FIELDS.contains(key) ||
                Message.RESERVED_SETTABLE_FIELDS.contains(key)
        ) {
            return;
        }
        if (!key.isBlank()) {
            malformedFields.add(key);
        }
    }


    private String invalidGelfMessageFormat(RawMessage rawMessage) {
        return String.format(Locale.ENGLISH, PREFIX_INVALID_MESSAGE, rawMessage.getId(), (rawMessage.getRemoteAddress() == null ? "" : "(received from <" + rawMessage.getRemoteAddress() + ">) "));
    }

    private void validateGELFMessage(JsonNode jsonNode, RawMessage rawMessage) {

        final JsonNode hostNode = jsonNode.path("host");
        if (hostNode.isMissingNode()) {
            if (log.isWarnEnabled()) {
                log.warn("{}is missing mandatory \"host\" field.", invalidGelfMessageFormat(rawMessage));
            }
        } else {
            if (!hostNode.isTextual()) {
                throw new IllegalArgumentException(invalidGelfMessageFormat(rawMessage) + "has invalid \"host\": " + hostNode.asText());
            }
            if (StringUtils.isBlank(hostNode.asText())) {
                throw new IllegalArgumentException(invalidGelfMessageFormat(rawMessage) + "has empty mandatory \"host\" field.");
            }
        }

        final JsonNode shortMessageNode = jsonNode.path(MESSAGE_KEY);
        final JsonNode messageNode = jsonNode.path("message");
        if (!shortMessageNode.isMissingNode()) {
            if (!shortMessageNode.isTextual()) {
                throw new IllegalArgumentException(invalidGelfMessageFormat(rawMessage) + "has invalid \"short_message\": " + shortMessageNode.asText());
            }
        } else if (!messageNode.isMissingNode()) {
            if (!messageNode.isTextual()) {
                throw new IllegalArgumentException(invalidGelfMessageFormat(rawMessage) + "has invalid \"message\": " + messageNode.asText());
            }
            if (StringUtils.isBlank(messageNode.asText())) {
                throw new IllegalArgumentException(invalidGelfMessageFormat(rawMessage) + "has empty mandatory \"message\" field.");
            }
        } else {
            throw new IllegalArgumentException(invalidGelfMessageFormat(rawMessage) + "is missing mandatory \"short_message\" or \"message\" field.");
        }

        final JsonNode timestampNode = jsonNode.path("timestamp");
        if (timestampNode.isValueNode() && !timestampNode.isNumber() && log.isWarnEnabled()) {
            log.warn("{}has invalid \"timestamp\": {}  (type: {})", invalidGelfMessageFormat(rawMessage), timestampNode.asText(), timestampNode.getNodeType().name());
        }
    }

    @Nullable
    @Override
    public CodecAggregator getAggregator() {
        return aggregator;
    }

    @FactoryClass
    public interface Factory extends AbstractCodec.Factory<GelfCodec> {
        @Override
        GelfCodec create(Configuration configuration);

        @Override
        Config getConfig();

        @Override
        Descriptor getDescriptor();
    }

    @ConfigClass
    public static class Config extends AbstractCodec.Config {
        @Override
        public ConfigurationRequest getRequestedConfiguration() {
            final ConfigurationRequest requestedConfiguration = super.getRequestedConfiguration();
            requestedConfiguration.addField(new NumberField(
                    CK_DECOMPRESS_SIZE_LIMIT,
                    "Decompressed size limit",
                    DEFAULT_DECOMPRESS_SIZE_LIMIT,
                    "The maximum number of bytes after decompression.",
                    ConfigurationField.Optional.OPTIONAL));

            return requestedConfiguration;
        }

        @Override
        public void overrideDefaultValues(@Nonnull ConfigurationRequest cr) {
            if (cr.containsField(NettyTransport.CK_PORT)) {
                cr.getField(NettyTransport.CK_PORT).setDefaultValue(12201);
            }

            // GELF TCP always needs null-byte delimiter!
            if (cr.containsField(TcpTransport.CK_USE_NULL_DELIMITER)) {
                cr.getField(TcpTransport.CK_USE_NULL_DELIMITER).setDefaultValue(true);
            }
        }
    }

    public static class Descriptor extends AbstractCodec.Descriptor {
        @Inject
        public Descriptor() {
            super(GelfCodec.class.getAnnotation(Codec.class).displayName());
        }
    }
}
