package org.graylog2.shared.journal;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableMap;
import com.google.common.hash.Hasher;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.configuration.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Registry that stores codec configuration payloads and provides persistent ids for reuse.
 */
@Singleton
public class CodecInfoRegistry {
    private static final Logger LOG = LoggerFactory.getLogger(CodecInfoRegistry.class);
    private static final CodecInfoRegistryState EMPTY_STATE = CodecInfoRegistryState.create(ImmutableMap.of());
    private static final HashFunction HASH_FUNCTION = Hashing.goodFastHash(64);

    private final ClusterConfigService clusterConfigService;
    private final ConcurrentMap<Long, StoredCodecInformation> entries;

    @Inject
    public CodecInfoRegistry(final ClusterConfigService clusterConfigService) {
        this.clusterConfigService = clusterConfigService;
        final CodecInfoRegistryState state =
                Optional.ofNullable(clusterConfigService.get(CodecInfoRegistryState.class)).orElse(EMPTY_STATE);
        this.entries = new ConcurrentHashMap<>(state.entries());
    }

    /**
     * Registers a codec configuration and returns the generated id. If the configuration already exists the same id will be
     * returned and {@link Registration#isNew()} will be {@code false}.
     */
    public Registration register(final String codecName, final Configuration configuration) {
        final String serializedConfig = configuration == null ? null : configuration.serializeToJson();
        final long id = generateId(codecName, serializedConfig);
        final StoredCodecInformation candidate = new StoredCodecInformation(codecName, serializedConfig);

        final StoredCodecInformation existing = entries.putIfAbsent(id, candidate);
        if (existing == null) {
            persist();
            return new Registration(id, true);
        }

        if (!existing.equals(candidate)) {
            LOG.warn("Codec configuration hash collision detected for id {} (existing={}, new={}).",
                    id, existing.codecName, codecName);
            return new Registration(id, true);
        }

        return new Registration(id, false);
    }

    /**
     * Attempts to load codec information for the given id.
     */
    public Optional<CodecInformation> get(final long id) {
        StoredCodecInformation stored = entries.get(id);
        if (stored == null) {
            reload();
            stored = entries.get(id);
        }

        return Optional.ofNullable(stored).map(CodecInformation::new);
    }

    private long generateId(final String codecName, final String serializedConfig) {
        final Hasher hasher = HASH_FUNCTION.newHasher();
        hasher.putString(Objects.toString(codecName, ""), StandardCharsets.UTF_8);
        hasher.putString(Objects.toString(serializedConfig, ""), StandardCharsets.UTF_8);
        return hasher.hash().asLong();
    }

    private void persist() {
        clusterConfigService.write(CodecInfoRegistryState.create(ImmutableMap.copyOf(entries)));
    }

    private void reload() {
        final CodecInfoRegistryState state =
                Optional.ofNullable(clusterConfigService.get(CodecInfoRegistryState.class)).orElse(EMPTY_STATE);
        for (Map.Entry<Long, StoredCodecInformation> entry : state.entries().entrySet()) {
            entries.putIfAbsent(entry.getKey(), entry.getValue());
        }
    }

    @VisibleForTesting
    ConcurrentMap<Long, StoredCodecInformation> getEntries() {
        return entries;
    }

    public static class Registration {
        private final long id;
        private final boolean isNew;

        Registration(long id, boolean isNew) {
            this.id = id;
            this.isNew = isNew;
        }

        public long id() {
            return id;
        }

        public boolean isNew() {
            return isNew;
        }
    }

    public static class CodecInformation {
        private final StoredCodecInformation delegate;

        private CodecInformation(StoredCodecInformation delegate) {
            this.delegate = delegate;
        }

        public String codecName() {
            return delegate.codecName;
        }

        public String configJson() {
            return delegate.configJson;
        }

        public Configuration configuration() {
            return Configuration.deserializeFromJson(delegate.configJson);
        }
    }

    private static class CodecInfoRegistryState {
        private final Map<Long, StoredCodecInformation> entries;

        @JsonCreator
        CodecInfoRegistryState(@JsonProperty("entries") Map<Long, StoredCodecInformation> entries) {
            this.entries = entries == null ? ImmutableMap.of() : ImmutableMap.copyOf(entries);
        }

        @JsonProperty("entries")
        Map<Long, StoredCodecInformation> entries() {
            return entries;
        }

        static CodecInfoRegistryState create(Map<Long, StoredCodecInformation> entries) {
            return new CodecInfoRegistryState(entries);
        }
    }

    static class StoredCodecInformation {
        private final String codecName;
        private final String configJson;

        @JsonCreator
        StoredCodecInformation(@JsonProperty("codec_name") String codecName,
                               @JsonProperty("config_json") String configJson) {
            this.codecName = codecName;
            this.configJson = configJson;
        }

        @JsonProperty("codec_name")
        public String getCodecName() {
            return codecName;
        }

        @JsonProperty("config_json")
        public String getConfigJson() {
            return configJson;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            StoredCodecInformation that = (StoredCodecInformation) o;
            return Objects.equals(codecName, that.codecName) && Objects.equals(configJson, that.configJson);
        }

        @Override
        public int hashCode() {
            return Objects.hash(codecName, configJson);
        }
    }
}
