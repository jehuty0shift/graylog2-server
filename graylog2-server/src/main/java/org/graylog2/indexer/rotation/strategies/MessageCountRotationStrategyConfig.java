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

package org.graylog2.indexer.rotation.strategies;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import org.graylog.autovalue.WithBeanGetter;
import org.graylog2.plugin.indexer.rotation.RotationStrategyConfig;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

@JsonAutoDetect
@AutoValue
@JsonDeserialize( builder = MessageCountRotationStrategyConfig.Builder.class)
@WithBeanGetter
public abstract class MessageCountRotationStrategyConfig implements RotationStrategyConfig {
    private static final int DEFAULT_MAX_DOCS_PER_INDEX = 20_000_000;

    @JsonProperty("max_docs_per_index")
    public abstract int maxDocsPerIndex();

    public static MessageCountRotationStrategyConfig create(@JsonProperty(TYPE_FIELD) String type,
                                                            @JsonProperty("max_docs_per_index") @Min(1) int maxDocsPerIndex) {
        return   MessageCountRotationStrategyConfig.Builder.builder()
                .type(type)
                .maxDocsPerIndex(maxDocsPerIndex)
                .build();
    }

    @JsonCreator
    public static MessageCountRotationStrategyConfig create(@JsonProperty("max_docs_per_index") @Min(1) int maxDocsPerIndex) {
        return create(MessageCountRotationStrategyConfig.class.getCanonicalName(), maxDocsPerIndex);
    }

    public static MessageCountRotationStrategyConfig createDefault() {
        return create(DEFAULT_MAX_DOCS_PER_INDEX);
    }

    @AutoValue.Builder
    public abstract static class Builder {

        @JsonCreator
        public static Builder builder() {
            return new AutoValue_MessageCountRotationStrategyConfig.Builder();
        }

        @NotNull
        @JsonProperty("type")
        public abstract Builder type(@NotNull String type);

        @NotNull
        @JsonProperty("max_docs_per_index")
        @Min(1)
        public abstract Builder maxDocsPerIndex(int maxDocsPerIndex);

        @NotNull
        public abstract MessageCountRotationStrategyConfig build();
    }

}
