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

package org.graylog2.indexer.retention.strategies;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import org.graylog.autovalue.WithBeanGetter;
import org.graylog2.plugin.indexer.retention.RetentionStrategyConfig;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

@JsonAutoDetect
@JsonDeserialize(builder = DeletionRetentionStrategyConfig.Builder.class)
@AutoValue
@WithBeanGetter
public abstract class DeletionRetentionStrategyConfig implements RetentionStrategyConfig {
    private static final int DEFAULT_MAX_NUMBER_OF_INDICES = 20;

    @JsonProperty("max_number_of_indices")
    public abstract int maxNumberOfIndices();

    @JsonCreator
    public static DeletionRetentionStrategyConfig create(@JsonProperty(TYPE_FIELD) String type,
                                                         @JsonProperty("max_number_of_indices") @Min(1) int maxNumberOfIndices) {
        return DeletionRetentionStrategyConfig.Builder.builder().type(type).maxNumberOfIndices(maxNumberOfIndices).build();
    }

    @JsonCreator
    public static DeletionRetentionStrategyConfig create(@JsonProperty("max_number_of_indices") @Min(1) int maxNumberOfIndices) {
        return create(DeletionRetentionStrategyConfig.class.getCanonicalName(), maxNumberOfIndices);
    }

    public static DeletionRetentionStrategyConfig createDefault() {
        return create(DEFAULT_MAX_NUMBER_OF_INDICES);
    }

    @AutoValue.Builder
    public static abstract class Builder {

        @JsonCreator
        public static Builder builder() {
            return new AutoValue_DeletionRetentionStrategyConfig.Builder();
        }

        @NotNull
        @JsonProperty("type")
        public abstract Builder type(@NotNull String type);

        @NotNull
        @JsonProperty("max_number_of_indices")
        @Min(1)
        public abstract Builder maxNumberOfIndices(int maxDocsPerIndex);

        @NotNull
        public abstract DeletionRetentionStrategyConfig build();
    }
}
