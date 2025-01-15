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
import org.joda.time.Period;

import javax.validation.constraints.NotNull;

@JsonAutoDetect
@AutoValue
@JsonDeserialize(builder = TimeBasedRotationStrategyConfig.Builder.class)
@WithBeanGetter
public abstract class TimeBasedRotationStrategyConfig implements RotationStrategyConfig {
    private static final Period DEFAULT_DAYS = Period.days(1);

    @JsonProperty("rotation_period")
    public abstract Period rotationPeriod();

    public static TimeBasedRotationStrategyConfig create(@JsonProperty(TYPE_FIELD) String type,
                                                         @JsonProperty("rotation_period") @NotNull Period maxTimePerIndex) {
        return TimeBasedRotationStrategyConfig.Builder.builder().type(type).rotationPeriod(maxTimePerIndex).build();
    }

    @JsonCreator
    public static TimeBasedRotationStrategyConfig create(@JsonProperty("rotation_period") @NotNull Period maxTimePerIndex) {
        return create(TimeBasedRotationStrategyConfig.class.getCanonicalName(), maxTimePerIndex);
    }

    public static TimeBasedRotationStrategyConfig createDefault() {
        return create(DEFAULT_DAYS);
    }


    @AutoValue.Builder
    public abstract static class Builder {
        @JsonCreator
        public static Builder builder() {
            return new AutoValue_TimeBasedRotationStrategyConfig.Builder();
        }

        @JsonProperty(TYPE_FIELD)
        public abstract Builder type(String type);

        @JsonProperty("rotation_period")
        public abstract Builder rotationPeriod(Period rotationPeriod);

        public abstract TimeBasedRotationStrategyConfig build();
    }

}
