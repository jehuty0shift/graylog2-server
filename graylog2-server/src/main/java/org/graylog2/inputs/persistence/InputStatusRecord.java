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
package org.graylog2.inputs.persistence;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;
import org.mongojack.Id;
import org.mongojack.ObjectId;

@AutoValue
@JsonAutoDetect
@JsonDeserialize(builder = AutoValue_InputStatusRecord.Builder.class)
public abstract class InputStatusRecord {
    private static final String FIELD_ID = "id";
    public static final String FIELD_INPUT_STATE_DATA = "input_state_data";

    @Id
    @ObjectId
    @JsonProperty(FIELD_ID)
    public abstract String inputId();

    @JsonProperty(FIELD_INPUT_STATE_DATA)
    public abstract InputStateData inputStateData();

    public static Builder builder() {
        return new AutoValue_InputStatusRecord.Builder();
    }

    @AutoValue.Builder
    public static abstract class Builder {
        @Id
        @ObjectId
        @JsonProperty(FIELD_ID)
        public abstract Builder inputId(String inputId);

        @JsonProperty(FIELD_INPUT_STATE_DATA)
        public abstract Builder inputStateData(InputStateData inputStateData);

        public abstract InputStatusRecord build();
    }
}
