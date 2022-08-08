package org.graylog2.rest.models.system.ux.responses;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.auto.value.AutoValue;
import org.graylog.autovalue.WithBeanGetter;

@AutoValue
@WithBeanGetter
@JsonAutoDetect
public abstract class UxStatusResponse {

    @JsonProperty("active")
    public abstract boolean active();

    @JsonCreator
    public static UxStatusResponse create(@JsonProperty("active") boolean active) {
        return new AutoValue_UxStatusResponse(active);
    }
}
