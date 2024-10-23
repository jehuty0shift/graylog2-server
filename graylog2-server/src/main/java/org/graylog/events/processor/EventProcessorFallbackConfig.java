package org.graylog.events.processor;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonTypeName;
import org.graylog.events.contentpack.entities.EventProcessorConfigEntity;
import org.graylog2.contentpacks.EntityDescriptorIds;
import org.graylog2.plugin.rest.ValidationResult;

@JsonTypeName(EventProcessorFallbackConfig.TYPE_NAME)
public class EventProcessorFallbackConfig implements EventProcessorConfig {

    public static final String TYPE_NAME = "fallback";

    @JsonIgnore
    @Override
    public String type() {
        throw new UnsupportedOperationException();
    }

    @Override
    public ValidationResult validate() {
        throw new UnsupportedOperationException();
    }

    @Override
    public EventProcessorConfigEntity toContentPackEntity(EntityDescriptorIds entityDescriptorIds) {
        return null;
    }
}
