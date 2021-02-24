package org.graylog2.rest.models.audit.response;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.auto.value.AutoValue;
import org.graylog.autovalue.WithBeanGetter;

import java.util.List;

@JsonAutoDetect
@AutoValue
@WithBeanGetter
public abstract class AuditResponses {

    @JsonProperty
    public abstract List<AuditResponse> auditMessages();


    @JsonCreator
    public static AuditResponses create(@JsonProperty("audit_messages") List<AuditResponse> auditMessages) {
        return new AutoValue_AuditResponses(auditMessages);
    }

}
