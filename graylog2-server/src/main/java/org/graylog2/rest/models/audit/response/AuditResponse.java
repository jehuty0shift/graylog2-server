package org.graylog2.rest.models.audit.response;


import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.auto.value.AutoValue;
import org.graylog.autovalue.WithBeanGetter;
import org.joda.time.DateTime;

import javax.annotation.Nullable;
import java.util.Map;

@JsonAutoDetect
@AutoValue
@WithBeanGetter
public abstract class AuditResponse {

    @JsonProperty
    public abstract String status();

    @JsonProperty
    public abstract DateTime timestamp();

    @JsonProperty
    public abstract String clientId();

    @JsonProperty
    public abstract String shortMessage();

    @JsonProperty
    public abstract String namespace();

    @JsonProperty
    public abstract String nodeName();

    @JsonProperty
    public abstract String object();

    @JsonProperty
    public abstract String actor();

    @JsonProperty
    public  abstract  String action();

    @JsonProperty
    @Nullable
    public  abstract Map<String, String> context();


    @JsonCreator
    public static AuditResponse create(@JsonProperty("status") String status,
                                       @JsonProperty("timestamp") DateTime timestamp,
                                       @JsonProperty("clientId") String clientId,
                                       @JsonProperty("shortMessage") String shortMessage,
                                       @JsonProperty("namespace") String namespace,
                                       @JsonProperty("node_name") String nodeName,
                                       @JsonProperty("object") String object,
                                       @JsonProperty("actor") String actor,
                                       @JsonProperty("action") String action,
                                       @JsonProperty("context") Map<String, String> context
                                       ) {
        return new AutoValue_AuditResponse(status, timestamp, clientId, shortMessage, namespace, nodeName, object, actor, action, context);
    }

}
