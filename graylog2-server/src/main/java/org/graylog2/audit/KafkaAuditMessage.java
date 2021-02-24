package org.graylog2.audit;

import java.time.Instant;
import java.util.Map;

public class KafkaAuditMessage {

    public enum Status {
        SUCCESS,
        FAILURE
    }

    private Status status;
    private Instant timestamp;
    private String clientId;
    private String shortMessage;
    private String namespace;
    private String nodeName;
    private String object;
    private String actor;
    private String action;
    private Map<String, String> context;

    public KafkaAuditMessage(Status status, Instant timestamp, String clientId, String shortMessage, String namespace, String nodeName, String object, String actor, String action, Map<String, String> context) {
        this.status = status;
        this.timestamp = timestamp;
        this.clientId = clientId;
        this.shortMessage = shortMessage;
        this.namespace = namespace;
        this.nodeName = nodeName;
        this.object = object;
        this.actor = actor;
        this.action = action;
        this.context = context;
    }

    public Status getStatus() {
        return status;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getClientId() {
        return clientId;
    }

    public String getShortMessage() {
        return shortMessage;
    }

    public String getNamespace() {
        return namespace;
    }

    public String getNodeName() {
        return nodeName;
    }

    public String getObject() {
        return object;
    }

    public String getActor() {
        return actor;
    }

    public String getAction() {
        return action;
    }

    public Map<String, String> getContext() {
        return context;
    }

    @Override
    public String toString() {
        return "KafkaAuditMessage{" +
                "status=" + status +
                ", timestamp=" + timestamp +
                ", clientId='" + clientId + '\'' +
                ", message='" + shortMessage + '\'' +
                ", namespace='" + namespace + '\'' +
                ", object='" + object + '\'' +
                ", actor='" + actor + '\'' +
                ", action='" + action + '\'' +
                '}';
    }
}
