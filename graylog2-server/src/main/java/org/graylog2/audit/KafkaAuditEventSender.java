package org.graylog2.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringSerializer;
import org.graylog2.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;

@Singleton
public class KafkaAuditEventSender implements AuditEventSender {


    private static final Logger LOG = LoggerFactory.getLogger(KafkaAuditEventSender.class);
    private final boolean enabled;
    private String clientId;
    private String nodeName;
    private String topic;
    private KafkaProducer kProducer;
    private ObjectMapper objMapper;
    private String XOvhToken;

    @Inject
    public KafkaAuditEventSender(Configuration configuration) {

        this.enabled = configuration.isKafkaAuditEnabled();
        LOG.info("Kafka audit is {}enabled", enabled ? "" : "not ");
        if (!enabled) {
            return;
        }

        final Properties kProp = new Properties();
        final String bootstrapServers = configuration.getKafkaAuditBootstrapServers();
        topic = configuration.getKafkaAuditTopic();
        clientId = configuration.getKafkaAuditClientId();
        XOvhToken = configuration.getKafkaAuditXOVHToken();
        nodeName = configuration.getKafkaAuditNodeName();
        final String securityProtocol = configuration.getKafkaAuditSecurityProtocol();
        final String SASLUsername = configuration.getKafkaAuditSaslUsername();
        final String SASLPassword = configuration.getKafkaAuditSaslPassword();
        final String SSLTruststoreLocation = configuration.getKafkaAuditSSLTruststoreLocation();
        final String SSLTruststorePassword = configuration.getKafkaAuditSSLTruststorePassword();


        LOG.info("Kafka audit Sender configuration is :  bootstrapServers={}, topic={}, clientId={}, securityProtocol={}, SASLUsername={}", bootstrapServers, topic, clientId, securityProtocol, SASLUsername);

        kProp.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        kProp.put(ProducerConfig.CLIENT_ID_CONFIG, clientId);
        kProp.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        kProp.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());

        if ("SASL_SSL".equals(securityProtocol) || "SASL_PLAINTEXT".equals(securityProtocol)) {
            kProp.put("security.protocol", securityProtocol);
            kProp.put("sasl.mechanism", "PLAIN");
            if (!SSLTruststoreLocation.equals("") && !SSLTruststorePassword.equals("")) {
                kProp.put("ssl.truststore.location", SSLTruststoreLocation);
                kProp.put("ssl.truststore.password", SSLTruststorePassword);
            }

            final String jaasConfig = "org.apache.kafka.common.security.plain.PlainLoginModule required \n" +
                    "  username=\"" + SASLUsername + "\" \n" +
                    "  password=\"" + SASLPassword + "\";";
            kProp.put("sasl.jaas.config", jaasConfig);
        }


        this.kProducer = new KafkaProducer<String, String>(kProp);
        this.objMapper = new ObjectMapper();

    }


    @Override
    public void success(AuditActor actor, AuditEventType type) {
        success(actor, type, Collections.emptyMap());

    }

    @Override
    public void success(AuditActor actor, AuditEventType type, Map<String, Object> context) {
        sendAuditMessage("success", actor, type, context);
    }

    @Override
    public void failure(AuditActor actor, AuditEventType type) {
        failure(actor, type, Collections.emptyMap());

    }

    @Override
    public void failure(AuditActor actor, AuditEventType type, Map<String, Object> context) {
        sendAuditMessage("failure", actor, type, context);
    }

    private void sendAuditMessage(final String status, AuditActor actor, AuditEventType type, Map<String, Object> context) {
        if (!enabled) {
            return;
        }

        Instant timestamp = Instant.now();

        ObjectNode auditNode = buildGelf(objMapper.createObjectNode(), (double)timestamp.toEpochMilli() / 1000.0f);

        auditNode.put("_status", status);
        auditNode.put("_actor", actor.urn());
        auditNode.put("_namespace", type.namespace());
        auditNode.put("_object", type.object());
        auditNode.put("_action", type.action());
        auditNode.put("short_message", type.toTypeString());

        context.entrySet().stream().forEach(e -> auditNode.put("_" + e.getKey(), e.getValue().toString()));

        try {
            final String auditString = objMapper.writeValueAsString(auditNode);
            kProducer.send(new ProducerRecord(topic, null, timestamp.toEpochMilli(), null, auditString));
            LOG.debug("sent audit event {}", auditString);
        } catch (JsonProcessingException ex) {
            LOG.error("fatal error on JSON Processing, shouldn't happen", ex);
            throw new IllegalStateException(ex);
        }
    }

    private ObjectNode buildGelf(final ObjectNode objNode, double timestamp) {
        objNode.put("version", "1.1");
        objNode.put("host", clientId);
        objNode.put("timestamp", timestamp);
        objNode.put("_type", "audit");
        objNode.put("_client_id", clientId);
        objNode.put("_node_name", nodeName);
        if (!XOvhToken.equals("")) {
            objNode.put("_X-OVH-TOKEN", XOvhToken);
        }
        return objNode;
    }
}

