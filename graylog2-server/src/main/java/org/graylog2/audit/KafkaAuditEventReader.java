package org.graylog2.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.PartitionInfo;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.glassfish.grizzly.http.server.util.Enumerator;
import org.graylog2.Configuration;
import org.graylog2.plugin.system.NodeId;
import org.hyperic.sigar.cmd.Top;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Singleton
public class KafkaAuditEventReader {

    private static final Logger LOG = LoggerFactory.getLogger(KafkaAuditEventSender.class);

    KafkaConsumer kConsumer;
    private final boolean enabled;
    private String clientId;
    private String topic;
    private ObjectMapper objMapper;
    private String XOvhToken;


    @Inject
    public KafkaAuditEventReader(Configuration configuration) {

        this.enabled = configuration.isKafkaAuditEnabled();
        LOG.info("Kafka audit Reader is {}enabled", enabled ? "" : "not ");
        if (!enabled) {
            return;
        }

        final Properties kProp = new Properties();
        final String bootstrapServers = configuration.getKafkaAuditBootstrapServers();
        topic = configuration.getKafkaAuditTopic();
        clientId = configuration.getKafkaAuditClientId();
        XOvhToken = configuration.getKafkaAuditXOVHToken();
        final String securityProtocol = configuration.getKafkaAuditSecurityProtocol();
        final String SASLUsername = configuration.getKafkaAuditSaslUsername();
        final String SASLPassword = configuration.getKafkaAuditSaslPassword();
        final String SSLTruststoreLocation = configuration.getKafkaAuditSSLTruststoreLocation();
        final String SSLTruststorePassword = configuration.getKafkaAuditSSLTruststorePassword();

        LOG.info("Kafka audit Reader configuration is :  bootstrapServers={}, topic={}, clientId={}, securityProtocol={}, SASLUsername={}", bootstrapServers, topic, clientId, securityProtocol, SASLUsername);

        kProp.put(ConsumerConfig.CLIENT_ID_CONFIG, clientId + "-reader");
        kProp.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        kProp.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        kProp.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        kProp.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, "false");
        kProp.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, 500);
        kProp.put(ConsumerConfig.MAX_POLL_INTERVAL_MS_CONFIG, 300000);
        kProp.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "latest");

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

        this.kConsumer = new KafkaConsumer<String, String>(kProp);
        this.objMapper = new ObjectMapper();
    }

    public synchronized List<KafkaAuditMessage> pollLastAuditMessages(int numMessages, Instant from) {

        LOG.debug("polling {} messages since {}", numMessages, from);
        List<KafkaAuditMessage> lastAuditMessages = new ArrayList<>(numMessages);

        List<PartitionInfo> pInfoList = kConsumer.partitionsFor(topic);

        int numByPart = numMessages / pInfoList.size();
        if(numByPart == 0) {
            numByPart = 1;
        }

        List<TopicPartition> topicPartitions = pInfoList.stream()
                .map(PartitionInfo::partition)
                .map(i -> new TopicPartition(topic, i))
                .collect(Collectors.toList());

        Map<TopicPartition, Long> endOffsets = kConsumer.endOffsets(topicPartitions);
        Map<TopicPartition, Long> beginOffsets = kConsumer.beginningOffsets(topicPartitions);

        if (endOffsets.entrySet().stream().map(e -> e.getValue() - beginOffsets.get(e.getKey())).reduce(Long::sum).get() < numMessages) {
            LOG.debug("num of message of topic is less than {}, consuming from start", numMessages);
            kConsumer.assign(topicPartitions);
            kConsumer.seekToBeginning(topicPartitions);
            ConsumerRecords<String, String> records = kConsumer.poll(Duration.ofSeconds(20));
            for (ConsumerRecord<String, String> record : records) {
                try {
                    LOG.debug("consumed audit message {}", record.value());
                    KafkaAuditMessage kAuditMessage = buildKAuditMessageFromJson(record.value());
                    lastAuditMessages.add(kAuditMessage);
                } catch (Exception ex) {
                    LOG.warn("couldn't deserialize AuditMassage {} due to {}", record.value(), ex);
                }
            }
        } else {
            LOG.debug("num of message of topic is more than {}, consuming {} message per partition", numMessages, numByPart);
            Map<TopicPartition, Long> offsetsForTime = kConsumer.offsetsForTimes(topicPartitions.stream().collect(Collectors.toMap(Function.identity(), tP -> new Long(from.toEpochMilli()))));
            for (Map.Entry<TopicPartition, Long> offset : offsetsForTime.entrySet()) {
                TopicPartition tPart = offset.getKey();
                kConsumer.assign(Collections.singletonList(offset.getKey()));
                LOG.debug("offsetTime for partition {} is {}", tPart.partition(), offset.getValue());
                if (offset.getValue() != null) {
                    kConsumer.seek(tPart, offset.getValue());
                } else {
                    long endOffsetTPart = endOffsets.get(tPart);
                    long beginOffsetTPart = beginOffsets.get(tPart);
                    long offsetFallback = endOffsetTPart - numByPart > beginOffsetTPart ? endOffsetTPart - numByPart : beginOffsetTPart;
                    LOG.debug("offset was null, offset fallback of partition {} is now {}", tPart.partition(), offsetFallback);
                    kConsumer.seek(offset.getKey(), offsetFallback);
                }
                int numOfRec = 0;
                while (numOfRec < numByPart) {
                    ConsumerRecords<String, String> records = kConsumer.poll(Duration.ofSeconds(3));
                    if (records.isEmpty()) {
                        LOG.debug("no more records on partition {}, breaking", tPart.partition());
                        break;
                    }
                    for (ConsumerRecord<String, String> record : records) {
                        LOG.debug("consumed audit message {}", record.value());
                        try {
                            KafkaAuditMessage kAuditMessage = buildKAuditMessageFromJson(record.value());
                            lastAuditMessages.add(kAuditMessage);
                            numOfRec++;

                            if (numOfRec == numByPart) {
                                //break to while loop
                                LOG.debug("got {} messages for partition {}", numOfRec, tPart.partition());
                                break;
                            }
                        } catch (Exception ex) {
                            LOG.warn("couldn't deserialize AuditMassage {} due to {}", record.value(), ex);
                        }
                    }
                }
            }
        }


        //sort by date desc
        lastAuditMessages.sort((k1, k2) -> {
            if (k1.getTimestamp().isAfter(k2.getTimestamp())) {
                return -1;
            } else if (k1.getTimestamp().equals(k2.getTimestamp())) {
                return 0;
            } else {
                return 1;
            }
        });

        return lastAuditMessages;
    }


    KafkaAuditMessage buildKAuditMessageFromJson(final String jsonString) throws Exception {
        JsonNode auditNode = objMapper.reader().readTree(jsonString);

        KafkaAuditMessage.Status status = auditNode.get("_status").asText().equals("success") ? KafkaAuditMessage.Status.SUCCESS : KafkaAuditMessage.Status.FAILURE;
        String actor = auditNode.get("_actor").asText();
        String namespace = auditNode.get("_namespace").asText();
        String object = auditNode.get("_object").asText();
        String action = auditNode.get("_action").asText();
        String message = auditNode.get("short_message").asText();
        String clientId = auditNode.get("_client_id").asText();
        String nodeName = auditNode.get("_node_name").asText();
        Instant timestamp = Instant.ofEpochMilli((long) (auditNode.get("timestamp").asDouble() * 1000f));

        List<String> mainAttributes = Arrays.asList(
                "_status",
                "_actor",
                "host",
                "_type",
                "_namespace",
                "version",
                "_object",
                "_action",
                "short_message",
                "_client_id",
                "timestamp",
                "_node_name",
                "_X-OVH-TOKEN");
        Map<String, String> context = new HashMap<>();

        for (Iterator<String> it = auditNode.fieldNames(); it.hasNext(); ) {
            String contextField = it.next();
            if (!mainAttributes.contains(contextField)) {
                context.put(contextField, auditNode.get(contextField).asText());
            }
        }

        return new KafkaAuditMessage(status, timestamp, clientId, message, namespace, nodeName, object, actor, action, context);
    }

}
