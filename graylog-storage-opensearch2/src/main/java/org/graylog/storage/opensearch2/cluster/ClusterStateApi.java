package org.graylog.storage.opensearch2.cluster;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Streams;
import org.graylog.storage.opensearch2.OpensearchGraylogClient;
import org.opensearch.client.Request;
import org.opensearch.client.Response;

import javax.inject.Inject;
import java.util.AbstractMap;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.stream.Collectors.groupingBy;
import static java.util.stream.Collectors.mapping;

public class ClusterStateApi {
    private final ObjectMapper objectMapper;
    private final OpensearchGraylogClient client;

    @Inject
    public ClusterStateApi(ObjectMapper objectMapper,
                           OpensearchGraylogClient client) {
        this.objectMapper = objectMapper;
        this.client = client;
    }

    public Map<String, Set<String>> fields(Collection<String> indices) {
        final Request request = request(indices);

        final JsonNode jsonResponse = client.execute((c, requestOptions) -> {
            request.setOptions(requestOptions);
            final Response response = c.getLowLevelClient().performRequest(request);
            return objectMapper.readTree(response.getEntity().getContent());
        }, "Unable to retrieve fields from indices: " + String.join(",", indices));

        //noinspection UnstableApiUsage
        return Streams.stream(jsonResponse.path("metadata").path("indices").fields())
                .flatMap(index -> allFieldsFromIndex(index.getKey(), index.getValue()))
                .collect(groupingBy(Map.Entry::getKey, mapping(Map.Entry::getValue, Collectors.toSet())));
    }

    private Stream<Map.Entry<String, String>> allFieldsFromIndex(String indexName, JsonNode indexMapping) {
        //noinspection UnstableApiUsage
        return Streams.stream(indexMapping.path("mappings").fields())
                .flatMap(documentType -> allFieldsFromDocumentType(indexName, documentType.getValue()));
    }

    private Stream<? extends Map.Entry<String, String>> allFieldsFromDocumentType(String indexName, JsonNode documentType) {
        //noinspection UnstableApiUsage
        return Streams.stream(documentType.path("properties").fields())
                .map(field -> new AbstractMap.SimpleEntry<>(indexName, field.getKey()));
    }

    private Request request(Collection<String> indices) {
        final StringBuilder apiEndpoint = new StringBuilder("/_cluster/state/metadata");
        if (!indices.isEmpty()) {
            final String joinedIndices = String.join(",", indices);
            apiEndpoint.append("/");
            apiEndpoint.append(joinedIndices);
        }

        return new Request("GET", apiEndpoint.toString());
    }
}
