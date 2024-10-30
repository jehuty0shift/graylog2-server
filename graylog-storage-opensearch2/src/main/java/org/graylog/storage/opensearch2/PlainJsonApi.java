package org.graylog.storage.opensearch2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.opensearch.client.Request;
import org.opensearch.client.Response;

import javax.inject.Inject;

public class PlainJsonApi {
    private final ObjectMapper objectMapper;
    private final OpensearchGraylogClient client;

    @Inject
    public PlainJsonApi(ObjectMapper objectMapper,
                        OpensearchGraylogClient client) {
        this.objectMapper = objectMapper;
        this.client = client;
    }

    public JsonNode perform(Request request, String errorMessage) {
        return client.execute((c, requestOptions) -> {
            request.setOptions(requestOptions);
            final Response response = c.getLowLevelClient().performRequest(request);
            return objectMapper.readTree(response.getEntity().getContent());
        }, errorMessage);
    }
}
