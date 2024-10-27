package org.graylog.storage.opensearch2.views.migrations;

import com.google.common.collect.ImmutableMap;
import org.graylog.plugins.views.migrations.V20200730000000_AddGl2MessageIdFieldAliasForEvents;
import org.graylog.storage.opensearch2.OpensearchGraylogClient;
import org.graylog2.indexer.ElasticsearchException;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.indices.PutMappingRequest;

import javax.inject.Inject;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Set;

import static org.graylog2.plugin.Message.FIELD_GL2_MESSAGE_ID;

public class V20200730000000_AddGl2MessageIdFieldAliasForEventsOS2 implements V20200730000000_AddGl2MessageIdFieldAliasForEvents.ElasticsearchAdapter {

    private final OpensearchGraylogClient client;

    @Inject
    public V20200730000000_AddGl2MessageIdFieldAliasForEventsOS2(OpensearchGraylogClient client) {
        this.client = client;
    }

    @Override
    public void addGl2MessageIdFieldAlias(Set<String> indexPrefixes) {

        final String[] prefixesWithWildcard = indexPrefixes.stream().map(p -> p + "*").toArray(String[]::new);

        final PutMappingRequest putMappingRequest = new PutMappingRequest(prefixesWithWildcard)
                .indicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN_CLOSED)
                .source(ImmutableMap.of("properties", ImmutableMap.of(FIELD_GL2_MESSAGE_ID, aliasMapping())));

        try {
            final AcknowledgedResponse acknowledgedResponse = client.execute((c, requestOptions) -> c.indices().putMapping(putMappingRequest, requestOptions));
            if (!acknowledgedResponse.isAcknowledged()) {
                throw new ElasticsearchException(errorMsgFor(prefixesWithWildcard) + " Elasticsearch failed to acknowledge.");
            }
        } catch (ElasticsearchException e) {
            throw new ElasticsearchException(errorMsgFor(prefixesWithWildcard), e);
        }
    }

    private String errorMsgFor(String[] prefixesWithWildcard) {
        return "Failed to add field alias " + FIELD_GL2_MESSAGE_ID + " for indices " + Arrays.toString(prefixesWithWildcard) + ".";
    }

    static LinkedHashMap<String, Object> aliasMapping() {
        LinkedHashMap<String, Object> aliasMapping = new LinkedHashMap<>();
        aliasMapping.put("type", "alias");
        aliasMapping.put("path", "id");
        return aliasMapping;
    }
}
