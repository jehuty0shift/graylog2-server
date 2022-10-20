package org.graylog.storage.opensearch2;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import org.opensearch.client.Node;
import org.opensearch.client.RestClient;
import org.opensearch.client.sniff.NodesSniffer;
import org.opensearch.client.sniff.OpenSearchNodesSniffer;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

class FilteredOpensearchNodesSniffer implements NodesSniffer {
    private final NodesSniffer nodesSniffer;
    private final String attribute;
    private final String value;

    static FilteredOpensearchNodesSniffer create(RestClient restClient, long sniffRequestTimeoutMillis, OpenSearchNodesSniffer.Scheme scheme, String filter) {
        final String attribute;
        final String value;
        if (!Strings.isNullOrEmpty(filter)) {
            final String[] conditions = filter.split(":");
            if (conditions.length < 2) {
                throw new IllegalArgumentException("Invalid filter specified for ES node discovery: " + filter);
            }
            attribute = conditions[0].trim();
            value = conditions[1].trim();
        } else {
            attribute = null;
            value = null;
        }
        final NodesSniffer nodesSniffer = new OpenSearchNodesSniffer(restClient, sniffRequestTimeoutMillis, scheme);

        return new FilteredOpensearchNodesSniffer(nodesSniffer, attribute, value);
    }

    @VisibleForTesting
    FilteredOpensearchNodesSniffer(NodesSniffer nodesSniffer, String attribute, String value) {
        this.nodesSniffer = nodesSniffer;
        this.attribute = attribute;
        this.value = value;
    }

    @Override
    public List<Node> sniff() throws IOException {
        final List<Node> nodes = this.nodesSniffer.sniff();

        if (attribute == null || value == null) {
            return nodes;
        }

        return nodes.stream()
                .filter(node -> nodeMatchesFilter(node, attribute, value))
                .collect(Collectors.toList());
    }

    private boolean nodeMatchesFilter(Node node, String attribute, String value) {
        return node.getAttributes()
                .getOrDefault(attribute, Collections.emptyList())
                .contains(value);
    }
}
