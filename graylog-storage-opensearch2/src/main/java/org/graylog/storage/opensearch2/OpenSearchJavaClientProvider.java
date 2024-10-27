package org.graylog.storage.opensearch2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.module.blackbird.BlackbirdModule;
import com.github.joschi.jadconfig.util.Duration;
import org.apache.http.HttpHost;
import org.apache.http.client.CredentialsProvider;
import org.graylog2.system.shutdown.GracefulShutdownService;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.client.json.jackson.JacksonJsonpMapper;
import org.opensearch.client.opensearch.OpenSearchClient;
import org.opensearch.client.sniff.NodesSniffer;
import org.opensearch.client.sniff.OpenSearchNodesSniffer;
import org.opensearch.client.sniff.Sniffer;
import org.opensearch.client.transport.OpenSearchTransport;
import org.opensearch.client.transport.rest_client.RestClientTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

@Singleton
public class OpenSearchJavaClientProvider implements Provider<OpenSearchClient> {

    private static final Logger LOG = LoggerFactory.getLogger(OpenSearchJavaClientProvider.class);

    private final OpenSearchClient client;
    private final ObjectMapper objectMapper;

    @SuppressWarnings("unused")
    @Inject
    public OpenSearchJavaClientProvider(
            GracefulShutdownService shutdownService,
            @Named("elasticsearch_hosts") List<URI> hosts,
            @Named("elasticsearch_connect_timeout") Duration connectTimeout,
            @Named("elasticsearch_socket_timeout") Duration socketTimeout,
            @Named("elasticsearch_idle_timeout") Duration elasticsearchIdleTimeout,
            @Named("elasticsearch_max_total_connections") int maxTotalConnections,
            @Named("elasticsearch_max_total_connections_per_route") int maxTotalConnectionsPerRoute,
            @Named("elasticsearch_max_retries") int elasticsearchMaxRetries,
            @Named("elasticsearch_discovery_enabled") boolean discoveryEnabled,
            @Named("elasticsearch_discovery_filter") @Nullable String discoveryFilter,
            @Named("elasticsearch_discovery_frequency") Duration discoveryFrequency,
            @Named("elasticsearch_discovery_default_scheme") String defaultSchemeForDiscoveredNodes,
            @Named("elasticsearch_use_expect_continue") boolean useExpectContinue,
            CredentialsProvider credentialsProvider) {
        client = buildClient(
                hosts,
                connectTimeout,
                socketTimeout,
                maxTotalConnections,
                maxTotalConnectionsPerRoute,
                useExpectContinue,
                credentialsProvider);
        objectMapper = new ObjectMapper().registerModules(new BlackbirdModule(), new Jdk8Module(), new JavaTimeModule());

    }


    @Override
    public OpenSearchClient get() {
        return client;
    }

    private OpenSearchClient buildClient(
            List<URI> hosts,
            Duration connectTimeout,
            Duration socketTimeout,
            int maxTotalConnections,
            int maxTotalConnectionsPerRoute,
            boolean useExpectContinue,
            CredentialsProvider credentialsProvider) {
        final HttpHost[] esHosts = hosts.stream().map(uri -> new HttpHost(uri.getHost(), uri.getPort(), uri.getScheme())).toArray(HttpHost[]::new);

        final RestClientBuilder restClientBuilder = RestClient.builder(esHosts)
                .setRequestConfigCallback(requestConfig -> requestConfig
                        .setConnectTimeout(Math.toIntExact(connectTimeout.toMilliseconds()))
                        .setSocketTimeout(Math.toIntExact(socketTimeout.toMilliseconds()))
                        .setExpectContinueEnabled(useExpectContinue)
                        .setAuthenticationEnabled(true)
                )
                .setHttpClientConfigCallback(httpClientConfig -> httpClientConfig
                        .setMaxConnTotal(maxTotalConnections)
                        .setMaxConnPerRoute(maxTotalConnectionsPerRoute)
                        .setDefaultCredentialsProvider(credentialsProvider)
                );
        final OpenSearchTransport transport = new RestClientTransport(restClientBuilder.build(), new JacksonJsonpMapper(objectMapper));
        return new OpenSearchClient(transport);
    }

}
