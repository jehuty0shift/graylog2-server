package org.graylog.storage.opensearch2;

import com.google.inject.assistedinject.FactoryModuleBuilder;
import com.google.inject.binder.LinkedBindingBuilder;
import org.apache.http.client.CredentialsProvider;
import org.graylog.events.search.MoreSearchAdapter;
import org.graylog.plugins.views.migrations.V20200730000000_AddGl2MessageIdFieldAliasForEvents;
import org.graylog.storage.opensearch2.client.OSCredentialsProvider;
import org.graylog.storage.opensearch2.migrations.V20170607164210_MigrateReopenedIndicesToAliasesClusterStateOS2;
import org.graylog.storage.opensearch2.views.migrations.V20200730000000_AddGl2MessageIdFieldAliasForEventsOS2;
import org.graylog2.indexer.IndexToolsAdapter;
import org.graylog2.indexer.cluster.ClusterAdapter;
import org.graylog2.indexer.cluster.NodeAdapter;
import org.graylog2.indexer.counts.CountsAdapter;
import org.graylog2.indexer.fieldtypes.IndexFieldTypePollerAdapter;
import org.graylog2.indexer.indices.IndicesAdapter;
import org.graylog2.indexer.messages.MessagesAdapter;
import org.graylog2.indexer.searches.SearchesAdapter;
import org.graylog2.migrations.V20170607164210_MigrateReopenedIndicesToAliases;
import org.graylog2.plugin.BackendVersion;
import org.graylog2.plugin.VersionAwareModule;
import org.opensearch.client.RestHighLevelClient;

public class Opensearch2Module extends VersionAwareModule {
    @Override
    protected void configure() {
        bindForSupportedVersion(CountsAdapter.class).to(CountsAdapterOS2.class);
        bindForSupportedVersion(ClusterAdapter.class).to(ClusterAdapterOS2.class);
        bindForSupportedVersion(IndicesAdapter.class).to(IndicesAdapterOS2.class);
        bindForSupportedVersion(IndexFieldTypePollerAdapter.class).to(IndexFieldTypePollerAdapterOS2.class);
        bindForSupportedVersion(IndexToolsAdapter.class).to(IndexToolsAdapterOS2.class);
        bindForSupportedVersion(MessagesAdapter.class).to(MessagesAdapterOS2.class);
        bindForSupportedVersion(MoreSearchAdapter.class).to(MoreSearchAdapterOS2.class);
        bindForSupportedVersion(NodeAdapter.class).to(NodeAdapterOS2.class);
        bindForSupportedVersion(SearchesAdapter.class).to(SearchesAdapterOS2.class);
        bindForSupportedVersion(V20170607164210_MigrateReopenedIndicesToAliases.ClusterState.class)
                .to(V20170607164210_MigrateReopenedIndicesToAliasesClusterStateOS2.class);
        bindForSupportedVersion(V20200730000000_AddGl2MessageIdFieldAliasForEvents.ElasticsearchAdapter.class)
                .to(V20200730000000_AddGl2MessageIdFieldAliasForEventsOS2.class);


        install(new FactoryModuleBuilder().build(ScrollResultOS2.Factory.class));

        bind(RestHighLevelClient.class).toProvider(RestHighLevelClientProvider.class);
        bind(CredentialsProvider.class).toProvider(OSCredentialsProvider.class);
    }

    private <T> LinkedBindingBuilder<T> bindForSupportedVersion(Class<T> interfaceClass) {
        return bindForVersion(BackendVersion.fromOS(Opensearch2Plugin.SUPPORTED_ES_VERSION), interfaceClass);
    }
}
