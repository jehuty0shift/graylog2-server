package org.graylog.storage.opensearch2;

import com.google.common.collect.ImmutableSet;
import org.graylog2.plugin.Plugin;
import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.PluginModule;
import org.graylog2.plugin.Version;

import java.util.Collection;

public class Opensearch2Plugin implements Plugin {
    public static final Version SUPPORTED_ES_VERSION = Version.from(2, 0, 0);

    @Override
    public PluginMetaData metadata() {
        return new Opensearch2Metadata();
    }

    @Override
    public Collection<PluginModule> modules() {
        return ImmutableSet.of(
                new Opensearch2Module(),
                new ViewsESBackendModule()
        );
    }
}
