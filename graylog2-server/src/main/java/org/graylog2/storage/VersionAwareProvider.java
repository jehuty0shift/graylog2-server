/**
 * This file is part of Graylog.
 *
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog2.storage;

import org.graylog2.plugin.BackendVersion;
import org.graylog2.plugin.Version;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Provider;
import java.util.Map;

public class VersionAwareProvider<T> implements Provider<T> {
    private final BackendVersion elasticsearchMajorVersion;
    private final Map<BackendVersion, Provider<T>> pluginBindings;
    private static  final Logger LOG = LoggerFactory.getLogger(VersionAwareProvider.class);

    @Inject
    public VersionAwareProvider(@SearchEngineVersion BackendVersion searchEngineVersion, Map<BackendVersion, Provider<T>> pluginBindings) {
        this.elasticsearchMajorVersion = majorVersionFrom(searchEngineVersion);
        this.pluginBindings = pluginBindings;
    }

    @Override
    public T get() {
        final Provider<T> provider = this.pluginBindings.get(elasticsearchMajorVersion);
        if (provider == null) {
            LOG.error("not found {}",  elasticsearchMajorVersion);
            LOG.error("plugin bindings :\n {}", pluginBindings);
            throw new UnsupportedElasticsearchException(elasticsearchMajorVersion);
        }
        return provider.get();
    }

    private BackendVersion majorVersionFrom(BackendVersion version) {
        return BackendVersion.from(version.getSearchEngine(), Version.from(version.getMajorVersion(), 0, 0));
    }
}
