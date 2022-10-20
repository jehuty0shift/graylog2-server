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
package org.graylog2.storage.providers;

import org.graylog2.plugin.BackendVersion;
import org.graylog2.plugin.Version;
import org.graylog2.storage.versionprobe.ElasticsearchProbeException;
import org.graylog2.storage.versionprobe.VersionProbe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

@Singleton
public class SearchEngineVersionProvider implements Provider<BackendVersion> {
    private static final Logger LOG = LoggerFactory.getLogger(SearchEngineVersionProvider.class);
    public static final String NO_HOST_REACHABLE_ERROR = "Unable to probe any host for Elasticsearch version";

    @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
    private final Optional<BackendVersion> fullVersionOverride;
    private final List<URI> backendHosts;
    private final VersionProbe versionProbe;
    private final AtomicCache<Optional<BackendVersion>> cachedVersion;

    @Inject
    public SearchEngineVersionProvider(@Named("search_engine") BackendVersion.SearchEngine searchEngine,
                                       @Named("elasticsearch_version") @Nullable Version versionNumberOverride,
                                       @Named("elasticsearch_hosts") List<URI> backendHosts,
                                       VersionProbe versionProbe,
                                       AtomicCache<Optional<BackendVersion>> cachedVersion) {

        this.fullVersionOverride = Optional.ofNullable(versionNumberOverride).map(v -> BackendVersion.from(searchEngine,v ));
        this.backendHosts = backendHosts;
        this.versionProbe = versionProbe;
        this.cachedVersion = cachedVersion;
    }

    @Override
    public BackendVersion get() {
        if (this.fullVersionOverride.isPresent()) {
            final BackendVersion explicitVersion = fullVersionOverride.get();
            LOG.info("Elasticsearch version set to " + explicitVersion + " - disabling version probe.");
            return explicitVersion;
        }

        try {
            return this.cachedVersion.get(() -> {
                final Optional<BackendVersion> probedVersion = this.versionProbe.probe(this.backendHosts);
                probedVersion.ifPresent(version -> LOG.info("Elasticsearch cluster is running v" + version));
                return probedVersion;
            })
                    .orElseThrow(() -> new ElasticsearchProbeException(NO_HOST_REACHABLE_ERROR + "!"));
        } catch (ExecutionException | InterruptedException e) {
            throw new ElasticsearchProbeException(NO_HOST_REACHABLE_ERROR + ": ", e);
        }
    }
}
