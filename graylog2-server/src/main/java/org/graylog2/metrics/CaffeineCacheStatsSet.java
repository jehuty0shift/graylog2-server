package org.graylog2.metrics;
import com.codahale.metrics.Gauge;
import com.codahale.metrics.Metric;
import com.codahale.metrics.MetricSet;
import com.github.benmanes.caffeine.cache.Cache;
import com.google.common.collect.ImmutableMap;

import java.util.Map;

import static com.codahale.metrics.MetricRegistry.name;

public class CaffeineCacheStatsSet implements MetricSet {
    private final Map<String, Metric> metrics;

    public CaffeineCacheStatsSet(final String prefix, final Cache<?, ?> cache) {
        this.metrics = ImmutableMap.<String, Metric>builder()
                .put(name(prefix, "requests"), (Gauge<Long>) () -> cache.stats().requestCount())
                .put(name(prefix, "hits"), (Gauge<Long>) () -> cache.stats().hitCount())
                .put(name(prefix, "misses"), (Gauge<Long>) () -> cache.stats().missCount())
                .put(name(prefix, "evictions"), (Gauge<Long>) () -> cache.stats().evictionCount())
                .put(name(prefix, "total-load-time-ns"), (Gauge<Long>) () -> cache.stats().totalLoadTime())
                .put(name(prefix, "load-successes"), (Gauge<Long>) () -> cache.stats().loadSuccessCount())
                .put(name(prefix, "load-exceptions"), (Gauge<Long>) () -> cache.stats().loadFailureCount())
                .put(name(prefix, "hit-rate"), (Gauge<Double>) () -> cache.stats().hitRate())
                .put(name(prefix, "miss-rate"), (Gauge<Double>) () -> cache.stats().missRate())
                .build();
    }

    @Override
    public Map<String, Metric> getMetrics() {
        return metrics;
    }
}
