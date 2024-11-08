package org.graylog2.security;

import com.codahale.metrics.MetricRegistry;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.common.primitives.Ints;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;
import org.graylog2.metrics.CaffeineCacheStatsSet;
import org.graylog2.shared.metrics.MetricUtils;

import javax.inject.Inject;
import java.util.Collection;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class CaffeineShiroCacheManager implements CacheManager {
    private final ConcurrentHashMap<String, CaffeineCacheWrapper<Object, Object>> caches;
    private final MetricRegistry metricRegistry;


    @Inject
    public CaffeineShiroCacheManager(MetricRegistry metricRegistry) {
        this.metricRegistry = metricRegistry;
        this.caches = new ConcurrentHashMap<>();
    }

    @Override
    public <K, V> org.apache.shiro.cache.Cache<K, V> getCache(String name) throws CacheException {
        return (org.apache.shiro.cache.Cache<K, V>) caches.computeIfAbsent(name, k -> new CaffeineCacheWrapper<>(createCaffeineCache(), metricRegistry));
    }

    private Cache<Object, Object> createCaffeineCache() {
        return Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterWrite(1, TimeUnit.SECONDS)
                .build();
    }

    public static class CaffeineCacheWrapper<K, V> implements org.apache.shiro.cache.Cache<K, V> {
        private final Cache<K, V> caffeineCache;

        public CaffeineCacheWrapper(Cache<K, V> caffeineCache, MetricRegistry metricRegistry) {
            this.caffeineCache = caffeineCache;
            MetricUtils.safelyRegisterAll(metricRegistry, new CaffeineCacheStatsSet(MetricRegistry.name(CaffeineShiroCacheManager.class, "cache"), caffeineCache));
        }

        @Override
        public V get(K key) throws CacheException {
            return caffeineCache.getIfPresent(key);
        }

        @Override
        public V put(K key, V value) throws CacheException {
            caffeineCache.put(key, value);
            return value;
        }

        @Override
        public V remove(K key) throws CacheException {
            V value = caffeineCache.getIfPresent(key);
            caffeineCache.invalidate(key);
            return value;
        }

        @Override
        public void clear() throws CacheException {
            caffeineCache.invalidateAll();
        }

        @Override
        public int size() {
            return Ints.saturatedCast(caffeineCache.estimatedSize());
        }

        @Override
        public Set<K> keys() {
            return caffeineCache.asMap().keySet();
        }

        @Override
        public Collection<V> values() {
            return caffeineCache.asMap().values();
        }
    }
}
