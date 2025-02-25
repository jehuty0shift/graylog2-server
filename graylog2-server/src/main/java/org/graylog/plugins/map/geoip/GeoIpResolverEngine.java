/**
 * This file is part of Graylog.
 * <p>
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * <p>
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p>
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog.plugins.map.geoip;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.net.InetAddresses;
import com.maxmind.db.CHMCache;
import com.maxmind.db.Reader;
import org.graylog.plugins.map.config.GeoIpResolverConfig;
import org.graylog2.plugin.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.codahale.metrics.MetricRegistry.name;

public class GeoIpResolverEngine {
    private static final Logger LOG = LoggerFactory.getLogger(GeoIpResolverEngine.class);

    private final Timer resolveTime;
    private Reader databaseReader;
    private boolean enabled;


    public GeoIpResolverEngine(GeoIpResolverConfig config, MetricRegistry metricRegistry) {
        this.resolveTime = metricRegistry.timer(name(GeoIpResolverEngine.class, "resolveTime"));

        try {
            final File database = new File(config.dbPath());
            if (Files.exists(database.toPath())) {
                this.databaseReader = new Reader(database, Reader.FileMode.MEMORY_MAPPED, new CHMCache(4096 * 2));
                this.enabled = config.enabled();
            } else {
                if (LOG.isWarnEnabled()) {
                    LOG.warn("GeoIP database file does not exist: {}", config.dbPath());
                }
                this.enabled = false;
            }
        } catch (IOException e) {
            LOG.error("Could not open GeoIP database {}", config.dbPath(), e);
            this.enabled = false;
        }
    }

    public boolean filter(Message message) {
        if (!enabled) {
            return false;
        }

        List<Map.Entry<String, Object>> geoFields = new ArrayList<>();
        for (Map.Entry<String, Object> field : message.getFieldsEntries()) { //avoid copy and ConcurrentModificationException
            final String key = field.getKey();
            if ((key.endsWith("_ip") || key.endsWith("address") || key.endsWith("Address")) && !key.startsWith(Message.INTERNAL_FIELD_PREFIX)) { //using _ip fieldName convention and use address for some friends
                final LookupResult geoLocationInformation = extractGeoLocationLookupResult(field.getValue());
                if (geoLocationInformation != null && geoLocationInformation.getLocation() != null) {
                    addGeoInformationToGeoFields(key, geoLocationInformation, geoFields);
                }
            }
        }

        for (Map.Entry<String, Object> geoField : geoFields) {
            message.addField(geoField.getKey(), geoField.getValue());
        }

        return false;
    }

    private void addGeoInformationToGeoFields(final String key, LookupResult lookupResult, List<Map.Entry<String, Object>> geoFields) {
        // We will store the coordinates as a "lat,long" string
        org.graylog.plugins.map.geoip.Location location = lookupResult.getLocation();
        geoFields.add(Map.entry(key + "_geolocation", location.getLatitude() + "," + location.getLongitude()));
        org.graylog.plugins.map.geoip.Country country = lookupResult.getCountry();
        if (country != null) {
            geoFields.add(Map.entry(key + "_country_code", country.getIsoCode()));
        } else {
            geoFields.add(Map.entry(key + "_country_code", "N/A"));
        }
        org.graylog.plugins.map.geoip.City city = lookupResult.getCity();
        if (city != null && city.getCityName() != null) {
            geoFields.add(Map.entry(key + "_city_name", city.getCityName().getName()));
        } else {
            geoFields.add(Map.entry(key + "_city_name", "N/A"));
        }
    }

    LookupResult extractGeoLocationLookupResult(Object fieldValue) {
        final InetAddress ipAddress;
        if (fieldValue instanceof InetAddress) {
            ipAddress = (InetAddress) fieldValue;
        } else if (fieldValue instanceof String) {
            ipAddress = getIpFromFieldValue((String) fieldValue);
        } else {
            return null;
        }

        if (ipAddress == null) {
            return null;
        }

        try (Timer.Context ignored = resolveTime.time()) {
            return databaseReader.get(ipAddress, LookupResult.class);
        } catch (IOException e) {
            LOG.warn("error while locating geoIp information");
            return null;
        }
    }

    @Nullable
    @VisibleForTesting
    InetAddress getIpFromFieldValue(String fieldValue) {
        if ((Character.digit(fieldValue.charAt(0), 16) != -1
                || fieldValue.charAt(0) == ':'
                || fieldValue.charAt(0) == '[') && fieldValue.chars().noneMatch(c -> c > 'f') &&
                InetAddresses.isInetAddress(fieldValue)) {
            return InetAddresses.forString(fieldValue.trim());
        } else {
            return null;
        }
    }
}
