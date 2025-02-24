package org.graylog.plugins.map.geoip;

import com.maxmind.db.MaxMindDbConstructor;
import com.maxmind.db.MaxMindDbParameter;

public class Location {
    private final double latitude;
    private final double longitude;

    @MaxMindDbConstructor
    public Location(
            @MaxMindDbParameter(name = "latitude") double latitude,
            @MaxMindDbParameter(name = "longitude") double longitude
    ) {
        this.latitude = latitude;
        this.longitude = longitude;
    }

    public double getLatitude() {
        return latitude;
    }

    public double getLongitude() {
        return longitude;
    }
}
