package org.graylog.plugins.map.geoip;

import com.maxmind.db.MaxMindDbConstructor;
import com.maxmind.db.MaxMindDbParameter;

public class CityName {
    private final String name;

    @MaxMindDbConstructor
    public CityName (
            @MaxMindDbParameter(name="en") String name
    ) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
