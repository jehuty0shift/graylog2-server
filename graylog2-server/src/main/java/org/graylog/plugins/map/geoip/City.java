package org.graylog.plugins.map.geoip;

import com.maxmind.db.MaxMindDbConstructor;
import com.maxmind.db.MaxMindDbParameter;

public class City {
    private final CityName cityName;

    @MaxMindDbConstructor
    public City(
            @MaxMindDbParameter(name = "names") CityName cityName
    ) {
        this.cityName = cityName;
    }

    public CityName getCityName() {
        return cityName;
    }
}
