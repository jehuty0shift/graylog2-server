package org.graylog.plugins.map.geoip;

import com.maxmind.db.MaxMindDbConstructor;
import com.maxmind.db.MaxMindDbParameter;

public class LookupResult {
    private final Country country;
    private final City city;
    private final Location location;

    @MaxMindDbConstructor
    public LookupResult(
            @MaxMindDbParameter(name = "country") Country country,
            @MaxMindDbParameter(name = "city") City city,
            @MaxMindDbParameter(name = "location") Location location
    ) {
        this.country = country;
        this.city = city;
        this.location = location;
    }

    public Country getCountry() {
        return this.country;
    }

    public City getCity() {
        return city;
    }

    public Location getLocation() {
        return location;
    }
}
