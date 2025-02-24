package org.graylog.plugins.map.geoip;

import com.maxmind.db.MaxMindDbConstructor;
import com.maxmind.db.MaxMindDbParameter;

public class Country {
    private final String isoCode;

    @MaxMindDbConstructor
    public Country(
            @MaxMindDbParameter(name = "iso_code") String isoCode
    ) {
        this.isoCode = isoCode;
    }

    public String getIsoCode() {
        return this.isoCode;
    }

}
